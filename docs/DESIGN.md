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

RA-6 (rule set 2.95.0) records deletion paths in the Python, JavaScript, Go and Rust models and reads shell deletion commands. Removing a home directory or its personal files, a filesystem/drive root, or repositories selected through recursive `.git` globs adds “deletes the user's files”: CRITICAL at install/build/import, MAJOR when found only in use-time code. Relative build/dist/fixture cleanup, created temporary directories and named application-cache subtrees are excluded. Unknown paths alone are not evidence of deletion of user files. The check is static; no target path is accessed.

RA-6 follow-up (rule set 2.99.0) exempts fully literal paths at least two components below home outside protected personal-data and credential subtrees. This is a lexical path rule, not proof that a package owns a folder. Home itself, whole top-level home folders, roots/drives, repository deletion and unknown/globbed home paths still trigger. Protected paths include personal folders, cloud storage, browser profiles, Mail/Messages/Photos and credentials; their ancestors are protected too because deleting an ancestor deletes that data. Matching is case-insensitive independent of the scanning host. Dot components and separators are normalized before classification, and unknown components cannot disappear through `..` to gain the new exemption. The existing named-cache exemption retains precedence, including unknown descendants under a known owner; whole caches and unknown owners are not exempt. Unknown paths without an identified home/root/repository target remain outside this detector's evidence. Import-risk attribution preserves the deleting call's line when another call adds no finding. No filesystem paths are accessed and no cleanup is executed.

RA-6 rework (rule set 2.101.0) restores protection for whole application-data containers and listed wallet, messenger, password-manager, keyring, mail, browser and developer-credential paths on macOS, Linux and Windows. Container ancestors remain protected; literal tool children outside the protected lists remain exempt. The names come from data categories, not benchmark or holdout samples. APPDATA/LOCALAPPDATA paths are recognized, and an unknown child directly under a root/drive remains dangerous.

A separate bounded provenance check can exempt a direct entry of the same exempt directory returned by a Node or Python directory listing, with optional literal suffixes. It follows single-source bindings, collection iteration, inline Node callbacks, filtering, indexing/destructuring and Python loops/comprehensions; Dirent and pathlib path forms retain the directory anchor. Reassignments, mutations, object escape, mismatched directories, extra unknown components, recursive listings, globs and visible API/symlink changes do not earn the new exemption. A Python comprehension's provenance stays within its expression. Provenance uses a separate work budget and reads its directory in literal-only mode; cycles cannot consume the original path reader's budget. This checks lexical containment and modeled native API origins, not filesystem ownership, absence of pre-existing symlinks, or API replacement outside the scanned source. The exempt directory is the boundary of the listed-name exception: an unknown entry name is not itself compared with protected basenames such as `.git` or vault-file suffixes. General import/use-time reachability is unchanged. The holdout is not inspected or scored here; John performs the one aggregate acceptance run against stack-0.1.9-b, then decides whether further narrowing or a revert is needed.

The native listing callee must have one unambiguous binding, followed through aliases without reassignment or escape; a conditional callee does not qualify. Name-array filters use the same mutation and escape checks as Dirent filters, including callback rest/third arguments, arguments, closures and helper calls. Python escape checks include positional and keyword values and star expansions. Its writes and escapes are keyed by lexical binding, including global/nonlocal writes, so an unrelated local with the same spelling does not invalidate a listing. Unknown scope ownership or an escaped native namespace keeps the original deletion reading.

Directory expressions at the listing and join also require single-write, scope-qualified literal/native provenance. Augmented, annotated, destructuring and other unsupported writes cannot reuse an earlier decoy value. Global/nonlocal declarations, dynamic namespace access and star imports conservatively disable listing exemptions in that source; failed provenance retains the may-resolve deletion reading. JavaScript global-object access similarly prevents an exemption.

F-05 (rule set 2.102.0) gives the path readers separate operations for Node join and resolve, Python POSIX and Windows joins, Go path/filepath joins, and Rust path pushes/joins. Later absolute components append in Node/Go joins; Python joins can reset the root or drive. Native-platform operations retain two correlated POSIX/Windows interpretations; either can add a deletion or credential-read finding, and a listing exemption requires the directory interpretations to agree. No target cwd or filesystem is consulted. A home API supplies an absolute symbolic anchor; a literal tilde component is not expanded by joining. Dot normalization retains unknown components when their cancellation would discard uncertainty. The shared path helper is removed. The regression matrix compares inert strings with Node/Python path libraries, plus Go standard-library tests selected for the running platform.

Path assembly checks a conservative MAX_TEXT bound before allocating intermediates, retains a bounded prefix plus unknown interpretation on overflow, and charges the engine work budget by text length. Callers collect each part once and evaluate the whole API operation only at completion (or once to check a listed-name prefix); resolve selects components before joining instead of repeatedly prepending strings. Shared input conversions and fixed-platform operations avoid duplicate work. These bounds preserve uncertainty instead of exempting truncated paths.

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
- **The scanned tree is read from its root's descriptor.** Every folder and
  file a project scan lists or reads under its root is reached from the root
  folder's descriptor a component at a time, no link followed (`core._Root`,
  LZ-03), never by a path the system resolves again. A reader you add takes
  the scan's `_Root` (`tree.read`, `tree.is_regular`, `tree.listdir_after`,
  which hold what it reads to what the walk found), not a path.

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
   the BOM and NUL sniff, PEP 263 cookies, every text codec Python has; for
   the Go reader, F-06, also `go_text`: Go source as the Go toolchain reads
   it, UTF-8 only, one BOM dropped, "\r\n" folded and a lone "\r" kept,
   where that is not the rules' text);
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
   `manifest_data`). A manifest's path is the walk's, root-relative with
   os.sep: on Windows the walk gives `scan_manifest` `windows` (core's
   `_WINDOWS_PATHS`, collect.js `WINDOWS`), so a backslash separates its
   folders there and a dependency's `node_modules\dep\test\package.json` is
   no package's root manifest (WIN-DEP-PATHS: `--deps` read the fixture's
   dependencies as the package's, SC-DEP-URL on Windows alone); elsewhere,
   and in a registry's members ('/'-separated on every system), a backslash
   is a file name's, as core reads a path on POSIX;
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

How the tree is read (LZ-03, the external security report of Oct 27:
CWE-367, time-of-check time-of-use). The MCP server checks a path against its
allowed roots once and then reads the tree; until this fix the walk and every
reader after it (`_collect`, the pycache, pruned-tree and marker probes, the
--deps and install-hook readers, the vendored-code readers, --verify-secrets'
lines) went by path, so whoever could change the tree during a
`scan_directory` or `quality_gate` call could swap a folder for a link and
have one outside the roots listed and read. Now a scan reads one `_Root`: the
root folder opened once (by the MCP server beneath its allowed root, a
directory at a time with no link followed; by the CLI as given, a link in its
path followed), every folder below it opened from its parent's descriptor
(`dir_fd`, `O_DIRECTORY | O_NOFOLLOW`) and listed with `os.scandir(fd)`, its
entries lstat'ed while it is open, and every file opened the same way
(`O_NOFOLLOW | O_NONBLOCK`), read and fstat'ed from its descriptor. A folder
is opened afresh from its parent when it is listed. Folders are kept open so
that reaching one costs a bounded number of opens whatever the tree's shape
(LZ-03's review, H3: with only the last eight kept, a "comb" N folders deep,
a leaf folder beside each level, reopened its path from the root for every
leaf, N²/2 opens: 1.8 million and 8 s of CPU at 1,900 levels, past 45 s at
3,000): the 16 used last, and every 16th folder on the way to the last one
opened (`_Root._spine`), so a folder is opened from one at most 16 levels
above it; the walk is linear in the folders it lists (about two opens per
folder on a comb). And the walk enters no folder deeper than 512 below the
root (`MAX_WALK_DEPTH`): one deeper is an SC-TRUNCATED finding ("it is nested
deeper than 512 folders"), and the result is incomplete. 512 is above
anything real: a path of 512 folders is longer than Linux's PATH_MAX (4,096
bytes) once its names average eight characters, so a project written, built
and installed by tools that open files by path stays far below it, nested
node_modules included (the walk before LZ-03 stopped at PATH_MAX by
accident, reporting the rest unreadable, INFO); what it bounds is a tree
made to be deep, which a tarball of a few kilobytes can be. A `__pycache__`
that deep is not entered either. The npm package's walk has the same cap
(`js/src/lib/collect.js`'s `MAX_WALK_DEPTH`, this one's twin: the same
finding, the same incomplete result and reason; its pruned-tree counts, its
probes for a dependency tree's markers and its --deps readers stop at it as
`_Root` does), so the two CLIs answer alike on a deeper tree whose paths
the system allows (`test_js_parity_core.DepthCapParityTests`: trees 511,
512 and 513 deep). The npm package goes by path, and a path longer than the
system allows (PATH_MAX: 4,096 bytes on Linux, 1,024 on macOS; a tree of
ten-character names passes it near 370 levels on Linux) stops its walk and
its --deps readers first: that folder or file is SC-TRUNCATED ("its path is
longer than this system allows") and the result incomplete ("N folders or
files were not read: their paths are longer than this system allows"),
where it was one Q-UNREADABLE note in a complete result (LZ-03's re-check).
The Python CLI reads such a tree whole below the cap; the two then differ in
findings, never in giving a complete result without them (the same test,
with ten-character names).
With the cap, the descriptors open at once are at most 32 + 16 besides the
root's (49 in all, far below the 256 a macOS process gets by default and
Linux's 1,024). The
kept ones are let go when the walk is done, so the readers after it reach
each folder by the name it has then. A kept folder that is renamed meanwhile,
even out of the root, is still the one read through its descriptor (LZ-03's
review, L1): what is reached through it is what is in that folder, which was
under the root when it was opened, and no link below it is followed; a file
put into it after it left the root would be read, which needs the same write
access that could put the file in the root.

What the walk found is held to what it found (LZ-03's review, H1 and H2). A
folder the walk found (`_Root.found`) that is a link, no folder or gone when
it is opened again, by the walk or a reader after it, and a regular file the
walk listed (`_Root.files`, `_file_record`: its device, inode, size and
modification and change times; on Windows its creation time for the change
time, below) that is a link, another kind of file (a
folder, a FIFO, a socket), another file (another inode, or one written since:
another size or time; a file deleted and made again under its name can get
the freed inode, as ext4 gives it, LZ-03's re-check 2, N5) or
gone when it is opened (the descriptor's fstat), looked at (`is_regular`: the
install hooks' stat, the vendored-code and agent-skill readers) or listed
again (`listdir_after`: the readers of a package's folder), changed while the
tree was read: it is not read, it is an SC-TRUNCATED finding ("it changed
while the tree was read"), and the result is incomplete. Before, a file
swapped for a folder or a FIFO between the walk's listing and its read was a
Q-UNREADABLE note, and one swapped after the walk was treated as absent by
the readers: a CRITICAL lost (SC-INSTALL-HOOK of the file a postinstall runs,
SC-USE-RISK of a vendored header) while the call stayed complete and the gate
passed. Q-UNREADABLE stays for a file that cannot be opened and is still the
file the walk listed (permission denied when listed and when read). What the
walk did not find (a file a hook names that was not there, a folder in a
pruned tree) is looked at as it is then, as before.

A reader's names come from a package's text (a hook's command,
`vendor/modules.txt`, an agent skill) and are held to the walk's listing as
the disk reads them (LZ-03's re-check, N1). A disk that takes some names for
one (macOS's APFS and Windows' NTFS by default ignore case and Unicode form;
Windows also drops a name's trailing dots and spaces and knows a file by its
8.3 short name) opens the walk's `lib/run.dat` for a hook's `LIB/RUN.DAT`,
so a check by the exact name let that file be swapped after the walk
unnoticed. A name not in the walk's listing of its folder (`_Root.names`:
every entry, its device, inode and kind) is looked up there (`_canon`,
`_alias`): what it reaches now is the walk's entry of the same device and
inode, and the reader is held to that entry as under its own name, where the
disk could take the reader's name for that entry's (LZ-03's re-check 2, N3:
an entry the walk listed under another name, renamed or hard linked into the
place of the one the name stood for, or a folder the walk listed put in the
place of the folder, is a change: the reader would be held to what that entry
was, not to what its own name stood for); where the walk listed no name the
disk could take it for (a folding this does not model), only while the walk's
own name still reaches that entry. What the walk did not list there (another
file, a link, a folder put in the entry's place or beside it) is a change. A
name shaped as an 8.3 short name may stand for any name the walk listed in
its folder: Windows makes the short name's extension from the long one's with
spaces left out and characters 8.3 cannot hold made `_` (`run.c++` is
`RUN~1.C__`; N4). A name that reaches nothing is a change too
where the walk listed a name the disk could take it for (in case, Unicode
form, trailing dots and spaces, an 8.3 name) and that entry is gone or
another now, or the folder changed while it was looked at (its modification
and change times, which every entry made, renamed or removed in it moves);
otherwise it names nothing, as when the walk listed the folder. On a disk
that tells names apart (Linux's usual ones) a hook's `LIB/RUN.DAT` is a file
that is not there, as before. Windows' listing (`DirEntry.stat`) has no file
IDs, so the walk lstat's each entry it lists there by its exact path (`\\?\`
and the absolute path: no name rewritten, no `MAX_PATH`) for its volume and
file ID (`_Root.listdir`), and holds every later lstat and fstat to them, as
to an inode: a file replaced by another is a change there too, whatever its
size and times (a copy made within one tick of the system's clock, some
15.6 ms, has the same ones on NTFS, which stamps a file's times from it; the
Windows runs of PR #17 met it by chance). Beside its size and modification
time, a file is held there to its creation time (`_held_time`), where POSIX
holds it to its change time: from Python 3.12 Windows' `os.lstat` and
`os.stat` give `st_ctime` the creation time (CPython's `win32_xstat` copies
`st_birthtime` into it) and `os.fstat` the change time, so the walk's lstat
and a read's fstat of a file written after it was made never agree on it;
`st_birthtime_ns` is the creation time in both, and on 3.10 and 3.11, which
have none, `st_ctime` is the creation time in both. An entry whose ID
cannot be had (its lstat fails) keeps the listing's stat, and no lstat or
fstat with an ID is taken for it; where neither has one (a disk that keeps
no file IDs), a name is the entry it is one name with, by the identity both
have now, and a regular file by its size and modification time. The counts
and probes that hold nothing to the listing (the pruned trees', the MCP
budget's, a dependency tree's probe) take the listing as it is, and the
walk's loop check uses no Windows file ID (3.10's and 3.11's 64-bit one of
ReFS's 128-bit IDs is not unique; nothing is followed there to loop).

These checks keep what is read consistent with what the walk found while the
tree is changed during a call (fail closed: SC-TRUNCATED and incomplete). The
boundary they serve is that nothing outside the root is listed or read, and
that holds whatever the tree does. Out of scope, as one who can change the
tree can change a file's content after the scan and before it is installed: a
write to a file while it is being read (after its open and fstat). Left, from
LZ-03's re-check 2:
- A disk whose times are coarse (FAT's two seconds, exFAT's ten
  milliseconds): a file written in place within one tick at the same size is
  not told from the file the walk listed (N5); and a name that reaches nothing
  while its folder's times did not move is taken for one that reached nothing
  then, so a file renamed away and back between two lookups on such a disk
  can be missed (N6, timing-dependent).
- Windows, where a file's writer can set every time NTFS keeps (creation,
  modification, change: `SetFileTime`, `SetFileInformationByHandle`), and no
  lstat gives the change time: a file written in place at the same size with
  its modification time kept or set back (or its time updates suspended) is
  not told from the file the walk listed, since writing in place never moves
  its creation time (POSIX's change time is the system's alone). A
  file replaced by another is told apart by its file ID; on Python 3.10 and
  3.11 a ReFS file ID is cut to 64 bits, which need not be unique. On a disk
  whose file IDs are 0 or can be reused (FAT and exFAT, which make a file's
  ID from where its entry is on the disk; some network redirectors), the old
  matching remains: a file is held to its size and modification time (and,
  where it has an ID, its creation time), and another file with the same
  ones is taken for it.
- A disk that takes names for one some other way (another Unicode version's
  case folding), for a name that reaches nothing because the walk's entry it
  stood for is gone.
- The npm package's walk on Windows: only `ENAMETOOLONG` is a path too long
  for the system (SC-TRUNCATED); if Windows reports a path past `MAX_PATH` as
  missing (`ENOENT`), that folder is a Q-UNREADABLE note in a complete
  result, as before (N7; not verified on Windows).

Nothing outside the root is listed or read, whatever the tree does
meanwhile; a link the listing shows is a Q-SYMLINK note and not followed, as
always. Not races, and as before: a hard link inside the root to a file
outside it is that file (read by its inode), and a folder mounted inside the
root (a bind mount) is walked. On a
normal tree nothing changes: the same files, findings and results, for both
packages (the npm package's walk, which has no MCP server, stays by path, with
the same depth cap; a path too long for the system is SC-TRUNCATED there).
Where there is no such open (Windows: no `dir_fd`, no
`scandir` of a descriptor, no `O_NOFOLLOW`), the tree is read by path and
checked: every folder on the way is lstat'ed (a link or a non-folder is
`_PathChanged`) and a folder is listed only when its final path
(`CreateFileW` with `FILE_FLAG_BACKUP_SEMANTICS`, then
`GetFinalPathNameByHandleW`) is under the root; a file is opened and kept
only when its handle's final path is (`_open_verified`). What this leaves on
Windows: a folder swapped between its check and its listing can have its
names listed (not a byte of its files read; those are checked one by one).
And the check opens what it checks, links followed: a link swapped in to a
UNC path (`\\host\share\x`) is opened before it is refused, which makes an
SMB connection, with the user's NTLM authentication, to that host (making
the link needs the symlink privilege or developer mode; the walk before
LZ-03, and `check_path`'s `realpath`, followed links anyway, so this is not
new). `FILE_FLAG_OPEN_REPARSE_POINT` is not used for the final-path check on
purpose: that check wants where the folder leads, links followed, to compare
it with the root; an lstat-like check of each component with it before the
open would close the UNC gap, and is left for a Windows pass. The tests stand Linux in for that path (`/proc/self/fd`, `F_GETPATH`
on macOS): `tests/mcp/test_mcp_path_race.py`. The cost, measured on a
20,000-file tree and on Lazaret's checkout: the walk within a few per cent
of its CPU time before; the path fallback about a third more on the larger
tree. On the comb trees of the review (CPU, min of 3): 2,143 opens and 0.11
s at 500 levels (the reviewed commit: 124,261 opens and 0.35 s); at 1,900 to
4,000 levels the walk stops at 512 (2,194 opens, 0.11-0.15 s); with the cap
lifted it reads them whole, 8,182 opens and 0.7 s at 1,900 levels, 12,928
and 1.3-1.6 s at 3,000 (the walk before LZ-03: 2.0-2.4 s at 1,900, and
2.4-2.6 s stopping at PATH_MAX at 3,000; the reviewed commit: 1.8 million
opens and 8.1-8.6 s at 1,900). The path fallback lstat's every folder on a
folder's way each time it reaches one, so its cost grows with the square of
the depth: a comb 512 deep costs it about 12 s (the Linux stand-in), which
the cap bounds.

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
A call of a helper is followed into it (0.1.9, Q-4; Python): a module-level
function of the file or one it imports from a project module (`f()`,
`mod.f()`), a method through `self`, through a name holding an instance made
in the same function (`x = C(…)`, `x = mod.C(…)`, the last such assignment),
on an instance made in place (`C(…).m()`) or on the class (`C.m()`). A
helper that returns untrusted data of its own — its body names a source, an
import whose summary reads one, or such a helper — gets a summary, the
pass's own reading of its body: the categories what its returns carry is
clean for. A call of it carries that data too.

Following only adds. The call's text is read as before — what its arguments
and receiver carry — and a placeholder name tainted with the summary's
categories is put among its arguments (one Yi syllable the text does not
hold; what neutralizes the call, `int(…)` or a sanitizer around it,
neutralizes the placeholder with it, and a finding through it says
"untrusted data that 'x.m()' returns"). Nothing a call's text carries is
ever taken away, however the helper is written, whatever state it reads and
however the call reaches it: a helper returning a constant clears nothing it
was given. So there is no summary of what a helper does with its parameters,
and none for a helper with no untrusted data of its own: its calls are their
text, as before. A helper the file defines twice, a property, a nested def,
a name more than `_HELPER_SAME_NAME` (8) defs of the file have, and an
import two of the project's files could be the module of add nothing.

A helper is read only when it may return a source and a call in the file
names it (a module's: when a file that imports it calls it), its callees
first; recursion is read as text where it recurses, a chain is followed six
deep (`_HELPER_DEPTH`), a file's helpers' bodies are read for at most
`_HELPER_LINES_BASE` + `_HELPER_LINES_PER_LINE` lines a line of it, 32 calls
of one statement (`_HELPER_CALLS`); a bound reached only leaves a call as
its text. A file in which nothing can be tainted (no source in its text, no
route handler, nothing imported that reads one) reads no helper. Another
file's helpers come from a project pre-pass (`taint_helpers`: the Python
files' imports resolved as the cross-file pass resolves them — `import a.b
[as c]`, `from [.]a import b [as c]`, a package's submodule — and, of the
modules whose text names a source or that import such a module,
`_HELPER_HOPS` deep, the functions and classes a file calls or reads an
attribute of summarized, what a module passes on of another's too, within
`_HELPER_PROJECT_LINES`): each file's scan gets the slice it imports as its
`"helpers"` argument, so the per-file pass still reads one file (the
commit-time gate's scan, a project scan of the staged files, follows those
files' helpers). A scan of a lone file and a registry scan in full mode
follow the file's own helpers alone.
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
- **Code in a string an eval call runs (EVAL-LITERAL, 0.1.9).** `eval("…")`,
  `Function("…")`, `new Function("a", "…")`, a global object's eval or
  Function by a computed name (`globalThis["ev" + "al"]("…")`, `window[k]("…")`)
  and Python's `eval`, `exec` and `compile` run the string they are handed;
  to the tests it was a string, so a send written inside one was quiet
  (found and first fixed by the external review agent, card 609dd639,
  Oct 21–22). The import-time and install-script tests now read each such
  string (`evalcode::codes`: a string literal or a template with no holes,
  or several joined by `+`, read as the runtime reads them; the call found
  on the text's tokens, so one in a comment or a string is none) with
  their own reading, as a text of its own, and give what it finds at the
  call's line, noted " (in a string it runs as code)". Strings in strings
  are read four deep (`_EVAL_DEPTH`); a text that nests them deeper is
  SC-TRUNCATED, never quiet. Each string is charged to the call's budget,
  its length and a fixed amount for its reading, which runs the whole
  test, so a text of many runs out (SC-TRUNCATED) rather than on. A
  string handed through a name (`eval(code)`) is not read: the
  received-code flows and the decoded view read what they can of those.
  docs/RUST_ENGINE.md §24.

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

Look-alike names and display text (0.1.9, FP-HOMOGLYPH-ORDINAL). SC-HOMOGLYPH reads names: each line with its
comments and literals left out (`names_code`), the literals being what every reading of the file agrees on. A file
that may hold JSX is read with JSX and without, and JSX text is code to the reading without JSX (where it would not
parse: an element begins where an expression may, `<` there being no operator), so a label's text was read as names:
`<span>Nº {index + 1}</span>` gave "'Nº' reads as 'No' but is spelled with U+00BA" (MAJOR, WARN; John's fp-tally of
Oct 21, `doomvault/src/library/LocalLibrary.tsx:581`). "Nº" is the usual way to write "number" in Spanish, Portuguese
and Italian. A look-alike matters where a name is resolved or trusted — identifiers, import and require specifiers,
package and host names, URLs, commands, a workflow's `uses:`. Now, when the look-alike found on a line of a file read
with JSX is a two-character name ending in an ordinal indicator and is not CRITICAL, the line's ordinals that are
display text are left out of the names too (`FileCtx::names_code_with`) and the line is read again: a look-alike after
them on the line is still found. A run is left out only when all of these hold (`ordinal_display_runs`; the review of
Oct 27, which found the first version's H1, ruled each):

- it is an ordinal (`ordinal_token`): digits, or one ASCII letter, then one ordinal indicator (U+00AA ª, U+00BA º),
  with no identifier character before or after it (a letter, a digit, `$`, `_`, ZWNJ/ZWJ, a `\`, any non-blank
  character past ASCII): `1º`, `2ª`, `Nº`, `nº`, `Mª`; `evªl`, `aºb`, `nºs` and any longer name holding one never are;
- it is not itself a look-alike of a dangerous name (CRITICAL is never lowered by this rule);
- the lexer's JSX reading holds it as text: JSX text, a JSX attribute's string, a string, a template's text, a
  comment. The lexer reads `of` (but after a `for` head's binding: `for (x of y)`) and a keyword used as a property's
  name (after `.` or `?.`) as operands: `of <b> evªl("1")` and `obj.return <b> evªl("1")` are valid JavaScript, two
  comparisons each, that it read as an element, so `evªl("1")` was JSX text (H1);
- the file is not JavaScript without JSX (`jsx_display_spans`): its plain parse (jsparse, as a script and as a module)
  fails — Node runs a `.js`, `.mjs` or `.cjs` file without JSX, and a file that parses so holds no display text — and
  its JSX reading parses (as JavaScript's, or as TypeScript's for a `.tsx` file);
- the parser's JSX reading holds it as text too: a JSXText node, a string Literal (a JSX attribute's among them) or a
  template's TemplateElement. Where the lexer's reading and the parser's differ, the run is a name.

The engine is not told a file's extension (the hosts say only whether it is read with JSX), so the plain-parse rule
holds for every file read with JSX; a `.jsx` or `.tsx` file that holds JSX never parses without it. Every other
look-alike in display text (`pаypal` with a Cyrillic а in JSX text: MAJOR, as before) and an ordinal in a name
(`const Nº`), in a file read without JSX, or after no letter or digit, are read as before; Python reads `Nº` as the
name `No` (NFKC), as it always did. The rule's other confusables were looked at in JSX text (synthetic labels, before
and after): the micro sign (`10µs`), a Cyrillic word of mapped letters alone (`Сорок`), `№` and Roman numerals (`Ⅻ`)
were already quiet (their skeleton is not ASCII, or holds no ASCII letter); superscript abbreviation letters (`Mᵐᵉ`,
`Mˡˡᵉ`), ligatures (`ﬁle`), fullwidth letters beside ASCII (`Ｗi-Fi`), the script l of `mℓ` and a Greek word with a
Latin letter (`ΗΟΤΕL`) are still MAJOR there: display text by the same reasoning, left as they are (only the ordinals
were asked for; a superscript letter is the nearest case, its quieting John's call).

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
   label sends, and raw IP addresses are independent reasons. D-22's
   `signs::label_view` blanks comments/docstrings only after the language
   model reads the text and no self-source or file-reading capability
   marker occurs. Any file read retains prose regardless of filename
   spelling, including aliases and assembled paths. Python parse/lex/model
   failures retain raw text. JavaScript keeps function/class/method/literal
   source spans. These are conservative scanner checks, not runtime proof
   (a string's address still counts) — at import time they and a
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

#### SC-EVAL-DECODE: proven visible execution (FP-PDFJS-DECODE, 0.1.9)

SC-EVAL-DECODE keeps BLOCKER unless a narrow proof establishes the exemption.
A RegExp receiver must be a literal, an intact global construction, or a single
binding whose uses preserve that proof; members and optional calls are not
proven. Both the literal fast path and tree path require file-wide integrity.
Any direct eval (including `eval("require")`), unresolved dynamic code,
reflection that can reach a regex, unknown computed property, or write to a
protected constructor, prototype or encoder closes the exemption. The tree can
prove a constructor/prototype read unrelated for primitive literals and fresh
containers. Above 2 MB a conservative lexical guard replaces that proof.

A round trip requires a single, unchanged encoding of literal source text and
an untransformed template passed directly to child_process `exec`/`execSync`.
The entire command must be plain `node`, one `-e`, `--eval` or `-p` flag, and
one quoted argument. That argument is parsed as exactly one supported
`eval`, `Function(…)()`, `new Function(…)()` or `vm.runInThisContext` expression
with the matching built-in decoder. Bindings, additional statements, command
options, shell transformations, tagged templates, stored commands, unknown
computed keys and encoder mutations retain BLOCKER. Proof work is bounded;
exhausting it leaves the warning intact.

Visible source is checked for unresolved dynamic execution before the
install-script risk heuristic is consulted. Nonliteral imports/require and
child commands are refused; eval/Function/vm and timer facilities are
conservatively refused even where a nested literal might eventually be
provable. A proven benign source is INFO; a risky source retains its risk
severity and reasons. Every accepted round trip on a line contributes its own
finding, including those before or after an unproven BLOCKER. Order and
minification do not discard a stronger result.

This external-review amendment supersedes the original `eval("name.path")`
relaxation and broad template-hole exemption. It intentionally gives up
precision where integrity or the complete child program is uncertain. Real
pdf.js files containing those facilities can therefore remain BLOCKER.
Python behavior and the rule-set assignment are unchanged. Acceptance cases
are shared in `rust/crates/lazaret-engine/tests/data/decode-review.json` and
run from Rust, Python, npm and native/WASM parity tests, including both sides
of the 2 MB boundary. Fixtures are inert text and are never executed.

#### Model files: what loading one runs (FP-MODEL-FILES, 0.1.9)

A PyTorch checkpoint is a zip by design (torch.save: `<archive>/data.pkl`, the storages as `data/<n>`, `version`,
`byteorder`), so every repository and package that shipped one was SC-NESTED-ARCHIVE (MINOR: WARN) — scan-all's run
of Oct 20 gave `github:ObsidianArch02/fireredasr2s-mlx` WARN for its `golden/golden.pt` alone — while the real risk
went unread: loading a checkpoint (torch.load without `weights_only=True`, a Lightning `.ckpt`, joblib.load,
pickle.load, numpy.load with `allow_pickle=True`) unpickles it, and a pickle runs whatever its globals name and its
REDUCE, BUILD, NEWOBJ, INST and OBJ opcodes call. The engine now reads a model file's pickles for what they would
run, never unpickling them (`rust/crates/lazaret-engine/src/pickle/`, RUST_ENGINE.md):

- **Which files.** By content, whatever the name: a zip whose first member is `<archive>/data.pkl` (torch.save
  writes it first), an `.npy` (numpy.savez) or a pickle by its name (pandas' `to_pickle('frame.pkl.zip')`, whose one
  member `read_pickle` reads: a zip of more than that pickle keeps SC-NESTED-ARCHIVE); PyTorch's legacy stream (its magic number pickled, then four more
  pickles) and its oldest tar; a pickle stream of protocol 2 to 5 (PROTO and an opcode); zlib or gzip around a
  pickle (joblib's compressors); a protocol 0 GLOBAL at the start of text that reads to its STOP. By name (`.pkl`,
  `.pickle`, `.pck`, `.pcl`, `.joblib`, and those before a compressor's extension): a pickle of protocol 0 or 1,
  and bzip2, xz, lzma or lz4 around one, which the engine cannot decompress. safetensors, ONNX, plain `.npy` data
  and the like hold no code and are not model files to Lazaret.
- **What is read.** Every pickle the loader would unpickle: each `.pkl` member of a checkpoint's zip (a second
  `data.pkl` too; the members are found through the central directory, as miniz finds them, stored or deflated:
  lazaret-verify's `inflate`, pratique's), the legacy stream's five pickles, the tar's `pickle`, `storages` and
  `tensors` (with the raw bytes between their pickles counted from the storage types' element sizes), an `.npy`'s
  object array (its header's dtype holds an `O`), each object array of an `.npz`, a joblib file's pickle with each
  `NumpyArrayWrapper`'s array bytes after its BUILD (joblib's `read_array`: a padding byte and its padding, then
  shape × itemsize bytes; an object array's own pickle), and the bytes handed to `torch.storage._load_from_bytes`
  (how PyTorch pickles a storage with plain pickle) or to `pickle.loads` and the like, read as a file of their own.
  The opcodes are read as CPython's unpickler reads them (every opcode of protocols 0 to 5, the memo, marks as its
  fences, Python 2's names through `_compat_pickle`'s mappings), on values that stand for what it would build.
- **What a global is.** The globals a tensor checkpoint is rebuilt from — PyTorch's own weights-only unpickler's set
  (`torch/_weights_only_unpickler.py`: `_rebuild_tensor_v2` and the other rebuild functions, the typed and untyped
  storages, `torch.Size`, `torch.device`, the dtypes, layouts and qschemes, `collections.OrderedDict`,
  `_codecs.encode`, `builtins.bytearray`, `set`, `complex`) — numpy's own pickling functions in numpy 1 and 2 naming,
  joblib's array wrappers, TorchScript's builders and `__torch__` classes, and constructors of plain data that run
  nothing else (`builtins`' types, `collections`, `datetime`, `decimal`, `fractions`, `uuid`, `pathlib`,
  `argparse.Namespace`, `types.SimpleNamespace`, `functools.partial`, `operator.getitem` for typing's aliases,
  copyreg's reconstructors), pyarrow's pickling helpers (an Arrow array, chunked array, table, record batch, schema,
  field, type, scalar or buffer pickles as `_restore_array`, `chunked_array`, `_reconstruct_table`,
  `_reconstruct_record_batch`, `schema`, `field`, `type_for_alias` and the type factories, `scalar`, `py_buffer`:
  pandas 3's Arrow-backed strings, a Hugging Face dataset's table), pandas' Arrow extension types' deserializers and
  dateutil's and pytz's zones are `PICKLE_SAFE_GLOBALS`: a model of the formats, what PyTorch itself trusts to load,
  not an exemption by package. The data types of modules of code, named exactly (`PICKLE_DATA_GLOBALS`: an enum or a
  named tuple such as `http.HTTPStatus`, `signal.Signals`, `socket.AddressFamily`, `os.stat_result`,
  `time.struct_time`, `subprocess.CompletedProcess`), are data; the rest of those modules stays code, and so does an
  attribute reached through one of them (`signal.Signals.__new__`). `getattr(<a global>, '<a name>')`, how pickle
  writes a bound method (a datetime's zone: `getattr(zoneinfo.ZoneInfo, '_unpickle')`; an Arrow extension type's
  `__arrow_ext_deserialize__`), is read as that dotted global and judged by its name, its call as that global's call;
  `getattr` in any other use (on a value the pickle computed, in a chain, with a default, given a name that is not
  one, put anywhere but as the callee of such a call, in either reading of a joblib array's bytes) stays builtins'
  `getattr`, CRITICAL. A global that runs code or touches the system (`PICKLE_CODE_MODULES`,
  `PICKLE_CODE_GLOBALS`, a dotted name through `PICKLE_CODE_ATTRS`) is SC-PICKLE-CODE (CRITICAL) in any use, and so
  are the shapes that run code whatever the names: a callable given to a special method in a dict a BUILD or a call
  receives (the next BUILD calls an object's `__setstate__`), BUILD on a class or function (it changes its
  attributes), a class made with `type()`, a dotted name of code handed to a call (`import_string('os.system')`).
  Any other global made by NEWOBJ and BUILD, or handed to a reconstructor as the class it rebuilds, is an object
  restored by its own class (sklearn's estimators, an omegaconf config, a Lightning AttributeDict, Cython's
  `__pyx_unpickle_*`, pandas' `_new_Index`): quiet. Called with text it is told to use — anything but a plain name: a
  command, code, a path, a URL, a module path, bytes — it is SC-PICKLE-GLOBAL (MAJOR), and so is an object the
  pickle computed and then calls (a gadget chain's shape); called with numbers, plain names and objects the pickle
  made (sklearn's `Tree(n_features, n_classes, n_outputs)`, pandas' `StringDtype('python', nan)`), quiet. A global
  of the scanned package's own modules (its module is a `.py` file of the project, the release, or the dependency's
  own folder under `--deps`: `torch.save(model)` of the package's own class) is SC-PICKLE-GLOBAL as INFO, listed and
  setting no verdict (John's decision of Oct 21): importing it runs that module's code when the file is loaded, and
  that code is the package's, which the scan reads (`pickle::own_imports`, the `model_own` call, once the scan knows
  its files). Such a function called with text it is told to use stays SC-PICKLE-GLOBAL, MAJOR, as any function's:
  the text decides what the code does. An enum's member pickles as its class called with its value
  (`Source('https://...')`): it is such a call, MAJOR, whatever the scan's source defines (model_file holds it in its
  `calls` for `model_own`, which reports it beside the own module's INFO). A waiver of a plain enum's member lookup
  (the precision review of Oct 21) was dropped by the external re-review of Oct 27: which file a module name is when
  the file is loaded is the loading program's import path (sys.path set by its code, PYTHONPATH, `.pth` files, the
  folder it runs in, what is installed, a project `enum.py`), which no scan of the files establishes.
- **What cannot be read** is SC-TRUNCATED (INCOMPLETE): a pickle cut short or garbled (what ran before the cut is
  reported too: a payload before a deliberate break, nullifAI's shape), a joblib array whose shape or dtype cannot be
  read or that runs past the file's end, a compression the engine cannot undo, a member in a zip method it cannot
  read, a model file other than a zip larger than the source-size limit (a pickle, the legacy stream: by its first
  bytes, as a source file over the limit is), a reading past its bounds. A checkpoint whose zip holds a member that
  is not the format's by its content keeps SC-NESTED-ARCHIVE beside its findings; a read one has none.
- **The external review of Oct 21 (H1–H7, M1–M4).** Each place the reader decided less than the loader reads:
  - *An .npy header* (`pickle/npy.rs`) is read as numpy reads it: `ast.literal_eval`'s grammar (escapes, implicit
    concatenation, comments, a duplicate key's last value, Python 2's `3L`), the header's three keys exactly, and its
    `descr` by numpy's dtype grammar (`descr_to_dtype`: a string's type codes and names, byte order, sizes, a
    datetime's unit, a subarray's `(1,)` or count, comma-separated fields; a (dtype, shape) tuple; structured lists
    at any depth, a field's (title, name)). Object (`'object'`, `'(1,)O'`, `'\x4f'`, a structured `object` field)
    reads the array's pickle; numeric for certain is quiet; anything it cannot place is SC-TRUNCATED, and an `.npz`
    with such a member keeps SC-NESTED-ARCHIVE. A joblib array's dtype goes by the same grammar.
  - *A zip's members* (`zip::entries`, with FP-NESTED-ARCHIVE's review of Oct 21): the union of what every common
    unpacker finds (Python's zipfile, miniz, adm-zip, yauzl, jszip, unzipper's directory reader and its streaming
    `Parse`, Info-ZIP's unzip), and `ambiguous`, why they may not agree: the end record's count, the directory's
    declared size, its offset and `end - size` disagreeing (every entry inside the declared size is read, and those
    that follow it); a zip64 locator, looked for always, whose record is not the end record's values or not where
    zipfile reads it; more than one end record a reader takes (the last, and any whose comment runs to the file's
    end); a local header that is not its directory entry's (name, method, flags, sizes: the local one is a member
    too); a member no directory lists (the local headers walked from the first byte); bytes before the first member,
    between the members and the directory or after the end record; members whose data overlap; a name with a NUL
    (zipfile's name, cut there, is a member too). A model file's ambiguous zip is SC-TRUNCATED and keeps
    SC-NESTED-ARCHIVE, and every member any view finds is read. Each entry carries the directory's `made_by` and
    `external` attributes (`unix_mode`, the upper 16 bits when not zero, whatever the creator; `executable`;
    `special_kind`, a type but a regular file's: FP-NESTED-ARCHIVE's reader). A zip64 record that agrees with
    its end record is no ambiguity: every reader lists the same members (a checkpoint past 4 GiB has one). The
    registry's streamed read keeps every member's local header (`_MODEL_HEADERS`, 16,000,000 bytes).
  - *A legacy tar's members*: every copy of a name is read (tarfile's `getmember` takes the last); two `storages` or
    `tensors` records are SC-TRUNCATED; a name twice keeps the archive opaque.
  - *Nested loads*: a byte string handed a loader past the 64 the reading queues, past three levels, or past the
    inflate budget (the copies are charged to it) is SC-TRUNCATED, not passed over.
  - *What is the format's* (`read_zip`): a checkpoint's `data.pkl` and its storages `data/<n>`; its records
    (`version`, `.format_version`, `.storage_alignment`, `.data/version`: a number; `byteorder`: `little` or `big`;
    `.data/serialization_id`: an id), read and held to that; a TorchScript archive's (one with `code/`)
    `constants.pkl`, `constants/<n>`, `code/**.debug_pkl`, and `code/**.py`, scanned as a dependency's Python file
    (its findings named for the member); an `.npz`'s `.npy` members; pandas' one member. Any other member keeps the
    archive opaque (SC-NESTED-ARCHIVE), is read as a pickle when its bytes are one, whatever its name (PROTO, a
    protocol 0 GLOBAL, PyTorch's legacy magic, or bytes that read to a STOP), and is reported as a program or an
    archive (SC-BINARY, SC-NESTED-ARCHIVE, named for the member) when its first bytes are one.
  - *BUILD state*: a pair that gives a special method a callable (a dunder key, or a key the pickle computes) is
    kept past a container's bound (`keep_pair`; a list's or a tuple's (key, value) pair too: dict.update reads a list
    of pairs); one even MAX_KEPT cannot keep marks its container lost; a BUILD on an object an earlier BUILD gave a
    `__setstate__` is that callable's call; the look through a state or a call's arguments goes through containers
    only (16,384 a look, 32 deep, 50,000,000 items a reading), and what it cannot see — a lost container, a computed
    key with a callable value, its bounds — is SC-TRUNCATED. What the format's data constructors make (a safe global
    named exactly, but not copyreg's, `type`, `functools.partial`, getitem or a TorchScript class) is no callable, and
    a numpy scalar of a number, a date or bytes no name: LightGBM's class map, `{np.int64(0): np.int64(0)}`, is data.
  - *A .pth file read whole* is read by the stream's byte-wise rule (`pth_bytes_issues`): a line counts when it
    starts `import ` under any decoding site.py may use (UTF-8, or the locale's latin-1 fallback, whose `\x85` is
    U+0085), the same on every route.
  - *Byte ranges* (`zip::Bytes::note`) are charged once, as the union of what is given and asked for; a member's
    window is clamped to its compressed size; an `.npy` member's header is read to its end and no further, its
    inflation charged to `PICKLE_MAX_INFLATED`. The pieces a stream kept (one a member, each touching the last) are
    joined in place, not copied whole per piece: a 50,000-member `.npz` in a release took more than 45 s.
  - *First bytes too few to tell*: a file larger than the scan reads whose first bytes (fewer than a legacy tar's
    magic at byte 257) start as a legacy checkpoint's member header is SC-TRUNCATED, not passed over (a member limit
    set that low, as the review's streamed routes set it).
  - *An extension code* (EXT1, EXT2, EXT4) is the global the loading program registered for it (none by default):
    called or made, SC-PICKLE-GLOBAL, MAJOR; `__torch__.` names are trusted inside a TorchScript archive only.
- **The external re-review of Oct 27 (5 HIGH).**
  - *A Unicode Path name* (Info-ZIP's extra field 0x7075, version 1, its CRC-32 the raw name's; central and local):
    a name of the member too (`zip::entries` adds it, not `listed`), so a storage's entry that Info-ZIP extracts as
    `archive/hidden.pkl` is read as that member; a name that is not the raw one makes the listing ambiguous
    (SC-TRUNCATED); one of a bad CRC or another version is ignored, as Info-ZIP ignores it.
  - *A subtype constructor* (numpy's `_reconstruct` and `_mareconstruct`, torch's `_rebuild_wrapper_subclass`)
    makes data only when the class it is handed is one of the format's own array or tensor types by its global
    (`DATA_TYPES`); any other class's object may be callable, and a BUILD that installs it as `__setstate__` is
    that object's call.
  - *The enum waiver is gone*: a call with text is SC-PICKLE-GLOBAL, MAJOR, whatever the scan's source says of the
    class (see above).
  - *An executable member*: before any member the format owns is passed over (a storage, a record), one whose
    directory entry a Unix system made with an execute bit keeps the archive opaque and is reported, SC-BINARY when
    its first bytes are a program's, else SC-NESTED-ARCHIVE (MINOR) naming it and its mode. A member a local header
    alone shows has no mode a reader trusts: its listing is ambiguous already (SC-TRUNCATED).
  - *One budget for a listing*: at most 16 end records a reader may take (more is SC-TRUNCATED); each directory a
    view names read once, whatever views name it; the entries and bytes all of them read charged to one budget
    (twice `PICKLE_MAX_ENTRIES` and `PICKLE_MAX_DIRECTORY`), past which the listing is SC-TRUNCATED.
- **The external re-review of Oct 27, its second (4 HIGH).**
  - *Every Unicode Path field*: each 0x7075 field of a central entry and of its local header is read, and each one
    a reader accepts (version 1, the raw name's CRC-32; a valid one after an invalid first too: Info-ZIP and
    zipfile take the last valid one, yauzl the first, jszip the central directory's last) names the member; more
    than one such field on an entry, in either header, makes the listing ambiguous (readers differ on which they
    take), as does any name but the raw one. Every name is read as a member (an ordinary one unless it is the
    format's own storage or record name).
  - *Constructors handed a class, audited* (`vm::data_maker`; `PICKLE_SAFE_GLOBALS`, 290 entries). Their value is
    data, never a callable, only when what decides its class is the format's own, positively:
    - an object of the class they are handed, data only when that class's global is one of `DATA_TYPES` (numpy's
      arrays, `array.array`, numpy's `SeedSequence`, `torch.Tensor`, `torch.nn.Parameter`): numpy's
      `_reconstruct` (`multiarray`, `_internal`, in `numpy.core` and `numpy._core`), `numpy.ma.core._mareconstruct`,
      `array._array_reconstructor`, `numpy.random.bit_generator.__pyx_unpickle_SeedSequence`,
      `torch._utils._rebuild_wrapper_subclass`;
    - an object of the class their BUILD state names, which joblib.load hands `_reconstruct` under numpy before
      2.0: joblib's `NumpyArrayWrapper` and `NDArrayWrapper` (`subclass`), `ZNDArrayWrapper` (`init_args[0]`)
      (read as joblib reads one, a `NumpyArrayWrapper` is the array it reads, an object the file loads);
    - an object of their argument's own type when it is not the base type, data only when that argument is:
      `torch.nn.parameter.Parameter` and `Buffer`, `torch._utils._rebuild_parameter`,
      `_rebuild_parameter_with_state`, `_rebuild_device_tensor_from_cpu_tensor` (`data.to()`),
      `numpy.ma.core.MaskedArray(data)` (followed 16 deep);
    - an object of the class their pyarrow type names (an extension type's `__arrow_ext_class__`), data only when
      that type is what pyarrow's or pandas' own constructors made: `pyarrow.lib._restore_array`,
      `pyarrow.lib.scalar`;
    - what they are handed, or a class, never data: numpy's `_DType_reconstruct`, `torch.jit._pickle`'s
      `restore_type_tag`, `build_intlist`, `build_tensorlist`, `build_doublelist`, `build_boollist`, numpy's
      `scalar` of dtype object;
    - never data by their models: `copyreg._reconstructor`, `__newobj__`, `__newobj_ex__`, `builtins.type`,
      `builtins.object`, `functools.partial`, `getitem`, numpy's `_ufunc_reconstruct` (a ufunc),
      `numpy.random._pickle`'s three constructors, `torch._tensor._rebuild_from_type(_v2)`,
      `torch.storage._load_from_bytes`, the text makers (`bytes`, `str`, `chr`, `codecs.encode`);
    - the rest make an object of their own type whatever they are handed, none of them callable: numbers, text and
      containers (`collections`' too: a `defaultdict` is no callable, its factory aside), datetime's, `Decimal`,
      `Fraction`, `uuid`, `pathlib`'s, `zoneinfo`, pytz's and dateutil's zones, `SimpleNamespace`, `Namespace`,
      `re._compile`, `logging.getLogger`, `numpy.dtype`, `numpy.ndarray`, `numpy.core.numeric._frombuffer`,
      pyarrow's types, tables, batches, chunked arrays and dictionary scalars, torch's dtypes, layouts, devices,
      storages and its other tensor rebuilds (a tensor made from a storage, numpy's bytes or sizes).
  - *A member's Unix mode, whatever system made it*: the upper 16 bits of the external attributes, when not zero,
    are judged whatever the creator (Info-ZIP applies them for Unix, VMS, Acorn, Atari, AtheOS, BeOS, QDOS and
    Tandem, and for FAT when they agree with its DOS bits): an execute bit keeps the archive opaque (SC-BINARY or
    SC-NESTED-ARCHIVE, as above). numpy's and zipfile's 0600 or 0644, torch's
    writer's 0, joblib's: none.
  - *A member's file type*: before any member is passed over as a storage or a record, its type from those bits: a
    regular file (or none given) only; a symlink, a directory, a device, a FIFO or a socket keeps the archive opaque
    and is SC-NESTED-ARCHIVE naming it and its type (Info-ZIP extracts a symlink's body as its target).
- **A zip read by range, whatever its size** (John's decision of Oct 21). A checkpoint is its storages, hundreds of
  MB, and a few KB of pickle; reading it whole up to the source-size limit made every checkpoint over 16 MB
  INCOMPLETE. The zip reader reads its bytes through `zip::Bytes`, the whole file or the pieces of it a host read:
  its end records (the last 65,557 bytes, and the zip64 locator and record), its central directory (at most
  `PICKLE_MAX_DIRECTORY`, 16,000,000 bytes), each `*pkl` member's local header and bytes, an `.npy` member's first
  128 KiB (more when deflate's empty blocks hold its header back) and an object array's whole, never a tensor
  storage. What it needs and was not given is noted (`Bytes::needs`), and `pickle::read_ranges` answers the ranges
  to read before it asks again; a host reads them and asks again, at most `PICKLE_MAX_READS` (8) times, the last of
  which makes what is still needed SC-TRUNCATED. The reading is the reading of the whole file: the same calls of the
  same reader, on bytes that are all there or not yet (`reading_by_range_is_reading_the_whole_file` holds them
  alike); what a reading may ask for in all is bounded (`range_cap`: `PICKLE_MAX_INFLATED` + `PICKLE_MAX_DIRECTORY`
  + 1 MiB), and a member past what it reads is SC-TRUNCATED without its bytes being read. A project scan and
  `--deps` read by range from the disk (collect_file's `{"need": {"read": "ranges"}}`, answered with every range read
  so far: core's `_read_ranges`, npm's `readRange`; the dashboard, which holds an upload's first bytes, reads one as
  before), a `.pth` checkpoint over the limit too. The registry reads an archive's members as a stream, once: an
  oversized member whose first bytes are a zip model file's is read on as the stream passes (`_ZipModelKeep`: its
  first 64 KiB, each `*pkl` and `.npy` member by its local header, its last 16 MB for the end records and
  directory) and handed to the engine as its last read (`model_file` with `pieces`), so a directory that names
  bytes the walk of local headers did not keep is SC-TRUNCATED, never quiet.
- **A `.pth` file too large to read whole is read in chunks** (John's decision of Oct 21; `.pth` is PyTorch's usual
  extension, and every `.pth` is checked, whatever its place or size). `binary::pth_stream` keeps, byte-wise and on
  the safe side whatever the decoding, each line site.py runs: one that starts `import ` or `import\t` (after a
  UTF-8 byte order mark on the first line), or a part of one that str.splitlines() splits off (after `\x0b`,
  `\x0c`, `\x1c`–`\x1e`, `\x85`, UTF-8's U+0085, U+2028, U+2029), from its import start to its end, at its line
  (lines end at `\n`, `\r` and `\r\n`, as pth_issues numbers them); between chunks the host keeps its state (the
  line, a `\r` at a chunk's end, the current line's last 16 bytes or what is kept of it). `pth_kept_issues` checks
  each kept line as `pth_issues` checks one, at its line in the file. A line longer than `PTH_MAX_LINE`
  (1,000,000 bytes), or kept lines past `PTH_MAX_KEPT` (16,000,000 bytes) in all, is SC-TRUNCATED; the rest of the
  file is read on. The routes: a project scan and `--deps` (collect_file's `{"need": {"read": "pth"}}`, answered
  with the lines: core's `_stream_pth`, npm's `streamPth` over `readRange`, a MiB at a time), the registry (the same
  one pass an oversized member gets, `_oversized_member`, beside `_ZipModelKeep`). A 200 MB `model.pth` checkpoint
  is then judged by its pickle (by range) and by its import lines (streamed): quiet when both are benign. Its other
  lines are paths to site.py and are not scanned as Python source in the registry, as a `.pth` read whole is.
- **Plain pickle.load over a joblib file.** joblib skips an array's bytes after its wrapper's BUILD; `pickle.load`
  would read them as opcodes. When the first of them is an opcode (an unaligned array of joblib before 1.2, or a
  crafted one), they are read that way too, a fork of the reading that changes nothing it shares, so a payload hidden
  as array bytes for `pickle.load` is still read. Aligned arrays start with their padding byte (1 to 16: no opcode).
- **Routes.** The registry (`repo.py`'s `_model`, the members read whole up to `MAX_MEMBER`, an oversized zip one by
  the pieces `_ZipModelKeep` kept; `_model_own` in the second pass), a project scan and `--deps` (collect.rs: a
  non-source file whose first 512 bytes `pickle::sniff` recognizes is read, a zip by range, another whole up to the
  size limit; collect_file's `model`; `core.model_own_issues` and npm's `modelOwnIssues` over the collection), one
  engine for both packages.
- **Bounds.** One pass, a step of the call's budget per opcode; `MAX_MEMO` 2,000,000 memo entries, `MAX_STACK`
  4,000,000 values, `MAX_KEPT` 2,000,000 container items kept in all (`ITEMS` per container; one past it is marked so
  and its text counts as unknown), 256 values looked at per call's arguments, `MAX_FORKS` 100,000 forks of
  `MAX_FORK_OPS` 65,536 opcodes, `PICKLE_MAX_INFLATED` 64,000,000 bytes decompressed, `PICKLE_MAX_ENTRIES` 100,000
  zip entries, `PICKLE_MAX_PICKLES` 64 pickles one after another, nested bytes three deep, the format's helpers
  handed helpers followed `MAX_DISPATCH` 16 deep; each limit reached is SC-TRUNCATED (the last, MAJOR). Values are
  let go of in one loop, however deep the pickle nests them (two million nested lists, a million calls of what the
  last returned), and none is put in a container it holds (`CYCLE_LOOK` 64 values looked at; one the look cannot
  clear makes the container a suspect whose contents go with the reading), so nothing a reading makes outlives it.

#### Media files and keystores: what a near-random file is (FP-OPAQUE-MEDIA, 0.1.9)

SC-OPAQUE-BLOB (MAJOR: WARN) reports a binary file whose first bytes are near-random (byte entropy over
`_OPAQUE_ENTROPY`, 7.2 bits, in its first `_OPAQUE_SAMPLE` bytes; at least `_OPAQUE_MIN_SIZE`): encrypted or packed
data can be a second stage that code decodes and runs. Compressed sound, pictures, video and fonts are near-random
too, and until 0.1.9 a list of first-bytes signatures (`BENIGN_MAGIC`, a font by its extension) exempted them, so
that a PNG signature glued onto a payload was quiet while an MP3 that starts at its first frame, with no ID3v2 tag,
was not. John's fp-tally over 261 GitHub scans (Oct 21) found 3 WARN verdicts SC-OPAQUE-BLOB set, 2 by it alone:
`music/music1.mp3` (an MP3 with no ID3v2 tag), Pillow's `Tests/images/bw_gradient.imt` (an IM Tools image: a text
header, then 2,560 bytes of a grey gradient, each of the 256 levels ten times — 7.9 bits a byte and nothing hidden)
and `signing/tiles-foss-debug.pkcs12` (a debug signing keystore).

- **By structure, never by name.** A near-random file is quiet only when its bytes are a format the engine walks, from
  the first byte to the last (`rust/crates/lazaret-engine/src/media/`): the chains of MPEG audio and ADTS frames
  (after their ID3v2 tags; ID3v1, APEv2 and Lyrics3 tags after them), Ogg pages and FLAC frames with their checksums,
  a transport stream's packets, ISO media boxes (MP4, MOV, M4A, 3GP, HEIC, AVIF, JPEG 2000), RIFF and AIFF chunks
  (WAV, AVI, WebP, RF64, big-endian RIFX), Matroska and WebM elements (clusters of unknown size too), PNG chunks with
  their checksums, JPEG segments and their entropy-coded scans (further images after the first, as a multi-picture
  file has them, and the MP4 a motion photo appends), GIF blocks, an Apple icon's elements; or the directory that
  names where a file's parts are: TrueType and OpenType fonts and collections, WOFF and WOFF2, BMP (its pixels a JPEG
  or PNG too), ICO and CUR, TIFF and BigTIFF (with their SubIFD, Exif and GPS directories), ICC profiles, TGA (raw and
  run-length pixels, version 2's footer and the areas it names); and an IM Tools or Netpbm (PBM, PGM, PPM, PAM)
  image's header and its width x height pixels. A directory's parts are claimed ranges: the file must hold each, and
  every byte no part holds must be zero (padding).
- **Fail closed.** Bytes the structure does not account for — a payload appended, a gap between a directory's parts,
  a chain broken anywhere, a checksum that does not match, a file cut short, read whole or as its stream passes (but
  an MP3's or AAC's last frame, after two whole ones), a first-bytes signature glued onto random bytes — leave the
  file what it was, SC-OPAQUE-BLOB, now saying what it was read as and where it stopped being that ("read as PNG
  image, it is not one to its end: bytes follow the image's end (IEND) at byte 7028"). So does a file no walker
  reads. What a format allows past its end is allowed, and zero bytes, which hold nothing.
- **Bounded (the review of Oct 27).** A walk to the end proves the file has the format's shape, not what its parts
  hold, so a header and a payload in a part that walks would be quiet; three bounds keep what a real file has and
  leave the rest opaque, the message naming the part:
  - *shapes no real file has*: an ISO media file with no file type box (`ftyp`, `styp`, JPEG 2000's signature) and
    no movie box (`moov`: QuickTime's older files start without `ftyp`), a box of size 0 (to the end) that is not
    the media data (`mdat`), a PNG with no image data (IDAT), a JPEG image with no frame header (SOF) or no scan
    (SOS), a GIF with no image, a transport stream with no program association table, a sound whose format names
    no channels, rate or block size (a WAV's `fmt ` chunk, an AIFF's `COMM`), a font without the tables every font
    has (`head` or `bhed`, `cmap`, `hhea`, `hmtx`, `maxp`, `name`), a font directory naming a table twice (the
    re-review of Oct 27: a TrueType or OpenType font's, each font's of a collection, a WOFF's, a WOFF2's, and each
    font's of a WOFF2 collection, whose own directory lists a table for each of its fonts), a TIFF directory naming a
    tag twice, an icon whose images overlap;
  - *free-form parts*, at most `FREE_MAX` (64 KiB) in all and a quarter of the file (`media::free`): ISO media's
    `free`, `skip`, `wide`, `uuid` and unknown top-level boxes; a PNG's text chunks and those no one registered; a
    JPEG's comments and the application segments no one registered (JFIF, Exif, XMP, ICC profiles, MPF, JUMBF,
    Photoshop's and Adobe's are registered); ID3's private (PRIV), object (GEOB) and unknown frames (the tag's frames
    are read now, its padding must be zero bytes) and a tag written unsynchronised; RIFF's and AIFF's JUNK, padding,
    application and unknown chunks, and a LIST of no defined type; a TIFF's private tags (32768 and up) but the
    well-known ones (Exif's, GPS's, IPTC, Photoshop's, ICC, GeoTIFF's, GDAL's, DNG's, ImageJ's and the microscopes');
    a font's unregistered tables and a WOFF's metadata and private data; Matroska's Void elements and attachments; a
    GIF's comments, plain text and application extensions but the looping (NETSCAPE2.0) and XMP ones; an Ogg stream
    whose first packet names no known codec; a FLAC file's application and undefined metadata blocks (its padding must
    be zero bytes); a TGA's developer area and an ICC profile's tags of no registered signature (`ICC_TAGS`: ICC.1's
    and the private ones in wide use; the re-review of Oct 27, N4); and the free-form parts of a part walked as a
    format of its own (an icon's PNG images), which count toward the file's 64 KiB and quarter;
  - *raw samples*: the formats that store their samples as they are (Netpbm, IM Tools, TGA, an uncompressed BMP, PCM
    in WAV, RIFX, RF64 and AIFF, and a WAV format of no name) are quiet only when the first `RAW_SAMPLE` (8 KB)
    bytes of their samples follow one another: the smallest entropy of their differences at lags 1 to 4 under
    `RAW_MAX_BITS` (7.0 bits a byte; Pillow's real images measure at most 6.5, random bytes 7.98). A noise-like
    recording (applause) measures as random bytes do, and stays opaque.

  What stays unbounded is what a codec decodes (an MP4's media data, an audio frame, a scan); a payload there is the
  code that reads it out, which the scan reads.
- **Formats still taken by their first bytes** (`UNWALKED_MAGIC`): PDF, PostScript and EPS, Photoshop, JPEG 2000's
  bare codestream, DDS, GIMP's XCF, SGI, Sun raster, FITS, QOI and Radiance images keep 0.1.8's exemption: no walker
  reads them yet, and leaving them out would make many PDFs opaque (of the 523 PDFs on the build machine, 222 are
  near-random in the registry's sample, their first 8 KB, and 144 in a project scan's, their first 512 bytes). A
  payload behind one of these signatures stays quiet, as it was.
- **Any size.** A file is walked whole when it is read whole (up to the source-size limit; the registry's members
  up to `MAX_MEMBER`), and as its stream passes when it is larger: the walk is a state machine fed chunks in order
  (`media::feed`, the `media_stream` call), its state carried by the host between them (a project scan's
  `collect_file` asks `{"need": {"read": "media"}}`: core's `_stream_media`, npm's `streamMedia`, a MiB a call,
  passing over what the walk skips, so a 300 MB MP4 is read in a few KB; the registry's `_oversized_member` feeds an
  archive member's stream as it passes). The host never passes over the file's end: where a part runs past it, the
  host says the file ends there (its size, or the byte before where the walk goes on, read) and the walk fails (`feed`
  checks that no part it began runs past the end), but for what a whole walk allows there too (an MP3's or AAC's last
  frame after two whole ones): streamed or whole, a file walks alike. A format read by a directory that may lie anywhere (TIFF, ICO,
  ICC) is read whole up to `MAX_CARRY` (1 MiB) when streamed; past it, it stays opaque. A TIFF's walk reads at most
  `TIFF_ENTRIES` directory entries and `TIFF_VALUES` strip, tile and directory offsets (a million each), and an icon's
  image once; a directory read as its stream passes (a font's or a collection's tables, a WOFF's, a bitmap's) names
  at most `MAX_CLAIMS` (65,536) parts, which the walk holds sorted from the last and drops once passed (the re-review
  of Oct 27, N1: dropping the first of a vector moved every other, so a collection of a thousand fonts of 4,096
  tables each cost minutes): past them a file stays opaque, so that no file is a walk of hours. The size a directory
  declares (a WOFF's, a BMP's) is checked at the file's end however its last chunks came (the re-review's N5: an
  empty chunk before the end passed over it).
- **Keystores are credential files.** A PKCS#12 keystore (DER: a version 3 PFX whose content is PKCS#7 data or
  signed data, its unencrypted parts' bags read, BER's indefinite lengths too), a JKS (0xFEEDFEED) or JCEKS
  (0xCECECECE) keystore (its entries and digest; a JCEKS secret key's SealedObject read as Java's serialization
  writes it) or a Bouncy Castle BKS keystore (its salt, entries, end mark and MAC), read to its last byte, is
  **S-SECRET** (`_KEYSTORE_RULE`, `_KEYSTORE_SEALED_RULE`, `_KEYSTORE_CERTS_RULE`): BLOCKER when it holds a private
  or secret key in the clear part of its structure (JKS's and BKS's entry types, PKCS#12's key, shrouded-key and
  secret bags), MAJOR when its entries are encrypted whole (keytool's PKCS#12 truststore: it may hold a key), INFO
  for certificates alone (a truststore). S-SECRET is the credential family: report-only, never a registry's verdict
  (SECRET_RULES; INFO in test code), BLOCKER in a project scan as a key in a `.pem` is (S-TOKEN). It is not hidden
  code: a keystore read to its end is not SC-OPAQUE-BLOB; one with bytes after its end, or cut short, is no keystore
  and stays opaque. A keystore is read whole, at most `KEYSTORE_MAX_BYTES` (4 MiB). Its parts have their shapes (the
  review of Oct 27): a certificate is a DER Certificate spanning its bytes (a CRL a DER CRL), an encrypted key an
  EncryptedPrivateKeyInfo, a key in the clear a PrivateKeyInfo (a BKS public key a SubjectPublicKeyInfo), a signed
  PKCS#12's content is read as an unsigned one's; a shell around random bytes is no keystore. The bytes no structure
  reads (encrypted data, a key's or a secret's bytes, a signature) are counted: past `KEYSTORE_ELEMENT_MAX_BYTES`
  (16 KiB) in one part or `KEYSTORE_OPAQUE_MAX_BYTES` (1 MiB) in all, SC-OPAQUE-BLOB stands beside S-SECRET (the
  `binary_classify` call answers with both; an RSA-16384 key is under 10 KB, a JDK trust store's certificates are in
  the clear). A certificate is read for its shape, not its fields (the re-review of Oct 27, N2), so every byte of it
  counts toward the total (the coordinator's ruling of Oct 27: a store of made-up certificates carries no more than
  `KEYSTORE_OPAQUE_MAX_BYTES`), and its signature with its bytes past `CERTIFICATE_MAX` (16 KiB: real ones are 1 to
  2 KB) is one part; an alias, and any other value
  nothing reads — a PKCS#12's MAC salt, a bag's attributes, an algorithm's parameters, a signer's names, a recipient's
  key, a serialized object's strings and names — counts past `NAME_MAX` (256) bytes, and a serialized object's
  arrays count whole, as its byte arrays did. The JDK's `cacerts` (123 certificates: 133,175 bytes counted, its
  largest part 513) and the 436 PKCS#12 files of `cryptography_vectors` stay under both bounds.
- **Routes.** `binary.rs`'s `classify_more` (the `binary_classify` call's `whole`, `walked` and `more`): a file whose
  first bytes would make it an opaque blob and start a walked format, or a keystore, needs the whole file (`Need`);
  collect.rs's `classify_read` reads it whole or streams it; core's `classify_binary(whole=, walked=)` and npm's
  `classifyBinary(…, {whole})` hand it over only when the first call asks; the registry passes a member whole, or
  the walk of an oversized one's stream. One engine for both packages and the dashboard.

#### The Gradle wrapper: a jar judged by Gradle's checksums (FP-GRADLE-WRAPPER, 0.1.9)

Nearly every Gradle project commits `gradle/wrapper/gradle-wrapper.jar`, and `./gradlew` runs it on every build, on
developers' machines and in CI, before Gradle itself is downloaded. SC-BINARY (MAJOR: WARN) reported each as a
compiled artifact to review. In John's fp-tally over 261 GitHub scans (Oct 21) SC-BINARY set 9 WARN verdicts, 3 by it
alone, this jar among its files. Gradle publishes the SHA-256 of each release's wrapper jar, and its own
wrapper-validation action fails a build whose jar matches none, so the engine checks the jar as that action does
(John's decision of Oct 21: "Yes, check checksums"; `rust/crates/lazaret-engine/src/gradle/`):

- **Where.** A file named `gradle-wrapper.jar` exactly, in a folder `wrapper` in a folder `gradle` (any depth: an
  Android library's `android/gradle/wrapper/`). A jar elsewhere or under another name is judged as any jar
  (SC-BINARY), as before; so is a wrapper jar of which a caller gives only the first bytes.
- **Quiet** when the jar's SHA-256 is one of `GRADLE_WRAPPER_CHECKSUMS` (the rule pack: version -> checksum, every
  release Gradle publishes a wrapper checksum for, 382 versions to Gradle 9.9.0-milestone-2, 97 distinct
  checksums), whatever version its properties name: the jar is regenerated only when `gradle wrapper` runs, so a
  project's properties often name a newer Gradle than its jar's (mockito's names 9.4.1 and commits 8.14's jar).
- **CRITICAL, SC-GRADLE-WRAPPER** (`_GRADLE_WRAPPER_RULE`) when it matches none, unless what follows says it can't
  be verified yet (the review of Oct 27: whatever else matches no checksum is a changed wrapper). The message names
  the list's size and newest version and the distribution named.
- **MAJOR, SC-GRADLE-WRAPPER, "can't be verified"** (`_GRADLE_WRAPPER_UNVERIFIED_RULE`) only when the list cannot
  judge it yet, and the jar is a wrapper jar: a zip holding `org/gradle/wrapper/GradleWrapperMain.class`. Then:
  - *the next release*: the version the last `distributionUrl` names (the one `java.util.Properties`, and so the
    wrapper, reads) is not listed, is in Gradle's release form (`^\d+\.\d+(\.\d+)?(-(rc|milestone)-\d+)?$`) and
    may well be the next one Gradle publishes (`gradle::newer`): newer than its line's newest listed release by at
    most two patches (Gradle publishes patches of an older line after newer releases: 9.8.1, on Oct 7 2026, came
    after 9.9.0-milestone-2), a new line of the list's newest major at most two minors past it, or the next major's
    first two lines. A nightly build (`9.9.0-20261021152326+0000`) when its base release is one of these and its
    timestamp is no older than the list (`GRADLE_WRAPPER_CHECKSUMS_DATE`). Any other version (`99.0`, a version of
    no form of Gradle's) is a changed wrapper's.
  - *a listed distribution, a newer jar*: the properties name a listed release and the jar's manifest
    (`Implementation-Version`, which wrappers before 5.0 write) names one that passes the same test
    (`_GRADLE_WRAPPER_MANIFEST_NEWER`); no properties, or no version named, is CRITICAL.
  - *no checksum published*: the manifest names a version of `GRADLE_WRAPPER_NO_CHECKSUM`, the versions Gradle
    publishes no wrapper checksum for (3.3 to 4.0.2 with their release candidates and milestones, whose wrapper
    jars were not reproducible: Netflix/Hystrix commits 4.0's; and 0.7 to 0.9.2, before Gradle 1.0), an explicit set
    the update script derives from `versions/all` (the entries without a `wrapperChecksumUrl`).
  - a Git LFS pointer committed in the jar's place; a jar not read whole (over the size limit) and no larger than
    `GRADLE_WRAPPER_MAX_BYTES` (1 MiB). One larger is CRITICAL: the 290 distinct wrapper jars gradle/gradle
    committed from 2012 to 2026 are 43 to 64 KB.
- **The distribution** (the review of Oct 27): `./gradlew` downloads and runs the distribution its properties name,
  so a genuine jar is judged by where that comes from too (`gradle::distribution_issue`): MAJOR over plain `http://`
  or from what is not a URL (`_GRADLE_DISTRIBUTION_RULE`); INFO, listed and not counted, over HTTPS from a host
  other than services.gradle.org without a `distributionSha256Sum` (`_GRADLE_DISTRIBUTION_HOST_RULE`: a company's
  mirror, often; there is no allow-list of hosts); quiet with a `distributionSha256Sum`, which the wrapper checks.
- **As Java reads the properties** (the re-review of Oct 27, N3). Gradle's `WrapperExecutor` reads
  `gradle-wrapper.properties` with `java.util.Properties.load(InputStream)`, and `gradle::read` reads it so:
  ISO-8859-1; `\r\n`, `\r` and `\n` each end a line, inside a continuation too; blank lines and `#` or `!`
  comments skipped; a line ending in an odd number of backslashes goes on with the next, whose leading blanks are
  dropped; the key ends at the first `=`, `:` or blank not escaped, then blanks and one `=` or `:` are dropped;
  `\uXXXX`, `\t`, `\n`, `\r`, `\f` and `\x` meaning `x` are decoded in keys and values; the last of a key's
  lines wins. The distribution judged (the version, the URL's scheme and host) is the last `distributionUrl` so
  decoded. It can't be verified (MAJOR, saying why; a jar matching no checksum is then CRITICAL, no release named)
  when the file is longer than `GRADLE_PROPERTIES_MAX_BYTES` (64 KiB: Java reads it whole, and a later
  `distributionUrl` wins), holds a `\uXXXX` escape that is not one (Properties.load refuses it from Java 17; Java 8
  and 11 read past the line), is read into another distribution by Java 8 than by later Java (whose reader, from Java
  9, tells a comment wherever a logical line is still empty and counts no backslash in it: a lone backslash continued
  onto a comment line, a comment ending in a backslash before a line of backslashes), or is there and not read (a
  symbolic link, which Java follows and the scan does not). Held to Java itself: 50,038 generated files read by JDK
  8, 11, 17 and 21's `Properties.load`, every one the engine reads giving the distribution and checksum each JDK that
  loads it reads, and every one it refuses one that a JDK refuses or that two JDKs read otherwise.
- **Every route reads the properties.** A project scan's `collect_file` asks for the jar whole and for the file
  beside it (`{"need": {"read": "sibling", "name": "gradle-wrapper.properties", "limit": 65537}}`, one byte more than
  is read, so that a longer file is told: core's `_read_sibling`, npm's `readSibling`, the dashboard's uploaded
  folder), a regular file only; one there and not read is `{error}`. The registry keeps each release's
  `gradle-wrapper.properties` (its first `GRADLE_PROPERTIES_MAX_BYTES` and one more; one over the member limit as
  not read) and judges its wrapper jars once every member is read (`_gradle_wrappers`), as an archive may hold the
  properties after the jar. `classify_binary` takes `props` (bytes, None, or `{"error": why}`).
- **The list** is Gradle's, as gradle/actions ships it (`sources/src/wrapper-validation/wrapper-checksums.json`,
  MIT; that repository also holds a proprietary caching component, not used), written into the pack in its
  canonical form with where it came from and when (`GRADLE_WRAPPER_CHECKSUMS_SOURCE`).
  `scripts/update_gradle_wrapper_checksums.py` (standard library only) refreshes it from
  https://services.gradle.org/versions/all, each release's `wrapperChecksumUrl`, over HTTPS with redirects only to
  Gradle's download hosts and GitHub; each checksum must be 64 hex digits, each new version's jar is downloaded and
  must hash to it, a published checksum that changed or a version that disappeared is refused; the versions with no
  `wrapperChecksumUrl` are written as `GRADLE_WRAPPER_NO_CHECKSUM`, the day as `GRADLE_WRAPPER_CHECKSUMS_DATE`;
  `--from-json` reads gradle/actions' file instead (its date given with `--date`), `--check` checks the pack's list
  offline. rust/NOTICE, which the wheels and the npm package carry (`native/NOTICE`), says where the list came from;
  a checksum is a fact computed from a file, so no licence applies to it (John, Oct 28: a checksum is a fact, said where
  it came from, not a copyright matter).
- SC-GRADLE-WRAPPER is not compared with a predecessor's (`prior.NOT_COMPARED`, as SC-BINARY): a release that moves
  to a Gradle newer than the list is not a new indicator.

#### A compiled artifact by its bytes (FP-BINARY-BY-NAME, 0.1.9)

SC-BINARY's description comes from a file's bytes: a program's magic (`EXEC_MAGIC`; in text, a DEX's whole magic;
0xCAFEBABE a universal Mach-O or a Java class by the number after it), a Windows executable's `MZ` in bytes that look
binary, or a compiled artifact's name (`COMPILED_EXTS`) unless the whole file is text (`binary::whole_text`, the
review of Oct 27). Text throughout means: read whole, to the size limit (`classify_more` asks for the whole file,
`Need`, when its first bytes are text; a file over the limit keeps the name's finding), no NUL byte, no window of 2 KB
(`_LOOKS_SAMPLE`, overlapping by half) that looks binary (`looks_binary`), not an ar archive's text headers
(`COMPILED_TEXT_MAGIC`, a static library or an import library), and for a format read from its end, no zip
end-of-central-directory record (`PK\x05\x06`) in the last 65,557 bytes of a `.jar`, `.war`, `.ear` or `.apk`
(`ZIP_READ_EXTS`: a Spring Boot executable jar is a shell launcher, then the zip, which `java -jar` finds from its end)
and no UDIF trailer (`koly`) in a `.dmg`'s last 512. The registry classifies a member read whole only when its first
2 KB look binary, so a name there seldom made text binary (a gap filed on its own: FP-BINARY-BY-NAME's review); the
project scan, `--deps`, the npm CLI and the GitHub scan route classified every file that is not source, so text named
`.node`, `.so`, `.dll` or `.class` was SC-BINARY there. The rule's other names, audited: `CONTAINER_DOCUMENT_EXTS`
(`.docx`, `.odg`, `.epub`, …) are quiet only when their bytes are their container's, a zip's local header (gzip for
`.svgz` and `.dia`: `CONTAINER_GZIP_EXTS`), else judged as any file (`container_bytes`); `.ts`, `.mts`, `.m2ts` are
read as transport streams only when their bytes are one; a model file's extension is a hint its bytes must confirm.

#### A protobuf file's descriptor generated code alone uses (FP-B64-PROTOBUF, 0.1.9)

protoc-gen-es (protobuf-es 2.x) embeds each `.proto` file's serialized FileDescriptorProto in the code it generates,
as base64, and hands it to the runtime: `fileDesc("Ci…", [deps])`, `fileDesc` imported from
`@bufbuild/protobuf/codegenv2` (`codegenv1` in 2.0 to 2.2), required from it in the CommonJS the generator writes
(`const { fileDesc } = require(…)`), or called as `(0, x.fileDesc)(…)` once TypeScript, Babel or esbuild compiled the
file. SC-B64 ("Base64 blob (200+ chars) embedded in code", MAJOR: WARN) reported every such file — John's fp-tally of
Oct 21 found it on `worker/src/gen/listentogether_pb.ts:13`.

A descriptor is not inert: the runtime keeps it, and the program can read it back (`file_x.proto…`, a schema's
`.file`, a registry's `getFile`), so text put in it is a payload any code of the program may take out and run. The
review of Oct 27 showed it (B-1): a comment of the descriptor's source information read and handed to `eval`, `new
Function`, `execSync` or `vm` went quiet, and on `--deps` and in the registry no other rule reports a dependency's eval
of a variable. So the file scan keeps reporting SC-B64 (`scanfile.rs` reads no descriptor), and whether a finding is
dropped is decided over the whole scan — a project, a `--deps` tree, a package: each read whole — where every file
that could read the descriptor back is in hand: `core.b64_descriptor_pass` (the registry's `_b64_descriptors`
phase, the npm package's `b64DescriptorPass`) asks the engine's `b64_descriptors` (`protodesc/usage.rs`) once, at the
end, with the scan's JavaScript, its manifests, and the files that may hold script or say where modules are. A route
that cannot (a file scanned alone) keeps the finding. A finding is dropped only when every run of its line that
SC-B64 counts passes, and all of these hold (else it stays):

- **Its bytes are one FileDescriptorProto, with no free text** (`protodesc.rs`, `file_descriptor`): read to its end by
  descriptor.proto's structure, every field a known field of its message with its wire type (as of protobuf 30 with
  editions 2024), the file's name a `.proto` path (no `..`), every name a protobuf name and every type name a dotted
  one, the syntax `proto2`, `proto3` or `editions`, every text UTF-8, each named message's name once, nothing left
  over, nesting at most 64 deep; and none of the fields that carry free text generated code never holds: no source
  information (the file's field 9: comments of any length), no JSON name (a field's 10) but the one protoc derives
  from the field's name (`json_name`: its `_`s dropped, the letter after each upper-cased; protoc-gen-es keeps it on an
  extension — protovalidate's 8, protoc-gen-es's 2 — and it carries nothing the name does not), a default value of at
  most 64 characters (`MAX_DEFAULT`; the longest of the 61 real descriptors the review measured was 12). Options are
  read as well-formed fields (custom options are extensions of any number: protovalidate's rules, googleapis' HTTP
  bindings); they are not bounded to a share of the descriptor (googleapis' files carry more options than structure:
  a median of a third of the bytes, up to 78% of 511 measured).
- **The literal is handed, whole, to the runtime's loader and bound as generated code binds it**: `(` before it and
  `)` or `,` after it, the callee `fileDesc`, `x.fileDesc` or `(0, x.fileDesc)` (the pack's `_B64_DESCRIPTOR_LOADERS`
  names the functions and their modules; `fileDesc` bound once by a value import, not aliased, or a destructuring
  `require` of one of them and used only in calls; `x` bound once by `require` (the call its declaration's whole
  value) or `import * as` and read only for properties not written to; `require` never rebound), followed by nothing
  but its dependency list, and its value bound and nothing else: `export const file_x = fileDesc(…)` (a type
  annotation allowed), `const file_x = …`, `exports.file_x = (0, x.fileDesc)(…)`.
- **The descriptor is used only as generated code uses it, in every file of the scan**: `file_x` (or `m.file_x`) is
  the first argument of the loader's `messageDesc`, `enumDesc`, `serviceDesc` or `extDesc`, an element of another
  `fileDesc`'s dependency list, an argument of the runtime's registry constructors (`_B64_DESCRIPTOR_CONSUMERS`:
  `createFileRegistry`, `createRegistry`, `createMutableRegistry`; protovalidate builds its registry so, which the
  review's list did not name: without it protovalidate stays WARN), a name in an import's, an export's or a
  destructured `require`'s list (not renamed), and in its own file `exports.file_x = file_x` or TypeScript's
  `exports.… = exports.file_x = … = void 0`. Nothing else names it, no string holds the name, a declaration file is
  types only, and no string but a module specifier names its file (a path handed to `fs`, `new URL`,
  `require.resolve`: its text read). A file of a kind that holds script the file scan does not read
  (`_SCRIPT_HOLDER_EXTS`: `.vue`, `.svelte`, `.html`, `.astro`, `.mdx` …) is read with them: its whole text for the
  name, its script blocks, front matter, event handlers and template expressions as code.
- **Its module is read for its members alone, wherever it may be loaded**: every specifier of the scan is resolved as
  far as the scan can tell — a relative path (the folder it names too: its index, what its package.json's `main`
  names), a tsconfig's or jsconfig's `paths` and `baseUrl`, a package the scan holds (any of its files: its `exports`
  map may name any), a package a manifest declares by a version range or one of Node's (none of the scan's files);
  anything else — undeclared, a `#` import, a name a manifest maps elsewhere (`file:`, `npm:`, a `browser` field) or
  the code aliases (an object's key, a `find:`), a pattern — may name any file — with its last part read as a file's
  name too and case ignored. Each module object that may be it is read only for its members (`m.y`, never written),
  and none loads it whole: `import(…)`, `import.meta.glob`, a `require(…)` handed on or followed by anything but its
  statement's end (`require(…)[k]`), a rest, computed or nested destructuring, `export * as ns`, a helper
  (`__importStar(require(…))`, `__exportStar`), a `?raw` or loader-prefixed import (its text). A module that
  re-exports it (`export * from`, `module.exports = require(…)`) is held to the same. And the module's own scope reads
  no export by a name made at run time: `exports`, `module`, and in CommonJS `this` and `arguments`, only as
  `exports.y`, `this.y`, `this && …` and `Object.defineProperty(exports, "__esModule", …)`.
- **No code of the scan runs text or reaches the module registry**: no `eval`, `Function`, vm call or `with` but with
  literals alone, no `.constructor(…)` call of text (`(() => {}).constructor(text)` is `Function`), no global looked up
  by a name made at run time (`globalThis[x]`, `window[x]`), no module loaded by a name made at run time
  (`require(x)`, `import(x)`, `createRequire`, `require.context`), no `require.cache`, `require.main`,
  `module.children`, `module.parent`, `process.mainModule`, `process.binding`, and no module of
  `_B64_RUNNER_MODULES` loaded (`child_process`, `worker_threads`, `vm`, `module`, `cluster`, `inspector`, `repl`,
  `wasi`, by any name: `node:`, a subpath). A key or a method's definition of such a name (`eval: {` in a type,
  protovalidate's `eval(val, cursor) {`) is not a reference to it; `c ? eval : x`, `f(eval)` and a call are. (So
  `--deps` of a project whose dependencies build code or run commands keeps every descriptor's finding.)
- **The loader is the runtime's** (B-3): no package.json from the descriptor's folder up maps `@bufbuild/protobuf` or
  a module of it to anything but a version range (`npm:`, `file:`, `link:`, git, a URL, `workspace:`), under any key
  that names it (its dependencies, `overrides`, `resolutions` and `pnpm.overrides` by `a>@bufbuild/protobuf`,
  `**/@bufbuild/protobuf`, `@bufbuild/protobuf@^2`, its `browser` field); a package's scan does not carry its own copy
  in its `node_modules`; no tsconfig or jsconfig of the scan has a `paths` entry that matches the runtime's modules
  (`*` patterns too), a `baseUrl` that holds an `@bufbuild` folder, or an `extends` the scan did not read (a package's
  config outside a `--deps` tree); no other file that tells a tool where modules are (`_B64_RESOLVER_CONFIGS`:
  Babel's, SWC's, Deno's, Bun's, an import map) names `@bufbuild/protobuf`; no code has `"@bufbuild/protobuf…"` as an
  object's key or a `find:` (a bundler's alias, rollup's and vite's `{ find, replacement }`, an import map in a page)
  or a pattern that names `bufbuild`; and no code uses a module of the runtime whole (a module object written to or
  handed on: `require("@bufbuild/protobuf/codegenv2").fileDesc = …` in another file).
- **The scan read everything**: it did not stop, no JavaScript file, folder or script-holding file of it is
  SC-TRUNCATED, unreadable or a link (`_B64_DESCRIPTOR_UNREAD`), no such file or module map was too large to read, and
  in the registry no member a limit left unread or a text member not kept.

The pass costs what one reading of the scan's files costs (B-2): the hosts do not ask it when no finding's file calls
`fileDesc` (no finding could be dropped); each file is lexed once (twice for one that may hold JSX) and read in turn,
what it loads, runs and names kept and its tokens dropped (memory holds one file's readings, and the findings'
files'); each reading's names, brackets (each one's closing bracket and what it holds) and `void 0` chains are
indexed once, so no question asked of a token walks the reading; the loader bindings, module objects and `require` are
worked out once and kept; each literal's token is found by a binary search; each specifier is resolved once, and the
files a module object, a load or a re-export may reach are found through an index of the keys a file may be named by
(its path, its name, the folders above it), each key and each file visited once. Base64 that is not such a descriptor
(code, a descriptor with bytes after it, a name that is not a `.proto` path, another message) and a descriptor handed
to anything else are SC-B64 as before. No path or file name exempts anything (`gen/`, `_pb.ts` or not): file names
decide only what more the pass reads (the kinds that hold script, the module maps), and what it could not read keeps
the finding. What other generators write was looked at by generating real code from npm: protobuf-es 1.x
(`proto3.makeMessageType`), ts-proto 1.40 to 2.18 (an object literal, with `outputSchema=true`), grpc-web with
protoc-gen-js (jspb), protobufjs's pbjs (static and JSON modules) embed no descriptor as base64. ts-proto with
`outputSchema=true` embeds a message-typed custom option's value as base64 (`ApiDoc.decode(bytesFromBase64("…"))`):
another message, so SC-B64 when it is 200 characters or more, as before. @bufbuild/protobuf's own well-known types
import `fileDesc` by a relative path (`../../../codegenv2/file.js`): a module named by its place, so they keep SC-B64.

Residual (for John's call): a descriptor's options carry bytes of any kind by design, and a schema the descriptor
made (`messageDesc(file_x, 0)`: what generated code exports and every user of it reads) holds the descriptor
(`.file`, `.proto`); `getOption`/`getExtension` read a custom option's value. No rule on `file_x` can see that read:
code that reads options so and runs them through a sink this pass reads (an eval, a `Function`, a vm call, a
constructor, `child_process`, `worker_threads`) keeps the finding; one that writes them to a file something else
runs later, sends them on, or hands them to `setTimeout` as a string does not. Where a module leads only at run time
(`NODE_PATH`, a loader or `--import` flag, a bundler's alias the code computes, a `paths` mapping the scan did not
read) the pass reads it as the scan's files say. A tree a project scan prunes (`node_modules` without `--deps`, a
checkout's committed copy of the runtime among it) is not read: what it holds is not scanned either.

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
reports a flood — more than `FLOOD_COUNT` (20) releases within a
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
`*_test.go`, a name with `_` or `.` first, a file below a `vendor/` folder's
own folders; a crate's `tests/`, `benches/`, `examples/`: `_never_built`)
gets neither the reader nor the file rules; a Go test file's name ends in
`_test.go` exactly, as Go reads it (`x_TEST.go` is built), and a package in
`vendor/` itself (`m/vendor`) is the module's and is read. A package in
`testdata/` is built when an import names it (F-06): the registry keeps a
module's testdata `.go` files (`go_testdata`) and gives the Go reader those of
a package its answer asks for (`wanted`: an import of the module's names it),
decoded and counted against `PACKAGE_CODE_CHARS` only then, and asks again
(`_testdata_wanted`, `TESTDATA_PASSES`); those it reads get the file rules
too, one it asks for that was not kept makes the module INCOMPLETE, and the
rest of `testdata/` is data. An import of another module's `testdata/`
package, which that module's own scan leaves out, is SC-GO-TESTDATA-IMPORT
(MAJOR), and so is one under the module's own path of a `testdata/` folder it
does not have (a nested module's, which the zip leaves out: the reader is told
the module's testdata folders). The Go reader reads each file as the Go toolchain reads its bytes
(`go_text`, given beside the rules' text), leaves out a file a build
constraint certainly confines to `ignore` (F-06: read as `go/build` reads the
header; `//go:buildignore` is a comment and the file builds;
docs/RUST_ENGINE.md §22), and numbers its findings as the rules number lines;
a `.go` file its parser refuses makes the module INCOMPLETE (SC-TRUNCATED: a
build may compile it), but for one in a `_`, `.` or `testdata/` folder no
import names (Go builds it only when imported) and one that does not decode
to text (its decoding's SC-TRUNCATED is the file's one). A `--deps` scan's
vendor tree holds what `go mod vendor` copied: the packages a build compiles,
which `vendor/modules.txt` lists, and the files their `//go:embed` patterns
match, which may be `.go` files below them (a `testdata/` fixture; with a main
module below `go 1.22`, the embeds of their tests too: cmd/go's `vendorPkg`). Each of its `.go` files but a test file or
one named with `_` or `.` first gets the file rules (the path below `vendor/`
begins with a module's path, which may hold a `testdata` or a `vendor`), but
one in a `testdata/`, `_` or `.` folder only as a package modules.txt lists
or one an import of a Go file read names (the project's or the tree's, a
chain followed: `go_imports`; a main module whose go.mod says a `go` below
1.23 builds an unlisted vendored package an import names, cmd/go's
`importFromModules`); another is data, as in the registry
(`_go_vendor_data`; a modules.txt that cannot be read, or lists no package,
leaves every file read). The reader
applies the rules above below each module's root, and reads every package it
is given (`listed`). A package over `PACKAGE_CODE_CHARS` (300 million
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
wall time is the same. A worker, and multiprocessing's resource tracker,
start as `python -c '…'` in the guard's working directory, the project, which
`-c` puts first on `sys.path`: the command line's pool (`WorkerPool(...,
isolated=True)`, which `guard.main` asks for) starts them with `-I` (F-01),
so a project's `multiprocessing/` is not imported; spawn gives the worker the
guard's `sys.path`. multiprocessing has no setting for a child's flags or
working directory, and moving the process's working directory would move it
under the guard's other threads, so while such a pool is open the standard
library's `multiprocessing.util._args_from_interpreter_flags` (the one in
`subprocess`, which spawn, the resource tracker and the forkserver call by
name in 3.10 to 3.14) is stood in for by one that puts `-I` first; the last
such pool to close puts the standard library's back, if the stand-in is still
the function in place. The stand-in is known by identity, not by an
attribute a wrapper could copy. Another library's function in place, put
there before a pool opens or while one is open, starts nothing: the pool, a
new executor of it or its next job is `FlagsReplaced` (an `Unavailable`: the
guard scans in its own process), and the last close leaves that function
where it is (another library can replace it at any moment: it is checked
before each submission, where a worker starts, and before an executor is
made, where the resource tracker starts, not prevented; a replacement
between the check and the start would start that process without `-I`, which
is outside the guard's threat model: Lazaret has no runtime dependencies,
and nothing else in its process uses multiprocessing). close() lets go of
the stand-in only once no executor is being made, whatever the executor's
constructor raised, and an executor made, or published, after close is ended
without a job; a close in the middle of the first job, a scan or a scan run
alone is `Unavailable` (the pool is closed), not a lost worker, so the scan
falls back to the guard's own process. A stand-in of the pool's that another
library's save and restore put back after the last pool let go passes the
flags through unchanged, and a later pool takes it for the function it
wraps. A library's own pool (`isolated=False`, the default) changes
nothing. A dedicated broker process run with `-I` and owning the pool was
considered: it would leave the stdlib alone even while the pool is open, but
it moves every archive, answer and failure (`Died`, `Hung`,
`Unavailable`) across a second process boundary, for the guard's command
line, where this process starts no other multiprocessing children. The
guard's question to the interpreter uv installs for (`interpreter_info`) is
`python -I -c …`.

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

Every path of the commit is written under its real name, and none over
another (`sources._Writer`, MAC-TESTS). The writer makes each folder itself
(`mkdir`) and creates each file where nothing is (`O_EXCL`), so on a disk
that tells names apart the checkout is the commit's tree. macOS's and
Windows' disks take paths that differ only in case or Unicode form for one
name and refuse the second (`App.py` beside `app.py`, a folder `.github/`
beside a file `.GITHUB`, `lib/` beside `Lib/`); that path is written whole,
under its real name, in a twin tree beside the checkout
(`<root>.lazaret-twin-N`, the first of at most `MAX_TWIN_TREES` where the
disk takes it; `Checkout.twins`). Once everything is written, each twin tree
is given every other file of the commit that it can hold (`overlay`: a hard
link to the file written, or a copy, made only where nothing is; never
through a link), so what a rule reads across files is beside it: the script
a task or a hook runs, the helper a tainted call goes into, a lockfile.
`MAX_OVERLAY_FILES` caps the files times the twin trees; past it each twin
tree holds its own files alone. The scan reads each twin tree as its own
project (`core.scan_twins`, for `core.main` and the registry's
`ghdiscover`): its paths are the commit's, so the rules that go by path (a
workflow under `.github/workflows/`, a `package.json`'s install hooks,
`.vscode/tasks.json`, a `setup.py`) read it as the commit's own. Its
findings join the root's at their paths in the commit, each once
(`core.merge_findings`: by rule, file and line, the most severe), its own
files count in the metrics, and `--verify-secrets` reads their lines in
their own tree. Two paths that are one name on the disk are never in one
tree, so a relation between them (`A.js` requiring `./a`) cannot be seen
there: a checkout with a twin tree is not read whole (the `case` gap,
naming the paths kept apart), INCOMPLETE for the CLI (unless
`--accept-incomplete`) and the registry, SUSPICIOUS where a strong
indicator is found all the same. On Linux a commit git made has no twin
tree, and nothing of this applies. Each path kept apart is an anomaly
(`case`) naming the path it is one name with, in each tree that refused
it: the archive reader's fold (`repo.case_fold`) names it, the disk
decides, so a disk that folds names some other way is held as well. A path
that no twin tree can hold, that the disk cannot hold at all (a name too
long, or one it refuses), or that Windows would not keep as given (a
device's name, `name:stream`, a trailing dot or space), is `skipped`, and
`sources.not_covered` makes it a part not read for both scans. The paths
the archive held are not fetched again by their blobs, so such a path is
never taken for one the archive left out.

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
rules: an impostor commit (or one only a version tag of the repository holds),
a version tag that moved since the pin book first saw it, a pin comment that
names another commit, and the action's own `action.yml` (an image without a
digest, a composite action's unpinned steps, two levels deep). What it could
not ask (the rate limit, its call budget, an expression in a ref, a private
repository) is `incomplete`, and an action not checked is not cleared. A
project scan does not call it: it needs the network, and the offline checks
(the engine's `ci_workflow`) are the scan's.

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
are off there), and the report says it was not made. A release process that
tags a commit no branch holds (built files committed on a detached head and
only the tag pushed) cannot be told from a moved tag by the branches alone;
such a commit is asked about once more (FP-IMPOSTOR-TAG, below).

A pin may name an annotated tag's object instead of a commit (the RA-4
follow-up: vercel/next.js pins `actions/github-script@d746ffe…`, the object
of v9.0.0, whose commit 3a2844b… is on `main`). GitHub Actions runs the commit
the object tags, and so do the contents API and the archive (whose pax header
names the commit), but the compare API does not take the object for it: John's
run of Oct 18 compared d746ffe… with 9 of the repository's 30 branches, none
held it, and the N-4 code fetch refused the archive as another commit's. A
SHA a branch's compare holds is a commit, so
`Branches.check(owner, repo, sha, pinned=True)`, for a pin the default branch's
compare does not hold (or with no default branch to compare), asks
`GET /repos/{o}/{r}/git/tags/{sha}` before any other branch is listed or
compared: one call of the run's budget, none for a pin the default branch
holds (most). With the branch check off (`LAZARET_NO_ACTION_BRANCHES`), or
stopped before it asked, the scan asks of every pinned SHA on its own; the
comment check never asks. 404 is no tag object, and the check goes on as
before; 200 is followed through nested tag objects (`MAX_TAG_DEPTH`, 4, in
all; each answer's `sha` must be the one asked about) to the commit, which is
checked in the pin's place (`Answer.tag_object` names the object), with its
own `MAX_COMPARES` after the pin's one compare: 10 in all. The commit is then
what the scan checks: the impostor check (a tag object of a commit in none of
the branches is SC-ACTION-IMPOSTOR, CRITICAL, named as a tag object),
`action.yml`, the code (its archive accepted because it names that commit) and
the report (`resolved`, and once for the use a note and `tag_objects`). The
pin's comment is compared with the object's name (another name is
SC-ACTION-PIN-MISMATCH; the comment's tag at another commit too), and the pin
book records the tag at the commit. GitHub not answering the call (an HTTP
status other than 404, the network: `Answer.tag_error`) is no answer either
way, so the pin is checked as a commit, as before the question was asked:
held by a branch, it is one; a fork's commit is SC-ACTION-IMPOSTOR as before,
with a note, and a commit is called `out` only when GitHub's commits endpoint
shows it as itself (one it shows as another commit, as it may a tag object's,
is unsettled); one GitHub does not show is incomplete, not the note a missing
commit gets. A 200 that cannot be followed to a commit (a tag of a tree, more
than 4 tag objects, an answer for another SHA), the rate limit and the call
budget leave the pin's commit unknown: `incomplete`, never a finding and never
a pass; such a pin is in no `resolved`, gets no "no action.yml" note and no
pin-mismatch. A refusal (`_Stop`) that this use has not said yet stops the run
as any other does (it and the uses after it are "not checked"), and a use left
unread because GitHub answers no more always says so.

A commit no branch holds that exactly one of the repository's own exact
version tags points to is, as far as the tags show, a release commit tagged
and never merged (FP-IMPOSTOR-TAG: John's run of Oct 18 had
`mmastrac/mmm-matrix@3edd85c…` CRITICAL, held by the lightweight tag v1.0.5
and by none of its 5 branches; JavaScript actions often build `dist/` only on
the release commit). For an `out` answer, and only then, the scan asks
`Branches.tags`: `GET /repos/{o}/{r}/tags?per_page=100`, whose `commit.sha`
is the commit an annotated tag tags (no call for each tag, as
`git/matching-refs/tags`, which names the tag objects, would need), at most
`TAG_PAGES` (3) pages, a page that is not full meaning every tag was read, a
full last page that more exist (the Link header is not read): one to three
calls, once per repository per command (the Auditors of one command's
workflow files share the listings, `Run`), out of the call budget, so that
with a tight budget a use further on may be left not checked where the scan
before FP-IMPOSTOR-TAG reached it. No exact version tag at the commit
(v4.1.0; a floating v4, latest or nightly does not count) is
SC-ACTION-IMPOSTOR, CRITICAL, as before. Two or
more version tags (annotated or lightweight) at that one commit are the shape
of tags moved onto one commit, as in actions-cool's, not a release kept by its
tag: CRITICAL whatever the pin book says, the tags named in the finding
(`version_tags`, at most 10, and `version_tag_count`) and a note. Only the
tags read count, so one version tag found while the listing did not reach
every tag (a full last page) may have a second among the rest: CRITICAL too,
with a note. The one tag, every tag read, is looked up in the pin book, as
the record was before the command first wrote to it (`Run.before`, shared by
the command's files): a record at this commit that carries the mark only
SC-ACTION-TAG-ONLY writes (`tag_only`: the commit it was given at and when,
`actionrefs.mark_of`), given at this commit before the command began
(`Run.started`), gives a note and no finding; no such mark (a first
sighting, a record the tag's own use, a pin's comment or an accept wrote, a
mark made in this command, one that names no commit, no pin book) gives
SC-ACTION-TAG-ONLY, MAJOR (a tag can be moved by whoever can push), and the
record is marked, so that a later command says whether the tag stayed. Only
that proof lowers it: a tag the pin book saw at another commit, or flagged
moved, keeps the CRITICAL (the record keeps its first commit and the move), as
does a commit a tag was moved onto, the move accepted (the record keeps the
commit it moved from, `moved_from`; a mark given at another commit than the
record's says the same of an older version's accept, whose update of the
database's row moves it and leaves the mark: accepting a move silences
SC-ACTION-TAG-MOVED, never SC-ACTION-IMPOSTOR, as a commit a tag was moved
onto is not a release commit kept by its tag, and the commit stays CRITICAL
until the tag's record is deleted by hand: the README gives the one-liners
for the pin book file, SQLite and Postgres), a listing that failed (an HTTP
error, a body that cannot be read) or was refused (the rate limit, the call
budget: the run stops as on any refusal), and a record that could not be read
or kept (the use `incomplete`, with the error), each with a note. A pin that
names a tag object and a use named by a tag are checked by the commit that
runs; a use whose own version tag the pin book found moved is not asked about
(SC-ACTION-TAG-MOVED and SC-ACTION-IMPOSTOR, CRITICAL, as before).
`--accept-moved` takes each such tag's present commit as for a use named by
it, and the run that accepts lowers nothing. In the registry's database the
marks are the columns `tag_only`, `tag_only_sha`, `moved_from` and
`moved_from_at` of `action_tags`, given to an older table when the Store
opens it (`repo._sqlite_add_columns`: a column another process added
meanwhile, its ALTER failing with "duplicate column name", is taken as there
once the table read again has it; the older `scans.artifacts` migration keeps
its own code). An older version's `--accept-moved` over the pin book file
rewrites the tag's record whole, marks and `moved_from` with it, so a later
run of this one sees the tag there for the first time: mixing versions over
one pin book file loses what the newer recorded.

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
`ssl` loads (Windows' store); `SSL_CERT_DIR` alone is not read. A server's
chain is held to RFC 5280's rules, as OpenSSL holds urllib's, and not to
the CA/Browser Forum's, which pratique's stores apply by default since its
commit of Oct 9 (its B-92: the leaf names serverAuth, RSA and ECDSA only,
issuer names byte for byte, matching key identifiers): pratique sets that
per store, and each of those stores may hold a private PKI's anchors (a
company's CA, its TLS-intercepting proxy's root put in the system bundle or
in `SSL_CERT_FILE`, a domain's roots in Windows' store), whose certificates
need follow RFC 5280 alone (`lazaret-net`'s `WEB_PKI_RULES`, off; John's to
decide).

Certificate policies (the external report's LZ-01, CWE-295: a critical
certificatePolicies, policyMappings, policyConstraints or inhibitAnyPolicy
was taken as if it were not there, so a private CA's requireExplicitPolicy
held nothing). **The native transport:** pratique processes no certificate
policy, and since its main of Oct 27 (`57c22cb0`) a critical one of the
four refuses the chain wherever it is, the trust anchor included (an anchor
that carries one is never used, so a chain that ends at it has no trusted
root); one that is not critical is ignored, as before. The refusal says
which extension it is (pratique gives its OID on a certificate the server
sent, and only "no trusted root" for an anchor: `lazaret-net`'s
`explain_refusal` names the extension, and the anchor left out, from the
store's anchors that mark one critical) and that Python's transport, with
`LAZARET_NETWORK=python`, has OpenSSL process them. **Python's
transport** (urllib and the keep-alive pool on `nativenet.tls_context()`,
secret verification on `secretverify_http.default_context()`), which
Lazaret uses by itself, not only with `LAZARET_NETWORK=python`: a redirect
to another host that the native transport hands over (LZ-02's, from the Go
guard or an SCA feed's download), the `UsePython` cases, and no native
library. There OpenSSL processes the policies (RFC 5280 6.1, with no
initial policy set), since `X509_V_FLAG_POLICY_CHECK` is set in both
contexts; before, OpenSSL checked none, and since it knows the four, a
critical one did not refuse the chain either. A chain that fails the
processing (an explicit policy required and none valid; a policy extension
that does not parse, critical or not) is refused there, and one that passes
it is taken; the trust anchor's own extensions are not part of the processing
(RFC 5280 6.1 starts below the anchor), so a critical one there is not
applied either. So a private CA whose chain fails OpenSSL's policy processing
is refused on both transports, and one whose CAs mark a policy extension
critical (RFC 5280 says policyConstraints and inhibitAnyPolicy MUST be) and
whose chain passes it is taken by Python's transport only: where Lazaret
falls back to it, or everywhere with `LAZARET_NETWORK=python`; no setting
of `lazaret-net`'s takes it (John's to decide whether one should). The
check refuses nothing public: pratique's 74 captured public chains (the 55
that verify), Mozilla's 121 roots, this machine's bundle and Sigstore's 10
certificates verify alike with `openssl verify -policy_check` (OpenSSL
3.0.13, Python 3.13's here). OpenSSL processes policies only once the chain
has verified to a trusted anchor, so only a CA the machine trusts can hand
it a policy tree. OpenSSL before 3.0.9, 3.1.1 and 1.1.1u (CVE-2023-0464 and
CVE-2023-0465, March 2023; distributions backport the fixes without
changing the version) could spend exponential time on a tree made to grow,
and skipped an invalid policy of a leaf; the flag is set on every version
all the same (fail closed), so on such an OpenSSL a trusted CA could stall
a handshake, and a policy it got wrong in a leaf goes unseen. The public
web's chains carry certificatePolicies, never critically, and none of the
other three; Sigstore's carry none. OpenSSL builds one path and does not try
another when it fails the processing, so a chain with a clean alternative
path can still be refused there. Not every chain the native transport
refuses and Python's takes is a policy case: a policy extension, not
critical, whose length is not DER's is refused by pratique for the
certificate's encoding (4 of the 70 such chains in the independent review's
set of 200). Two clients process no
policy, as before: the npm package's `--verify-secrets` (`js/src/verify.js`,
`node:https`: Node has no setting for OpenSSL's policy flag; it takes the
report's chain) and the Postgres client (`pg/connection.py`), as `psql`'s
libpq does not either.

The native random source: where the kernel's `getrandom` is refused (an old
kernel, a sandbox that blocks the call), pratique since `57c22cb0` reads
`/dev/urandom` only once `/dev/random` opens and polls readable, and fails
otherwise: where `/dev/random` is missing too, every native request fails
(kind "network", "No such file or directory"), with no fall-back to urllib,
where the library before it read `/dev/urandom` and answered. Failing
closed is the library's choice, and Lazaret keeps it.

pratique has not had an independent review, which Lazaret had asked for
before relying on its TLS; decision 12 (John, Oct 6) made it the default
anyway, with urllib one variable away.

The other callers (NET-1's second part): the guard's `Fetcher.open` (and so
`fetch`, `fetch_to_file`, the Go relay and the pip index's relay) sends an
https request through it, with the fetcher's hosts (and the URL's own,
already checked) as the rule, for the Go guard's fetcher too (below: where its
redirects may lead); `_NativeResponse` reads like
urllib's response (`headers.get`, `read`, TooLarge over the budget).
`sources._http` sends the `github:` and `gitlab:` sources' requests,
`sca_feeds.fetch` a feed's download (the feed's own host as the rule: a
redirect elsewhere is judged by its address, below). What stays on urllib: plain http (a registry served on this machine).
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

Where the Go guard's and the SCA feeds' redirects may lead (LZ-02, the
external security report of Oct 27: CWE-918, server-side request forgery). A Go module proxy may send
a zip on to its storage (Athens, Artifactory, a CDN), so the Go guard's
fetcher (`Fetcher(https_redirects=True)`, `LocalGoProxy`'s) follows a
redirect to an https host its `GOPROXY` does not name. Until this fix that
was any https host, on both transports (the native one had no host rule for
it): a malicious or compromised proxy could send the guard's GET to
`https://127.0.0.1:…`, `https://10.…` or `https://169.254.169.254/…`, a
blind request from the developer's machine. A list of storage hosts is not
the answer (no allow-lists by host: John's rule), and neither is refusing
every private address, since a company's Athens on 10.x may send go to its
own MinIO or S3 gateway on 10.y. So such a hop is judged by the address it
connects to (`scanner/netaddr.py`'s `Hops`: `guard._Hops`), against the class of the
configured host the fetch reached last:

| The hop's address | Followed when |
|---|---|
| unspecified, multicast, broadcast, reserved (240/4, the rest of 0/8), link-local (169.254/16, fe80::/10: where most clouds' metadata services are), site-local (fec0::/10), the clouds' metadata and platform addresses outside link-local (below), documentation, any other that is not globally routable | never |
| loopback (127/8, ::1) | the proxy is on loopback itself |
| private (10/8, 172.16/12, 192.168/16), unique-local (fc00::/7), carrier-grade NAT (100.64/10), benchmarking (198.18/15) | the proxy is on a private or loopback address |
| public (globally routable) | always, as before |

The metadata services of AWS, Azure, Google Cloud, Oracle Cloud,
DigitalOcean, IBM Cloud (VPC: 169.254.169.254; Power Virtual Server:
169.254.169.253), Hetzner, Tencent Cloud (169.254.0.23) and OpenStack
(fe80::a9fe:a9fe over IPv6) are link-local. Those the clouds document
outside it are `never` rows of their own (LZ-02's review): Alibaba Cloud's
metadata service, 100.100.100.200 (in carrier-grade NAT); AWS's over IPv6,
fd00:ec2::254, with its DNS resolver (fd00:ec2::253) and time server
(fd00:ec2::123), and its EKS Pod Identity Agent over IPv6, fd00:ec2::23
(a pod's credentials) (unique-local); Google's over IPv6, fd20:ce::254
(unique-local); and Azure's WireServer, 168.63.129.16 (the VM agent's
channel to the platform, DHCP and DNS: a public address).

An IPv4 address inside an IPv6 one is judged as that IPv4 address (mapped,
translated, compatible, NAT64's two prefixes, 6to4, Teredo's server and
client), each form read by `netaddr` itself, since `ipaddress`'s answers for
them differ between Python versions; `is_global` decides only what no table
names, and the classes are the same on 3.10 to 3.14. NAT64's local-use
prefix (64:ff9b:1::/48, RFC 8215) is private at best, and a network may cut
its translation prefix from it at any of RFC 6052's lengths from /48 to /96,
which the address does not say: so it is read at each (/48, /56, /64, /96)
and the strictest reading counts. The cost is precision on a network that
translates through it: the zero bits of a /96 prefix read as 0.0.0.0 at /48,
so a redirect to an address it synthesizes is refused, as before this
review. Hops to the configured
hosts are made as before (and tell the proxy's class); a refused hop is a
`HopRefused` (a FetchError) that says why: "redirect to a private address
(10.1.2.3) refused: the proxy is on a public address". The address judged is
the one connected to: on Python's transport each connection of such a fetch
(urllib's and the pool's, `_open_socket`) looks the name up once, judges
every address it gives before any is tried, connects to those, and judges
the peer (getpeername) once more, the configured proxy's too (that is how its
class is known); a kept connection is judged again before each fetch uses
it. A name that answers a public address and then a private one (DNS
rebinding) is judged by the answer it is connected by. An address written in
the Location is refused by `check` already. Through an outbound proxy
(HTTPS_PROXY's tunnel, HTTP_PROXY's forward request for a plain-http
`GOPROXY`, the system's) the peer is that proxy, which is no hop (the
connection to it is not judged), and the names are looked up there. A
lookup made here only ever refuses. The hop's name is looked up here too and
every address it gives judged, and a name that cannot be looked up here is
refused. The configured proxy's name is not looked up at all: the tunnel
goes where the outbound proxy's own lookup says, and the proxy's operator
answers both lookups, so a lookup here would let a malicious `GOPROXY`
answer 127.0.0.1 (or 10.x) to this machine and its real address to the
outbound proxy, and be taken for a proxy on loopback (a private network)
whose redirects there are followed (LZ-02's review, H1). Reached through an
outbound proxy, the configured proxy counts as on a public address
(`netaddr.RELAYED`: "the proxy is reached through an outbound proxy, so it
counts as on a public address"), unless its URL names an address, whose
class it then is. **The precision this trades:** a company's private
`GOPROXY` reached *through* the outbound proxy can send go to public
addresses only, not to its private storage. Internal hosts are normally in
NO_PROXY and reached directly, where the proxy's peer is judged as above and
its storage is reached as before (through the outbound proxy or not); naming
the proxy by its address in `GOPROXY` does the same. **The gap that
remains** is the outbound proxy's own lookup of a hop's name: a name that
answers this machine a public address and the outbound proxy another (split
DNS, or rebinding between the two lookups) is judged by what it answered
here, and the guard cannot see where the proxy connected. The outbound proxy
is the user's own configuration, and what it can reach is its own policy. A
configured host written without a port (`GOPROXY=https://athens.corp`) is
configured on every port, as it was before LZ-02, on both transports: a hop
to `https://athens.corp:6443/` is made as one to a configured host.

The native transport cannot judge an address: pratique's host rules are of
names, its resolver is `pub(crate)`, and it is vendored unmodified. So for
the Go guard too it gets the fetcher's hosts as its rule: a redirect to a
configured host is followed there as before, and one elsewhere is refused
there (`redirect N refused: host not allowed`), and the fetch is made again
on Python's path, where the rule above holds; the proxy gets the first
request twice (a GET), and the two transports give the same answer. Each hop
still gets its own host's credentials and no other's (decision 14). Asked of
pratique's next drop: an address rule in its client (a hook given each
address a hop resolves to, or the classes above as a setting), applied to
every address it tries, so that the native transport can follow such a
redirect itself.

The SCA feeds' download (`sca_feeds.fetch`, `lazaret-sca --update-bundle`)
followed a feed's redirect to any https host on both transports
(`hosts=None`), as a feed may move: the same request, from the machine that
builds the bundle. It is held to the same rule (`sca_feeds._feed_hops`):
the feed's own host is the configured one, so a redirect from OSV's, CISA's
or EPSS's host (public) may lead to a public address only, and one from a
mirror on a private or loopback address (`--osv-url`, `--kev-url`,
`--epss-url`) to one of its class (through an outbound proxy the feed's host
counts as on a public address, as a `GOPROXY` does); the native transport gets the feed's
host as its rule and a download it refuses for a redirect elsewhere is made
again on Python's transport (`_HttpsRedirects` and `_HTTPSHandler` carry
the rule on a request's `lazaret_hops`). Those two are the only fetchers
that follow a redirect off their hosts. The others' rules are names: the
npm, PyPI and Cargo guards' fetchers (their registries, and the file hosts
their indexes name, `Fetcher.allow`), `repo._RegistryOpener` and the
registry modules (`_ModuleRedirects`, their hosts), and the sources
(`_Hop`).

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
once. No schema change then: the states are new values of `github_candidates`'s
`state`, and the two cursors rows of `discovery_cursors` (GH-SCAN-GQL adds
`github_listed`, below). GH Archive has
missed most events since 2025, so the files' source is a setting
(`--github-events-url`, `LAZARET_GITHUB_EVENTS_URL`; `ghevents.source`: an
https host and a folder, the default port, no credential, query or
fragment): OpenDigger's mirror (`ghevents.MIRROR`) serves the same files,
and a run whose hour holds under `THIN_HOUR` events says so. A scan GitHub
answers 404 or 409 (gone, made private, empty) drops its candidate and is
counted (`gone`), not an error of the run. The CLI prints an OK scan in one
line and the others in full, and `progress` lines on stderr (an hour being
read, every `LISTING_PROGRESS_EVERY` pages, each scan).

A scan-all repository's own workflow hygiene (SCANALL-HYGIENE, 0.1.9; John's
decision of Oct 21, "INFO in scan-all only"). Scan-all reads random new
repositories for hostile ones, and an action not pinned, a workflow's token
permissions, a cache in a release, an OIDC token where dependencies install
(`SCAN_ALL_HYGIENE_RULES`: SC-WORKFLOW-UNPINNED, -PERMISSIONS, -CACHE,
-OIDC-INSTALL) are the owner's configuration risks, not signs of that. In a
repository scan-all queued (`repo._scan_all_row`, as `list` tells them: a
filter `all: …`, so a REST-checked one without a node ID too), `result(…,
scan_all=True)` makes such a finding at MAJOR or MINOR INFO before anything
is counted (`_hygiene_listed`): its message ends with `HYGIENE_NOTE` ("(scan-all:
the owner's workflow configuration, MAJOR in a project scan: listed, not
counted)"), the findings are put back in severity order, `sevCounts` counts
them as INFO (the stored `majors` no longer), the result's `hygieneInfo` by
rule, and the verdict's reason and an OK scan's line say how many were listed
as INFO, as the owner's configuration. The record says what happened in the
finding itself, as test code's INFO findings do ("(in test code: listed, not
counted)"), so every reader of the stored findings (`report`, fp-tally)
sees it with no new field. No verdict changes: these four are CI
hardening checks (`core.HARDENING_RULES`), which this section's verdict
counted only at CRITICAL from the start, and the engine grades none of them
CRITICAL; one that were CRITICAL would not be listed and would still count.
So `--ci`, the candidates' verdicts and `list` are as before. Where: `_scan`
passes `scan_all` for scan-all's own rows only, the one place scan-all alone
uses; a filter's candidate (in a scan-all run or not), `lazaret-registry scan
github:` (`cmd_scan`), `lazaret scan github:` and package scans grade the four
as before, and every other rule (SC-WORKFLOW-PR-CHECKOUT, -SECRETS, …) is
untouched. Scans stored before keep their findings as stored (MAJOR or MINOR,
the same verdicts): scan-all scans a repository once, and a rescan
(`lazaret-registry scan github:owner/repo@commit --rescan`) is not scan-all.

Which new repositories got code, from GitHub's GraphQL API (GH-SCAN-GQL,
0.1.9; John's choice of Oct 18). His runs that day: OpenDigger's mirror sent
his Mac some 1.5 KB/s (a 335 MB hour), and GH Archive's hour 2026-10-17-4
held 6,044 events and no `PushEvent` or `CreateEvent` at all, so three hours
of scan-all queued nothing that got code. So scan-all asks GitHub instead:
each listed repository newer than scan-all's start that no filter, exclude
or campaign marker kept (a filter's candidate keeps its REST content checks)
is kept in `github_listed` (repo ID, the listing's `node_id`, name,
description, fork, `listed_at`, `state` unasked, empty or fork,
`next_check`, `checks`, `fails`, `last_error`; a table older SQLite and
Postgres databases get when opened, `CREATE TABLE IF NOT EXISTS` and an
index on `listed_at`, and `schema.sql`; a table of the first versions,
without `fails`, gets it then, `LISTED_ADDED`: `_sqlite_add_columns`,
Postgres's `ADD COLUMN IF NOT EXISTS`, 0 for its rows; the third review's
p14) before the cursor moves past its page, and asked about after it, one
call for the page: `POST https://api.github.com/graphql` with `nodes(ids:
$ids)` (`... on Repository { databaseId nameWithOwner isEmpty isFork
isPrivate createdAt pushedAt diskUsage }`) and `rateLimit { cost remaining
resetAt }`, the IDs as the query's variables and nothing else. While it has
no code it is asked again at `CHECK_HOURS` after it was listed (the first of
them still to come), in each run after the scans and before the listing, 100
a call: `GRAPHQL_DUE_SHARE` (a quarter) of the run's calls, and as much of
its `GRAPHQL_RUN_SECONDS`, go to the due rows listed longest ago, oldest
first (the nearest their last check, and the first the size bound would
evict), so that fresh pages cannot starve them; the rest go newest first,
down to where the oldest-first walk stopped (by (`listed_at`, `repo_id`), a
row-value keyset the index serves). The answer, node by node, every field
asked for present and of its type: `isEmpty` false is queued in
`github_candidates` (`ALL_GRAPHQL`) as of when its code arrived
(`_code_time`: `pushedAt` held to [`createdAt`, now], the run's time when it
is not known), judged again by `Filters.judged` on GraphQL's name (a rename
to a campaign marker is reported and never downloaded; the scan reads the
default branch under that name), and leaves `github_listed`; empty is asked
again; a null node that `NOT_FOUND` errors alone name, or a private one, is
gone, dropped; each counted. A fork is queued once `pushedAt` is later than
`createdAt` (at the same instant it is not; an untouched fork carries its
parent's `pushedAt`), which is what GH Archive's push to a fork did: a fork
was never queued for being made, only for a push. **Fresh and late finds**
(the re-review's p10, Oct 18): the scans take the queue newest first, so
what decides between a repository found with code when it is listed (fresh)
and one found by a later ask (late) is the time each is queued as and when
each is first offered to the scans. Queued as of the finding run (the first
amendment), the late finds of a run beat the fresh ones of the run before;
asked before the scans, they are offered a run sooner than the fresh finds
of the same hour. The re-review's ruling was `pushedAt` held to
[`listed_at`, now] with the asks kept before the scans. A model of the
steady state (each hour 300 fresh finds and 300 late ones, pushed in the
same hour, 100 scans a run, 40 runs) gave: that ruling, 0 fresh and 4,000
late scanned (a late find's push comes after the fresh finds' of its hour,
and it is offered first); [`listed_at`, now] with the asks after the scans,
3,900 and 0 (a fresh find had its code when listed, so its push is held up
to its `listed_at`, after every late find's of that hour); [`createdAt`,
now] with the asks before the scans, 0 and 4,000; [`createdAt`, now] with
the asks after the scans, 1,919 and 1,981. So the asks come after the scans
(still before the listing, which cannot starve them: the scans come first
and GraphQL spends none of REST's calls), and the bound below is
`createdAt`, which `listed_at` never precedes: each kind is offered to the
scans in the run after it was found, by its push time. The test
(`PushTimeTests`) gives each repository its own push times; with one
`pushedAt` for every repository, as the review's probe has, the ties go to
the higher repository ID. **Late finds** (John, Oct 20; the third review's
p10b: a repository found at the 6 hours' ask, pushed 2 to 5 hours after it
was listed, lost the newest-push queue to each new hour's and was pruned by
its bound as soon as it was found: none scanned in 14 runs): code found at
an ask `LATE_HOURS` (6) or more after the listing is queued with `late_at`,
the run's time (`github_candidates.late_at`, added on open to an older
table, `CANDIDATE_ADDED`), and `_scans` gives `LATE_SCAN_SHARE` (a quarter)
of the scans the ready candidates leave, rounded up, to late finds, the
first found first, then the rest newest push first, late finds among them,
so that a share not used goes to the other. `_bound_queue` keeps the
`QUEUE_MAX` newest pushes and, apart, the `QUEUE_MAX` late finds found last
(`prune_github_candidates(late=)`), each counted as skipped (`lateSkipped`
the late ones); the report says the late finds queued, scanned and left.
p10b now scans 21 of them; the test (`LateShareTests`) has 3 of 10 scans a
run go to them once there are any, and the scans as before without.
**Dropped for age** only when its last scheduled ask (72 hours) answered
that it has no code (`expired`); a row never answered (errors, the budget,
an outage, a row GitHub cannot answer about) waits until it is, however
long, and the only other bound is `LISTED_MAX` (500,000, the newest kept),
whose evictions are counted and said on stderr; the report counts those
waiting from over 72 hours ago (`aged`). **Fail closed** (`read_nodes`): an
error naming a node leaves that node unanswered unless it is null and every
error for it is `NOT_FOUND`; a null node no error names, an error naming no
node (or a node past the list), an answer whose `data.nodes` is not the list
asked for (shorter, longer), a node with a field missing (`pushedAt` and
`diskUsage` too, which may be null but must be there), of another type, a
time UTC cannot hold (`9999-12-31T23:59:59-23:59`) or another repository's
`databaseId`, an HTTP error, a body over `GRAPHQL_BYTES` or not JSON leave
every repository concerned as it was (unasked, or its check still due),
`last_error` set; nothing is dropped or taken as empty. A row GitHub could
not answer about (an error naming it, its fields) waits 1, 2, 4 … hours, at
most `GRAPHQL_BACKOFF_MAX_HOURS` (72), before its next ask (`_backoff`, by
`fails`, which an answer resets), so that the oldest-first share moves past
it; it is never dropped for it. **A batch of which nothing could be read**
(an error of the whole query, or an answer not as asked; the re-review's
p12: one such row kept the 99 others of its batch unanswered run after run,
and three such batches at the old end spent the run's failures each run, so
that nothing else was asked) is isolated (`_Asker._isolate`): its halves are
asked, and the halves of those that fail so, level by level (breadth first)
down to single rows, `GRAPHQL_SPLIT_DEPTH` (7) levels for 100, within the
run's calls and seconds; a row that fails so alone, while GitHub answers
others, is backed off as above, and the rest are answered: one such row
costs some 15 calls, three in three batches some 45. Two levels in a row of
which nothing could be read (all four quarters, for a first try) are
GitHub's failure, or a failing row in every group. A control call elsewhere
tells which (`_control`; the third review's p12b: three oldest batches with
such a row in every quarter took 21 calls and stopped the asking, run after
run, the set waiting growing from 600 to 1,500): about a repository GitHub
answered about (`_known`: of this run's answers the last, kept as they come,
`GRAPHQL_CONTROL_KNOWN`, or else the newest an earlier run found empty or a
fork, in `github_listed`; its answer read, not stored), or else about the
newest due rows not asked yet this run (an ask like another; the due walk
leaves them out after, `_batches`). With neither it cannot tell, and the
batch counts as GitHub's failure: the fourth review's p16 showed why a call
about no repository (`nodes(ids: [])`, the third amendment's fallback)
proves nothing, GitHub answering it while failing every query that names
one, so that the run blamed the rows: 360 calls and 100 healthy rows backed
off with only fresh rows, 760 and 300 with rows due too; now 21 and 24
calls, nothing backed off, stopped as an outage. The very first run, with
nothing answered yet and no other row due, cannot tell either: p12b's first
run stops so (21 calls), and its next runs find what the halving finds, all
of it by the third. Answered, the groups are isolated on from their level
(`_answering`) and the asking goes on (p12b: 288 found by its second and
third runs, the 12 such rows backed off); not, they wait, with their level,
for GitHub to answer another call, and a moment's failure of GitHub so backs
nothing off. What stops the GraphQL part: `GRAPHQL_FAILURES` (3) failures of
the call (an HTTP error, a body not JSON or over the budget: never backed
off, and split only when GitHub ended the call at its own time limit, below),
or that many batches in a row of which nothing could be read, nor of their
halves and quarters, nor their control calls (8 calls each), with nothing
backed off; and `GRAPHQL_RUN_SECONDS` (900) spent in it, on its wall clock
(below). The seconds split as the calls do: the oldest-first share stops at
a quarter of either. A header not understood (`X-RateLimit-Remaining: ²`, a
reset no clock holds) is unknown, in REST's `Budget.read` and
`sources._explain` too, never an error of the run. Rate limits:
`rateLimit.remaining` or the
answer's `X-RateLimit-Remaining`, the lower, at `GRAPHQL_RATE_FLOOR`, a
`RATE_LIMITED` error (its type, or its extensions' code) or an error
speaking of a rate limit, or a 403 with no points left is GraphQL's own
hourly limit, which stops the asking and not the listing (what it lists
waits, unasked); a `Retry-After` on any answer (200 included), an error
about a secondary rate limit, a 429 or another 403 is a secondary limit,
which GitHub counts over the token's REST and GraphQL calls alike, and stops
the run as REST's limit does (the cursor, the candidates and the waiting
rows kept). REST's own limits stop REST's calls alone (`Budget.stopped`):
GraphQL spends none of them, so its asks go on after the checks or the scans
stopped on one (the third review's p15: a refusal in a scan left 199 due
rows unasked, 0 calls; now 2 calls, none left); a REST refusal that is a
secondary limit (one with a `Retry-After`, or a 429 that does not say REST's
requests are spent; `sources._refused` keeps an error answer's rate-limit
headers as `SourceError.limits`) stops them too (`Budget.shared`); a 403
without a `Retry-After` is REST's own limit (`sources._explain` calls a 403
a rate limit only with a `Retry-After` or no requests left). Budgets:
`--max-graphql-calls` (`DEFAULT_MAX_GRAPHQL_CALLS`, 4,000: a 1,000-page
listing's calls and 3,000 asking again; refused without
`--github-scan-all`), counted apart from `--max-calls`; GitHub's points
(5,000 an hour; a nodes query costs 1); the queue's `QUEUE_MAX` holds after
the listing's asks too. A listing item without a usable `node_id` cannot be
asked about: it becomes a candidate of the REST content checks
(`ALL_NO_NODE`), counted and said on stderr. A push GH Archive reads to a
repository waiting there queues it as before (`ALL_PUSHED`), and the next
ask leaves it to the candidates. Two runs at once on one Postgres database
(the review's probe: a deadlock, 40P01, escaped `run()` 3 times of 3):
`save_github_listed` locks its rows first in `repo_id` order (`SELECT …
ORDER BY repo_id FOR UPDATE`) and writes them in that order,
`add_github_listed` and `add_github_candidates` insert in that order, and a
batch rolled back for a deadlock or a serialization failure (40P01, 40001)
is done again, `PG_ROLLBACK_TRIES` times at most (each batch is idempotent;
`Store._pg_batch`). The POST is `sources.Client.post`: https to
`api.github.com` alone (not codeload or raw), the token with it (a
credential of that host on the native transport, a header of the one request
on urllib's), no redirect followed (`max_redirects=0`; urllib's
`_NoRedirect`), `POST_BYTES` and a total deadline of `GRAPHQL_SECONDS` (the
native transport's total timeout; on urllib's, `guard._Deadline`, F-07's,
with its watchdog and each read cut to the time left); the GETs keep their
per-read timeouts. GitHub's documentation, read Oct 18 (cited in
`ghdiscover.py`): the endpoint and a JSON body with `query`; the fields'
names and types; `nodes(ids:)` with no maximum stated, so a call asks about
100, the most `first`/`last` take; the primary limit answered 200 with an
error and `X-RateLimit-Remaining` 0, secondary limits 200 or 403 with
`Retry-After`; the error's `type` and `path` are GitHub's shapes, not
documented, and anything else fails closed. The run's report and the CLI
(`_print_github_graphql`): asked about, had code, empty, forks, gone, not
answered, the calls, the points left, what was dropped, the calls of which
nothing could be read (`unreadable`) and the rows backed off by isolation
(`isolated`), the late finds (`late`; the queue's `lateScanned`, `lateLeft`,
`lateSkipped`), why it stopped and how many wait; `list` counts
`github_listed` by state. GH Archive stays for the repositories made public;
its thin hour no longer points to the mirror as the fix (the mirror stays a
setting).

Calls at once, paced (GH-SCAN-GQL-SPEED, 0.1.9; John's go-ahead of Oct 20).
His profile of a real run: 907 s, of which 903.6 s waiting inside
`nativenet.request` for GitHub's answers; a call about 100 node IDs some 3.5
s, GitHub's time linear in the repositories asked (some 35 to 40 ms each: 25
IDs 1.0 s, 50 IDs 1.9 s), Lazaret's transport as fast as urllib, SQLite and
JSON some 2 s in all. So the run's 900 GraphQL seconds asked some 250 calls
(25,000 repositories) while a catch-up listing adds some 85,000 a run
(111,577 were waiting). A cheaper query was measured too: `isEmpty` agrees
with `defaultBranchRef` and a `HEAD` object on 800 repositories and is the
fastest of them, so the query stays. **GitHub's CPU-time limit** (its
rate-limits page, read Oct 21: "No more than 90 seconds of CPU time per 60
seconds of real time", "No more than 60 seconds of this CPU time may be for
the GraphQL API", estimated "by measuring the total response time for your
API requests"): one call at a time of 3.5 s already spends some 60 s of
response time a minute, so calls at once alone would end every run on a
secondary limit. One at a time cannot pass it (its calls do not overlap, and
CPU time is less than response time), and is not paced (the review of Oct
21: John's runs at some 60 s a minute never met the limit, and pacing them
to 50 cost 16 to 30% of their calls; `PacingTests`: 3.5 s calls back to
back, 35 in 120 s, no wait, 60 s of calls in any minute at most). Several at
once are paced (`_paced`, `_cpu_wait`): the run keeps the response time of
each call that ended (measured around `Client.post` on the call's own
thread) over the last `GRAPHQL_CPU_WINDOW` (60) seconds of its clock, and
starts no call while those, with an estimate for each call in flight and for
the call itself (the median of the last `GRAPHQL_CPU_RECENT` calls' times,
or a call's own time so far, the more), would pass `GRAPHQL_CPU_PER_MINUTE`
(50, a margin under GitHub's 60, as the REST listing's calls share GitHub's
90); it waits for a call in flight to end, or, none in flight, until enough
of those calls leave the window. At 3.5 s a call that is some 14 calls a
minute (a burst of 14, a wait, then one as each leaves the minute), fewer
than one at a time's 17: more at once help only while GitHub answers fast. A
call in flight is counted at the median until it passes it, so a sudden
slowdown of GitHub's can pass the minute's 50 s, by each call in flight's
time over the median: at most the concurrency times GitHub's 10 s for a call
(`PacingTests`: calls of 1 s and one of 9 s, 53 s; 58 were a call in flight
counted at the median alone). GitHub answers a minute over its limit with a
secondary limit, which stops the run cleanly, as any secondary limit does;
so `--graphql-concurrency` is raised only while calls are fast. A Ctrl-C
with calls in flight (over 1 only) waits for them to end, each within its
`GRAPHQL_SECONDS` (60) in all, their threads joined in `run()`'s `finally`;
a second Ctrl-C exits at once, the call threads being daemon threads (tried
by hand at 8: fake calls of 20 s in flight, the first Ctrl-C returned after
some 20 s, no call thread left; the second at once). **`--graphql-seconds`**
(`GRAPHQL_RUN_SECONDS`, 900, by default; at most `GRAPHQL_RUN_SECONDS_MAX`,
3,600) is the GraphQL part's time in a run, so that John can let a catch-up
run ask longer; the due share's quarter scales with it, and the pacing's
waits count towards it. **`--graphql-concurrency`**
(`DEFAULT_GRAPHQL_CONCURRENCY`, 1, one at a time as before; at most
`GRAPHQL_CONCURRENCY_MAX`, 8) makes several calls at once, which helps only
while GitHub answers fast. At 1 the call is made on the run's thread, no
thread made. Over 1, `_Calls` runs each call's HTTP (`_post`:
`sources.Client.post` and nothing else) on a thread of its own (`_spawn`,
named `lazaret-graphql-N`) and hands what it got back in the order the calls
end; everything else stays on the run's thread (`_Asker._ended`: the JSON
read, `read_nodes`, `_apply`, the points, the limits; `_after`, a batch's
follow-up: isolation, control calls, the streak), so every database read and
write is the run's, on SQLite (whose connection would refuse another thread)
and on Postgres alike. The transports are safe for it: urllib's makes a
connection for each call (a new opener, F-07's deadline its own); the native
one's shared client (pratique's clones share the pool behind a lock) hands
each call a connection of its own on HTTP/1.1, or a stream of its own on
GitHub's HTTP/2 connection, which pratique's tests run from 8 and 16 threads
at once (`TransportTests` sends eight POSTs at once on each transport to a
local HTTPS server that answers none until all eight are in: a connection
each, each its own answer). **The window** (`_room`, `_ended`): one call at
a time until an answer was read with GitHub's points left in it (until then
the points' margin below cannot be kept), then up to the concurrency; any
other answer (a failure of the call, a rate limit, an answer of which
nothing could be read, GitHub's time limit) closes it, and no call starts
until the calls then in flight have ended, their answers read and stored,
then one at a time until a call started since is read: a secondary limit or
a failure stops new calls at once, and nothing in flight is lost or stored
twice. A follow-up that makes calls of its own (`_collect`) lets every call
in flight end first and makes them one at a time (`_ask`), so isolation
keeps its exact semantics (its sub-calls are not made at once: simpler, and
GitHub failing a batch is when fewer calls are wanted) and a control call
names a repository GitHub answered about, in completion order. **The
bounds:** the GraphQL seconds and the due share's are the GraphQL part's
wall clock while calls are in flight or it waits for the CPU-time limit
(`_seconds`), not the sum of the calls' times, which would make calls at
once gain nothing; a call in flight when they run out still ends and is
stored, as one call could before. The due share's room is waited for before
the share is judged, so it is judged on the clock as it is then.
`--max-graphql-calls` counts a call as it starts, so the calls in flight are
within it; no call starts while GitHub's points left (the latest answer's)
less one for each call in flight would be at `GRAPHQL_RATE_FLOOR`. A failure
of a call started before the last failure counted was in flight with it and
is not counted again (`strikes`): three failures still means three calls,
each started after the one before was seen to fail (`failed` counts them
all). The due asks start in their order, a quarter oldest listed first and
the rest newest first; the answers may end in any order without changing
what is asked or stored. The listing reads the calls that ended before each
page (`_goes_on`), so a secondary limit one of them met stops it there.
`run()` ends every call's thread (`_Asker.close`, in a `finally`) after an
error too; the rows of calls whose answers were not read stay as they were.
**GitHub's time limit** (John, Oct 20: two 502s in ten heavier calls of some
8 s; GitHub's GraphQL API ends a call over 10 seconds with a 502 or 504,
`GRAPHQL_TIMEOUTS`): a batch's call so answered is no failure of the call;
its rows are kept as they were and asked again in halves through the
isolation above (smaller calls end sooner), and a half that fails is the
failure of the call it would have been (counted, the batch's other half left
as it was, no control call); a single row, or with `GRAPHQL_SPLIT_DEPTH` 0,
is a failure as before. GitHub answering 502 to everything still stops the
part after three failures, each batch costing two calls (`timeouts` counts
them). The run's report adds the calls' wall clock of the seconds allowed,
the most at once of those allowed, the pacing's waits (`paced`,
`pacedSeconds`) and the calls GitHub ended at its time limit. **Tests:**
`test_ghdiscover_concurrency` holds each call on its thread until the run
waits for one (`Held`), so that calls overlap and end in any order chosen
(first, last, seeded), or each takes so many seconds on a fake clock (the
pacing), the same at each run of the tests; the three discovery modules run
at the default, one call at a time, and `test_ghdiscover_at_eight` runs
their runs again at eight at once, each call answered before the run goes
on.

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
