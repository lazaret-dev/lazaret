# Lazaret

Static security & quality analysis for Python, JavaScript, and SQL — a lightweight toolkit. No dependencies at all: it runs on the Python standard library and any browser, and even building it downloads nothing.

## Install

```bash
pip install lazaret          # from PyPI: one package, zero dependencies
```

This gives four commands: `lazaret` (project scanner), `lazaret-registry` (npm/PyPI package auditing), `lazaret-mcp` (MCP server), and `lazaret-sca` (dependency CVE matching). Each also runs as a module, e.g. `python -m lazaret`.

On a machine with Node but no Python, the project scanner is also on npm, with the same rules and zero dependencies:

```bash
npx lazaret check .          # or: npx lazaret .   (or: npm install -g lazaret)
```

The npm package is the project scanner only; registry auditing, cross-file taint (`X-*` findings), custom taint specs, SCA and the MCP server come with the Python package. The npm CLI takes the same flags as the Python one (`--deps`, `--exclude`, `--out-dir`, `--html`/`--json`, `--sarif`, `--baseline`, `--ci`, `--force-overwrite`, `--no-redact-secrets`, `-q`) and rejects unknown ones. The two engines are tested to agree exactly: every finding including its severity and message, the metrics, ratings, quality gate and exit code (`tests/architecture/test_js_parity.py`, which also runs an adversarial fixture set). The browser dashboard carries a port of the same engine and is held to the same findings (`tests/scanner/test_review_dashboard_parity.py`).

From a checkout, `pip install ./python` (or `pip install -e ./python` for development) works with no network access: Lazaret builds with its own standard-library build backend.

## Components

| Module / command | What it is |
|---|---|
| `lazaret` (`lazaret.scanner.core`) | CLI: scan a directory tree, produce project reports |
| `lazaret.scanner.flow` | Interprocedural / cross-file taint engine (used by the CLI, MCP, registry) |
| `lazaret-sca` (`lazaret.scanner.sca`) | Dependency CVE scanner: matches installed npm/PyPI packages against a CVE bundle |
| `lazaret-registry` (`lazaret.registry`) | Registry scanner: audit npm/PyPI packages, track state in a DB |
| `lazaret-mcp` (`lazaret.mcp`) | MCP server: lets Claude scan code and changes via tools |
| `lazaret/web/lazaret.html` | Web dashboard: paste or upload code, scan in the browser |
| `lazaret.pg` | PostgreSQL client used for the registry state DB (pure stdlib) |
| `lazaret.safexml` | Safe XML parsing (a defusedxml-style layer over the stdlib) |
| `examples/` | Taint-spec template and MCP client configuration template |

## Scanning a project

```bash
lazaret <directory>                 # scan + write lazaret-report.{html,json} under the scan root
lazaret . --html out.html           # custom report path (relative paths: under the scan root)
lazaret . --out-dir /tmp/cg-reports # write reports elsewhere (must exist and be writable)
lazaret . --exclude fixtures -q     # skip extra dirs, summary only
lazaret . --ci                      # exit 1 if quality gate fails (for CI)
lazaret . --deps                    # also audit node_modules/venv for supply-chain indicators
lazaret . --sarif out.sarif         # SARIF 2.1.0 for GitHub code scanning
lazaret . --baseline prev.json      # mark issues not in a previous report as new
lazaret . --no-redact-secrets       # keep credential lines in reports (default: redacted)
lazaret . --taint-config taint.json # extend the taint model (see "Custom taint config")
```

**Secret redaction (on by default):** credentials are replaced with a
placeholder *before* they reach any artifact — terminal, JSON/HTML/SARIF
report, and the registry state DB — so scanning your own code doesn't copy
real credentials into CI artifacts (audit L1). That covers the flagged line of
a credential finding (S-SECRET, S-TOKEN, SQL-CRED, S-ENTROPY) and every
*context* line shown with any finding: whole PEM private-key blocks (BEGIN
through END), the file's entropy-flagged literals wherever they appear, URL
userinfo, GitHub tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`),
and SQL `IDENTIFIED BY` / `PASSWORD` in any letter case. Finding messages and
the install-hook `cmd` field are redacted the same way. Baselines keep
matching because the placeholder is deterministic for a given rule + secret.
Pass `--no-redact-secrets` when you are auditing a leak and need the exact
bytes in the report.

**Baselines:** a baseline must be a report this engine wrote, and a hostile
repo must not be able to supply one (audit G17), because a hand-crafted
"previous report" would hide its findings as "not new". The engine marker
alone is public, so it is not trust:

- With `LAZARET_BASELINE_KEY` set, JSON reports carry an HMAC-SHA256
  `baselineSignature` over their finding fingerprints, and a baseline is
  trusted only if its signature verifies with that key.
- Without a key, a baseline stored *inside* the scanned tree is untrusted —
  keep it outside (e.g. `$RUNNER_TEMP`). One outside the tree is trusted if it
  carries the engine marker.

An untrusted baseline counts every finding as new (a warning says why).

**Where reports go, and why a scan never ends in a lost result:** report files are written under the
directory you scanned (or the directory you pass to `--out-dir`), never the current working directory —
so read-only CI checkouts and containers don't pay for a full scan and then fail to save it. The CLI
checks that every report destination is writable *before* scanning begins (exit code `3`, with a clear
message, if not). Pre-existing files at a report path are never silently overwritten: Lazaret re-writes
its *own* earlier reports (that's the re-scan workflow; any report size) but refuses to replace a file it
didn't produce — use `--force-overwrite` to override that explicitly. Directory, symlink and special-file
destinations are always refused, even with `--force-overwrite`. Writes are atomic (temp file + rename), so
an interrupted run leaves the previous report intact, and a re-scan keeps the existing report's file
permissions.

**Exit codes:** `0` scan ok (gate passed, or no `--ci`); `1` gate failed with `--ci` — and, without
`--ci`, only for SC-MANIFEST-DEPTH (a manifest built to crash scanners); `2` usage error (unknown option,
missing, non-directory, unreadable or empty target); `3` report output error; `4` taint-config rules
rejected (see "Custom taint config"); `5` internal error (`error: internal: …`; set `LAZARET_DEBUG=1` for
the traceback). A crash never looks like a failed gate.

**What gets scanned:** `.py .js .jsx .ts .tsx .mjs .cjs .sql` sources, `package.json` and `binding.gyp`
(install hooks), and every other regular file by magic bytes (executables, shared objects, nested
archives, opaque blobs — see Binary artifacts). `.git` is always skipped. `node_modules`,
`bower_components` and `site-packages` are pruned unless `--deps`; `vendor`, `venv`, `.venv` and `env`
are pruned only when they look like dependency trees (a `pyvenv.cfg`, `modules.txt`, `autoload.php`,
`package.json` or `*.dist-info`/`*.egg-info` directly inside) — otherwise they are first-party code and
scanned. `dist/`, `build/` and `migrations/` are scanned. `__pycache__` is not scanned as source, but every
`.pyc` in it is checked: an unchecked-hash pyc (PEP 552; Python runs it without looking at the source) is
SC-PYC-UNCHECKED (CRITICAL), and one with no matching source is SC-PYC-ORPHAN (MAJOR). Every pruned tree
is listed as a Q-SKIPPED-TREE note, so the coverage gap is visible.

Only regular files are opened: symbolic links are never followed (Q-SYMLINK note — a link can't pull a
file from outside the repo into your report), FIFOs, sockets and unreadable entries become Q-UNREADABLE
notes instead of hanging or aborting the scan, and the walk is iterative (no recursion limit on deep
trees). Source files and manifests over 2,000,000 bytes get SC-TRUNCATED instead of a silent skip; other
large files are classified from a header sample. Each file also has a 30-second time budget (SC-TRUNCATED
"scan time budget exceeded" if it is ever hit — a backstop; the rules are linear-time).

**Encodings:** a BOM decides first (UTF-8, UTF-16 LE/BE); a NUL in the first four bytes is read as
BOM-less UTF-16 only when the result is text (otherwise `/*\0*/eval(…)` would hide as UTF-16 garbage);
Python files honor PEP 263 coding cookies exactly as the interpreter does. Anything that isn't plain UTF-8
gets a Q-ENCODING note and is scanned as decoded. A UTF-7 cookie is SC-UTF7 (CRITICAL): in UTF-7, text
every editor shows as a comment can be code.

File names and scanned text printed to the terminal are sanitized: C0 controls (except tab/newline), DEL,
C1 controls (U+0080–U+009F) and bidi controls are shown as `·`, so a hostile file name can't rewrite your
terminal.

## Detection capabilities

- **63 pattern rules** across Python, JavaScript, and SQL: injection (SQL/command/code), unsafe deserialization, SSTI, XXE, hardcoded secrets, weak crypto/ciphers, TLS/SSH verification, XSS sinks, prototype pollution, NoSQL injection, insecure config, Trojan Source bidi controls (S-BIDI), bugs, code smells, complexity, duplication.
- **SQL rules** (`.sql` scripts, stored procedures, migrations): `xp_cmdshell` OS execution, dynamic SQL built by concatenation, hardcoded credentials, `GRANT ALL`/`TO PUBLIC`, `OUTFILE`/`LOAD_FILE` filesystem access, `OPENROWSET`, disabled integrity checks, `TRUSTWORTHY ON`, `DELETE`/`UPDATE` without `WHERE`, `NOLOCK` dirty reads, and `SELECT *`. SQL is pattern-scanned (no taint/complexity metrics); comments are `--` and `/* … */`.
- **Comments are lexed, not guessed**: comment state (block comments, strings, JS template literals) is tracked across lines, and a line is skipped as a comment only if all of it is comment — `/**/eval(…)` or a minified file that opens with a `/*! license */` banner is scanned. JavaScript lines also end at U+2028/U+2029, as the runtime reads them.
- **Unicode tricks**: Python lines are matched in NFKC form (`ｅｘｅｃ(…)` is `exec(…)` to the interpreter); JavaScript identifier escapes (`\u0065val`) and U+FEFF-as-whitespace are normalized before matching; bidi control characters anywhere in a source line are S-BIDI (CRITICAL).
- **Taint tracking** (intra-file): follows user input (`request.*`, `req.*`, `argv`, decode functions) through variable assignments — including annotated assignments (`x: str = request.args[…]`) and JavaScript destructuring (`const { file } = req.query`) — into sinks: SQL, command, code, path traversal, SSRF, open redirect, XSS, SSTI. Findings name the tainted variable and where it originated.
- **Interprocedural / cross-file taint** (`lazaret.scanner.flow`): whole-program analysis that follows untrusted data *through function calls and across files* — a source in one module reaching a sink in another is caught (`X-*` findings name both the source and sink locations), including a source returned by a helper and passed straight into a sink. Python analysis is AST-based: calls resolve through imports (aliases, relative imports, re-exports), `self`/`cls`/`super`, constructors and typed locals; arguments bind like a real call (keywords by name, positional-only, `self` skipped); summaries are kept per sink category; module-level code and `if __name__ == "__main__":` blocks are analyzed; a worklist fixpoint composes `f → g → sink` chains. Taint flows through `await`, conditional expressions, containers and comprehensions, `for` targets, `match`, walrus and `self.attr`. JavaScript uses a bounded heuristic over a literal-aware lexer (braces in strings, comments and template literals don't confuse it). A file the engine can't parse is named in a Q-FLOW-SKIPPED note; the rest of the project is still analyzed.
- **Category-aware sanitizers** (SonarQube/Semgrep model): a value passed through a sanitizer stops being tainted for the categories that sanitizer covers, which is the main defense against false positives. `int()`/`Number()` fully cleanse; `shlex.quote()` clears command injection only; `html.escape()`/`DOMPurify.sanitize()` clear XSS only; `os.path.basename()` clears path traversal; DB-driver `.escape()` clears SQL. Using the *wrong* sanitizer for a sink (e.g. `html.escape` before a shell call) is still reported. Clearance propagates transitively through assignments and across function boundaries (a helper that wraps `shlex.quote` clears what `shlex.quote` clears).
- **Configurable taint spec** (Semgrep-style, `--taint-config`, or the repository's own `.lazaret-taint.json` with `--trust-repo-config`): add your own `sources`, `sinks`, and `sanitizers` without touching the engine; the same file drives both the intra-file and interprocedural passes. See "Custom taint config" below.

All taint passes run in directory scans, MCP `scan_directory`, and registry `--full` scans.
- **Secrets**: provider token signatures (AWS, GitHub, Slack, Stripe, Google, private keys, JWTs), name-based credential detection, and Shannon-entropy analysis for random-looking literals.
- **Supply-chain / obfuscation indicators**: decode-then-execute patterns (also split across lines, through a variable, or behind a member prefix like `globalThis.atob`), packed JS (`p,a,c,k,e,d`), `_0x…` obfuscator identifiers, dense hex-escape and charCode string building, large embedded base64 blobs, marshalled Python bytecode, unchecked-hash or orphaned `.pyc` files, UTF-7 source, suspicious `package.json` / `binding.gyp` install hooks (an unparseable root manifest is SC-MANIFEST-UNPARSEABLE; one nested deeper than 500 levels is SC-MANIFEST-DEPTH), and **binary artifacts** — magic-byte detection of smuggled executables/shared objects, nested archives, and opaque high-entropy blobs (see Registry scanning → Binary artifacts). With `--deps`, dependency directories are audited with this rule pack (quality rules stay off to avoid noise; dep files are excluded from quality metrics).
- **Install hooks**: `preinstall`, `install` and `postinstall` everywhere, plus `preprepare`, `prepare` and `postprepare` for your own project (npm runs those on a local `npm install`). A hook that downloads and runs code, or sends environment or credential data out, is CRITICAL. In your own project a harmless prepare-family hook (`husky install`, `patch-package`) is an INFO note and doesn't fail the gate. A UTF-8 BOM in `package.json` is stripped the way npm strips it.
- **Inline suppression**: `# nosec`, `// NOSONAR`, `-- nosec` (SQL), or `lazaret-ignore: RULE-ID[,RULE-ID]`, with an optional free-text reason after it (`# nosec - reviewed by bob`). The marker must be inside a real comment (not a string or an expression), on the flagged line or on a comment-only line directly above. SC-* (supply chain) and X-* (cross-file) findings are never suppressed, and nothing is suppressed in dependency files (`--deps`).
- **Report size stays bounded**: snippet lines are clipped to 240 characters (the flagged line is windowed around the match), and low-value findings (INFO/MINOR/smells) are capped at 200 per file and rule with one Q-CAPPED note for the rest. Security findings are never capped.

## Custom taint config

Pass `--taint-config path.json`. It extends the built-in model for both the intra-file and cross-file taint engines:

```json
{
  "python": {
    "sources":    ["mylib\\.read_untrusted", "flask\\.request\\.view_args"],
    "sinks":      [{"pattern": "mylib\\.run_shell", "category": "command injection"}],
    "sanitizers": {"full": ["mylib.validate_id"],
                   "partial": {"mylib.clean_cmd": ["command injection"]}}
  },
  "javascript": {
    "sources":    ["getUserInput"],
    "sinks":      [{"pattern": "runShell", "category": "command injection"}],
    "sanitizers": {"full": ["toSafeInt"], "partial": {"myEscape": ["cross-site scripting"]}}
  }
}
```

`sources` and `sink.pattern` are **regular expressions** matched against the call/attribute text; `sanitizer` names are **exact call names** (`module.func` or `func`). `category` must be one of: `SQL injection`, `command injection`, `code injection`, `template injection`, `path traversal`, `server-side request forgery`, `open redirect`, `cross-site scripting`. A `full` sanitizer cleanses every category; a `partial` one cleanses only the listed categories. A ready-to-edit example ships as `examples/lazaret-taint.example.json`.

**A config inside the scanned repository is not trusted by default.** The repository controls that file, and sanitizers in it could silence real findings (declare `str` a sanitizer and a cross-file command injection disappears). So a `.lazaret-taint.json` in the scan root is loaded only with `--trust-repo-config` — otherwise the CLI prints a one-line note that it was found and not loaded — and even then only its `sources` and `sinks` are applied; its `sanitizers` are ignored with a warning. A used repository config is recorded in the report as a Q-TAINT-CONFIG note. A file you name with `--taint-config` is trusted fully.

Every field is type-checked (a string where a list is expected is an error, not a list of characters), and user regexes are guarded against catastrophic backtracking: at most 500 characters, no nested quantifiers, no repeated alternation, no backreferences, and each match sees at most 2,000 characters of text.

Rules that fail validation — unknown `category` (e.g. `"sql"` instead of `"SQL injection"`), missing/empty `pattern`, a wrong type, an unsafe regex — are **never silently dropped**: each prints a `warning:` naming the config file, the rule and the reason, plus the list of valid categories. When the config comes from an explicit `--taint-config`, or from the repository with `--trust-repo-config --strict-taint-config`, rejected rules additionally fail the run with exit code `4` — CI cannot silently lose coverage. (Quoting a category still needs the exact spelling; the warning lists all valid spellings.)

## Comparison vs. established scanners

| Capability | Lazaret | SonarQube | Semgrep | Bandit | Gitleaks |
|---|---|---|---|---|---|
| Pattern rules (Py/JS) | ✔ | ✔ | ✔ | Py only | — |
| Taint/dataflow | intra-file + interprocedural | ✔ (commercial) | ✔ (Pro) | — | — |
| Cross-file / interprocedural taint | ✔ Python (AST), heuristic JS | ✔ (commercial) | ✔ (Pro) | — | — |
| Category-aware sanitizers | ✔ | ✔ | ✔ | — | — |
| User-configurable taint spec | ✔ (JSON) | limited | ✔ (YAML) | — | — |
| Secret signatures + entropy | ✔ | partial | paid | — | ✔ |
| Obfuscation/supply-chain indicators | ✔ | — | partial | — | — |
| Quality gate + ratings | ✔ | ✔ | — | — | — |
| SARIF output | ✔ | ✔ | ✔ | ✔ | ✔ |
| Baseline / new-code focus | ✔ | ✔ | ✔ | ✔ | ✔ |
| Registry package auditing (npm/PyPI) | ✔ | — | partial | — | — |
| Dependency CVE scanning (SCA) | ✔ (with a CVE bundle) | ✔ | ✔ | — | — |
| Languages | 3 (Py/JS/SQL) | 30+ | 30+ | 1 | any (secrets) |

Honest limits: the cross-file taint engine is summary-based and import-resolved (it doesn't model constructor-argument → `self.attr` → method flows, dynamic dispatch, or framework-specific routing, and a method call on an unknown receiver only matches rare method names), JS interprocedural analysis is heuristic rather than parser-backed, there's no framework modeling, and SCA needs a CVE bundle exported from the Redline knowledge base (Lazaret ships no vulnerability database of its own). For deep dataflow on large or polyglot codebases, consider Semgrep/SonarQube alongside Lazaret.

## Dependency CVE scanning (SCA)

`lazaret-sca` inventories the npm and PyPI packages actually installed or pinned in a project — `node_modules` (nested copies included), `package-lock.json` v1–v3 (nested entries, `npm:` aliases, workspaces), `yarn.lock` (v1 and berry), `pnpm-lock.yaml` (v5/v6/v9), virtualenv `site-packages`, `requirements*.txt` and `requirements/*.txt` (following `-r`/`-c`), `pyproject.toml` (PEP 621 dependencies, dependency groups, `tool.poetry`), `Pipfile.lock`, `poetry.lock`, `setup.py` — and matches each `name@version` against a CVE bundle exported from the Redline vulnerability knowledge base (KEV, NVD, Wordfence, EPSS, with affected-version ranges).

```bash
lazaret-sca . --bundle cve-bundle.json            # scan and report
lazaret-sca . --bundle cve-bundle.json --ci       # exit 1 if the gate fails
lazaret-sca . --bundle cve-bundle.json --inventory-only
lazaret-sca . --bundle cve-bundle.json --sarif sca.sarif --baseline prev.json
```

A known-exploited (KEV) CVE on an installed version is a **BLOCKER**; otherwise severity follows CVSS. Nothing is ever cleared by default: a package with no range data, and an installed version or range bound that can't be compared (`*`, `2.*`, a git or URL dependency, an unpinned name), is reported as SCA-CVE-UNKNOWN. Versions compare the way each ecosystem does: PEP 440 for PyPI (epochs, pre/post/dev releases, `1.0 == 1.0.0`; a public bound ignores a `+local` label, as pip does) and semver 2.0 for npm (prerelease identifiers compared field by field, build metadata ignored). Package names are normalized per ecosystem (PEP 503 for PyPI); a scoped npm package never matches its unscoped namesake (`@types/lodash` is not `lodash`).

The bundle is validated entry by entry: malformed entries are skipped and counted in a warning, and a bundle that can't be used exits 4. A missing, unparseable or future `generatedAt` fails the freshness condition (naive timestamps are read as UTC). Output uses the same report format (JSON, HTML, SARIF), safe report paths (`--out-dir`, `--force-overwrite`), baselines and exit codes as `lazaret`.

## Registry scanning (npm / PyPI)

Audit published packages for supply-chain compromise before you depend on them. Archives are downloaded from `registry.npmjs.org` / `pypi.org` and scanned **in memory** (never extracted — immune to tar-slip). Scan state is tracked in a database so you can do full or incremental sweeps.

```bash
lazaret-registry add npm:express pypi:requests   # track packages
lazaret-registry scan npm:left-pad@1.3.0         # scan a specific version
lazaret-registry scan pypi:six --full            # full ruleset, not just supply-chain
lazaret-registry scan-all                        # scan latest of every tracked package
lazaret-registry scan-all --rescan --ci          # re-scan all; exit 1 on SUSPICIOUS or INCOMPLETE
lazaret-registry list                            # tracked packages + last verdict
lazaret-registry report npm:left-pad@1.3.0       # stored findings for one scan
```

Each scan answers one question, "does this package look malicious?", with a verdict and a one-line reason:

| Verdict | Meaning |
|---|---|
| **SUSPICIOUS** | A strong supply-chain indicator: decode-then-execute, packed or obfuscated code, code hidden in hex escapes, or an install script that sends environment or credential data over the network or contacts a known exfiltration endpoint. |
| **INCOMPLETE** | Part of the package couldn't be scanned, so it can't be cleared. Nothing strong was found in the part that was scanned. Causes: a member over the size limit; too many files or artifacts; the decompression budget (every decompressed byte counts) or the per-archive time limit (`--scan-timeout`, default 120 s); an archive in the wrong codec (bz2/xz served as `.tgz`), a truncated stream, trailing data, an invalid tar header or entries after an end-of-archive block (npm's extractor would still read them); a source file that isn't text; an unparseable root `package.json` or `binding.gyp`; an entry point or hook target that can't be read. |
| **WARN** | Weaker indicators or capabilities worth a look: an install script, shipped binaries, nested archives, opaque blobs. Plenty of legitimate packages do these things (esbuild and puppeteer download a platform binary at install; setuptools and pip ship Windows launchers). |
| **OK** | None of the above. |

Weaker indicators inside test code are listed as inventory and don't count, since tests aren't imported or run when a package is installed; strong indicators count wherever they are. Test code means exact directory names (`test`, `tests`, `testing`, `__tests__`, `spec`, `specs`, `fixtures`, `__fixtures__`, `testdata`, `test_data`, `test-data`, `test-fixtures`, `unittests`, `test cases`) or test file names (`*.test.js`, `*.spec.js`, `test_*.py`, `*_test.py`) — never a file reachable from `main`/`bin`/`exports` (`index.js` by default), an install hook, or `setup.py` and its local imports. **Secrets and code-quality findings are reported but never decide the verdict**: a test key inside someone else's package isn't a threat to you. With `--ci`, SUSPICIOUS and INCOMPLETE fail the run; a partial scan never passes.

Only the scripts npm runs on install count as install hooks (`preinstall`, `install`, `postinstall`, and a root `binding.gyp`, which is npm's implicit `node-gyp rebuild`); publisher-side scripts like `prepack` run only on the maintainer's machine. Lazaret follows each hook to what it runs — commands are tokenized like a shell (`cd dir && node x`, flags, `sh ./install.sh`), targets resolved the way Node resolves them (`x`, `x.js`, `x/index.js`) — and judges it by what that script does. For PyPI, an sdist's `setup.py` and any in-tree PEP 517 build backend are install scripts too, checked for Python network calls and environment/credential reads.

What actually runs is what gets scanned: `main`/`bin`/`exports` targets are scanned as JavaScript whatever their extension, extensionless files with a `#!` line by their interpreter, and `.pth` files in wheels (Python executes their `import` lines at every interpreter start) as SC-PTH-EXEC. Archive members are read the way installers extract them: in-archive hardlinks and symlinks in sdists and wheels are resolved and scanned under the link's name (npm drops links, as its extractor does); links that escape the archive, duplicate paths after normalization and unsafe paths are SC-ARCHIVE-LINK / SC-ARCHIVE-DUP / SC-ARCHIVE-PATH (MAJOR). Members are decoded as their runtime reads them (BOM, UTF-16, PEP 263 cookies incl. UTF-7), and a file isn't skipped as "binary" just because it contains accented text or a NUL.

Package specs: `npm:name`, `npm:@scope/name`, `pypi:name`, each with an optional `@version`. For PyPI, every artifact of the release is scanned — the sdist and each distinct wheel, each checked against its own digest — and the verdict is the worst one, with per-artifact detail in the result and the state DB (`--max-artifacts`, default 50; more makes the verdict INCOMPLETE). pip installs a wheel when one matches, so scanning only the sdist would miss the code you actually get.

Already-scanned versions are skipped unless `--rescan` is passed: `scan-all` resolves each package's latest version first and doesn't download what it has already scanned, so incremental sweeps are cheap. A package that fails to scan or store is reported, the sweep continues, and the command exits 1 at the end.

### Discovering new packages (time-windowed)

Instead of a fixed watchlist, you can pull packages **newly published or updated in a recent window** and scan them — useful for supply-chain threat hunting across the ecosystem:

```bash
lazaret-registry discover --since 7d                       # list new PyPI+npm pkgs (last week)
lazaret-registry discover --since 2w --ecosystem pypi      # PyPI only, last two weeks
lazaret-registry discover --since 24h --scan --ci          # scan them; exit 1 on SUSPICIOUS or INCOMPLETE
lazaret-registry discover --since 7d --limit 100 --add     # just add to the watchlist
```

`--since` accepts `7d`, `2w`, `24h`, or an ISO date. PyPI discovery uses the timestamped RSS feeds (`packages.xml` + `updates.xml`), bounded to roughly the most recent ~100 releases per feed. npm discovery uses the replication `_changes` feed and needs network access to `replicate.npmjs.com`; if it's unreachable, npm is skipped with a warning rather than failing the run. Malformed feed rows and invalid package names are skipped with a warning, feeds are fetched under a 5 MB cap, and a package whose scan fails is counted as flagged (INCOMPLETE), never dropped. Full-ecosystem scanning of *every* package isn't offered (npm ≈3M / PyPI ≈600k) — use the window, a watchlist, or `--add` to build one up over time.

This pairs naturally with a schedule — e.g. a daily task running `discover --since 25h --scan --ci` to catch newly published malicious packages before they land in your builds.

### Binary artifacts

Archives are classified file by file. Source files run through the normal ruleset; **binary/compiled files are inspected by content (magic bytes), not extension**, because smuggled binaries are a primary supply-chain vector — malicious code inside a compiled blob never appears in reviewable source. The scanner flags:

- **Executables / shared objects** (ELF, PE/DLL, Mach-O, WebAssembly, `.node`, `.pyc`, Java `.class`) — **MAJOR** (WARN) when found in a source distribution or npm tarball, but **INFO inventory** in a wheel, where compiled extensions are expected and the verdict stays OK.
- **Nested archives** (zip/gzip/xz/tar inside the package) — a known way to hide a second-stage payload from review. Document formats that are archives by design (`.docx`, `.odg`, `.epub`, ...) are not flagged.
- **Opaque high-entropy blobs** — possible encrypted/packed payloads decoded at runtime. Recognized data assets (images including JPEG 2000 and Photoshop, fonts, ICC color profiles, audio, PDF) are not flagged.

Oversized binaries aren't loaded whole — only a header/entropy sample is read — so a large image or font is still classified, and doesn't make the scan INCOMPLETE. Only source files that would be scanned in full count toward INCOMPLETE. The same magic-byte detection runs in directory scans on every non-source file, by content rather than name: a committed ELF renamed `logo.png`, a `.so`/`.exe`/`.node`, a nested archive or an opaque blob in your tree (or, with `--deps`, your dependencies) is flagged (**SC-BINARY**, SC-NESTED-ARCHIVE, SC-OPAQUE-BLOB).

### State backend

By default state lives in a local SQLite file (`lazaret-registry.db`, no dependencies). For a shared/persistent deployment, point it at PostgreSQL:

```bash
# Create a NEW dedicated database on your existing server — do NOT merge into
# an existing application DB (e.g. edgar). One-time setup:
psql -h HOST -U admin -c "CREATE DATABASE lazaret;"
psql -h HOST -U admin -d lazaret -f "$(python -c 'import importlib.resources as r; print(r.files("lazaret.registry") / "schema.sql")')"   # optional; the app self-creates tables too

export LAZARET_DB="postgres://lazaret_app:PASSWORD@HOST:5432/lazaret?sslmode=verify-full&sslrootcert=system"
lazaret-registry scan-all
```

`LAZARET_DB` (or `--db`) accepts a `postgres://`/`postgresql://` URL in any letter case, a libpq keyword string (`host=… dbname=… user=…`), `sqlite:PATH`, `sqlite:///PATH`, or a plain SQLite path; a path containing `=` is refused rather than silently becoming a SQLite file named after your DSN. libpq keepalive parameters (`keepalives_idle=…`) work in the DSN and are worth setting for long sweeps. A long-lived state connection (the MCP server, `scan-all`) reconnects once and retries once after a dropped session (admin shutdown, `idle_session_timeout`, a network blip) — never inside a transaction. Values the database can't store (a NUL byte, a non-UTF-8 file name) are escaped, so a hostile package can't make its own verdict unstorable.

`lazaret.pg` refuses to send an MD5 or cleartext password over TLS whose certificate wasn't verified (`sslmode=prefer`/`require`). Use `sslmode=verify-full` (or `verify-ca`) or a SCRAM-SHA-256 role. If you can't yet, `LAZARET_PG_ALLOW_MD5_OVER_UNVERIFIED_TLS=1` and `LAZARET_PG_ALLOW_CLEARTEXT_PASSWORD=1` are insecure escape hatches for the state DB (a DSN can't carry those options).

No driver install: the Postgres backend speaks the PostgreSQL wire protocol
directly (`lazaret.pg`, pure Python standard library — SCRAM-SHA-256
authentication and TLS included). The scanner uses a separate database so its `packages`/`scans` tables never collide with your other data; the same `LAZARET_DB` DSN is read by the MCP server for the `scan_package`/`registry_status` tools. Pair with `mcp__scheduled-tasks` (or cron) to run `scan-all --rescan` nightly across your dependency set.

## MCP setup (use Lazaret to test changes)

1. `pip install lazaret` into the Python the MCP client will launch.
2. Copy `examples/mcp-config.json` and replace `/ABSOLUTE/PATH/TO/lazaret-registry.db` in the `env` block
   with the absolute path where the registry state DB should live. An absolute DB path matters: the MCP
   server resolves a relative one against whatever directory the client launched it in, so a relative
   path silently creates a NEW empty DB (or finds a different one) instead of the one your `scan-all`
   sweeps write.
3. Register the server:
   - **Claude Code**: copy the `lazaret` entry into your project's `.mcp.json`
     (or run `claude mcp add lazaret -- lazaret-mcp`)
   - **Claude Desktop**: merge the entry into `claude_desktop_config.json`
     (Settings → Developer → Edit Config), then restart the app.

### Tools exposed

- `scan_directory(path, exclude?, include_deps?, max_issues?)` — full project scan: gate, metrics, ratings, issues
- `scan_files(paths)` — scan just the files you changed
- `scan_snippet(code, language)` — check code before writing it to disk
- `scan_package(spec, full?)` — fetch and audit a public npm/PyPI package (e.g. `npm:left-pad@1.3.0`)
- `registry_status()` — tracked packages and their latest verdicts
- `discover_packages(since, ecosystem?, scan?, limit?)` — find npm/PyPI packages newly published/updated in a recent window, optionally scanning them
- `quality_gate(path)` — compact PASSED/FAILED check after making changes

Typical workflow: edit code → `scan_files` on the changed files → fix findings → `quality_gate` on the project.

### Limits and safety

The MCP client is a model, and a model can be steered by content it has read, so the server bounds what a tool call can do:

- **Allowed roots:** set `LAZARET_MCP_ROOTS` (paths separated by `:` — `;` on Windows) and any path outside them is a tool error. Unset, any path the server's user can read is allowed.
- **Per-call caps:** `LAZARET_MCP_MAX_FILES` (default 20,000), `LAZARET_MCP_MAX_BYTES` (200,000,000) and `LAZARET_MCP_MAX_SECONDS` (300). A call that hits one returns what it scanned, marked `"incomplete": true` with an SC-TRUNCATED finding, so it can never pass the gate.
- **Responsiveness:** tool calls run on a worker thread; `ping` is answered while a scan runs, and `notifications/cancelled` stops the scan between files.
- **Same pipeline as the CLI:** `scan_directory` and `quality_gate` run exactly what `lazaret <dir>` runs (`lazaret.scanner.core.scan_project`), including `binding.gyp` hooks, pruned-tree notes and the cross-file pass.
- **Protocol:** JSON-RPC 2.0 over stdio; protocol versions 2025-11-25, 2025-06-18 and 2024-11-05 are negotiated; malformed JSON gets a -32700 error, notifications are never answered, and stdout carries protocol frames only.

## Postgres connector (`lazaret.pg`)

A PostgreSQL client written in pure Python, using only the standard library, so lazaret keeps zero runtime dependencies.

```python
from lazaret import pg

with pg.connect("postgresql://lazaret@db.example.com/lazaret",
                sslmode="verify-full", sslrootcert="system") as conn:
    conn.execute("INSERT INTO scans (package, verdict) VALUES ($1, $2)", "requests", "ok")
    rows = conn.fetch("SELECT package, verdict FROM scans WHERE verdict <> $1", "ok")
    for row in rows:
        print(row.package, row["verdict"])

    with conn.transaction():             # commit on success, roll back on exception
        conn.executemany("INSERT INTO seen (name) VALUES ($1)", [("a",), ("b",)])

    for row in conn.iterate("SELECT * FROM big_table", batch_size=1000):  # streams
        ...
```

API: `execute`, `fetch`, `fetchrow`, `fetchval`, `executemany` (pipelined and atomic; result rows such as `RETURNING` are discarded, and an error raised at commit — a deferred constraint, a serialization failure — is raised, never lost), `iterate` (streaming; also raises commit-time errors, and ends cleanly when its `transaction()` block exits or the connection closes), `execute_script` (multi-statement migrations), `transaction()` (nested blocks use savepoints), `cancel()` (thread-safe), `reconnect()` (same parameters), `register_decoder()` for custom types (a decoder that fails falls back to the text value instead of breaking the connection), plus `notice_handler` and `notifications` for LISTEN/NOTIFY. A server that ends the session (admin shutdown, `pg_terminate_backend`, `idle_session_timeout`) raises `ServerOperationalError` with its SQLSTATE; errors pickle and copy, so they cross process boundaries.

Parameters: Python `int` is sent as `int4`, `int8` or `numeric` by size, so functions like `repeat(text, int)` resolve; lists of `str` are sent untyped (use a cast for polymorphic functions: `unnest($1::text[])`); `timedelta` is encoded with a sign on every field, so it means the same under every `IntervalStyle`.

Connection settings follow libpq: a `postgresql://` URL (parsed the way libpq parses it: an unencoded `#` or `?` in a password is part of the password, `+` is not a space) or `key=value` string, keyword overrides, `PG*` environment variables, and `~/.pgpass` (only the default Unix-socket directories — `/tmp`, `/var/run/postgresql`, `/run/postgresql` — match `localhost`; other socket directories match their own path). Implemented libpq parameters include `hostaddr`, `connect_timeout`, `keepalives*`, `tcp_user_timeout`, `target_session_attrs`, `application_name`/`fallback_application_name`, `client_encoding` (UTF8), `sslpassword`, `sslcertmode`, `sslcrl`/`sslcrldir`, `sslsni`, `ssl_min_protocol_version`/`ssl_max_protocol_version` (never below TLS 1.2), `requiressl` and `requirepeer` (Linux); GSS/OAuth/load-balancing parameters are accepted with a warning and ignored; `service` and `replication` are refused. libpq's default client certificate and key (`~/.postgresql/postgresql.crt`/`.key`) and CRL are used when present; an encrypted client key without `sslpassword` is an error, never a terminal prompt.

Security behavior:
- **No SQL injection by construction.** Queries use the extended protocol with `$1, $2, ...` placeholders, so values travel separately from SQL and are never spliced into it.
- **TLS** with `sslmode` `disable` / `prefer` (default, as in libpq) / `require` / `verify-ca` / `verify-full`, TLS 1.2 minimum. Use `verify-full` for anything beyond localhost. As in libpq, `require` verifies the chain (like `verify-ca`) when `sslrootcert` is set or `~/.postgresql/root.crt` (`%APPDATA%\postgresql\root.crt` on Windows) exists. `sslrootcert=system` (public CAs) is only accepted with `verify-full`, since `verify-ca` against public CAs would accept any publicly issued certificate; given alone, it selects `verify-full`.
- **SCRAM-SHA-256** with SASLprep (matching PostgreSQL's own, so Unicode passwords log in), and **channel binding** (`tls-server-end-point`) automatically over TLS. `channel_binding=require` enforces it.
- **No password for an unverified server:** under `prefer` or `require` without a verified certificate, a man-in-the-middle that terminates TLS could simply ask for the password in cleartext or MD5. Lazaret refuses both over unverified TLS (opt back in with `allow_cleartext_password=True` / `allow_md5_over_unverified_tls=True`), so SCRAM with channel binding is the only thing such an attacker gets to see, and that can't be relayed. Under `prefer` an active attacker can still strip TLS entirely; use `verify-full` or `require_auth="scram-sha-256"` for real protection.
- The server must prove it knows the password: a server that skips the SCRAM final step or sends a forged signature is rejected.
- `require_auth` (as in libpq) pins the allowed methods, e.g. `require_auth="scram-sha-256"` to refuse downgrades to MD5, cleartext, or no authentication.
- A **cleartext password is never sent over unencrypted TCP or unverified TLS** (only over a Unix socket or `verify-ca`/`verify-full`) unless you pass `allow_cleartext_password=True`.
- `~/.pgpass` is ignored if it's readable by group or others, and passwords never appear in `repr()` or error messages.
- Defensive parsing: oversized messages, unexpected messages, malformed messages and protocol violations close the connection with a `pg.Error` rather than being trusted. Pipelined `executemany` reads replies while it writes, so a chatty server can't deadlock it.

Not supported: COPY (refused cleanly; the connection stays usable), GSSAPI/SSPI/Kerberos (parameters accepted and ignored), service files, multiple hosts, and replication.

## Safe XML parsing (`lazaret.safexml`)

A defusedxml-style layer over the stdlib XML parsers, also standard-library only. Use it for any XML that comes from outside, such as CycloneDX SBOMs, package metadata, feeds, and XML-RPC responses. Module names mirror the stdlib and defusedxml, so switching is one import line:

```python
from lazaret.safexml import ElementTree as ET     # instead of xml.etree.ElementTree
root = ET.fromstring(untrusted_bytes)             # returns normal ElementTree objects
for event, elem in ET.iterparse("sbom.xml"):      # streaming works too
    ...

from lazaret.safexml import minidom, sax, pulldom, xmlrpc
proxy = xmlrpc.ServerProxy("https://pypi.org/pypi")   # safe XML-RPC client
```

What it blocks, in every API (ElementTree, minidom, SAX, pulldom, XML-RPC):
- **Entity bombs** (billion laughs, quadratic blowup) and **XXE** (reading local files, server-side requests), by refusing entity declarations. `EntitiesForbidden`
- **Attribute-default blowup**: `<!ATTLIST>` defaults are copied onto every matching element, a quadratic blowup that needs no entity at all. Declared defaults are budgeted (`max_attlist_defaults`, 65,536 characters in total plus 64 per declaration), and once any default is declared the attributes reported may not exceed 100× the input after 8 MiB. `LimitExceeded`
- **Content-model crashes**: `<!ELEMENT>` content models are never converted (pyexpat does that recursively in C, and a deeply nested model crashed the interpreter).
- **External entity references.** `ExternalReferenceForbidden`
- **External DTDs and parameter entities are never loaded**, in any API, with any options. A DOCTYPE that points to an external DTD is accepted but ignored. The tests prove this with a local HTTP server that must receive zero requests.
- **Deep nesting**: `max_depth`, 500 by default. `LimitExceeded`
- **Oversized input**: `max_bytes`, unlimited by default, except 32 MiB for XML-RPC responses. The XML-RPC cap is measured after gzip decompression, and gzip replies are decompressed while they are read with the compressed size capped too (`max_bytes` + 1% + 64 KiB), so "zip bomb" responses are cut off without buffering them. Error replies are read only when their declared length is ≤ 8 KiB; otherwise the connection is closed.
- Optionally, any DOCTYPE at all: `forbid_dtd=True`. `DTDForbidden`. This is the default for XML-RPC (`loads`, `ServerProxy`, `Transport`, `monkey_patch`), which never legitimately carries a DOCTYPE.

Options and exception names match defusedxml (`forbid_dtd`, `forbid_entities`, `forbid_external`, `DefusedXmlException`), and refusals are `ValueError` subclasses. On normal documents, output is identical to the stdlib's; the compatibility tests compare them directly.

`lazaret.safexml.ElementTree` exports every name in `xml.etree.ElementTree` — the non-parsing ones (`Element`, `SubElement`, `tostring`, …) are the stdlib's own objects — plus safe `XMLParser`, `XMLPullParser`, `iterparse`, `XMLID`, `canonicalize` and an `ElementTree` class whose `parse()` is safe. A `parser` argument must be a safexml parser (for minidom and pulldom, one from `safexml.sax.make_parser()`), otherwise `TypeError` — never a silent fallback to an unsafe parser. In `iterparse` and `XMLPullParser`, errors and refusals are raised after the events that precede them, and `flush()` works as in the stdlib.

Differences from defusedxml:
- It adds `max_depth`, `max_bytes` and `max_attlist_defaults`, and XML-RPC `ServerProxy`/`Transport` classes, in addition to the global `xmlrpc.monkey_patch()`.
- minidom's `Text.isWhitespaceInElementContent` is always False, because content models are not converted.
- `forbid_entities=False` is only allowed when the Python's libexpat is 2.4.1 or later, whose built-in amplification limit still stops entity bombs. Otherwise it raises `NotSupportedError`.
- The stdlib SAX reader asks for external DTDs, so defusedxml's SAX API rejects documents that merely reference one. Here every API behaves the same way: the reference is ignored and nothing is loaded.
- It has no lxml support and no global `defuse_stdlib()` patching.

Never call `xml.etree.ElementInclude.include()` on untrusted documents; XInclude loads the files it points to, and that isn't covered here.

## Notes

Pattern- and heuristic-based analysis (63 pattern rules plus supply-chain and coverage findings: injection, secrets, weak crypto, XSS sinks, deserialization, bugs, code smells, complexity, duplication). Useful for catching common issues early; not a replacement for a full security audit or dependency scanning.

## Dependencies & licensing

Lazaret is licensed under **Apache-2.0** and has **no external dependencies**, at any layer:

- **Runtime:** only the Python standard library. The Postgres state backend speaks the wire protocol itself (`lazaret.pg`), and registry feeds are parsed with `lazaret.safexml`, so there are no optional extras either.
- **Build:** `python/pyproject.toml` declares no build requirements; a small standard-library backend in `python/_build/` produces the wheel and sdist. `pip install` works with no network index.
- **Tests:** plain `unittest`; the whole suite runs on a stock interpreter.
- **Dashboard:** `lazaret.html` is one self-contained file, with no CDN assets, web fonts, or third-party scripts; its content-security policy is `default-src 'none'` and allows only the page's own inline script, by SHA-256 hash (no `'unsafe-inline'`; run `python3 scripts/dashboard_csp.py` after editing the script — `test_dashboard.py` enforces it). Its engine is a port of the npm engine and reports the same findings as the CLI, redacts secrets the same way, and exports under its own name (`lazaret-dashboard-export.json`, marked `generatedBy: lazaret-dashboard-1`) so an export is never mistaken for a CLI report.

Tests enforce this: `tests/architecture/test_stdlib_only.py` fails on any non-stdlib import in the package or the build backend, and `tests/build/test_build_backend.py` checks that the wheel declares no dependencies. Test fixtures that mention third-party packages (`flask`, `requests`, `evil-pkg` …) are scan *targets*; nothing imports them.

**Provenance note:** the version-comparison engine in `lazaret.scanner.sca` started as a port of `redline/packages/core/src/version-range.ts` (same authoring team, internal sibling project) and now implements PEP 440 and semver 2.0 ordering directly. No third-party code is vendored anywhere in this repository.

## Development

```bash
cd python
python -m unittest discover -s tests -t .      # the whole suite, stock interpreter
python -m unittest discover -s tests/safexml -t .   # one component
python _build/lazaret_build.py dist            # build the wheel and sdist into dist/

LAZARET_TEST_PG_DSN=postgresql://user:pw@localhost/lazaret_test \
  python -m unittest tests.pg.test_integration tests.pg.test_review_live tests.registry.test_pg_backend  # live Postgres; user needs CREATEDB

cd ../js && node --test                        # the npm engine
```

`STRUCTURE.md` describes the repository layout, where tests and fixtures live, and what ships to the registries. `docs/RELEASING.md` covers claiming the package names, trusted publishing, and cutting a release. Security reports: see `SECURITY.md`.
