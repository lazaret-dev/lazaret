# lazaret (npm)

Quarantine for your dependencies: security & quality scanner for Python and
JavaScript projects.

Its rules run in Lazaret's native engine, written in Rust and compiled to
WebAssembly (`native/lazaret.wasm`, in the package: nothing to compile at
install, no native addon, no dependency): every pattern rule, the
obfuscation, entropy and secret detection, the supply-chain tests and the
cross-file received-code follower — the same engine the Python package's
platform wheels carry, held to the Python package's `lazaret.scanner` case by
case. The intra-file taint and SQL-sink analyzers, the cross-file taint pass
and the reports are JavaScript, ported from the Python package. For a project
scan, `npx lazaret` and `python -m lazaret` are tested
(`python/tests/architecture/test_js_parity.py`) to report the same issues
(rule, file, line, severity, message), metrics, ratings, gate result and exit
code. Both run the JavaScript half of the cross-file flow engine (`X-*`
findings: a request value passed into a function, in the same or another
file, whose parameter reaches a sink — directly or through the local
variables that hold it — or a helper's returned request value reaching one; a
proven RegExp's `exec()` is not a command sink; calls bind through
`require()`/`import` to the function the file names, and a call it can't
resolve reaches every project function of that name). The Python engine
additionally follows flows through Python files and accepts taint configs;
registry auditing (`lazaret-registry`) is Python-only. When the project has
Python files, the gate's cross-file condition says so: `No cross-file taint
flows (JavaScript only: 3 Python files not analyzed)`. Through 0.1.7 this
package ran JavaScript ports of those rules and tests; the findings are the
same.

```
npx lazaret check ./my-project
```

## What it does

Scans a project directory and writes the **lazaret report format**:

- `lazaret-report.json` — first key `"generatedBy": "lazaret-cli-1"`, then
  `project`, `scannedAt`, `pass`, `conditions` (quality gate), `metrics`
  (files/ncloc/comments/duplication), `counts` by issue type, `ratings`
  (security/reliability/maintainability A–E), `supplyChain`/`crossFile`
  counters, `perFile`, and the full `issues` list (rule, message, why, fix,
  CWE reference, file/line, ±2-line snippet, each line clipped to 240
  characters).
- `lazaret-report.html` — the JSON report wrapped in a marker-carrying page.
- with `--sarif PATH`, a SARIF 2.1.0 report for GitHub code scanning.

Report paths are checked before the scan starts: a directory, symlink, FIFO
or device at a report path is refused, and so is an existing file that is
not already a Lazaret report (unless `--force-overwrite`), or two reports
resolving to one file. Writes are atomic
(temp + rename) and keep an existing report's file mode.

## Detection families

- **Injection**: `eval`/`exec`, shell command execution (`exec`/`execSync` as
  a free call or on a receiver like `cp.exec` — not on `this.`/`self.`/
  `super.`, and not method definitions), SQL injection —
  including the flow-sensitive SQL-sink analyzer that catches SQL built into a
  variable and then passed to `execute(q)` (G12).
- **Taint flows**: request/argv input reaching command/XSS/SQL sinks without
  visible sanitization (`T-*` rules), including annotated assignments
  (`x: str = request.args[…]`) and destructuring (`const { a, b: c } = req.query`).
- **Secrets**: token signatures, high-entropy literals, credential-looking
  assignments, SQL `IDENTIFIED BY`/`PASSWORD`, PEM private keys. Credentials
  are redacted when an issue is created — in every snippet line, message and
  install-hook command — so the report (and the library API) persists
  `[redacted…]`, never the credential.
- **Supply chain** (`SC-*`): install hooks, meaning the scripts npm runs on
  install (`preinstall`, `install`, `postinstall`, plus `preprepare`,
  `prepare`, `postprepare` in your own project, where a non-suspicious one is
  INFO inventory; publisher-only scripts like `prepack` never run on
  install). A hook is MAJOR; one that fetches or evaluates code is CRITICAL,
  though `node -e "require('./local-file')"` is not treated as eval.
  `binding.gyp` actions and command expansions (`<!(cmd)`, `>!(cmd)`, `^!(cmd)`,
  an argv list, `<!pymod_do_main(module)`: CRITICAL when one fetches or
  evaluates code, INFO inventory when it runs a file of the package; at most
  100 listed per file, SC-TRUNCATED past 100,000 values); an unparseable
  root manifest (`SC-MANIFEST-UNPARSEABLE`); decode-then-execute
  (`SC-EVAL-DECODE`, also across lines, through an inline import such as
  `__import__("base64").b64decode`, and, in dependencies, across statements
  within 10,000 characters of the decode);
  executable `.pth` lines (`SC-PTH-EXEC`); readable text hidden in hex escapes; base64 blobs and
  strings built from character codes written in the call or in an array it uses; `javascript-obfuscator` identifier signatures (MAJOR since 0.1.8: what the obfuscated code does is read instead); compiled binaries;
  unchecked or orphaned `.pyc` files; UTF-7 source (`SC-UTF7`); your own code
  running a download piped into a shell or substituted into a command line
  (`execSync("curl … | bash")`, `execSync('bash -c "$(curl …)"')`,
  `SC-PIPE-SHELL`); and a run of invisible characters carrying hidden bytes
  — variation selectors or tag characters, the GlassWorm carrier
  (`SC-HIDDEN-UNICODE`, CRITICAL when the file also runs code from a string,
  else MAJOR; a flag emoji is left alone). Since 0.1.8: code that renames its
  package and runs `npm publish`, the registry floods' `auto.js`
  (`SC-SELF-PUBLISH`, CRITICAL); code after a run of 150 or more blanks on a
  line, where editors and review don't show it (`SC-OFFSCREEN-CODE`, CRITICAL
  when it loads or runs more code); eval of an inline decoder applied to
  hundreds of character codes or a long literal (`SC-EVAL-DECODER`,
  CRITICAL); and, in a dependency's install hook, a
  script that runs `npm publish`, collects npm access tokens, runs a DLL of
  its own with `rundll32`/`regsvr32`, or sets a program to start at login or
  boot (a systemd unit, a launchd agent, a crontab, a Windows Run key or
  scheduled task, the Startup folder, an XDG autostart entry: the
  CanisterWorm releases of @emilgroup's packages), or writes a command that
  downloads or runs code to a shell's startup file (`~/.bashrc`,
  `~/.zshrc`, `~/.profile` …; not a PATH line or a completion).
- **Unicode evasion**: JS identifier escapes (`\u0065val`) and Python NFKC
  spellings are matched as the runtime reads them; bidirectional control
  characters are `S-BIDI` (Trojan Source); a name spelled with look-alike
  letters from another alphabet (`\u0435val`, a Cyrillic e), an invisible
  U+200C/U+200D or a fullwidth letter, that reads as an ASCII name it is not,
  is `SC-HOMOGLYPH` (CRITICAL when it reads as eval, require & co. or another
  name in the file; names in comments, strings and regex literals do not count).
- **Quality**: function length/complexity, duplication, empty catches, and
  the rest of the code-smell set.

## What gets scanned

- `.py`/`.pyw`, `.js`/`.jsx`/`.ts`/`.tsx`/`.mts`/`.cts`/`.mjs`/`.cjs` and `.sql` sources, scripts
  whose `#!` line names Node (or bun, deno, ts-node, tsx) or Python whatever
  their name (`bin/cli`, a hook's `./setup`; shell scripts are not read), every
  `package.json`, `binding.gyp` and other `.gyp`/`.gypi` file, and `.pth` files (only the `SC-PTH-EXEC`
  check runs on them; they are not counted in the metrics; a directory with
  only a `.pth` file is a valid target).
- Since 0.1.9, a project's own `.go` and `.rs` sources, with comments and
  strings read as Go and Rust read them: hardcoded credentials (`S-SECRET`),
  token formats (`S-TOKEN`), Trojan Source characters (`S-BIDI`), TODO markers
  and the obfuscation and encoding checks every text gets. Their lines count
  in the metrics but not in the duplication. With `--deps`, a Go `vendor/` and a
  `cargo vendor` tree are read with the engine's Go and Rust readers (since 0.1.9:
  init code, build scripts, procedural macros); another dependency tree's Go and
  Rust files are not.
- GitHub Actions workflows and GitLab CI files: the shapes the worms planted,
  and since 0.1.9 the hardening checks (`SC-WORKFLOW-*`: an action not pinned
  to a commit, `pull_request_target` checking out the pull request's code, a
  cache in a release workflow, write permissions, an OIDC token in a job that
  installs, `curl … | sh`; `SC-GITLAB-*`: includes and images not pinned, `curl
  … | sh`, a merge request's text run as code, a publishing token in a job
  that installs), security hotspots; only a CRITICAL one fails the gate. Every other regular file is classified by
  its magic bytes (`SC-BINARY`), and a source file whose bytes are a program
  (an ELF or Windows executable named `.js` or `.py`) is `SC-BINARY`
  CRITICAL; one whose bytes don't decode to text is `SC-TRUNCATED`.
  Sources and manifests over 16,000,000 bytes
  (`--max-source-bytes`, env `LAZARET_MAX_SOURCE_BYTES`) are `SC-TRUNCATED`,
  never silently skipped; so is a file whose rules exceed
  a 30-second time backstop (checked inside each rule's match loop).
- Encodings are sniffed (UTF-8/UTF-16 byte-order marks, BOM-less UTF-16, PEP
  263 coding cookies in `.py` files): anything but plain UTF-8 is decoded
  explicitly and reported as `Q-ENCODING`.
- `.git` is never scanned. Dependency trees — `node_modules`,
  `bower_components`, `site-packages`, and `vendor`/`venv`/`.venv`/`env` when
  they look like one (`pyvenv.cfg`; `modules.txt`, `autoload.php`, a
  `package.json` or `*.dist-info`/`*.egg-info` directly inside `vendor`) —
  are pruned unless `--deps` is given; with `--deps` their files get the
  supply-chain and secret rules only, each install hook of a dependency —
  package.json scripts, binding.gyp actions and the command expansions that
  run a file of the package — is read as a program and followed to the
  files it runs (a hook whose command or script sends data read from the
  machine over the network, pipes a download into a shell, or runs code it
  receives over the network — a download handed to eval, exec, `new
  Function`, a shell or an interpreter's inline code — is CRITICAL; a file
  it runs that is not a
  source file is read and scanned as JavaScript), a dependency whose package
  root has a `binding.gyp` and no install script gets npm's implicit
  `node-gyp rebuild` hook (MAJOR), and a dependency's other JavaScript and
  Python files get the import-time test (`SC-IMPORT-RISK`: CRITICAL for the
  whole environment or a credential store read and sent over the network,
  what local commands print about the machine sent (both wherever they go,
  since rule set 2.17), local data sent to a raw socket's hard-coded public
  address, a download run through a shell, or a value received over the
  network run as code (also under an alias or an indirect `eval`); MAJOR when
  the value is deserialized (`pickle.loads`, unsafe `yaml.load`,
  `unserialize`; CWE-502), used as a dynamically imported module name, or
  written to a file the same code then runs). Since 0.1.8 both
  tests also fail on data sent to a webhook or a bot whose secret is in
  the code (any service's), credential files sent to a raw IP
  address, a sweep of three or more credential folders, the host name sent
  to an address kept base64-encoded or in a DNS name the code builds, the
  public IP address sent to a data-capture service, a reverse shell, a
  cryptocurrency miner, and code run from what a file reads back from itself or a data file
  next to it, at once or asynchronously (a `readFile` callback, `.then()`);
  a script a hook runs is followed to the scripts it starts with node or
  python (`spawn(process.execPath, [file])`, `fork(file)`), bun or deno, or
  any program a variable names given a file of code, the tests read the
  strings a file decodes as it runs (hex, base64, a file's own decoding
  helpers, a home-made XOR or character-code decoder, javascript-obfuscator's
  string arrays and proxy objects), and — as in the Python engine — a
  package's files are followed
  into each other: a value received in one file and run in another, through
  wrappers and re-exports, classes, object literals, callbacks and Promises,
  caches, dynamic imports and environment variables, or a function of the
  package that runs its argument, is `SC-IMPORT-RISK` (CRITICAL), naming the
  other file. A
  dependency that launches your AI coding agent in an autonomous mode
  (`claude --dangerously-skip-permissions`, `gemini --yolo`, the s1ngularity
  attack) is `SC-AGENT-HIJACK` (CRITICAL).
  `__pycache__` is not source-scanned,
  but its `.pyc` files are checked. Every pruned tree is listed as an INFO
  `Q-SKIPPED-TREE` finding.
- Symbolic links are never followed (`Q-SYMLINK`); only regular files are
  opened; unreadable entries and special files become INFO `Q-UNREADABLE`
  findings instead of errors. File names that are not valid UTF-8 are
  reported with `\xNN` escapes.
- Suppressions: `# nosec`, `// nosec`, `NOSONAR` or
  `lazaret-ignore: RULE[,RULE]` (a free-text reason may follow) inside a real
  comment — not a string — on the flagged line or on a comment line directly
  above; `--` comments count in `.sql` files only. `SC-*`/`X-*` findings and
  anything in dependency files are never suppressed.
- Findings identical on rule, file, line and message are reported once, and
  every non-security rule (anything but `S-`, `T-`, `SC-`, `X-`, `SQL-`) is
  capped at 200 per rule and file, with one `Q-CAPPED` note for the rest;
  security findings are never capped.

## CLI

```
lazaret check <directory> [options]
lazaret <directory> [options]          # the same, like the Python CLI

  --out-dir DIR         directory for the default reports (default: the scan
                        root); must already exist and be writable
  --json PATH           JSON report path (relative paths: under --out-dir)
  --html PATH           HTML report path
  --sarif PATH          also write a SARIF 2.1.0 report
  --no-json / --no-html do not write that report
  --force-overwrite     replace an existing report file Lazaret did not write
                        (directories, symlinks and special files are always
                        refused)
  --deps                also scan dependency trees (alias: --include-deps)
  --exclude NAME        extra directory name to skip (repeatable)
  --baseline PATH       previous JSON report; findings not in it are marked new
  --no-redact-secrets   keep credential lines in reports (default: redacted)
  --excerpt-width N     characters of the flagged line shown per finding
  --max-source-bytes N  largest source file or manifest read (16,000,000; env
                        LAZARET_MAX_SOURCE_BYTES)
  -q, --quiet           only print the summary
  --ci                  exit 1 when the quality gate fails
  --version, -h/--help
```

A scan with much to read (a megabyte of source or more besides its largest
file) spreads the files over worker threads, one per core up to 8, each with
its own instance of the engine; `LAZARET_THREADS` sets how many (`1`: none).
The findings and their order are the same whatever the number.

Options are parsed like the Python CLI's: `--opt=value` and unique prefixes
work, `--` ends the options, and an unknown option is a usage error. The
Python-only options (`--taint-config`, `--strict-taint-config`,
`--trust-repo-config`) are refused with a pointer to `pip install lazaret`.

Exit codes: `0` ok (also a failed gate without `--ci`) · `1` gate failed
with `--ci`, or a hostile-depth manifest (`SC-MANIFEST-DEPTH`: `package.json`
or `binding.gyp` nested deeper than 500 levels, the same limit as the Python
engine on every Python version) · `2` usage
error (unknown option; missing, non-directory or empty target; in a source
checkout, the WebAssembly engine not built yet) · `3` report
output error (unsafe or unwritable report path, checked before the scan) ·
`5` internal error (`error: internal: …`; set `LAZARET_DEBUG=1` for a stack
trace). Exit `4` (rejected taint config) exists only in the Python CLI.

**Baselines.** `--baseline` accepts only a Lazaret JSON report. With
`LAZARET_BASELINE_KEY` set, every JSON report carries a `baselineSignature`
(`{"alg": "HMAC-SHA256", "value": "<hex>"}` over the report's finding
fingerprints, the same as the Python engine's) and a baseline is used only if
its signature verifies. Without a key, a baseline inside the scanned tree is
untrusted — the repository under review could have planted it — so keep it
outside (e.g. in `$RUNNER_TEMP`). An untrusted baseline counts every finding
as new.

**Terminal output.** File names, messages and excerpts come from the scanned
tree; C0 control characters (except tab and newline), DEL, C1 controls
(U+0080–U+009F) and bidi controls in them are printed as `·`, exactly as the
Python CLI prints them, so a hostile file name can't rewrite your terminal.

## Library

```js
import { scanFile, buildResult, run } from "lazaret";
```

`scanFile({ name, content, lang, dep })` returns issues with credentials
already redacted; `setRedactSecrets(false)` opts out. The supply-chain tests
are exported too (`installScriptRisk`, `importTimeRisk`, `followHook`, …),
answered by the native engine. The rule tables (`RULES`, `TEXT_RULES`) are
no longer exported since 0.1.8: they live in the engine's rule pack.

Zero dependencies, ES modules, Node 22+. From a source checkout, build the
engine first: `npm run build` (it needs Rust and `rustup target add
wasm32-unknown-unknown`, and writes `native/lazaret.wasm` from the
repository's `rust/`), then `npm test` (built-in `node --test` runner).

Licensed under Apache-2.0, except for the Unicode 13.0 and codec tables,
which are Unicode data, under the Unicode License v3 (`LICENSE-UNICODE`; see
`NOTICE`). The native engine is Lazaret's own work (`native/NOTICE`). The
package's license is `Apache-2.0 AND Unicode-3.0`.

Website: https://lazaret.dev · Source: https://github.com/lazaret-dev/lazaret
