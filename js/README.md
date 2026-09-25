# lazaret (npm)

Quarantine for your dependencies: security & quality scanner for Python and
JavaScript projects.

The JavaScript engine is a port of Lazaret's scanner (the Python package's
`lazaret.scanner` and the browser dashboard, `lazaret/web/lazaret.html`): the
same detection rules, the intra-file taint and SQL-sink analyzers, and the
obfuscation/entropy secret detection. For a project scan, `npx lazaret` and
`python -m lazaret` are tested (`python/tests/architecture/test_js_parity.py`)
to report the same issues (rule, file, line, severity, message), metrics,
ratings, gate result and exit code. The Python engine additionally runs the
cross-file flow engine (`X-*` findings) and accepts taint configs; registry
auditing (`lazaret-registry`) is Python-only.

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
not already a Lazaret report (unless `--force-overwrite`). Writes are atomic
(temp + rename) and keep an existing report's file mode.

## Detection families

- **Injection**: `eval`/`exec`, shell command execution, SQL injection —
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
  `binding.gyp` actions and command expansions (`<!(cmd)`); an unparseable
  root manifest (`SC-MANIFEST-UNPARSEABLE`); decode-then-execute
  (`SC-EVAL-DECODE`, also across lines and, in dependencies, across
  statements); readable text hidden in hex escapes; base64 and char-code
  blobs; `javascript-obfuscator` identifier signatures; compiled binaries;
  unchecked or orphaned `.pyc` files; UTF-7 source (`SC-UTF7`).
- **Unicode evasion**: JS identifier escapes (`\u0065val`) and Python NFKC
  spellings are matched as the runtime reads them; bidirectional control
  characters are `S-BIDI` (Trojan Source).
- **Quality**: function length/complexity, duplication, empty catches, and
  the rest of the code-smell set.

## What gets scanned

- `.py`, `.js`/`.jsx`/`.ts`/`.tsx`/`.mjs`/`.cjs` and `.sql` sources, every
  `package.json` and `binding.gyp`. Every other regular file is classified by
  its magic bytes (`SC-BINARY`). Sources and manifests over 2,000,000 bytes
  are `SC-TRUNCATED`, never silently skipped; so is a file whose rules exceed
  a 30-second time backstop.
- Encodings are sniffed (UTF-8/UTF-16 byte-order marks, BOM-less UTF-16, PEP
  263 coding cookies in `.py` files): anything but plain UTF-8 is decoded
  explicitly and reported as `Q-ENCODING`.
- `.git` is never scanned. Dependency trees — `node_modules`,
  `bower_components`, `site-packages`, and `vendor`/`venv`/`.venv`/`env` when
  they look like one (`pyvenv.cfg`; `modules.txt`, `autoload.php`, a
  `package.json` or `*.dist-info`/`*.egg-info` directly inside `vendor`) —
  are pruned unless `--deps` is given; with `--deps` their files get the
  supply-chain and secret rules only. `__pycache__` is not source-scanned,
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
- Low-value findings (INFO/MINOR/smells) are capped at 200 per rule and file,
  with one `Q-CAPPED` note for the rest; security findings are never capped.

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
  -q, --quiet           only print the summary
  --ci                  exit 1 when the quality gate fails
  --version, -h/--help
```

Options are parsed like the Python CLI's: `--opt=value` and unique prefixes
work, `--` ends the options, and an unknown option is a usage error. The
Python-only options (`--taint-config`, `--strict-taint-config`,
`--trust-repo-config`) are refused with a pointer to `pip install lazaret`.

Exit codes: `0` ok (also a failed gate without `--ci`) · `1` gate failed
with `--ci`, or a hostile-depth manifest (`SC-MANIFEST-DEPTH`: `package.json`
or `binding.gyp` nested deeper than 500 levels, the same limit as the Python
engine on every Python version) · `2` usage
error (unknown option; missing, non-directory or empty target) · `3` report
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
already redacted; `setRedactSecrets(false)` opts out.

Zero dependencies, ES modules, Node 22+. Tests: `npm test` (built-in
`node --test` runner).

Website: https://lazaret.dev · Source: https://github.com/lazaret-dev/lazaret
