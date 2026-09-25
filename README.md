# Lazaret

Static security & quality analysis for Python, JavaScript, and SQL — a lightweight toolkit. No dependencies at all: it runs on the Python standard library and any browser, and even building it downloads nothing.

## Install

```bash
pip install lazaret          # from PyPI: one package, zero dependencies
```

This gives four commands: `lazaret` (project scanner), `lazaret-registry` (npm/PyPI package auditing), `lazaret-mcp` (MCP server), and `lazaret-sca` (dependency CVE matching). Each also runs as a module, e.g. `python -m lazaret`.

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
```

**Secret redaction (on by default):** the flagged line of a credential finding
(S-SECRET, S-TOKEN, SQL-CRED, S-ENTROPY) is replaced with a placeholder
*before* it reaches any artifact — terminal, JSON/HTML/SARIF report, and the
registry state DB — so scanning your own code doesn't copy real credentials
into CI artifacts (audit L1). Baselines keep matching because the placeholder
is deterministic for a given rule + secret. Pass `--no-redact-secrets` when
you are auditing a leak and need the exact bytes in the report.

Note: a baseline must be a report THIS engine wrote (it carries the engine marker);
anything else is treated as untrusted — all findings count as new — so a hostile
repo cannot zero your CI gate with a hand-crafted "previous report" (audit G17).

**Where reports go, and why a scan never ends in a lost result:** report files are written under the
directory you scanned (or the directory you pass to `--out-dir`), never the current working directory —
so read-only CI checkouts and containers don't pay for a full scan and then fail to save it. The CLI
checks that every report destination is writable *before* scanning begins (exit code `3`, with a clear
message, if not). Pre-existing files at a report path are never silently overwritten: Lazaret re-writes
its *own* earlier reports (that's the re-scan workflow) but refuses to replace a file it didn't produce —
use `--force-overwrite` to override that explicitly. Directory, symlink and special-file destinations are
always refused, even with `--force-overwrite`. Writes are atomic (temp file + rename), so an interrupted
run leaves the previous report intact. Exit codes: `0` scan ok (gate passed, or no `--ci`), `1` gate
failed with `--ci`, `2` usage error, `3` report output error, `4` taint-config rules rejected (see
"Custom taint config" — only with an explicit `--taint-config` or `--strict-taint-config`).

Skips `node_modules`, `.git`, `venv`, `dist`, etc. automatically (unless `--deps`). Scans `.py .js .jsx .ts .tsx .mjs .cjs .sql`, plus `package.json` install hooks. (Note: SQL migration files under a `migrations/` directory are skipped by default — point the CLI directly at that folder to scan them.)

## Detection capabilities

- **~55 security & quality rules** across Python, JavaScript, and SQL: injection (SQL/command/code), unsafe deserialization, SSTI, XXE, hardcoded secrets, weak crypto/ciphers, TLS/SSH verification, XSS sinks, prototype pollution, NoSQL injection, insecure config, bugs, code smells, complexity, duplication.
- **SQL rules** (`.sql` scripts, stored procedures, migrations): `xp_cmdshell` OS execution, dynamic SQL built by concatenation, hardcoded credentials, `GRANT ALL`/`TO PUBLIC`, `OUTFILE`/`LOAD_FILE` filesystem access, `OPENROWSET`, disabled integrity checks, `TRUSTWORTHY ON`, `DELETE`/`UPDATE` without `WHERE`, `NOLOCK` dirty reads, and `SELECT *`. SQL is pattern-scanned (no taint/complexity metrics); comments use `--`.
- **Taint tracking** (intra-file): follows user input (`request.*`, `req.*`, `argv`, decode functions) through variable assignments into sinks — SQL, command, code, path traversal, SSRF, open redirect, XSS, SSTI — and reports the tainted variable and where it originated.
- **Interprocedural / cross-file taint** (`lazaret.scanner.flow`): whole-program analysis that follows untrusted data *through function calls and across files* — a source in one module reaching a sink in another is caught (`X-*` findings name both the source and sink locations). Python analysis is AST-based with function summaries and a call-graph fixpoint (so `f → g → sink` chains and tainted return values compose); JavaScript uses a bounded regex/brace heuristic.
- **Category-aware sanitizers** (SonarQube/Semgrep model): a value passed through a sanitizer stops being tainted for the categories that sanitizer covers, which is the main defense against false positives. `int()`/`Number()` fully cleanse; `shlex.quote()` clears command injection only; `html.escape()`/`DOMPurify.sanitize()` clear XSS only; `os.path.basename()` clears path traversal; DB-driver `.escape()` clears SQL. Using the *wrong* sanitizer for a sink (e.g. `html.escape` before a shell call) is still reported. Clearance propagates transitively through assignments and across function boundaries.
- **Configurable taint spec** (Semgrep-style, `--taint-config` or auto-loaded `.lazaret-taint.json`): add your own `sources`, `sinks`, and `sanitizers` without touching the engine; the same file drives both the intra-file and interprocedural passes. See "Custom taint config" below.

All taint passes run in directory scans, MCP `scan_directory`, and registry `--full` scans.
- **Secrets**: provider token signatures (AWS, GitHub, Slack, Stripe, Google, private keys, JWTs), name-based credential detection, and Shannon-entropy analysis for random-looking literals.
- **Supply-chain / obfuscation indicators**: decode-then-execute patterns, packed JS (`p,a,c,k,e,d`), `_0x…` obfuscator identifiers, dense hex-escape and charCode string building, large embedded base64 blobs, marshalled Python bytecode, suspicious `package.json` install hooks, and **binary artifacts** — magic-byte detection of smuggled executables/shared objects, nested archives, and opaque high-entropy blobs (see Registry scanning → Binary artifacts). With `--deps`, dependency directories are audited with this rule pack (quality rules stay off to avoid noise; dep files are excluded from quality metrics).
- **Inline suppression**: `# nosec`, `// NOSONAR`, or `# lazaret-ignore: RULE-ID` on the flagged line or the comment line above.

## Custom taint config

Drop a `.lazaret-taint.json` in the scan root (auto-loaded) or pass `--taint-config path.json`. It extends the built-in model for both the intra-file and cross-file taint engines:

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

Rules that fail validation — unknown `category` (e.g. `"sql"` instead of `"SQL injection"`), missing/empty `pattern` — are **never silently dropped**: each prints a `warning:` naming the config file, the rule and the reason, plus the list of valid categories. When the config comes from an explicit `--taint-config`, or `--strict-taint-config` is set, rejected rules additionally fail the run with exit code `4` — CI cannot silently lose coverage. (Quoting a category still needs the exact spelling; the warning lists all valid spellings.)

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

Honest limits: the cross-file taint engine is summary-based and name-resolved (it doesn't model classes/methods deeply, dynamic dispatch, or framework-specific routing), JS interprocedural analysis is heuristic rather than parser-backed, there's no framework modeling, and SCA needs a CVE bundle exported from the Redline knowledge base (Lazaret ships no vulnerability database of its own). For deep dataflow on large or polyglot codebases, consider Semgrep/SonarQube alongside Lazaret.

## Dependency CVE scanning (SCA)

`lazaret-sca` inventories the npm and PyPI packages actually installed or pinned in a project (`node_modules`, lockfiles, virtualenv `site-packages`, `requirements*.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`, `setup.py`) and matches each `name@version` against a CVE bundle exported from the Redline vulnerability knowledge base (KEV, NVD, Wordfence, EPSS, with affected-version ranges).

```bash
lazaret-sca . --bundle cve-bundle.json            # scan and report
lazaret-sca . --bundle cve-bundle.json --ci       # exit 1 if the gate fails
lazaret-sca . --bundle cve-bundle.json --inventory-only
```

A known-exploited (KEV) CVE on an installed version is a **BLOCKER**; otherwise severity follows CVSS. A package with no range data is reported as *unknown*, never cleared as patched. Output uses the same report format, baselines and exit codes as `lazaret`.

## Registry scanning (npm / PyPI)

Audit published packages for supply-chain compromise before you depend on them. Archives are downloaded from `registry.npmjs.org` / `pypi.org` and scanned **in memory** (never extracted — immune to tar-slip). Scan state is tracked in a database so you can do full or incremental sweeps.

```bash
lazaret-registry add npm:express pypi:requests   # track packages
lazaret-registry scan npm:left-pad@1.3.0         # scan a specific version
lazaret-registry scan pypi:six --full            # full ruleset, not just supply-chain
lazaret-registry scan-all                        # scan latest of every tracked package
lazaret-registry scan-all --rescan --ci          # re-scan all; exit 1 on any SUSPICIOUS
lazaret-registry list                            # tracked packages + last verdict
lazaret-registry report npm:left-pad@1.3.0       # stored findings for one scan
```

Each scan yields a verdict: **OK**, **WARN** (a critical finding), or **SUSPICIOUS** (a blocker or any supply-chain indicator). Already-scanned versions are skipped unless `--rescan` is passed, so incremental sweeps are cheap.

### Discovering new packages (time-windowed)

Instead of a fixed watchlist, you can pull packages **newly published or updated in a recent window** and scan them — useful for supply-chain threat hunting across the ecosystem:

```bash
lazaret-registry discover --since 7d                       # list new PyPI+npm pkgs (last week)
lazaret-registry discover --since 2w --ecosystem pypi      # PyPI only, last two weeks
lazaret-registry discover --since 24h --scan --ci          # scan them; exit 1 on anything SUSPICIOUS
lazaret-registry discover --since 7d --limit 100 --add     # just add to the watchlist
```

`--since` accepts `7d`, `2w`, `24h`, or an ISO date. PyPI discovery uses the timestamped RSS feeds (`packages.xml` + `updates.xml`), bounded to roughly the most recent ~100 releases per feed. npm discovery uses the replication `_changes` feed and needs network access to `replicate.npmjs.com`; if it's unreachable, npm is skipped with a warning rather than failing the run. Full-ecosystem scanning of *every* package isn't offered (npm ≈3M / PyPI ≈600k) — use the window, a watchlist, or `--add` to build one up over time.

This pairs naturally with a schedule — e.g. a daily task running `discover --since 25h --scan --ci` to catch newly published malicious packages before they land in your builds.

### Binary artifacts

Archives are classified file by file. Source files run through the normal ruleset; **binary/compiled files are inspected by content (magic bytes), not extension**, because smuggled binaries are a primary supply-chain vector — malicious code inside a compiled blob never appears in reviewable source. The scanner flags:

- **Executables / shared objects** (ELF, PE/DLL, Mach-O, WebAssembly, `.node`, `.pyc`, Java `.class`) — **CRITICAL** when found in a source distribution or npm tarball (they don't belong there), but **INFO inventory** in a wheel, where compiled extensions are expected and the verdict stays OK.
- **Nested archives** (zip/gzip/xz/tar inside the package) — a known way to hide a second-stage payload from review.
- **Opaque high-entropy blobs** — possible encrypted/packed payloads decoded at runtime. Recognized data assets (images, fonts, audio, PDF) are not flagged.

Oversized files aren't loaded whole — only a header/entropy sample is read — so a large binary is still classified without blowing up memory. The same detection runs in directory scans (`--deps`): a committed `.so`/`.exe`/`.node` in your tree or dependencies is flagged as **SC-BINARY**.

### State backend

By default state lives in a local SQLite file (`lazaret-registry.db`, no dependencies). For a shared/persistent deployment, point it at PostgreSQL:

```bash
# Create a NEW dedicated database on your existing server — do NOT merge into
# an existing application DB (e.g. edgar). One-time setup:
psql -h HOST -U admin -c "CREATE DATABASE lazaret;"
psql -h HOST -U admin -d lazaret -f "$(python -c 'import importlib.resources as r; print(r.files("lazaret.registry") / "schema.sql")')"   # optional; the app self-creates tables too

export LAZARET_DB="postgres://lazaret_app:PASSWORD@HOST:5432/lazaret"
lazaret-registry scan-all
```

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

API: `execute`, `fetch`, `fetchrow`, `fetchval`, `executemany` (pipelined and atomic), `iterate` (streaming), `execute_script` (multi-statement migrations), `transaction()` (nested blocks use savepoints), `cancel()` (thread-safe), `register_decoder()` for custom types, plus `notice_handler` and `notifications` for LISTEN/NOTIFY.

Connection settings follow libpq: a `postgresql://` URL or `key=value` string, keyword overrides, `PG*` environment variables, and `~/.pgpass`.

Security behavior:
- **No SQL injection by construction.** Queries use the extended protocol with `$1, $2, ...` placeholders, so values travel separately from SQL and are never spliced into it.
- **TLS** with `sslmode` `disable` / `prefer` (default, as in libpq) / `require` / `verify-ca` / `verify-full`, TLS 1.2 minimum. Use `verify-full` for anything beyond localhost. `sslrootcert=system` (public CAs) is only accepted with `verify-full`, since `verify-ca` against public CAs would accept any publicly issued certificate.
- **SCRAM-SHA-256** with SASLprep, and **channel binding** (`tls-server-end-point`) automatically over TLS, so a man-in-the-middle that terminates TLS can't relay the login. `channel_binding=require` enforces it.
- The server must prove it knows the password: a server that skips the SCRAM final step or sends a forged signature is rejected.
- `require_auth` (as in libpq) pins the allowed methods, e.g. `require_auth="scram-sha-256"` to refuse downgrades to MD5, cleartext, or no authentication.
- A **cleartext password is never sent over unencrypted TCP** unless you pass `allow_cleartext_password=True`.
- `~/.pgpass` is ignored if it's readable by group or others, and passwords never appear in `repr()` or error messages.
- Defensive parsing: oversized messages, unexpected messages, and protocol violations close the connection rather than being trusted.

Not supported: COPY (refused cleanly; the connection stays usable), GSSAPI/SSPI/Kerberos, multiple hosts, and replication.

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
- **External entity references.** `ExternalReferenceForbidden`
- **External DTDs and parameter entities are never loaded**, in any API, with any options. A DOCTYPE that points to an external DTD is accepted but ignored. The tests prove this with a local HTTP server that must receive zero requests.
- **Deep nesting**: `max_depth`, 500 by default. `LimitExceeded`
- **Oversized input**: `max_bytes`, unlimited by default, except 32 MiB for XML-RPC responses. The XML-RPC cap is measured after gzip decompression, so compressed "zip bomb" responses are cut off.
- Optionally, any DOCTYPE at all: `forbid_dtd=True`. `DTDForbidden`

Options and exception names match defusedxml (`forbid_dtd`, `forbid_entities`, `forbid_external`, `DefusedXmlException`), and refusals are `ValueError` subclasses. On normal documents, output is identical to the stdlib's; the compatibility tests compare them directly.

Differences from defusedxml:
- It adds `max_depth` and `max_bytes`, and XML-RPC `ServerProxy`/`Transport` classes, in addition to the global `xmlrpc.monkey_patch()`.
- `forbid_entities=False` is only allowed when the Python's libexpat is 2.4.1 or later, whose built-in amplification limit still stops entity bombs. Otherwise it raises `NotSupportedError`.
- The stdlib SAX reader asks for external DTDs, so defusedxml's SAX API rejects documents that merely reference one. Here every API behaves the same way: the reference is ignored and nothing is loaded.
- It has no lxml support and no global `defuse_stdlib()` patching.

Never call `xml.etree.ElementInclude.include()` on untrusted documents; XInclude loads the files it points to, and that isn't covered here.

## Notes

Pattern- and heuristic-based analysis (about 58 rules: injection, secrets, weak crypto, XSS sinks, deserialization, bugs, code smells, complexity, duplication). Useful for catching common issues early; not a replacement for a full security audit or dependency scanning.

## Dependencies & licensing

Lazaret is licensed under **Apache-2.0** and has **no external dependencies**, at any layer:

- **Runtime:** only the Python standard library. The Postgres state backend speaks the wire protocol itself (`lazaret.pg`), and registry feeds are parsed with `lazaret.safexml`, so there are no optional extras either.
- **Build:** `python/pyproject.toml` declares no build requirements; a small standard-library backend in `python/_build/` produces the wheel and sdist. `pip install` works with no network index.
- **Tests:** plain `unittest`; the whole suite runs on a stock interpreter.
- **Dashboard:** `lazaret.html` is one self-contained file, with no CDN assets, web fonts, or third-party scripts; its content-security policy is `default-src 'none'`.

Tests enforce this: `tests/architecture/test_stdlib_only.py` fails on any non-stdlib import in the package or the build backend, and `tests/build/test_build_backend.py` checks that the wheel declares no dependencies. Test fixtures that mention third-party packages (`flask`, `requests`, `evil-pkg` …) are scan *targets*; nothing imports them.

**Provenance note:** the version-comparison engine in `lazaret.scanner.sca` is a port of `redline/packages/core/src/version-range.ts` (same authoring team, internal sibling project). No third-party code is vendored anywhere in this repository.

## Development

```bash
cd python
python -m unittest discover -s tests -t .      # the whole suite, stock interpreter
python -m unittest discover -s tests/safexml -t .   # one component
python _build/lazaret_build.py dist            # build the wheel and sdist into dist/

LAZARET_TEST_PG_DSN=postgresql://user:pw@localhost/lazaret_test \
  python -m unittest tests.pg.test_integration tests.registry.test_pg_backend  # live Postgres; user needs CREATEDB
```

`STRUCTURE.md` describes the repository layout, where tests and fixtures live, and what ships to the registries. `docs/RELEASING.md` covers claiming the package names, trusted publishing, and cutting a release. Security reports: see `SECURITY.md`.
