# Changelog

All notable changes to Lazaret are recorded here. The Python (PyPI) and npm
packages share a version and are released together (see `docs/RELEASING.md`).
This log starts at 0.1.6; for earlier releases see the git history and tags.

The format is based on [Keep a Changelog](https://keepachangelog.com); the
project is pre-1.0, so the 0.x API may still change.

## [0.1.7] — unreleased

### Added
- **`lazaret-sca` reads `uv.lock`, `pylock.toml` and `bun.lock`.** Projects
  locked with uv or a PEP 751 lock file were inventoried from `pyproject.toml`
  alone, so their transitive dependencies went unchecked (six advisories
  missed in the audit benchmark), and Bun's text lockfile was not read at all.
  All three now count as locked truth, like `poetry.lock` and
  `pnpm-lock.yaml`: a registry release is matched by its version, a git, URL
  or local-archive package is kept with an unknown version (a matching
  advisory is reported unknown, never cleared), and first-party entries (the
  project, workspace members, local project directories, links) are not
  inventoried. `pylock.<name>.toml` files are read too. A project with only
  Bun's binary `bun.lockb` gets a warning naming it. On the benchmark
  projects all three now match an independent OSV matcher exactly (216 of
  216 advisory groups for uv and pylock, 104 of 104 for Bun, none extra).

- **Config and data files are checked for credentials (both engines; audit
  P0).** Only Python, JavaScript and SQL were read, so a credential in a
  `.env`, JSON, YAML, TOML, INI / `.cfg` / `.conf`, `.properties`, shell
  script, `.pem` / `.key` or SSH key, Dockerfile, `.npmrc` / `.pypirc` /
  `.netrc` or `*.tfvars` file was never seen: 19% recall on the audit's
  labeled corpus. Those files are now read as text (outside dependency trees)
  and checked by S-TOKEN (not AWS's `AKIA…EXAMPLE` key or jwt.io's sample
  token; a private-key header only with real key material) and by a config
  form of S-SECRET: a key named like a credential whose value looks like one,
  a password in a URL (not on localhost), and Slack / Discord webhook URLs.
  References (`${VAR}`, `{{ … }}`), paths, names (`root-ca`, `ACCESS_TOKEN`),
  translations and placeholders are not reported. Lockfiles, Lazaret's own
  reports and binary files are not read; a config file over 2 MB gets a
  Q-SKIPPED-CONFIG coverage note. Config files count in no code metric; the
  report's new `metrics.configFiles` says how many were checked, and the
  terminal summary lists them. Suppression markers work in their comments.
  The MCP `scan_files` tool accepts config files too. On the corpus: 94.9%
  recall (was 19.2%) with no new false positives; a sweep of 11,490 config
  files in 17 public repositories flagged only committed credentials (test
  fixtures, Kubernetes Secret data, private keys, documented default
  passwords), and 476 in the benign package corpus flagged nothing.

- **Taint follows values into f-strings and template literals, and knows
  Flask's and Django's responses (both engines; audit P0).** The intra-file
  engine removed every string literal before reading a line, so
  `open(f"/srv/{name}")` and ``exec(`ls ${dir}`)`` were not flows. It now
  reads the fields of a Python f-string and of a JavaScript template literal
  no tag reads (``sql`…${id}` `` is parameterized), a statement over up to 8
  lines (`subprocess.run(` / `f"echo {q}",` / `shell=True)`), and augmented
  assignments (`html += f"<li>{q}</li>"`). New sources: Flask's `get_data`,
  `query_string`, `stream`, `full_path` and Django's `GET`, `POST`,
  `COOKIES`, `META`, `FILES`, `body`. New sinks: `codecs.open`, `io.open`,
  `os.open`, `shutil` copies and moves, `os.remove` / `rename` / `listdir`
  and kin (path traversal); `flask.redirect` and Django's
  `HttpResponseRedirect` (open redirect); `make_response`, `Response`,
  `HttpResponse`, `Markup` and `mark_safe` (XSS), and the value a Flask view
  returns, unless it is a JSON container, a template, a redirect, a file or
  another function's result. New sanitizers: an autoescaping
  `render_template`, `jsonify`, `url_for` (XSS and open redirect),
  `escape…()`, Django's `conditional_escape` / `format_html`, werkzeug's
  `safe_join`, and Flask's typed `request.args.get(…, type=int)`. The
  cross-file engine (`X-*`) knows the same sources, sinks and sanitizers. On
  OWASP BenchmarkPython (Python 3.13) the score of all rules went from
  +0.10 to +0.19 (true positives 36% → 47%, false positives 27% → 29%;
  Semgrep CE with its community rules: +0.16), and of the taint findings
  alone from +0.00 to +0.11 (8% → 22% of real flaws found): XSS 0 → 55%,
  path traversal 3% → 40%, open redirect 0 → 61%. The benchmark's false
  positives were used while this was built (they pointed at the cases under
  Changed below), and the `escape…()` rule also matches its
  `escape_for_html` helper. Still missed: values that pass through a
  container (`d["k"] = q`, `lst.append(q)`, a ConfigParser), loop variables,
  and branches only constant folding would rule out.

### Changed
- **Taint reads only what can carry the injection (both engines).** A sink's
  arguments ran to the end of the line, so `exec(cmd); log(location.href)`
  and a minified bundle's later code were read as the sink's input, and every
  argument counted: a parameterized query `execute(sql, (q,))`, a response's
  headers, `requests.post(url, data=d)`, `render_template_string(t, n=q)`.
  Now a query, a response body, a redirect, a template and `eval` read their
  first argument (a response's `(body, headers)` tuple its body), commands,
  paths and SSRF targets their positional arguments, anything else the
  call's own arguments; a redirect to a path on the same site
  (`redirect("/user/" + id)`) is not a finding. A path check that leaves the
  function (`if ".." in name: abort(400)`, `if not p.startswith(BASE):
  return`, `if (name.includes("..")) return …`) clears path traversal. A
  taint lives in the function body it was made in (read from indentation:
  another function's variable of the same name was taken for it), a
  reassignment in the same block replaces the value (`p =
  secure_filename(p)` is clean; `name = "fixed"` untaints), and one in a
  branch adds to it. `new URLSearchParams()` with no argument is not a
  source. T-* findings on seven open-source web apps (CTFd, Redash,
  microblog, Flask, djangoproject.com, bakerydemo, Express) went from 65 to
  27; SQL injection's false-positive rate on BenchmarkPython from 36% to 0.

### Fixed
- **`unescape()` is not an XSS sanitizer.** The intra-file engine's `escape(`
  pattern matched inside `html.unescape(q)`, which makes a value more
  dangerous, and cleared it for XSS.
- **One finding per dependency version, however it is spelled
  (`lazaret-sca`).** A version pinned as `3.2.0` in `pyproject.toml` and
  locked as `3.2` in `poetry.lock` or `uv.lock` was inventoried twice, so
  every advisory for it was reported twice (37 duplicate findings in a
  benchmark project). Versions that matching treats as equal (PEP 440 and
  semver zero padding, a `v` prefix, semver build metadata) now count once;
  the first entry is kept, as before.

### Security
- **Feed decompression is budgeted (`lazaret-sca --update-bundle`).** Only the
  downloaded size of a feed was capped, so a small gzip could expand a
  thousandfold: a 612 KB EPSS file holding one 600 MB line took the reader to
  1.2 GB of memory before it failed. The EPSS reader now charges every
  decompressed byte (256 MiB) and refuses a line over 64 KiB, and an OSV
  export's zip central directory is checked before `zipfile` parses it: its
  declared record count, its declared size and the records it actually holds
  must fit the record budget (the registry's archive reader already worked
  this way). Reachable only through `--epss-url` / `--osv-url` or a compromised
  feed host.
- **MCP path tools read only inside allowed roots by default (audit I1).**
  With `LAZARET_MCP_ROOTS` unset, `scan_directory`, `scan_files` and
  `quality_gate` read any path the server's user could read, at the request of
  a model that may have been steered by something it read. They now read only
  inside the roots the MCP client shares: the server asks with `roots/list`
  after `notifications/initialized` and again on
  `notifications/roots/list_changed`, and a call waits up to 10 s for the
  answer (Claude Code shares the directory it was started in and any added with
  `--add-dir`). A client that shares no roots gets a tool error that says to
  set `LAZARET_MCP_ROOTS`, which still takes precedence when set. Tools that
  take no path, and direct calls to `lazaret.mcp.server.tool_*` from Python, are
  unchanged. MCP 2026-07-28 deprecates Roots in favour of server configuration;
  the server negotiates 2025-11-25 and earlier, where it is current, and
  `LAZARET_MCP_ROOTS` remains the setting to rely on.

## [0.1.6] — 2026-09-28

Received-code detection — the check for a value received over the network that
is then run as code — gained new sink families, cross-file coverage, and a
shared source of truth for both engines.

### Added
- **More received-code sinks (both engines).** Beyond running a received value
  (eval / `Function` / `vm` / a shell / an interpreter's inline code), the
  detector now flags:
  - **deserialization** of a received value — `pickle` / `marshal` /
    `jsonpickle`, an unsafe `yaml.load` (a `SafeLoader` / `safe_load` call is
    not), and node-serialize's `unserialize` (CWE-502);
  - **dynamic import of a received specifier** — `import(x)`, `require(x)`,
    `__import__(x)`, `importlib.import_module(x)`;
  - **download-to-file-then-run** — a received value written to a file that is
    then executed. This is a MAJOR-only signal (it is also the shape of a
    prebuilt-binary installer), so it never escalates an install hook to
    CRITICAL.
  A received value is also followed to a runner reached under an alias
  (`const e = eval; e(payload)`) or indirectly (`(0, eval)(…)`, `eval.call`,
  `window['eval']`).
- **Cross-file received code (Python engine).** A value received in one file of
  a dependency package and run in another — the source and the sink split
  across modules — is now caught under `--deps`, in both Python packages
  (`from ._c2 import pull; exec(pull())`) and npm packages
  (`const { pull } = require('./fetcher'); pull().then(c => eval(c))`). The
  tainted export can be a module-level function or value, or a **class method**
  called on an instance made in the importing file (`c = Client(); exec(c.pull())`,
  `const c = new Client(); c.pull().then(eval)`). SC-IMPORT-RISK (MAJOR); the
  message names the source module. Detection runs only in the Python engine; the
  npm engine stays single-file with an honest gate, and the finding is excluded
  from the engine-parity comparison like the cross-file taint engine's `X-*`
  findings. Export detection masks strings and comments — including a docstring's
  usage example — so a `requests.get(...)` shown in documentation is not mistaken
  for a real export, and the pass has its own tight bounds (a smaller body-scan
  window and hard caps on files, exports and seeds per package).

### Changed
- **Shared spec for the received-code detector.** Its data (name sets, character
  sets, limits) and all patterns (27 plain regexes and 6 alternation groups) are
  now authored once in `python/src/lazaret/scanner/received_spec.json` and
  compiled by both engines, synced by `scripts/sync-received-spec.py` and held
  together by a drift test. No behaviour change — the pattern text and name sets
  are byte-identical to before.

### Fixed
- The cross-file received-code pass no longer perturbs `--deps` stop / time-budget
  accounting: it had run an extra `should_stop` check that could swallow a stop
  reason and report a stopped scan as complete.
