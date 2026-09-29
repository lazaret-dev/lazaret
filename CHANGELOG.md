# Changelog

All notable changes to Lazaret are recorded here. The Python (PyPI) and npm
packages share a version and are released together (see `docs/RELEASING.md`).
This log starts at 0.1.6; for earlier releases see the git history and tags.

The format is based on [Keep a Changelog](https://keepachangelog.com); the
project is pre-1.0, so the 0.x API may still change.

## [Unreleased]

### Fixed
- **`lazaret guard` with npm in a folder without a package.json.** npm then
  works in the nearest folder up that has a package.json or a node_modules
  folder (a home folder, often); the guard looked for the lockfile in the
  current folder, said "npm wrote no lockfile to check", and left that
  folder's package.json and package-lock.json as npm had changed them,
  even with `--plan`. The guard now asks npm where it works (`npm prefix`,
  with the command's own `--prefix`), checks and restores the files there,
  and says which folder that is.

## [0.1.7] — 2026-09-29

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
  `escape_for_html` helper. Still missed: a ConfigParser, loop variables,
  and branches only constant folding would rule out (containers: see the
  next entry).

- **Taint knows Flask's, Django's, FastAPI's and Express's routes (both
  engines).** A route handler's parameters were not sources, so
  `def dl(name): return send_file("/srv/" + name)` under
  `@app.route("/dl/<path:name>")` was no finding. Both taint passes
  (intra-file T-*, cross-file X-*) now take the parameters a framework fills
  from the request: a Flask or Quart view's URL variables (not `int`,
  `float`, `uuid` or `any` converters); a FastAPI path operation's
  parameters, but not what FastAPI injects (`Depends(…)`, `Security(…)`, an
  `Annotated[…, Depends(…)]` alias, `Response`, `BackgroundTasks`,
  `Request`) or validates to no free text (`int`, `bool`, `UUID`, dates,
  `Decimal`, `Literal[…]`, constrained numbers, an Enum member, also inside
  `Optional`, `Annotated`, a list or a union with `None`); a Django view's
  URL parameters after `request` (not `pk`, `id`, `slug`, `year`, `…_id` and
  the like, nor typed ones). New sources: `request.query_params` /
  `path_params` (Starlette, FastAPI, Django REST framework), a websocket's
  messages, Express's `req.url`, `originalUrl`, `path`, `hostname`,
  `signedCookies`, `files`, `req.get(…)`, and a request object named
  `request`. New sinks: FastAPI's `HTMLResponse`, `RedirectResponse`,
  `FileResponse`; Django's `Manager.raw`, `RawSQL`, `QuerySet.extra`,
  `SafeString`; `executescript`; a jinja2, Mako or Django `Template` (in a
  file that imports one) and `Environment.from_string`; `httpx`;
  `asyncio.create_subprocess_shell`; Express's `res.send` / `write` / `end`
  (a string is sent as HTML; a whole parsed object such as
  `res.send(req.query)` as JSON), `res.location`, `fs` writes and removals,
  EJS / Pug / Handlebars / Mustache / Nunjucks / doT / lodash templates
  compiled from a value, `vm`, knex's and Sequelize's raw SQL, `got`,
  `needle`. New sanitizers: Django's `render_to_string` and Starlette's
  `TemplateResponse` (XSS), `reverse()` and the Referer (open redirect), and
  what an ORM lookup returns (`get_object_or_404`, `Model.objects…`,
  `Model.query…`, `session.execute(…)`) or a file read gives (not request
  data). Not sinks: a response with a non-HTML content type
  (`content_type="text/plain"`, `res.type("text/plain").send(…)`),
  `send_from_directory`'s file name and Express's `sendFile` / `download`
  given a `root` (both refuse a path that climbs out), a redirect to a fixed
  host, an element looked up by a request value (`users[req.params.id]`) or
  a `slice()` index. In the cross-file engine an ORM query builder
  (`select(…).where(…)`, `filter_by`, `values`) binds its values, and a
  CRUD-named method on a receiver it cannot identify (`get_one`, `create`,
  `delete`, …) no longer binds to every project function of that name.

- **Taint follows values through containers and allowlists (both
  engines).** A value written into a container taints it (`d["k"] = q`,
  `xs.append(q)`, `arr.push(q)`), followed by literal key (`d["other"]`
  stays clean). A check against a collection of the code's own (`if name in
  ALLOWED:`, `if (allowed.has(name))`) clears the value inside the block,
  and past a check that leaves when it fails (`if name not in PLUGINS:
  abort(404)`); the cross-file engine now reads these guards and the path
  checks the intra-file one already did.

  On OWASP BenchmarkPython (Python 3.13) these two entries took the score of
  all rules from +0.19 to +0.21 (true positives 47% → 51%, false positives
  29% → 30%) and of the taint findings alone from +0.11 to +0.16 (22% → 30%
  of real flaws found: command injection 38% → 77%, path traversal 40% →
  52%, code injection 60% → 75%). Open redirect lost ground (false positives
  8 → 11 of 21): a list's elements are not told apart after `pop()`, and a
  URL checked through `urlparse(…).netloc` is not read as a guard. On 19
  open-source web apps — the seven above; FastAPI's full-stack template and
  RealWorld app, mealie, healthchecks, hackathon-starter and the Express
  RealWorld app; and six deliberately vulnerable apps (vulpy, pygoat, dvna,
  NodeGoat, python-insecure-app, vfapi) — T-* findings went from 52 to 135:
  79 new ones are routes in Express's and Flask's own tests and examples
  that echo a URL variable or a header, 4 are true positives in the
  vulnerable apps (pygoat's raw SQL, python-insecure-app's template
  injection), 6 false positives went away, and application code got 5: a
  FastAPI password-recovery page that renders its `email` query parameter
  unescaped (for superusers only), and 4 false positives (a registry
  lookup's result, a version replaced out of a path, an SVG badge another
  module escapes, a test helper's `req.path`). X-* findings went from 45 to
  52: vfapi's 4 SQL injections through a helper, and 3 false positives in
  mealie (a file extension with its dots removed). The npm engine reports
  the same T-* findings as the Python engine on all 3,748 files.

- **Install scripts fail on the PyPI malware shapes they missed (both
  engines; audit P0).** On the audit's malware corpus Lazaret passed two
  thirds of the malicious PyPI packages, most of which ran their payload
  from `setup.py` in ways the install-script test did not read. `setup.py`,
  an in-tree build backend and the modules they import from the sdist (now
  also from `src/` and through relative imports), and npm install hooks, now
  fail (SC-INSTALL-HOOK, CRITICAL) on: PowerShell that hides or fetches what
  it runs (an `-EncodedCommand` / `-enc` / `-e` argument, decoded and read; a
  download cradle such as `irm URL | iex` or
  `IEX (New-Object Net.WebClient).DownloadString(URL)`; a file downloaded
  and started); a script carried in a string literal that downloads and
  runs code (a stager written to a temporary file and started); a reverse
  shell (a socket made a shell's standard streams, `bash -i >& /dev/tcp/…`,
  `nc -e`); the machine's user or host name, or `whoami` / `ifconfig`
  output, sent over the network (the dependency-confusion beacon); and, in
  the code pip runs, a download written to a file and run.

- **Import-time code that no library needs is SUSPICIOUS (both engines;
  audit P0).** SC-IMPORT-RISK was MAJOR (WARN at most) whatever it found. It
  is now CRITICAL for code received over the network and run, a download
  run through a shell or with the Python interpreter, PowerShell that hides
  or fetches what it runs (as an exec call's argument), a stager string, a
  reverse shell, credentials or the whole environment sent to a named
  exfiltration service (a Discord webhook, a Telegram bot), and the user or
  host name sent to a data-capture service (webhook.site, Burp Collaborator
  and other OAST hosts, interact.sh, pipedream, requestbin …). What ordinary
  code can share stays MAJOR: the whole environment next to other network
  code, a download written to a file and run as a binary.

- **More of a package's import-time code is read (registry review).** A
  wheel's top-level modules, now an sdist's too (not `setup.py`,
  `conftest.py` and the like), and the modules they import — `import x.a`,
  `from x import b`, `from . import c`, `from .m import d`, up to 300
  modules — get the import-time test. Before, only a wheel's top-level
  files did, so a payload one import away was never read.

- **The dependency decode flow reads aliased decoders and decrypted
  payloads (both engines).** `from base64 import b64decode as invoke` then
  `exec(invoke(…))`, `from zlib import decompress as z`, and
  `Fernet(key).decrypt(…)` now feed SC-EVAL-DECODE.

  On the audit's malware corpus (945 packages) these four took the share of
  malicious PyPI packages judged SUSPICIOUS from 34% to 84% (GuardDog, the
  audit's reference: 88% high risk) and of malicious npm packages from 46%
  to 50%, with no benign package newly SUSPICIOUS or WARN (429 packages:
  the top 100 of each registry, 198 more from the top 2,000, and 31 chosen
  to look risky).

- **Persistence targets: agent and editor settings, workflows, editor
  extensions (both engines; audit).** The 2025-26 npm worms stayed where no
  scanner looked. Mini Shai-Hulud (May 2026) and the keyv wave (August)
  committed a Claude Code SessionStart hook (`.claude/settings.json`) and a
  VS Code folder-open task (`.vscode/tasks.json`) to every repository they
  reached, each running a copy of a loader that fetches the Bun runtime to
  run the payload, so opening a checkout ran the worm; Shai-Hulud planted
  GitHub Actions workflows that dump every repository secret, and a
  discussion-triggered one that runs the discussion's text on a self-hosted
  runner it registered on the victim's machine; GlassWorm installed editor
  extensions. Now:
  - **SC-AUTORUN** lists what an editor's or AI agent's settings in the
    tree run on their own: VS Code folder-open tasks (with the tasks they
    depend on, each platform's variant and npm tasks), Claude Code's hooks,
    status line and helper commands (`settings.json`,
    `settings.local.json`), Cursor's and Gemini CLI's hooks, and the MCP
    servers `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` and
    Gemini's settings start. Each is INFO inventory, which does not fail the
    gate, and CRITICAL when the command, or a file of the tree it runs
    (followed like an install hook's, `$CLAUDE_PROJECT_DIR` and
    `${workspaceFolder}` read as the folder), fails the install-script test
    or is obfuscated: the worm's pair is CRITICAL twice. A settings file
    that names commands but cannot be read as JSON is MAJOR (comments and
    trailing commas are read, as VS Code writes them). Writing the agent's
    own settings is not held against its hooks (a WorktreeCreate hook
    copies them).
  - **SC-WORKFLOW-SECRETS** flags `${{ toJSON(secrets) }}` in a job's
    environment or a script (not an action's input): MAJOR, and CRITICAL
    when the workflow also uploads an artifact or runs a network command.
    **SC-WORKFLOW-BACKDOOR** (CRITICAL) flags text from an issue, a
    discussion, a comment or a pull request put into a command on a
    self-hosted runner by a workflow those events start. Workflows are read
    by a small outline reader (Lazaret has no YAML library).
  - **The install-script test** (install hooks and now their own command,
    the code pip runs, what SC-AUTORUN follows) also fails on writing an AI
    agent's or editor's auto-run settings, a GitHub Actions workflow (a
    file, `git add`, the contents API), installing an editor extension
    (`code --install-extension`, a copy into `~/.vscode/extensions`),
    registering a self-hosted runner, and a Bun release fetched from GitHub
    and run (the worms' loader). At import time only a workflow that dumps
    every secret counts (CRITICAL): a CLI's `init` command writes agent
    hooks, editor tasks, MCP servers and workflows on purpose.

  On the audit's malware corpus the install hooks of the 7 Mini Shai-Hulud
  releases (`preinstall: node setup.mjs`) are CRITICAL now; before, only
  the obfuscated payload (and, for one, a truncated scan) made them
  SUSPICIOUS, which another obfuscator would have avoided. No verdict
  changed, benign packages included. On 1,426 workflows (50 popular repositories — VS Code,
  TypeScript, Bun, React, Next.js, Supabase, Gemini CLI, claude-code-action
  and others — and the earlier corpora, GitHub's starter workflows among
  them) nothing is flagged; their 66 agent and editor settings files give 55
  INFO entries and one MAJOR, a `.claude/settings.json` in claude-flow that
  no JSON reader accepts. The registry's engine version is 2.8.0, so stored
  scans are redone with 0.1.7's tests.

- **`lazaret guard`: check what npm, pnpm, pip or uv is about to install,
  before it runs.** `lazaret guard npm install express` (also `npm ci`,
  `npm update`, global installs, `pnpm add` / `install` / `update`,
  `pip install`, `uv add` / `sync` / `lock`, `uv pip install` / `sync`, and
  the `lazaret-guard` command) fetches and scans every package the command
  would install, with the registry auditor's tests, and installs nothing if
  one is SUSPICIOUS, can't be checked, or is younger than `--min-age`
  (default 2 days).
  - npm, pnpm and uv projects resolve first and install nothing
    (`--package-lock-only`, `--lockfile-only`, `uv add --no-sync`,
    `uv lock`); each package the new lockfile adds on this machine is
    fetched from where the tool will fetch it and checked against the
    lockfile's digest, so the bytes scanned are the bytes it installs. A
    blocked install puts `package.json`, the lockfile and `pyproject.toml`
    back. After an install, what was installed is compared with what was
    checked; anything else fails the run. Packages for other platforms
    (`os` / `cpu` / `libc`, npm's rules) are left out.
  - pip and uv pip install through an index on 127.0.0.1 that relays PyPI
    (`LAZARET_GUARD_PYPI_URL` for a mirror): new files are left out of it,
    every file is scanned before the tool gets it (an sdist before pip or uv
    can build it), and the tool's dry run is scanned first. Other indexes
    and local archives are refused, also in requirement files.
  - Release age: npm's `before` and pnpm's `minimum-release-age` hold new
    releases back; what a lockfile already pins is aged by the guard (the
    tarball's `Last-Modified`, confirmed by the registry; uv.lock's upload
    time). npm always resolves with `before`, so the install can't pick a
    release published while the guard checked.
  - `--allow-new NAME` lets a new release through the age check (still
    scanned); `--trust NAME` installs what the guard blocks or can't check
    (a private registry, a reviewed finding; still reported); `--plan`
    installs nothing; `--block-warn` blocks WARN and INCOMPLETE too;
    `--json` writes every package checked.
  - Verdicts are cached by artifact digest and engine version
    (`~/.cache/lazaret/guard-verdicts.json`, or `LAZARET_GUARD_CACHE`;
    `--no-cache` or `LAZARET_GUARD_CACHE=/dev/null` turns it off), so a
    package is fetched and scanned once; scans run in worker processes
    (`--jobs`). A first guarded
    `npm install next react react-dom typescript eslint` takes about 48
    seconds on a 2-core machine, most of it scanning the 42 MB `next`
    tarball; a repeat `npm ci` of `express` takes under a second.
  - Tested against the real npm, pnpm, pip and uv with fake registries on
    127.0.0.1 (`test_guard_npm.py`, `test_guard_python.py`).

### Changed
- **The README compares by measurement (audit P0).** Its capability table
  (✔ / —, which implied taint on a par with Semgrep's and SonarQube's) is
  replaced by the audit's benchmark, rerun on 0.1.7: 66% of 516 real
  malicious releases SUSPICIOUS (0.1.6: 45%; GuardDog 70%) with 0.7% of 429
  popular packages (GuardDog 4.2%); 95% of planted credentials (19%;
  Gitleaks 94%); OWASP BenchmarkPython +0.22 (+0.10; Semgrep CE +0.16);
  every expected advisory on eight lockfile formats; and `lazaret guard`
  blocking exactly the SUSPICIOUS npm samples end to end (165 of 300, and 2
  of 219 popular packages).
- **The cross-file JavaScript pass parses the code (both engines).** It read
  JavaScript and TypeScript with patterns: a function was a line that looked
  like one, a call any name followed by `(`, and a value flowed wherever its
  name appeared further on, so a minified bundle's regular expressions were
  taken for commands and one bundle's functions were bound to another's. On
  the 19 web apps above it reported 1,035 JavaScript X-* findings and none
  was a real flow: 1,032 were in vendored or built bundles (jQuery, Swagger
  UI, Redoc, CTFd's own) and 3 were requests to a fixed host. Both engines
  now carry a JavaScript reader with no dependency
  (`lazaret.scanner.jsparse`, `src/lib/jsparse.js`) that reads ES2025 with
  JSX, TypeScript and Flow annotations into ESTree trees: on 21,295 real
  files it gives acorn's tree node for node, and in 9,416 TypeScript files
  it finds every call, function and JSX element TypeScript's own parser
  finds. It reads in linear time (a single-line minified bundle,
  TypeScript's ambiguous `f<…>(`, runs of open brackets), and a file nested
  deeper than 256 levels is not read. The pass on top of it summarizes each
  function — which parameters reach which sinks, what it returns — callees
  first, to a fixpoint, so chains of any length are followed. Names resolve
  through scopes (hoisting, blocks, closures) and calls through `require()`
  and `import` (ESM and CommonJS, re-exports, `./x.js` naming `x.ts`,
  `import x = require()`, `export =`), object literals, classes (`this`,
  `super`, static members, inheritance) and assignments; values are followed
  through locals per branch, loops, destructuring, spreads, containers,
  templates, closures, callbacks and a module's exported variables
  (`export const target = process.argv[2]`). New: an Express-style route
  handler gets the request and the response whatever their names
  (`app.get('/p', (rq, rs) => …)`, `router.route('/p').post(…)`,
  `app.use(…)`, a wrapped `asyncHandler(…)`, an error handler; Koa's `ctx`),
  and a request's or a response's methods bind to no project function; a
  call on `$`, `jQuery` or `_` binds nothing; for SQL a value must be joined
  into the query text (a bound parameter, a whole query passed through or a
  tagged template is not a finding); a URL that starts with a fixed host or
  a path on this site is no SSRF or open redirect; a Server-Sent Events
  frame (`data: …`) is no HTML; a project function named like a sink (its
  own `exec`) is analyzed, not taken for the sink; React's
  `dangerouslySetInnerHTML` is an XSS sink. Declaration files (`.d.ts`) are
  not read. A file the reader rejects is named in a Q-FLOW-SKIPPED note with
  the line and the reason, and the rest of the project is still analyzed; a
  work budget proportional to the code's size bounds the pass, and a
  Q-FLOW-INCOMPLETE note says where it stopped. Coverage notes no longer
  count as code smells in the npm engine's maintainability rating (they did
  not in Python's). On the 19 apps the pass reports no JavaScript X-*
  finding; the npm engine reports exactly the Python engine's findings on
  the unit tests' 198 projects, the 19 apps, 1,428 installed npm packages
  and 600 generated projects. It is slower than the pattern pass: the 1,530
  JavaScript and TypeScript files of the 19 apps take 32 s in the Python
  engine (were 12 s), most of it CTFd's built bundles.
- **The import-time test reads code, not prose (both engines).** A Python or
  JavaScript file that fails it is read again without its comments and, in
  Python, the strings that stand alone as statements (docstrings); and
  PowerShell counts there only as an argument of an exec call. Once more of
  a package was read, a docstring naming ``id_rsa`` made paramiko WARN, and
  a CLI's self-update command shown in a comment and a docstring made
  huggingface-hub SUSPICIOUS. A file that reads its own source
  (`open(__file__)`, `Path(__file__).read_text()`, `linecache`,
  `__loader__.get_source`, `__doc__`; `readFileSync(__filename)`,
  `import.meta.url`, a function's `.toString()`) keeps its prose: a comment
  can hold the address it sends to, or the code it runs.
- **Code read back from the file itself is SUSPICIOUS (both engines).** An
  install script or import-time code that runs what it reads from its own
  source — a payload kept in a comment or a docstring
  (`exec(open(__file__).read().split('"""')[1])`, `exec(__doc__)`,
  `eval(readFileSync(__filename, 'utf8').split('/*')[1])`, a function's
  `.toString()` handed to `new Function`) — or from a data file shipped next
  to it (`exec(open(join(dirname(__file__), "logo.png")).read())`) fails
  with CRITICAL; the value is followed through the names it is assigned to.
  Running a `.py` or `.js` file is not flagged: setup.py's
  `exec(open("pkg/version.py").read())` reads a version. No hit in 10,950
  installed Python files or 20,456 installed JavaScript files.
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
