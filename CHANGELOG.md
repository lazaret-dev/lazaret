# Changelog

All notable changes to Lazaret are recorded here. The Python (PyPI) and npm
packages share a version and are released together (see `docs/RELEASING.md`).
This log starts at 0.1.6; for earlier releases see the git history and tags.

The format is based on [Keep a Changelog](https://keepachangelog.com); the
project is pre-1.0, so the 0.x API may still change.

## [Unreleased]

### Changed
- **The native engine scans each dependency file itself (phase 2 of
  `docs/RUST_ENGINE.md`, dependency mode).** Where it is installed, the
  per-file scan of a registry or guard scan's source files and of a `--deps`
  scan's dependency files runs in it: the supply-chain and credential rules
  — the pattern rules and their multi-line join, private-key headers and
  their key material, JWTs, hex-escaped text and names, look-alike and
  invisible characters, char codes, base64 blobs, off-screen code,
  high-entropy literals, obfuscator names, self-publishing, the decode flow
  — with core's findings, texts, lines and snippets (clipped, secrets
  redacted), in core's order. On litellm's 2,643 source files that part of
  its registry scan took 21.6 s with the Python engine and takes 2.1 s (2
  threads). The benchmark's 945 registry scans take 299 s, against 1,141 s
  with the Python engine and 853 s with 0.1.8's native engine (litellm
  11.4 s, 42.1 s and 30.6 s), with the same verdicts and findings. Two new
  differential modules hold it to the Python engine
  (`test_rust_parity_scanfile.py`: every family and variant, each line's
  comment layout and match text, and the four normalization forms;
  `test_rust_parity_lexer.py`); CI's rust job and the wheel jobs run them.
  Compared file by file on every source file of the benchmark's 945 releases
  (55,161 files) and on the 13,568 distinct files the test suites hand
  `scan_file`, the two engines' findings are the same. The engine gained
  NFKC (Unicode 13.0's tables, which `make_rust_tables.py --check` holds to
  each Python's by the normalization stability policy), the token pattern's
  linear-time JWT search, and hand-written matchers for the lexer's literal
  patterns, each used only while the pack holds the pattern it was written
  for.
- **Registry and guard scans read a batch of source files at a time** (64,
  on threads, with the native engine; one at a time with the Python engine,
  as before), as `--deps` now does with a project's dependency files. The
  deadline is still checked before each file (a batch already queued is
  scanned first), and `should_stop` between batches.
- **core's finding texts are module-level values.** Every finding
  `_scan_file` makes takes its texts from a rule dict of the module
  (`_HEXSTR_TEXT_RULE`, `_LOOKALIKE_RULE` …; a message with fields is a
  `str.format` template), so the rule pack carries them, and the pack holds
  the token pattern (`RULES`' S-TOKEN, the redaction list) as well. The
  findings are the same.

## [0.1.8] — 2026-09-30

### Added
- **More of the malware the 0.1.7 benchmark missed (backlog items 1-4, from
  its 177 misses).** On the same 516 malicious releases, 76% are now
  SUSPICIOUS (was 66%; GuardDog 70%), and 80% with the registry's live
  dependency history; the same 3 of 429 popular packages, and no popular
  package's verdict changed at all. `lazaret guard` blocks 214 of the 300
  npm samples end to end (was 165), still 2 of 219 popular ones. Registry
  engine 2.9.0, so stored and cached verdicts are redone.
  - **SC-SELF-PUBLISH** (both engines, CRITICAL): code that renames its
    package and publishes it — an assignment to an object's `name`, a write of
    that object to package.json, and `npm publish` (pnpm, yarn, bun) run by an
    exec call. The 2025-26 registry floods shipped it as `auto.js`: 39 of the
    misses, and half of what GuardDog caught that Lazaret didn't. Release
    tools publish but never rename.
  - **Install scripts that publish, collect npm tokens or run a DLL** (both
    engines): three more reasons of the install-script test. A script an
    install hook runs that calls `npm publish`, reads npm access tokens
    (`.npmrc`'s `_authToken`, `npm config get …:_authToken`: the @emilgroup
    worm handed them to a detached deploy script), or runs a DLL of its own
    with `rundll32` / `regsvr32` (eslint-config-prettier 9.1.1; string pieces
    are joined first, `"rund"+"ll32"`).
  - **SC-OFFSCREEN-CODE** (both engines and the dashboard): code after a run of
    150 or more blanks on a line, in code rather than a string or a comment,
    where editors and review don't show it — CRITICAL when it loads or runs
    more code (@react-native-aria/radio 0.2.14 hid its loader 731 columns
    right), else MAJOR.
  - **SC-USE-RISK** (registry): the import-time test's CRITICAL shapes in the
    files a package runs only when it is used — a logger's constructor, a
    middleware, a script a CLI spawns — not in tests, examples, docs, demos,
    benchmarks or a web app's static assets. Not read once a package is
    SUSPICIOUS, smallest files first, within 3 s per archive (a first guarded
    plan of next, react, react-dom, typescript and eslint: 53 s, 50 s before).
  - **SC-NEW-DEPENDENCY** (registry): a release that adds a dependency first
    published less than 7 days before it (MAJOR under 30), outside the
    package's npm scope, from an account that doesn't maintain the package.
    The @mastra compromise changed no code, it only added `easy-day-js`, created
    19 hours before: all 17 releases in the benchmark, with live registry
    data, and none of the 429 popular packages at the benchmark's versions.
    One document for the package and one per added dependency (at most five);
    `LAZARET_NO_DEPENDENCY_HISTORY=1` turns it off.
- **Payloads a file decodes, downloads staged over several steps, and the
  cross-file follower in both engines (backlog items 5-11).** On the same 516
  malicious releases, 80% are now SUSPICIOUS (76% after items 1-4, 66% in
  0.1.7; GuardDog 70%), 84% with the registry's live dependency history: npm
  77% (was 71%), PyPI 84% (was 83%). Still the same 3 of 429 popular
  packages, and no popular package's verdict changed. `lazaret guard` blocks
  232 of the 300 npm samples end to end (214 after items 1-4, 165 in 0.1.7),
  still 2 of 219 popular ones. A registry scan takes about 7% longer on the
  benchmark's heaviest packages (the two engines timed one after the other on
  one machine; litellm, 2,471 modules, 20%).
  Registry engine 2.10.0, so stored and cached verdicts are redone.
  - **Names and code in strings a file decodes as it runs** (both engines):
    the install-script and import-time tests read a file a second time with
    its encoded strings decoded — `Buffer.from(…, 'hex' | 'base64')
    .toString()`, `atob`, `bytes.fromhex` / `b64decode` / `unhexlify(…)
    .decode()`, and the file's own hex or base64 helpers — a constant array of
    strings read where it is indexed, and a member named by a literal
    (`process["env"]`) read as one. A reason found only there says so.
    tailwind-book-icon and five more loggers of one campaign kept every name
    hex-encoded: `require(g('6178696f73'))` is axios.
  - **SC-EVAL-DECODER** (both engines and the dashboard, CRITICAL): eval of an
    inline decoder function applied to 200 or more character codes or a
    literal of 1,000 or more characters — one campaign's letter-shift
    obfuscation (12 files; no popular package).
  - **The received-code test reads more of how a value reaches a runner**
    (both engines): `Function.constructor(…)`, a statement a formatter spread
    over several rows (`axios` then `.post(…)` on the next row; a call's
    arguments on the rows below it), an environment variable that carries a
    value from one statement to the next (`os.environ['P'] = r.text` …
    `exec(os.getenv('P'))`), TypeScript's `(0, ns.fn)(…)`, members read by
    name (`getattr(m, 'x')`, `m['x']`) and a runner handed to a call
    (`p.then(eval)`, `res.on('data', eval)`) — a second reading of a file of
    up to 1 MB when the first finds nothing.
  - **A script downloaded or decoded, written to a file and run** with a shell
    or an interpreter (`fs.writeFileSync(f, await r.text()); spawn('bash',
    [f])`; litellm 1.82.7's `proxy_server.py` wrote a base64 payload to
    `p.py` and ran it with `sys.executable`) is CRITICAL at import time and in
    an install script: "downloads a script and runs it with bash", "writes
    code it decodes to a file and runs it with Python". A download run without
    a named interpreter stays MAJOR (a prebuilt binary's installer).
  - **Scripts a script starts** with node or python —
    `spawn(process.execPath, [path.join(__dirname, 'worker/run.js')],
    { detached: true })`, `fork(…)`, `subprocess.Popen([sys.executable,
    start])` — are followed to the package file each runs, three starts deep,
    and tested like the script that started them: from a dependency's install
    hook with `--deps` (both engines), and in registry scans from install
    scripts, import-time code and setup.py. react-thunk-log's postinstall did
    nothing but start another file of the package.
  - **The cross-file follower reads several hops, classes and objects, and
    runs in both engines and on releases.** A value received in one file of a
    package and run in another is followed through wrappers and re-exports up
    to four files deep (it was one), class methods called directly
    (`Client().pull()`, `new ns.C()`), static members and object literals'
    members (`module.exports = { async pull() {…} }`), a callback or a
    Promise's `resolve` handed what a function received, a module-level cache
    a function fills, an instance kept on `self` / `this`,
    `importlib.import_module` / `__import__` / `import()` of a literal name,
    `require(path.join(__dirname, …))`, TypeScript's `__importDefault` and
    `exports.default`, and an environment variable set in one file and read
    in another; the other way round, a function of the package that runs its
    parameter as code (`def run(c): exec(c)`) called with a value this file
    received is the same finding, and says so. The npm engine runs it too
    (`js/src/lib/crossfile.js`; the engines agree on the follower's cases and
    a generated stream of 700 packages), so it is no longer a Python-only
    exception; registry and guard scans run it on a release, naming the file
    (not on tests, docs or examples, and not once the package is SUSPICIOUS).
  - **An adversarial pass on the follower**: 28 ways to carry the value
    between files or run it are read (each a test), 8 crafted look-alikes stay
    quiet, and 2 known misses are documented and tested (an event emitter
    between files; two top-level modules of site-packages in a `--deps` scan).
- **Data sent to a chat bot, a webhook or a capture service, and the other
  shapes GuardDog caught that Lazaret didn't.** The benchmark's PyPI samples
  were re-prepared first (below); on them, 86% of the 516 malicious releases
  are now SUSPICIOUS (82% after items 1-11, 68% in 0.1.7; GuardDog 71%), 89%
  with the registry's live dependency history: PyPI's malicious-intent set
  95% (GuardDog 88%) and all 16 compromised PyPI releases (GuardDog 12).
  Of the releases GuardDog catches, one was still missed (react-zutils' XOR
  decoder, caught by the next item). `lazaret guard` blocks 238 of the 300
  npm samples end to end (232 before). Still the same 3 of 429 popular
  packages, and no popular package's verdict changed; none of the new
  shapes fires on the popular packages or on 37,783 files of installed
  Python and npm packages. Registry engine 2.11.0, so stored and cached
  verdicts are redone.
  - **A chat bot or webhook whose secret is written in the code** (both
    engines, CRITICAL wherever found: install scripts, import-time code, the
    files a package runs when used): a Telegram bot token next to
    api.telegram.org, a Discord webhook's token or a Slack webhook's key, in
    a file that makes network calls. A library for these services takes the
    key from its user; a package that carries its author's key reports whoever
    runs it: figlets zipped Exodus wallets and sent them to its bot, requestn
    uploaded every file in the working folder. Placeholders are not keys.
  - **Credentials sent out**: credential files (.env, .npmrc, .pypirc, .netrc,
    .git-credentials, ~/.aws/credentials, SSH keys, Docker's and kubectl's
    configs) read in a file that sends data to a raw public IP address; three
    or more credential folders named in one place (.ssh, .aws, .ethereum,
    .kube …) in a file that makes network calls, a sweep of the home folder
    (data-pipeline-check and env-loader-cli, one campaign); and a copy of the
    whole environment serialized (`d = dict(os.environ)` … `urlencode(d)`).
  - **The machine's names and address sent out**: the user or host name sent
    to an address the file keeps base64-encoded, or looked up in DNS inside a
    name the code builds (the dependency-confusion DNS beacon); the public IP
    address (ipify, ip-api …) sent to a data-capture service. An ngrok
    tunnel's own address now counts as a capture service, and `os.hostname`
    handed on as a value as host information.
  - **And**: a reverse shell given to an exec call as an argument list, or
    pointed at an ngrok TCP address; a cryptocurrency miner, a Monero wallet
    address with a mining pool's arguments (ultralytics 8.3.42); curl or wget
    given `-o path` in an argument list, the file then run with Python
    (mistralai 2.4.6's `client/__init__.py`); and at install time a raw socket
    to a hard-coded address (as a URL with one already was) and browser
    shortcuts rewritten to load an extension (python-dateuti).
- **Services started at login, payloads read back asynchronously, XOR
  decoders, and names like a popular package's** (the backlog's last four
  detection items). On the same 516 malicious releases, 87% are now
  SUSPICIOUS (447; 86% before), 90% with the registry's live dependency
  history: npm's compromised releases 82% (was 80%), npm's malicious-intent
  set 80% (79%). Every release GuardDog catches at its strictest verdict,
  Lazaret now catches too. `lazaret guard` blocks 242 of the 300 npm
  samples end to end (238 before), still 2 of 219 popular ones. Still the
  same 3 of 429 popular packages, and no popular package's verdict changed;
  none of the new shapes fires on the popular packages or on 37,800
  installed files. Registry engine 2.12.0, so stored and cached verdicts are
  redone.
  - **Programs set to start at login or boot** (both engines, a reason of the
    install-script test): a systemd unit written or `systemctl enable` run,
    a launchd agent written or loaded, a crontab installed, a Windows Run key
    written or a scheduled task created, the Startup folder or an XDG
    autostart entry written. The CanisterWorm releases of @emilgroup's
    packages installed a systemd user service from their install script.
    Never at import time, where a library that manages services is normal;
    shell rc files are left out.
  - **Code run from what a file reads back asynchronously** (both engines):
    a `readFile` callback's data, a `.then()` parameter or Python's
    `with open(…) as f`, read by a path's name from the file itself or a
    data file next to it, and run as code. react-thunk-log 2.23.2 started a
    script that decrypted its own LICENSE and ran it. A value read by a
    path's name counts only in a code runner.
  - **Home-made XOR decoders** (both engines): the decoded view reads a
    file's own XOR helper — a function called five times or more with base64
    or hex literals, whose calls turn into printable text (nine in ten) with
    a short key among the file's own strings — so the decoded strings are
    tested as if they were written in the clear. react-zutils 1.0.1 kept
    the 83 strings of its browser stealer that way, its ngrok address among
    them.
  - **SC-TYPOSQUAT** (registry, MAJOR): a release whose name, or a
    dependency it declares, is one change from one of the 5,000
    most-downloaded packages of its registry — a character added, dropped or
    changed, two swapped, or the separators changed. 13 of the malicious
    releases carry one (requesxs, python-dateuti, tiketoken, sklearns, nhmpy;
    @hestjs's packages depend on @hestjs/core, one change from
    @nestjs/core), and none of the popular packages. A name the popular
    lists know is never one (mysql2, delegates, fastai), and neither is a
    name near a popular one under 5 characters or near one in its own npm
    scope. The lists come from npm-high-impact (MIT) and Top PyPI Packages
    (CC BY 4.0), with their notices, and `scripts/update-popular-names.py`
    rebuilds them.
- **A native engine for the supply-chain tests** (Python package; Rust,
  `rust/`, `docs/RUST_ENGINE.md`). The install-script and import-time tests
  and everything they read — the received-code detector, the decoded view,
  the exfiltration shapes, services at login — run in a library written with
  no external crates: its own regex engine (a port of CPython's, Python `re`
  semantics on code points), JSON and Unicode 13.0 tables, with the patterns
  extracted from `core.py` into a rule pack (`scripts/make_rust_tables.py`;
  `--check` in CI). `--deps`, registry and guard scans send files to it in
  batches of 64, read on up to 8 threads, answers in order; a file it can't
  answer (its work budget spent, an error) is answered by the Python engine,
  so it never loses a finding. It gives the Python engine's answers exactly:
  differential tests on every pattern (Python 3.10–3.14) and on ~36,900
  cases for 15 hook fields and 24 detectors, and the whole Python suite
  passes with either engine. On real files: the benchmark's 945 registry
  scans give the same verdicts and findings with both engines, and both
  tests answer identically file by file on 85,415 files (installed packages
  and every source file of the benchmark's archives). The 945 scans take
  853 s instead of 1,097 s (22% less; the 95th percentile 6.2 s instead of
  9.5 s): the per-file rules, still Python, take most of the rest. The import-time test over 678
  of litellm's modules takes 5.7 s instead of 15.6 s on one thread, 3.2 s on
  two; a registry scan of the litellm wheel, 31 s instead of 40 s.
  `--engine rust|python`
  and `LAZARET_ENGINE` choose (default: native where installed; `--engine
  rust` fails when it isn't), and `--version` says which answers:
  `lazaret 0.1.8 (engine: rust 0.1.8)`. A platform wheel carries it
  (`LAZARET_NATIVE_LIBRARY` and `LAZARET_WHEEL_PLATFORM` in the build
  backend); the pure wheel and the npm package run as before. CI builds it
  on Linux, macOS and Windows and checks that no crate from outside the
  repository appears (`scripts/check_rust_deps.py`).
- **Platform wheels with the native engine** (PyPI). A release also
  publishes five platform wheels: Linux x86-64 and ARM64 (manylinux_2_28,
  glibc 2.28 or later), macOS arm64 (11.0 or later) and x86-64 (10.12 or
  later), and Windows x64, each the pure wheel's files plus the library for
  its platform. pip installs one where it matches and the pure wheel
  everywhere else (musl, 32-bit, other architectures), with the same
  findings. Release CI (`.github/workflows/wheels.yml`, which also runs on
  pull requests that change what goes into a wheel) builds each library on
  its own platform with a pinned Rust (1.95.0), the Linux ones in PyPA's
  manylinux_2_28 images pinned by digest and the Windows one with its C
  runtime linked statically; checks it against its wheel's tag
  (`scripts/check_native_library.py`: the glibc symbol versions and
  libraries a manylinux tag allows, the minimum macOS, no Visual C++
  runtime, the exported functions), loads it and runs the parity modules
  on that platform; builds the seven files from one checkout and checks
  them against each other; and installs each platform wheel with pip on its
  platform and runs it. The build backend takes `--platform TAG=LIBRARY`.
- **The native engine's notices.** Its regular expression engine, its shell
  tokenizer and the Final_Sigma rule of `str.lower()` are Rust translations
  of CPython code (`Lib/re/_parser.py`, `_compiler.py`, `_constants.py`,
  `Modules/_sre/sre_lib.h` and parts of `sre.c`; `Lib/shlex.py`;
  `handle_capital_sigma`). `rust/NOTICE` lists them with the originals'
  Secret Labs and PSF notices and a summary of the changes,
  `rust/LICENSE-PYTHON` is CPython 3.14.0's LICENSE, each translated file
  carries its notices, and the crates and the platform wheels declare
  `Apache-2.0 AND Python-2.0.1` and carry both files
  (`tests/architecture/test_rust_notices.py`). The pure wheel, the sdist and
  the npm package hold none of that code.
- **`--version` on every Python command** (`lazaret`, `lazaret guard` /
  `lazaret-guard`, `lazaret-registry`, `lazaret-sca`, `lazaret-mcp`). Which
  install was on the PATH could only be told by importing the package, and
  an older one earlier on the PATH (0.1.0 in Homebrew's Python ahead of a
  pipx 0.1.7) answered `lazaret guard …` with the scanner's usage error.
- **The PyPI description names `lazaret guard`.** It is `python/README.md`,
  which 0.1.7 did not update; PyPI shows it from the next release.

### Changed
- **The native engine is released in lockstep with the packages.**
  `scripts/check-versions.sh` (CI's `versions` job, `tag-release.sh` and the
  release's `verify-tag`) also reads `rust/Cargo.toml`'s workspace version
  and `rust/Cargo.lock`'s two entries, so `engine: rust X` in `--version` is
  the release's own version. The workspace is back at 0.1.7 until the
  release bump.

### Fixed
- **chromedriver's installer read as a call to RequestBin** (both engines;
  in the registry since 0.1.0). The list of addresses typical of exfiltration
  matched `requestbin` anywhere in the text, and chromedriver's and
  phantomjs-prebuilt's `install.js` define `requestBinary()` to download
  their binaries: each install hook was CRITICAL ("contacts an address
  typical of data exfiltration (requestBin)"), so a `--deps` or registry
  scan called chromedriver SUSPICIOUS and `lazaret guard` blocked it.
  RequestBin now counts by its host names (`requestbin.com`, `.net`, `.io`,
  `requestb.in`); postb.in needs a word boundary after it too. Found by the
  0.1.8 sweep of every strong reason over installed packages; none of the
  benchmark's malicious releases relied on the bare word.
- **The benchmark read the wrong files for 11 PyPI samples.** For compromised
  releases the corpus script took the shallowest folder with a setup.py:
  the upstream source tree the dataset ships next to the release
  (`sources/<name>`), or a folder inside the package. For litellm and nhmpy
  it took the shallowest archive: an old litellm_enterprise sdist, and a
  gzipped pickle of test data. And some samples store each file inside a
  folder named by its own path, which hid a package's layout. Each sample is
  now the release's own files (a wheel repacked as a wheel), and
  every tool was rerun on the 36 that changed: 0.1.7 catches 68% of the 516
  (66% before), GuardDog 71% (70%), and of the 16 compromised PyPI releases
  0.1.7 catches 13 (6 before) and GuardDog 12 (7). The numbers above for items
  1-11 were measured before the correction (on the corrected samples: 82%).
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
