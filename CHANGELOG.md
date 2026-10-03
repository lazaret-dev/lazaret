# Changelog

All notable changes to Lazaret are recorded here. The Python (PyPI) and npm
packages share a version and are released together (see `docs/RELEASING.md`).
This log starts at 0.1.6; for earlier releases see the git history and tags.

The format is based on [Keep a Changelog](https://keepachangelog.com); the
project is pre-1.0, so the 0.x API may still change.

## [Unreleased] — the Rust-first refactor

The native engine becomes Lazaret's only engine. Until now it was held,
answer for answer, to the Python engine it was ported from: every detection
landed twice, and the engine could be no better than its twin's structure.
The refactor retires the twin. Its first phase changes no finding — the
engine answers what it answered at the baseline (tag `rust-first-baseline`,
whose outputs were recorded on the benchmark's files and on installed
packages) — and the phases that follow rebuild the detectors on the
engine's lexers and parsers (`docs/RUST_ENGINE.md` §8), each change to a
finding a reviewed difference in the recorded outputs. The lexers (phase
2) change none on real files; the registry's rule set is 2.18.0, so stored
verdicts are scanned again. Whether it ships as 0.1.8 or 0.2.0 is decided
before the release.

### Changed

- **One engine.** The Python package's supply-chain tests, per-file rules
  and cross-file follower are the native engine's alone. `core.py` (18,815
  lines → about 7,700) keeps the project walk, archives, the registry and
  the guard, the manifest and workflow checks, project mode's passes after
  the rules (SQL, function metrics; taint is the engine's: below), the
  suppression markers and the reports. `--engine` and `LAZARET_ENGINE` are gone; `--version` still names
  the engine, and without the library the scanning commands stop with exit
  code 2 and say what is missing.
- **A file the engine can't finish is SC-TRUNCATED in both packages**
  (CRITICAL, so it fails the gate): its work budget spent on a hostile input
  ("reading it spent the engine's work budget") or an internal error ("its
  scan failed"), in `scan_file`, the manifests and the registry's
  import-time and use-time tests; a later step of a registry scan the
  engine can't finish marks the release, naming the step. The Python engine
  used to answer instead. A package that
  spends the cross-file follower's budget, or a follower call the engine
  refuses, gives no cross-file finding, as in the npm package.
  `engine.WORK_BUDGET` sets the budget.
- **Every wheel is a platform wheel.** There is no pure (py3-none-any)
  wheel: it would install a package with no engine. The sdist carries the
  engine's sources (`rust/`), and pip compiles them where no platform wheel
  fits (musllinux, Windows ARM64, other systems), so Rust is needed there;
  `pip install .` and `pip install -e .` compile it too (an editable install
  puts the library in `src/lazaret/_native/`). The sdist and every wheel
  carry `LICENSE-PYTHON` and `NOTICE` and declare `Apache-2.0 AND
  Python-2.0.1 AND Unicode-3.0`. `wheels.yml` installs the sdist with pip on
  Linux, compiling the engine, and `check_native_library.py --dist` holds
  each wheel to the sdist's package files.
- **The rule pack is the source of the rules**
  (`rust/crates/lazaret-engine/rules/lazaret-rules.json`), edited by hand:
  `make_rust_tables.py --check` holds it in its canonical form, every
  pattern compiling with `re`, its rule set the registry's
  `ENGINE_VERSION`, and the values core still keeps for the Python side
  equal to it. `received_spec.json` is retired into it.
- **The engine is held to its recorded outputs**
  (`python/tests/architecture/test_snapshot_*.py`, `snapshots/`, a hash per
  100 outputs): the hooks corpus' ~44,000 cases, the detectors one by one,
  `scan_file` and `scan_rules` on the scan_file corpus and the fixtures, the
  comment lexer, hook commands read as programs, hidden and look-alike
  names, off-screen code and the cross-file follower. A change to what the
  engine finds is a reviewed difference: `scripts/snapshot.py record` and
  `diff` show every case it moves. The Python engine's parity modules
  (`test_rust_parity_*`, but the regex engine's) are retired.
- CI: every job that runs Python tests builds the library first and proves
  it loads; `python-unit` runs the whole suite on it on the three systems.
- **The engine's patterns run on linre** (below) wherever it accepts them:
  616 of the pack's 657, with `re`'s answers, never backtracking; the 41 it
  refuses stay on the port of CPython's matcher. Nothing it finds changes,
  and the five main per-file calls take 6.9 s instead of 10.5 s on 1,500
  installed files (the import-time test 3.1 s instead of 5.1 s). A
  hostile text can no longer make those patterns backtrack without end.
  linre charges the work budget what its automata read, as pyre charges
  its scans: no file needs more of the budget than it did.
- **The engine's lexers read JavaScript and Python as their runtimes do**
  (`docs/RUST_ENGINE.md` §15), for every caller that asks where a text's
  comments and literals are: the per-file rules' comment layout and
  names, the import-time test's prose, the cross-file follower, and
  project mode and the suppression markers in both packages. A template's
  `${…}` and an f-string's replacement fields are code (a call or a
  look-alike name there is found, a comment there is a comment);
  templates nest; a regular expression is told from a division by what
  comes before it; a JavaScript line comment or string ends at any line
  terminator (CR, U+2028 and U+2029 too: the old lexer ran a comment on to
  the next LF, over the code after them), a Python comment at a CR too; a
  first-line `#!` is a comment; t-strings are read as Python 3.14 reads
  them. Where two runtimes read a text differently — with JSX or without,
  Python 3.12 and later or 3.11 — only what both read as prose is prose.
  What a runtime would refuse hides nothing below it: a quote not closed
  on its line is a string to the line's end, and Annex B's `<!--` and
  `-->` stay code (they are code in a module). The npm package's comment
  lexer (`lexer.js`, about 450 lines) asks the engine instead. The
  dashboard keeps its own lexer for now, which reads a template's `${…}`
  and an f-string's fields as text. On real files nothing moved (none of
  the 561,324 recorded outputs on the benchmark's and installed packages'
  files; the holdout's counts); the reviewed differences are in the
  recorded outputs' adversarial corpora, and one benchmark release moved
  from SUSPICIOUS to INCOMPLETE (a Windows executable named `_build.py`,
  whose machine code the old lexer happened to read a look-alike name in;
  still SC-TRUNCATED, still failing the gate). The lexers read every
  literal the JavaScript parser finds in the benchmark's 26,903 parsing
  JavaScript files, and every string, f-string and comment Python 3.13's
  `tokenize` finds in its 19,044 Python files.

- **The self-read reads JavaScript and Python with the lexers.** In the
  import-time test, a quote or a backtick in a comment or in a regular
  expression no longer hides the code after it from "runs code it reads
  back from its own file" (a lone backtick in a comment hid a self-read to
  the end of the file, and a self-read in a template's `${…}` was text). A
  function's source read with `.toString()` counts only where the function
  ends in a comment (the payload kept there), so a browser-automation
  bundle that serializes functions to run in a page (playwright's) is not
  one. The data flow and the dead drop still pair quotes as they come
  until they run on scopes.

- **The decoded view reads JavaScript's and Python's strings as their
  runtimes do.** A literal with some of its characters written as escapes
  (`'child_pro\x63ess'`, `'\u{63}url'`, Python's `'\N{…}'`) is read as its
  text; before, only a literal written wholly in `\x` and `\u` escapes was.
  Literals the runtime joins are joined across lines, quote kinds,
  templates and comments, and Python's adjacent literals (`'cu' 'rl'`),
  where nothing binds tighter (`'a' + 'b'.trim()` is not `'ab'.trim()`);
  never inside a string's own text, as the old pattern could. A literal
  with an escape the runtime refuses has no value. The install-script test
  is given the language of each script it reads (`install_script_risk`,
  `spawned_scripts` and `decoded_view` take `lang`, in both packages: an
  install hook's targets and the scripts they start, a start-up module, a
  hook command's `node -e` and `python -c` code); a text of no known
  language keeps the old reading. On real files no finding moved (the
  benchmark's and installed packages' files; the holdout's counts); in the
  recorded outputs' generated cases 13 import-time answers gained a reason.

- **Project mode's JavaScript taint is the engine's, in both packages.** The
  `X-*` flows and `Q-FLOW-*` notes for JavaScript and TypeScript come from
  the engine's pass (`js_flow`, below), which the Python package
  (`flow._analyze_js`) and the npm package (`scanner/flow.js`) both ask,
  each building its findings from its outputs; `jsflow.py`, `jsparse.py`
  and the npm package's twins of them (11,357 lines) are retired. No
  finding changes: the pass gave jsflow.py's outputs on the parity corpus
  and on 1,490 installed npm packages, and the Python package's findings
  through it are the npm twin's on every field. A host can lower the limit
  of one function's reading (`run_limit`), never raise it. Natively the
  engine runs its calls that recurse on nested input (this pass and both
  parsers) on a thread of its own with an 8 MiB stack, kept per calling
  thread: a host thread with a small stack (512 KiB on macOS, 128 KiB on
  musl) no longer decides whether the deepest nesting the parser reads can
  be read. The parser's trees and the pass's outputs are held to their
  recorded ones (`test_snapshot_js_parse`, `test_snapshot_js_flow`), the
  WebAssembly build to the library (`test_wasm_parity_jsflow`).
- **Project mode's Python taint is the engine's, in both packages: the npm
  package reports Python flows too.** The `X-*` flows and `Q-FLOW-*` notes
  for Python come from the engine's pass (`py_flow`, below), which the
  Python package (`flow._analyze_python`) and the npm package
  (`scanner/flow.js`) both ask; flow.py's own pass (1,505 lines) is
  retired. The npm package had no port of it: its project scans now report
  the same flows on Python files as the Python package's, and its gate's
  cross-file condition no longer says how many Python files it did not
  analyze. No finding changes on real code: the pass gave flow.py's
  outputs on the test suite's file sets, on generated projects and on 455
  installed packages and standard-library modules read as projects, with
  the default and a configured model; it took 6.2 s where flow.py took
  55 s. Bounds are deterministic: flow.py's 120 s time budget is a work
  budget per syntax tree node, as for JavaScript (a host can lower each
  limit, never raise it), and a pathologically long chain — `x()()()…`,
  `a.b.c…` thousands deep, which flow.py read at the cost of its length
  squared — now spends that budget and ends with a Q-FLOW-INCOMPLETE note.
  Where flow.py stopped on deeply nested code at Python's recursion limit
  (a Q-FLOW-RECURSION note), the pass stops at the same nesting as flow.py
  run from the `lazaret` command, whatever its caller. Files are read as
  Python 3.13 reads them, on every Python the package runs on (flow.py read
  them with the running Python's `ast`, so on 3.10 and 3.11 a file using
  newer syntax was a Q-FLOW-SKIPPED note).
- **The supply-chain data flow reads JavaScript on its tree.** Whether a
  script sends what it reads from the machine — the install-script and
  import-time tests' "sends … over the network" reasons — is answered on
  the JavaScript parser's tree for every JavaScript text and its decoded
  view (`docs/RUST_ENGINE.md` §18), with names resolved by scope where the
  text follower followed them by name within a window of text. A quote in a
  regular expression or a backtick in a comment, padding or thousands of
  assignments before the payload, a name that means two things in a bundle,
  and a module kept under another name (`const r = module.require;
  r('http')`) no longer decide the answer; code in a string (a React
  component that shows a payload's code) and a local object named
  `process` are not what they look like. The tree also follows what the
  text follower missed: closures, callbacks (`exec('whoami', (e, out) =>
  …)`), accumulators (`res.on('data', d => body += d)`), `this.x`, implicit
  globals, and the script's own wrappers of exec, of a read and of
  `process.env[name]`. A send carrying several kinds of local data is
  reported by its strongest — the instance's credentials, the whole
  environment, a credential store — so a payload's field order no longer
  decides its grade. A text the parser doesn't read, or that passes the
  pass's work budget, keeps the text follower (Python's is read on its own
  tree too: below). On the benchmark's files 48 import-time answers moved,
  all of malicious samples (four gained a reason, one lost one: a React
  component that only displays the code; its package is still caught); on
  installed packages none moved.
- **Received code reads JavaScript on its tree too.** "Runs code it
  receives over the network", "loads a module named by data it receives"
  and "deserializes data it receives" are answered by the same reading
  (`docs/RUST_ENGINE.md` §18). What it now finds: a response run by
  `Module._compile` through `require` kept under another name
  (model-providers), by `eval` 80 lines after the request, by the
  script's own runner or downloader defined elsewhere in the file,
  through `.then(eval)`, `new Function.constructor(…)` or a variable of the
  environment it was stored in. What it no longer claims: code in a string
  (a stager's text is "carries a script that downloads and runs code"),
  Python handed as JavaScript, the third argument of `eval`, a fixed
  program given received data as its argument (`curl …?ip=` + data, `npm
  publish --registry=…`), and a library's loader for its caller (a request
  addressed by a parameter, `this` or an option; a browser's
  XMLHttpRequest, which jQuery 1.x's and CoffeeScript's script loaders
  run). A command taken from a constant list is read for what it prints:
  a recon script running `id`, `env` and others in a loop sends the whole
  environment. On the benchmark model-providers becomes SUSPICIOUS (445 of
  516 malicious releases; the popular packages unchanged), and the holdout
  gains a release (627 of 747); on installed packages nothing moved.
- **Python's data flow and received code read Python on its tree too.** The
  install-script and import-time tests' "sends … over the network" and
  received-code reasons are answered for every text handed as Python by the
  Python taint pass's supply-chain model (`docs/RUST_ENGINE.md` §19), as
  JavaScript's are by its own: names resolved by scope, the script's own
  functions by their summaries, `self.x` through the class, a closure's
  variables, the globals a function declares, a thread's target and its
  arguments, an object given data in its attributes (`req.data = …` for a
  request later sent), a session or a client, a variable of the environment
  the script stores something in, a container of the module's or of an
  object's that a function fills (`INFO['h'] = …`, `self.items.append(…)`),
  a variable a nested def assigns `nonlocal`, a class's own statements, a
  parameter's default, a lambda called by its name, what a lookup answers
  for the machine's own name (its address), a digest or the characters'
  codes of the data (still the data), a star import's names, and a callee
  under another name (`s = os.system`, `getattr(m, 'x')`,
  `__builtins__.__dict__['exec']`). A comment's triple quotes, padding, and
  a name that means two things no longer decide the answer, and code in a
  string or a comment is not code (a stager's text is the stager test's). A
  request a library makes to its caller's address is not the script's
  download, unless the script calls it with its own. A text the parser
  doesn't read (Python 2, a fragment) keeps the text detectors. On the
  benchmark no verdict moved, and eight malicious releases' findings name
  more exact data or gain received code; the holdout gains two PyPI
  releases (629 of the 745 it keeps: two releases opened to find a shape
  the tree missed left it); on installed packages nothing moved. Rule set
  2.18.0.
- **Import time grades what no library sends, wherever it goes.** Code that
  runs when a package is loaded (SC-IMPORT-RISK) is CRITICAL, not MAJOR,
  when it sends the whole environment or a credential store (an SSH key,
  git credentials, browser storage) anywhere — before, only to a
  data-capture service, an exfiltration service or a public IP address —
  and when it sends what local commands print about the machine (`ps aux`,
  `netstat`, `ifconfig` …; not what Node's `os` module answers). A raw
  socket's hard-coded public address is an IP address
  (`net.connect(4444, '203.0.113.7')`, `s.connect(('203.0.113.7', 4444))`;
  not this machine's, a private network's, a link-local or a carrier-grade
  NAT address). An SDK's shapes stay as they were: one variable sent (its
  own key, to its service), variables listed by a prefix, a cloud metadata
  address, its own service named; a file downloaded and then run stays
  MAJOR. `os.environb` reads as `os.environ` does: a variable read from it
  (pyarmor's `os.environb.get(b'http_proxy')`) was the whole environment.
  The same reasons count in what a package runs when it is used
  (SC-USE-RISK). On the benchmark no verdict moved (the popular packages:
  3 SUSPICIOUS, 29 WARN, as before), and five malicious releases' use-time
  findings now name the whole environment sent; the holdout gains two npm
  releases (629 of 747), each on SC-IMPORT-RISK; on installed packages
  nothing moved.
- **The release workflow restores no caches and runs one release at a
  time.** `setup-node`'s package-manager cache is off in the release jobs:
  a cache restored into the job that can mint a publishing token is a
  cache-poisoning path, and those jobs install nothing to cache. A second
  `v*` tag waits for a running release instead of publishing alongside it.
- **A file written, then run, and decoded code run, are read on the trees.**
  The install-script and import-time tests find a script that writes a
  file and then runs it, when the file holds code or a program the script
  decodes, carves out of another file, or downloads and hands an
  interpreter (`docs/RUST_ENGINE.md` §20): "writes code it decodes to a
  file and runs it with Python", "runs a program it extracts from inside
  another file (docs/_static/logo.png)" (a new strong reason:
  requests-darwin-lite's executable cut out of a PNG it ships), "downloads
  a script and runs it with node". The JavaScript and Python models match
  the path written to the path run by its binding or the string it holds,
  through a joined path, a command line made of parts or written out, an
  interpreter's flags, and a function that writes and another that runs. A
  binary downloaded and run is not reported (installers do that: esbuild
  runs `--version` on the binary it fetched), and `cmd` runs a batch file
  as a script and anything else as a program. A reason that names the
  interpreter takes the place of the text detectors' for the same run that
  names none. In dependency scans SC-EVAL-DECODE reads decoded code run on
  the trees too, for a JavaScript or Python file whose text has a candidate
  or that writes out a decoder the text doesn't know (an XOR, characters
  made of their codes, a reversal …) and calls a runner, both in code; the
  tree's answer stands, and it counts the sinks the text's reading counts
  (any object's `execSync`, child_process from `await import`). `chr` decodes in a comprehension or `map(chr, …)`,
  not alone (numpy's crackfortran evaluates `chr(params[n])`), and a
  WebAssembly module made of decoded bytes is not code run (es-module-lexer,
  in tsx and vitest). On the benchmark no popular package is SUSPICIOUS
  any more (3 before): cypress (the look-alike keyword below) and inspect-ai
  are WARN and jiti is OK. jiti's decoded value is never run on its tree,
  and inspect-ai's is a web worker's source held in a template literal
  (below). Three malicious releases become SUSPICIOUS (448
  of 516): pywhool's XOR-decoded `exec` in setup.py and requests-darwin-lite
  (both misses the backlog named), and quasarlib, which was INCOMPLETE; five
  more gain a reason. The holdout gains two PyPI
  releases (631 of 745), both sharing no code with the benchmark; on
  installed packages nothing moved. `scan_file` and the import-time test
  take the time they took. Rule set 2.19.0.
- **SC-EVAL-DECODE's flow skips literals.** A decode call or a sink in a
  string, a template's text or a regular expression is not code, so a name
  decoded or run there starts or ends no flow: in 129 of the scan_file
  corpus's 4,257 recorded outputs, all generated fragments, and on the
  benchmark in inspect-ai's web worker, whose source is a template
  literal in its 6 MB bundle. The per-line pattern still reads strings.
- **A keyword's look-alike is a name mixing alphabets** (SC-HOMOGLYPH,
  MAJOR), not "another name in this file" (CRITICAL): no binding can be
  called `function`, and jQuery's typings, which cypress ships, name a
  parameter `funсtion` with a Cyrillic с. A look-alike of a name the rule
  watches for (`import`, `eval` …) stays CRITICAL.

### Added

- The engine's port of project mode's cross-file JavaScript taint pass
  (`js_flow`: jsflow.py's scopes, bindings, points-to and summaries, on the
  engine's JavaScript parser's trees), held to jsflow.py output for output
  (`test_jsflow_reference.py`, retired with jsflow.py); on 1,490 installed
  npm packages read as projects it gave the same outputs about twelve times
  faster.
- The engine's port of project mode's cross-file Python taint pass
  (`py_flow`: flow.py's summaries, resolution model and route parameters,
  on the engine's Python parser's trees), held to flow.py's pass output for
  output before it retired; held to its recorded outputs
  (`test_snapshot_py_flow`), the WebAssembly build to the library
  (`test_wasm_parity_pyflow`), and its route parameters to the intra-file
  engine's (`test_pyflow_frameworks`).
- The engine's JavaScript parser (`js_parse`: jsparse.py's trees, node for
  node, until jsparse.py retired) and Python parser (`py_parse`: Python 3.13's `ast` trees, node for
  node, with its errors), about 60 MB/s each, for the detectors to be
  rebuilt on (`docs/RUST_ENGINE.md` §12, §13).
- linre, a linear-time regular expression engine with `re`'s answers on 616
  of the pack's 657 patterns (lazy DFAs, a bounded backtracker, a Pike VM,
  prefilters; §14).
- The engine's lexers as calls: `lex.tokens` (one reading's tokens) and
  `lex.structure` (what the detectors ask: comments, strings, literals),
  held to the engine's JavaScript parser and to Python 3.13's `tokenize`
  by `test_lex.py` (§15).
- `scripts/bench.py`, the benchmark harness: registry scans of a labelled
  set of release files (resumable, a deadline each), and the comparison of
  two runs — every release whose verdict or strong findings moved, or, for
  a holdout set, the counts alone.
- **SC-UNUSED-DEPENDENCY** (registry, INFO): an npm release's runtime
  dependency that no file of it names — no text quotes it as a module or
  package name, no field of `package.json` but the dependency lists names
  it — and that is neither one of npm's 5,000 most-downloaded packages nor
  in the package's own scope. It is installed, and its install scripts run,
  for nothing the package does: each @mastra release of June 2026 gained
  such a dependency, `easy-day-js`, and changed no code. Packages also keep
  ones their build inlined, so on its own it is context; a brand-new one
  (SC-NEW-DEPENDENCY) is CRITICAL even past 7 days. Listed only when every
  text of the release was read whole. The check is
  `lazaret/registry/unused_deps.py`, language-neutral (declared names,
  used names and an ecosystem's normalizer in; the declared names nothing
  uses out), for the crates and Go modules to come. Rule set 2.22.0.
- **SC-TYPOSQUAT compares npm names with Node's built-in modules** named
  with a separator (`child_process`, `worker_threads`, `perf_hooks`,
  `async_hooks`, `trace_events`, `diagnostics_channel`): a dependency on
  `child-process` installs a stranger's package, since
  `require('child_process')` loads the built-in.
- **A GitHub Action** (`action.yml`; README.md, "In CI"): it installs
  Lazaret from the commit a workflow pins, compiling the engine with the
  runner's cargo, so what runs is that commit's code rather than a package
  fetched by its version number; scans with `--ci`; and writes a SARIF
  report for code scanning, whose path is its `sarif` output. Its inputs
  reach its scripts through the environment, never spliced into them.

### Fixed

- **The zip reader on what the 0.1.9 lane's fuzzers found** (F-2, F-6,
  F-7). A zip entry with no name raised `IndexError` out of the reader on
  Python 3.10 and was dropped without a word on 3.11+: it is an anomaly
  (SC-ARCHIVE-PATH), and the entry is not read. An LZMA entry declaring a
  4 GiB dictionary raised `MemoryError` where memory is capped: a dictionary
  over 64 MiB is refused before zipfile allocates it, and `MemoryError`
  reading an entry makes it unread. Entries whose bytes overlap (the shape
  of a zip bomb) were a warning on Python 3.12.3+, an exception under
  `-W error`, and no finding: SC-ARCHIVE-OVERLAP (MAJOR), on every version.
  Rule set 2.23.0.
- **safexml: a declared encoding Expat can't read** (F-1) ended a parse
  with `LookupError` or `ValueError`, as in the standard library, so a
  caller catching the parse error was ended by it (the PyPI release feed's
  reader among them). Each API now raises its parse error for it
  (`ParseError`, `ExpatError`, a fatal `SAXParseException`), saying
  "unknown encoding" without the document's text.
- **A program under a source file's name made a release INCOMPLETE, not
  SUSPICIOUS.** An executable's bytes in a `.py` or `.js` member (num2words
  0.5.15's `_build.py` is a Windows executable) were an unreadable source
  file (SC-TRUNCATED) and a binary to review (SC-BINARY, MAJOR; in a wheel,
  inventory). No build ships one, so it is SC-BINARY, CRITICAL, in every
  kind of release: a disguise. A binary named for what it is (`.so`,
  `.node`) stays as it was, and bytes that are no program stay unread
  (INCOMPLETE). Registry and guard scans. Rule set 2.21.0.
- **A directory scan read a source file that isn't text as mojibake.** Bytes
  that don't decode to anything text-like (more than 30% invalid bytes or
  control characters) in a `.py` or `.js` file of your tree, or with
  `--deps` of a dependency, got one INFO note and passed the gate; the
  registry already calls the same member SC-TRUNCATED. Both CLIs
  read source files the registry's way now (`decode_member`), so the file is
  SC-TRUNCATED and the scan can't pass. None of 61,538 source files in the
  benign corpora and installed packages is.
- **A directory scan read a program under a source file's name as text.**
  The same file in your tree, or with `--deps` in your dependencies, got no
  supply-chain finding and passed the gate. It is SC-BINARY, CRITICAL, there
  too (an oversized one by its first bytes), and in the MCP server's
  `scan_files`. Both CLIs.
- **Python's decode-then-run didn't count a shell.** A decoded value handed
  to `os.system`, `os.popen`, `subprocess` with `shell=True` or
  `subprocess.getoutput` got no finding, while JavaScript's
  `execSync(atob(…))` was SC-EVAL-DECODE, BLOCKER: an sdist whose `setup.py`
  ran `os.system(base64.b64decode('d2hvYW1p').decode())` was OK. The text's
  reading has no Python shell among its sinks, so no candidate sent the file
  to its tree, which counts them; a Python text with a decoder the text
  knows (base64, hex, zlib, `codecs`) and a shell is read on its tree now.
  It reads 24 more of 56,422 benign Python files, and none of them is
  flagged; 5 more of the benchmark's 745 holdout releases are SUSPICIOUS.
  Rule set 2.24.0.
- **S-TOKEN missed GitHub's fine-grained tokens.** A `github_pat_…` token
  (22 and 59 characters around an underscore) got only S-ENTROPY (MAJOR),
  though secret redaction already knew it; it is S-TOKEN (BLOCKER) in
  source and config files, in both packages and the dashboard (the CI/CD
  review's gap). Rule set 2.20.0.
- A file's decoded view that the work budget cut short was remembered for
  the file's next call (the install-script test, the import-time test and
  the string-array test read it in turn), which could then answer from the
  unfinished reading instead of failing closed. Only a finished reading is
  remembered.

## [0.1.8] — 2026-10-01

0.1.8 reads malware by what it does. A round late in its cycle audited
every strong detector for whether it names a behaviour or recognizes the
samples it was written from, and rewrote the second kind (the behaviour
pass: the first four entries under Added, and Changed); its last round read
further into what that pass left at WARN or did not connect (the detection
round: data flows it did not connect, code built around an obfuscator's
string array, wallet addresses swapped, the cross-file follower's known
misses; the entries marked so). Every benchmark number in these notes is
in-sample: it was measured, at the round it names, on the 516 malicious
releases and 429 popular packages read while the detectors were written.
So 0.1.8 also measures a holdout: 747 other malicious releases of the same
dataset that no detector was written from, looked at only in aggregate.

| 0.1.8: before the behaviour pass → after it → after the detection round | Benchmark (516, in-sample) | Holdout (747) |
| --- | --- | --- |
| SUSPICIOUS | 87% (448) → 83% (430) → 86% (445) | 85% (634) → 78% (583) → 84% (626) |
| SUSPICIOUS on a behaviour or a generic technique | 69% (354) → 82% (424) → 85% (439) | 66% (495) → 77% (574) → 83% (617) |
| Share of SUSPICIOUS verdicts resting on one | 79% → 99% → 99% | 78% → 98.5% → 98.6% |
| SUSPICIOUS or WARN | 90% → 90% → 90% | 90% → 89% → 89% |
| Holdout releases sharing no code with the benchmark (499): SUSPICIOUS | | 79% → 72% → 77% |
| 0.1.7, for comparison: SUSPICIOUS (on a behaviour or a technique) | 68% | 70% (53%); 74% of the 499 |

The behaviour pass made the strict verdict catch less: 19 benchmark
releases and 56 holdout releases were no longer SUSPICIOUS (most became
WARN), while 1 and 5 others became so. Of the holdout's 56, 50 had rested
only on a tool's mark, a list of services or a hook's tokens — `_0x` names
in 38 (with the Bun loader rule in 14), a list in 11, tokens in 4 — and 6 on
a host name read near a network call, which the data flow did not connect.
The detection round won most of them back on what the code does: 41 of the
holdout's 56 are SUSPICIOUS again — the 38 javascript-obfuscator releases on
the technique itself (install-time or import-time code built around a
string array), 3 on a host name the data flow now follows to its send — and
13 of the benchmark's 19; it catches 2 holdout and 2 benchmark releases that
were never SUSPICIOUS, and loses none. What is SUSPICIOUS still nearly always
says what the code does. On the 499 holdout releases that share no code with
the benchmark, 0.1.8 is SUSPICIOUS on 77% and 0.1.7 on 74%, and 0.1.8's
verdicts there rest on a behaviour or a technique for 76% of the 499 (0.1.7:
55%); on the 248 campaign siblings of the benchmark's samples, 97% (0.1.7:
63%). Of the 365 benchmark releases GuardDog calls high_risk, Lazaret calls
363 SUSPICIOUS (all 365 before the behaviour pass, 350 after it; the other 2
rested on a list of services, now only a label). The same 3 of the 429
popular packages are SUSPICIOUS (68% of the 516 in 0.1.7; GuardDog 71%), and
the registry's live dependency history still adds the 17 @mastra releases
(89.5% with it). Registry engine 2.15.0, so stored and cached verdicts are
redone.

0.1.8 also runs both packages on the native engine (`docs/RUST_ENGINE.md`):
the Python package's platform wheels carry it, and the npm package runs it
compiled to WebAssembly, so a detection lives in Python and Rust instead of
three times. A performance round, before the detection round, made scans
faster with the same findings in the same order (the last four entries under
Changed). On two cores, against 0.1.8 before it (the npm package in
JavaScript, the Python package with the native engine in dependency mode
only):

| Two cores; the same findings, in the same order | Before | After |
| --- | --- | --- |
| npm CLI, `--deps` over an installed tree (1,155 dependency files) | 7.6 s | 3.5 s (5.1 s on one thread) |
| npm CLI, a 616-file project | 6.1 s | 4.9 s (5.4 s on one thread) |
| npm CLI, a tree whose 11.5 MB bundle is most of the scan | 11.8 s | 8.2 s |
| Python CLI, `--deps` over the same tree | 5.6 s | 2.5 s |
| Python CLI, the 616-file project | 18.1 s | 14.7 s |
| Python CLI, BenchmarkPython (1,230 files) | 6.6 s | 5.2 s |
| The benchmark's 945 registry scans (their scan time) | 547 s | 305 s |

The registry scans give the same verdicts, reasons and findings for every
package; litellm's takes 10.5 s instead of 16.6 s, playwright-core's 5.8 s
instead of 10.6 s, next's 8.9 s instead of 10.4 s.

### Added
- **An install hook's command is read as a program** (both engines).
  0.1.7 made a hook CRITICAL when its command merely contained curl, wget,
  eval, base64, `node -e`, `sh -c` or powershell: tokens a hook that fetches
  a platform binary shares, and one written with other tools avoids. They are
  now only a hint in the MAJOR finding's message. What escalates a hook is
  what its command does (`core.hook_command_risk`): the install-script test
  on the command; the code it hands an interpreter inline (`node -e` / `-p`,
  `python -c`, and `sh -c`, `eval` and `cmd /c` command lines, three levels
  deep), read the same way; and its network commands, parsed as a shell
  parses them (quotes, escapes, `$(…)` and backquotes, pipes, redirections,
  `&&`, `||`, `;`): a local file uploaded (`curl -d @file`, `-F`, `-T`,
  `wget --post-file`, `< file` or `cat file |` into the command), what a
  command that reports on the machine prints sent (`whoami`, `hostname`,
  `env`, `ls`, `uname -a` … in `$(…)`, or piped through `base64` or
  `xargs`), a variable naming the user or the host or holding a secret
  (`$USER`, `%USERNAME%`, `$NPM_TOKEN` …) sent, the user or host name in the
  name a lookup resolves, and a beacon: a request whose answer is thrown
  away, or a lookup, whose only effect is to tell a server the package was
  installed. A request whose exit status decides what runs next is a
  connectivity check, and a download that keeps what it gets may name the
  platform, the version and paths in its address. The command lines a script
  hands a shell (`os.system`, `execSync`, a shell string to `subprocess`,
  `sh -c` in an argument list) are read the same way.
- **Exfiltration is read as a data flow** (both engines). What an
  install script sends decides, not where it sends it (a list of
  exfiltration services does not know a Feishu bot, a new tunnel service or
  the attacker's own server). Data read from the machine is followed to a
  send (`core.local_data_sent_at`): an environment variable that names the
  user or the host or holds a secret, the whole environment copied, listed or
  serialized (not narrowed to the package's own settings), files and folders
  outside the package (an absolute path, the home or working folder, a name
  given one), what a command that reports on the machine prints, the
  machine's names and addresses, what the cloud's instance metadata service
  gives (the instance's credentials) and the public IP address a lookup
  service answers; through assignments, destructuring, loops, `with … as`,
  `.then()` chains, a read's callbacks, returns and the parameters of the
  script's own functions; to the data of a request, a socket's or a
  connection's write, or a command a script runs that holds curl, wget or nc.
  A request's address and a DNS name count too, for all but the environment,
  the metadata and the public IP address (a download's address may carry a
  mirror or a token). A value tested rather than used, the path a read is
  given, a child process's options and a callback handed to a request are
  not data sent. The lists of exfiltration and data-capture services now
  only label where the data goes ("contacts an address typical of data
  exfiltration (…)"). At import time the same flow is CRITICAL when it goes
  to a data-capture service or a public IP address, or when the whole
  environment, the instance's credentials or a credential store go to an
  exfiltration service. A
  request to a webhook or a bot whose secret is written in the code is read
  for any service: a credential in the URL's path (20 to 200 characters
  mixing upper case, lower case and digits), not only Telegram's, Discord's
  and Slack's shapes.
- **Obfuscated JavaScript is read as what it does** (both engines). The
  decoded view, which the install-script and import-time tests read a second
  time, now reads javascript-obfuscator's string arrays (and those of the
  tools that copy it): the strings kept in one array and read back through an
  accessor with an offset, undecoded, in base64 over the accessor's own
  alphabet or in RC4 with the key each call passes; the rotation its
  checksum loop applies, found by working out the loop's arithmetic as
  JavaScript does (nothing is run, and nothing is read unless the checksum
  holds); and calls through aliases, wrapper functions, and indexes written
  as arithmetic or kept in objects of constants. It reads the proxy objects
  of its control-flow flattening (`o['oEnxQ'](require, o['OKaPt'])` is
  `require('child_process')`), and a file's own character-code decoder
  whatever its arithmetic: a function that builds text with
  `String.fromCharCode` or `chr` from the codes it walks and its other
  parameters, worked out by a small evaluator of 32-bit integer arithmetic
  (@fnos/app XORed every string of its runner with a key that changes with
  the position). So the tests see what such a file does: the 2026 setup.mjs
  payloads' 2 MB `router_init.js` now reads as "sends environment variables
  over the network (the whole environment)", "writes an AI agent's or
  editor's auto-run settings (.vscode/tasks.json)" and "contacts an address
  typical of data exfiltration (http://169.254.169.254)".
- **Programs a hook or a script starts, whatever the runtime** (all three
  engines). A hook's `bun x.js`, `bun run x.ts`, `deno run -A x.ts`, `tsx`,
  `ts-node` or `vite-node` is followed to the package file it runs, as
  `node x.js` is (`bun run build` runs the package's script; `bun install` is
  a subcommand). A script that starts any program a variable names — a
  runtime it downloaded — with a file of code is followed to that file
  (`execFileSync(bun, [path.join(dir, 'router_init.js')])`), and so is a
  path built from an ES module's folder (`dirname(fileURLToPath(
  import.meta.url))`, `import.meta.dirname`) or with pathlib's `/`, or one the
  script decodes as it runs. This replaces the rule for one loader (a Bun
  release fetched from GitHub and run): what a loader starts is now read and
  tested, whatever it fetched. SC-AUTORUN follows what a planted setting's
  command starts too.
- **DNS names built from values, and addresses fetched at run time** (both
  engines). A DNS name built from values outside a template is now read
  too: a sum ending in
  a literal domain (`h + '.x.example.com'`), `%` or `.format()`, a name
  assigned earlier in the file, a lookup command run from code
  (`os.system('nslookup ' + host + …)`), and in a shell command `$(whoami)`,
  `` `hostname` ``, `$USER`, `%USERNAME%` or `$env:COMPUTERNAME` in the name
  `nslookup`, `dig`, `host`, `ping`, `curl`, `wget` or `Resolve-DnsName`
  resolves — not a reserved domain (`.local`, `.internal`, `.test`, …), and in
  code only in a file that reads the machine's user or host name. And a
  destination fetched at run time: the value a fetch of a hard-coded URL
  gives (a GitHub Pages config, a pastebin, a gist), followed through
  assignments, destructuring, `for` loops, callbacks, `.then()` chains and
  returns to a POST, PUT, PATCH or sendBeacon, in a file that reads the host
  or user name: "sends the machine's user or host name to an address it
  fetches at run time (from HOST)", CRITICAL. The host name read through
  `require('os').hostname()`, a destructured `require('os')` or `node:os`
  import, or `from socket import gethostname` counts as reading it. Compared
  with the round before on every source file of the benchmark's 945 releases and 29,629
  installed files, no benign file's answer changed; on the benchmark one
  more malicious release is SUSPICIOUS (@helpcentre/tesco-help, whose install
  script posts `require('os').hostname()`), and no popular package's verdict
  changed. Registry engine 2.13.0, so stored and cached verdicts are redone.
- **The cross-file follower follows event emitters** (Python and npm
  engines): a value received over the network in one file and emitted there
  (`bus.emit('code', data)`) reaches the listeners of that event in other
  files on the same emitter — a module's export resolved through imports, an
  imported name, `process`; not `this` or a parameter, which are their own
  file's — and a listener that runs it (`bus.on('code', c => eval(c))`,
  `bus.on('code', eval)`) is SC-IMPORT-RISK, CRITICAL, as the other
  cross-file flows are. An emit or a listener in a comment is not one. It was
  the adversarial pass's known miss.
- **The data flow connects what it did not** (both engines; the detection
  round). The flow that replaced a host name read near a network call did
  not connect 6 of the holdout's verdicts, nor some shapes of the
  benchmark's own files. It now follows a name spread whole (`{...info}`,
  `f(...args)`); a function's own return (the innermost function whose body
  holds it, not the last one defined before it); a method called on a
  receiver (`this.info()`) and the `.then()` after a call of a function that
  returns data; a callback the script's own function calls with data
  (`collect((info) => …)`); a constructor's parameters by its class
  (`new C(x)`) and a thread's target's by its `args`; merges
  (`Object.assign`), destructured loops and callback parameters, and Python
  tuples (`out, err = p.communicate()`); the machine's modules under another
  name (`const o = require('os')`, `import socket as s`, `platform.node()`);
  and HTTP clients under the script's own names (node-fetch, request,
  undici, got; `axios.create()`, `requests.Session()`,
  `with httpx.Client() as c`). New sources: command runners under the
  script's own names (`util.promisify(exec)`, execa,
  `asyncio.create_subprocess_shell`), files under `%APPDATA%` and
  `%LOCALAPPDATA%`, a database opened from outside the package
  (`sqlite3.connect`, `new Database(p)`: a browser's Login Data), and a file
  copied from outside the package and read from its copy. And it connects
  less that only shares a name: a parameter holds what it is given only in
  its function; a receiver's member is the name (`this.env`, not `this`,
  which every method shares); keywords, an object literal's methods and a
  callback handed to a call name no data; in a text over 256 KB (a bundle,
  whose modules reuse `data`, `cb`, `e`) a name carries data only 20,000
  characters from where it was given it; the environment handed to a call
  as `env=` is the program's that runs with it. On the benchmark three more malicious releases' host-name
  sends are connected (an MCP server's telemetry among them), and the flows
  read in playwright-core's, cypress's and paramiko's files are gone (no
  verdict rested on them); on the holdout, 3 of the 6 verdicts are back.
- **Wallet addresses swapped for the script's own** (both engines; the
  detection round). A clipper or a page script that hooks the wallet shows
  three parts, all needed (`core.wallet_swap_at`): patterns of wallet
  addresses of two kinds or more, written as a regex (an Ethereum address,
  base58, bech32, a Tron address, Bitcoin Cash); where the user's addresses
  pass, intercepted — the clipboard read and written (`navigator.clipboard`,
  `execCommand('paste'|'copy')`, pyperclip, clipboardy, win32clipboard,
  pbpaste/pbcopy, xclip …), or the page's requests and its wallet (`fetch`
  or `XMLHttpRequest.prototype` replaced, `window.ethereum.request`
  wrapped); and a wallet address written in the code. A validator has the
  patterns, a wallet's page the clipboard, a monitoring SDK wraps fetch: none
  has all three. "Swaps the cryptocurrency wallet addresses its user copies
  or sends for its own" is an exfiltration shape: CRITICAL in an install
  script and a strong import-time reason, read in the decoded view too.
  error-ex 1.3.3 and @coveops/abi 2.0.1 (the September 2025 compromise's
  hooked fetch and XMLHttpRequest) were WARN; no benign release of the
  benchmark, nor 50 wallet and web3 packages (ethers, viem, wagmi, web3,
  MetaMask's and Coinbase's SDKs, multicoin-address-validator, web3.py,
  pyperclip …: about 30,000 files), has the three.
- **Code built around a string array is a sign of its own, and more of the
  obfuscator is read** (both engines; the detection round). An install
  script, a script it starts, or import-time code built around a string
  array whose calls the decoded view reads says "hides its code in a string
  array it decodes as it runs (an obfuscator's technique)": CRITICAL at
  install time and a strong import-time reason, however little of what it
  decodes the other tests understand — an obfuscated payload often runs
  what they miss (a wrapper that downloads, a native addon it starts). No
  benign release of the benchmark, nor any of the ~60,000 files of popular
  packages read for it (installed trees, the 172 popular packages with
  install hooks, 50 web3 packages), is built that way; 14 benchmark
  releases and 38 holdout releases are SUSPICIOUS on it now (WARN or
  INCOMPLETE before). The decoded view also reads a string literal written
  wholly in `\x` and `\u` escapes, three or more (the unicodeEscapeSequence
  option: `'\x63\x68\x69\x6c\x64…'`), as its text when that is printable
  ASCII without a quote or a backslash, before string arrays and proxy
  objects are read (escaped module and member names, proxy keys, an
  accessor's alphabet: nanoid-js 1.0.1's setup.js was not decoded); a
  character or two escaped (`'\x20'`, `"<\x2fscript>"`) is left as written,
  and so are raw, bytes and f-string literals. And a proxy object's name the
  obfuscator reuses in each function is read at each use as the object it
  was last given before it (a name given two objects was not read at all).
- **The cross-file follower's known misses** (both engines; the detection
  round). A function that hands its parameter to a runner of the package —
  in another file or its own (`def go(c): execute(c)`) — runs it too: each
  function with parameters is read with them seeded and the names that
  name a runner in its module as runners, a round per hop. Wrappers,
  re-exports and such relays are followed 16 hops deep (4 before). A
  `getattr` whose name the file builds of what it holds — literals joined
  with `+` (`getattr(m, 'pu' + 'll')`), a name given such a value on a row
  of its own and nothing else anywhere (`NAME = 'pull'`) — reads as `m.pull`
  in the received-code test, and a runner named through the builtins or the
  global object (`getattr(builtins, 'exec')`, `__builtins__.__dict__['eval']`,
  `globalThis.eval`, `window.Function`) as the runner itself. And in a
  `--deps` scan the top-level modules and packages one distribution installs
  into site-packages are one package to the follower, as a registry scan
  reads a release: its `.dist-info/RECORD` lists them (a real directory, at
  most 4 MB, no link followed); top-level names no RECORD lists together
  stay apart. Nothing changed on the installed trees' 1,760 npm packages
  and 179 Python packages (170 once their RECORDs join them), nor in the
  received-code test's answer on about 32,600 benign files and archives.
- **`lazaret guard` for yarn, Bun, uvx and uv run.** yarn 2+ resolves with
  `--mode=update-lockfile` (nothing linked or built) and its registry
  packages are checked against the integrity the registry publishes (yarn
  pins a checksum of its own zip, which then keys the cached verdict); yarn 1,
  which has no lockfile-only mode, resolves in a temporary copy of the
  project with scripts off, and what that copy installed is checked. Bun
  resolves with `--lockfile-only`. New releases are held back by yarn's
  `npmMinimalAgeGate` (yarn 4.10+) and Bun's `--minimum-release-age` (Bun
  1.3+), as npm's `before` and pnpm's minimum-release-age hold them.
  `uvx`, `uv tool run` and `uv tool install` go through the guard's local
  index: the tool's requirements are compiled through it first (every file
  scanned), then the command runs, every download scanned before uv gets it.
  `uv run` in a project is guarded as `uv sync` is and then runs with
  `--frozen`; what else it installs (`--with`, a script's dependencies) comes
  through the local index.
- **Private registries and indexes in the guard.** The guard fetches with
  the credentials the package manager's own settings give (the new
  `lazaret.registry.pmsettings`): the `.npmrc` keys npm, pnpm, yarn 1 and Bun
  read (`//host/path/:_authToken`, `_auth`, `username` + `_password`, with
  `${VAR}`), yarn 2+'s `npmAuthToken` / `npmAuthIdent` (top level,
  `npmScopes`, `npmRegistries`), Bun's `bunfig.toml`, a Python index URL's
  `user:password@`, uv's `UV_INDEX_<NAME>_USERNAME` / `_PASSWORD`, and
  `.netrc`. A credential goes only to the host — for npm's keys, the path —
  it is set for, over https or to this machine, never over a redirect to
  another host, and never into the output, the cache or `--json`. pip and uv
  still talk only to 127.0.0.1, without credentials. The local index now
  relays the indexes pip and uv are set to use (pip's index-url and
  extra-index-url, uv's indexes from its environment, `uv.toml` and
  `pyproject.toml`, and those on the command line, which 0.1.7 refused),
  reading PEP 503 HTML pages as well as JSON ones.
- **Notices.** The npm package's shell tokenizer is a translation of
  CPython's shlex: the package now carries `LICENSE-PYTHON` and a `NOTICE`
  saying what was translated and changed. The Unicode 13.0 tables
  (`_unicode13.py`, `unicode13.js`, `unicode13.rs`) and the single-byte codec
  tables (`codecs.js`, and the dashboard's copies) are Unicode data: each
  carries the Unicode notice, and every package that ships them carries the
  Unicode License v3 (`LICENSE-UNICODE`) and declares it — the sdist and the
  pure wheel `Apache-2.0 AND Unicode-3.0`, the platform wheels, the crates
  and the npm package `Apache-2.0 AND Python-2.0.1 AND Unicode-3.0`.
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
    `LAZARET_NO_DEPENDENCY_HISTORY=1` turns it off. (The detection round)
    PyPI's owners count too: its JSON API now carries `ownership` (the
    project's owners and maintainers by username, and its organization), so
    a requirement one of the project's own accounts or its organization
    publishes (a project splitting off `acme-core`) no longer counts, and
    another account's names its owners, as on npm; a document without it (a
    mirror) changes nothing.
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
    obfuscation (12 files; no popular package). Any decoder function since
    the last round (Changed).
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
    received is the same finding, and says so. The npm package runs it too
    (the native engine's `cross_file`, under Changed, which agrees with core
    on the follower's cases and a generated stream of 700 packages), so it
    is no longer a Python-only exception; registry and guard scans run it on
    a release, naming the file (not on tests, docs or examples, and not once
    the package is SUSPICIOUS).
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
    Any service's webhook since the last round (exfiltration as a data flow).
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
    shortcuts rewritten to load an extension (python-dateuti; any program's
    shortcuts since the last round).
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
- **The native engine's project-mode rules** (`scan_rules`, phase 2 of
  `docs/RUST_ENGINE.md` in project mode) and its reference in core
  (`core.scan_rules`: `scan_file`'s first part, before the passes that
  follow it, the markers and the cap), held to each other by
  `test_rust_parity_project.py`. Both packages run it (below).
- **More of core in the engine:** the agent-hijack checks
  (`agent_hijack`, `agent_hijack_in_command`), a hook's command read as a
  program (`hook_command_risk`) and what makes a hook suspicious
  (`hook_is_suspicious`), the import-time code of a JavaScript or Python
  file (`import_code`), the cross-file follower (`cross_file`, below),
  core's values by name (`pack.values`, for what the npm package still
  reads: limits and the S-TOKEN rule), and a work budget per call
  (`budget`).
- **SQL-DYNAMIC in linear time.** `re`, and so the engine's port of it, takes
  quadratic time on a line of many `EXEC("` (14 s for one 120 KB line in
  Python); the engine matches that pattern by hand in linear time
  (`linear.rs`), as the npm package's JavaScript did, while the rule pack
  holds its exact text.
- **Tests.** `test_wasm_parity.py` and `test_wasm_parity_signs.py` (the
  WebAssembly build against the native library, call for call, on the hooks
  corpus, the scan_file corpus and this repository); the comparisons that
  held the npm package's JavaScript to core now hold the engine to it
  (`test_rust_parity_hook_commands`, `_hexname`, `_offscreen`,
  `_lookalike`); the hooks parity reads its corpus (~44,400 cases) in two
  modules (`test_rust_parity_hooks.py` and `_hooks_b.py`), each well under
  45 s. Workflow tests check that every module needing the WebAssembly build
  runs in a job that builds it and every native parity module in each job
  that builds a library, and the npm pack test that the tarball carries the
  engine and its notice and nothing else of `native/`. CI's `js` job builds
  the engine, runs the npm tests and, on Node 24, the CLI-level parity
  modules; its `rust` job runs the WebAssembly parity.
  `test_rust_parity_crossfile.py` holds the engine's follower to core (its
  own cases and a generated stream of 700 packages, every package of the
  stream in one call on threads, a registry scan's reading, Windows
  separators, skipped files, a package that spends its budget read by core)
  and `test_wasm_parity_crossfile.py` the npm binding to the Python one;
  `test_rust_parity_project_scan.py` the Python package's project-mode
  routing (`engine.scan_files`) to `core.scan_file`;
  `test_engine_cross_file.py` the follower's routing and fallbacks; the
  regex parity gains patterns for leads and start tests and runs every pack
  pattern with a text gate open; `test_rust_pack.py` checks the pack's rule
  set against `ENGINE_VERSION`, so a version bump that doesn't regenerate
  the pack fails every suite run; `js/test/pool.test.js` the npm CLI's
  reports with 1, 2 and 3 worker threads.

### Changed
- **Detectors written from samples now read the behaviour** (the audit of
  every strong detector for whether it names what code does or recognizes
  the samples it was written from). An install hook's download and evaluation tools and the
  lists of exfiltration services became hints and labels (above). The rule
  for one loader — a Bun release fetched from GitHub and run — is gone: the
  runtime it starts, and the file it runs, are followed instead. Browser
  shortcuts rewritten to load an extension became the shortcuts of any
  program on the machine rewritten: a search for `.lnk` files,
  `CreateShortcut`, and a shortcut's `Arguments` or `TargetPath` set,
  whatever the program now starts. SC-EVAL-DECODER, written for one
  campaign's letter shift (eval of an inline function), is now eval,
  `Function` or vm's `runIn…Context` given what any function — written into
  the call or named — computes from 200 or more character codes or 1,000 or
  more characters of text. SC-OBF-IDENT (`_0x` names) and SC-PACKER (Dean
  Edwards' p,a,c,k,e,d) are MAJOR: a tool's mark is not what the code does,
  and the decoded view reads what javascript-obfuscator hides; a packed
  payload that runs is SC-EVAL-DECODER's.
- **Large bundles took longer to scan.** The data flow and the readings of
  the behaviour pass cost most on big bundles: with the native engine on 2
  cores, playwright-core's registry scan took 11.2 s after the pass (4.7 s
  before it; 18.1 s with the Python engine), litellm's 16.7 s (12.2 s),
  next's 11.0 s (10.6 s). The final round's speedups (the last four
  entries here) bring them to 5.8 s, 10.5 s and 8.9 s. The flow follows
  names, so in a 3 MB bundle short names can collide: playwright-core's
  `utilsBundle.js` gets an import-time MAJOR ("reads credentials or the
  whole environment and sends data over the network") it doesn't earn; no
  verdict changed (`docs/DESIGN.md` §12).
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
  with the Python engine and 853 s when the native engine answered only the
  install-script and import-time tests (litellm 11.4 s, 42.1 s and 30.6 s),
  with the same verdicts and findings. Two new
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
  scanned first), and `should_stop` between batches. SC-USE-RISK's batches
  hold at most 1,000,000 characters (or one file), so its 3 s per archive
  holds: a batch of truffle's bundles took 20 s.
- **core's finding texts are module-level values.** Every finding
  `_scan_file` makes takes its texts from a rule dict of the module
  (`_HEXSTR_TEXT_RULE`, `_LOOKALIKE_RULE` …; a message with fields is a
  `str.format` template), so the rule pack carries them, and the pack holds
  the token pattern (`RULES`' S-TOKEN, the redaction list) as well. The
  findings are the same.
- **The native engine is released in lockstep with the packages.**
  `scripts/check-versions.sh` (CI's `versions` job, `tag-release.sh` and the
  release's `verify-tag`) also reads `rust/Cargo.toml`'s workspace version
  and `rust/Cargo.lock`'s two entries, so `engine: rust X` in `--version` is
  the release's own version.
- **The npm package runs the native engine, as WebAssembly.** The Rust
  engine the Python package's platform wheels carry (`rust/`,
  `docs/RUST_ENGINE.md`) ships in the npm package as `native/lazaret.wasm`
  (2.1 MB; it imports nothing, and Node's own `WebAssembly` runs it, so the
  package keeps zero dependencies and needs no native addon). It answers
  the supply-chain tests — install scripts and the hooks they run,
  import-time code, received code, the decoded view, spawned scripts,
  persistence, the exfiltration shapes, a hook's command read as a program,
  agent hijacking — and `scan_file`: whole in dependency mode, and in
  project mode its rules part (every pattern rule and family on every line,
  Q-LONGLINE, SC-PIPE-SHELL, the file-level and whole-text rules), to which
  the npm package adds the SQL, taint and function passes, the suppression
  markers and the cap. Same findings: the parity tests hold the engine to
  the Python engine case by case and the WebAssembly build to the native
  library byte for byte, and on real trees the CLI before and after reports
  the same findings in the same order (a `--deps` scan of an installed tree
  of 1,155 dependency files, a 616-file project, an 11.5 MB bundle). With
  the speedups below, on one core, the `--deps` scan takes 5.1 s instead of
  the JavaScript's 7.6 s, the project scan 5.4 s instead of 6.1 s and the
  bundle 8.2 s instead of 11.8 s. `npm run build` makes the module from a
  checkout (Rust and its `wasm32-unknown-unknown` target; the workspace has
  no crates to download); release CI builds it with the platform wheels'
  pinned compiler, runs the npm tests on it, and fails a tarball without it
  or its notice.
- **A file that spends the engine's work budget is SC-TRUNCATED** in the npm
  package (CRITICAL, so it is never cleared: "reading it spent the engine's
  work budget", or "its scan failed" from a dependency check), as a hostile
  file is; the Python package's native engine hands such a call to its
  Python engine instead. No file of the corpora or the benchmark comes near
  the budget. The npm package's per-file time backstop now bounds only the
  passes that stay in JavaScript.
- **The npm CLI refuses to scan without its engine** (a source checkout
  that has not run `npm run build`): exit 2, naming the missing file, where
  every file would have been SC-TRUNCATED. `npm pack` and `npm publish` from
  a checkout check that `native/` holds the engine of the package's version
  and its notice (`prepack`); nothing runs when the package is installed.
- **The npm package's notices** are the engine's: `native/NOTICE` is
  `rust/NOTICE` (the regular expression engine and shell tokenizer
  translated from CPython, the Unicode 13.0 tables), beside `LICENSE-PYTHON`
  and `LICENSE-UNICODE`; `NOTICE` points to it. The license expression is
  unchanged: `Apache-2.0 AND Python-2.0.1 AND Unicode-3.0`.
- **Your own files' rules are the native engine's in the Python package
  too.** With the native engine, the first part of a project file's scan —
  every pattern rule of its language on every line, with Q-LONGLINE and
  SC-PIPE-SHELL, the families, the file-level rules and `TEXT_RULES`
  (`core.scan_rules`) — is the engine's `scan_rules`, read on threads a
  batch at a time; core runs the passes that follow on the engine's
  findings (the SQL statements without WHERE, taint, the SQL-sink pass, the
  function metrics), the suppression markers and the cap
  (`core.scan_file_after_rules`), and scans any file the engine does not
  answer. A project scan reads its own files a batch at a time, as it reads
  dependency files (`should_stop` is checked before each batch). On two
  cores BenchmarkPython (1,230 files) takes 5.2 s instead of 6.6 s and a
  616-file project 14.7 s instead of 18.1 s, with the same findings; most of
  what is left is the taint and flow engines, in Python.
- **The cross-file follower is the native engine's** (`cross_file`,
  `crossfile.rs`, ported from core function for function, with core's
  patterns, limits and finding texts from the rule pack; core's texts moved
  to module values, `_XF_RULE`, `_XF_TAILS` and `_XF_FIXES`). One call reads
  every package of a scan, each on its own work budget, on threads in the
  Python package, and the findings come back in core's order. In the Python
  package (`engine.cross_file_issues`: `--deps`, registry and guard scans) a
  package whose budget is spent, or that meets an internal error, is read
  by the Python engine in its place, and a refused call is answered by it
  whole. The npm package, which had no follower in 0.1.7, runs it as
  WebAssembly; there a package whose budget is spent gives no cross-file
  finding, as a package whose reading raises gives none in core. On one
  core the follower reads an installed npm tree (41 packages) in 0.60 s
  instead of core's 1.86 s (0.38 s on two cores), and litellm's 2,471
  modules, read as one package as a registry scan reads them, in 1.1 s
  instead of 3.1 s; as WebAssembly in 0.91 s and 1.55 s. On the benchmark's
  513 malicious and 434 benign releases, read as `--deps` and as a registry
  scan reads them, the findings are core's.
- **The import-time and install-script tests skip what cannot match** (the
  native engine). They run about sixty patterns over each whole file. A
  search now starts only where its pattern can (the zero-width tests a
  match makes before its first character, a one-character lookbehind, the
  strings every match starts with); a text's pairs and triples of
  characters are read once per call, so a pattern whose strings need one
  the text lacks answers at once (`textgate.rs`); the data flow answers
  early when a file reads no local data; and the scans for literal strings
  (a pattern's required strings and literal prefix, a MULTILINE `^`'s next
  line, core's `in` and `find`) look for the string's rarest character,
  sixteen characters at a time (`pyre/scan.rs`). On one core, over an
  installed npm tree's 1,061 JavaScript files, the import-time test takes
  0.85 s instead of 2.22 s and the install-script test 0.98 s instead of
  2.51 s; over litellm's 2,471 modules the import-time test takes 8.0 s
  instead of 19.3 s. No answer changes: the old and new engines answered the
  two tests, the data flow and `scan_file` identically on 18,370 files (the
  npm tree, litellm, the benchmark's malicious samples).
- **The npm CLI spreads a large scan over worker threads**
  (`js/src/pool.js`): each file's scan and `--deps`' checks of each
  dependency file (the import-time and agent checks, the cross-file
  follower), on workers that each run their own instance of the engine (the
  module compiled once and handed over) with the main thread's settings.
  `run()` stays synchronous, and the answers are taken in the order asked,
  so the findings and their order are the same with any number of threads.
  By default it starts one worker per core, up to 8, for a scan with a
  megabyte or more to read besides its largest file; `LAZARET_THREADS` sets
  how many (`1`: none). A worker that cannot start sends its tasks back to
  the main thread, and a task with no answer for 120 s (a worker that died)
  is run there. On two cores the `--deps` scan of an installed tree takes
  3.5 s instead of 5.1 s.

### Removed
- **The npm package's JavaScript twins of what the engine answers:**
  `js/src/lib/hooks.js`, `received.js`, `shellpipe.js` and the synced
  `received-spec.json`, `js/src/scanner/linear.js`, and the rule loop,
  families and dependency decode flow of `js/src/scanner/scan.js` (with
  `scripts/sync-received-spec.py` and `test_js_parity_hooks.py`). The
  library no longer exports `RULES` and `TEXT_RULES` (the rules live in the
  engine's rule pack); the supply-chain tests it exports are the engine's.

### Fixed
- **A Python package's browser bundle was import-time code to `--deps`** (both
  packages; the detection round). `--deps` gives every JavaScript and Python
  file of a dependency the import-time test, where the registry reads what
  runs; litellm's proxy UI ships a Next.js export whose chunk of guardrail
  test prompts (one shows `curl … | sh`) the test read as code, so a `--deps`
  scan of the litellm wheel was CRITICAL. A dependency's JavaScript file in a
  `_next`, `static` or `public` directory of its package is now left out of
  the import-time test and the cross-file follower unless its npm package's
  entry points reach it — what Node runs for the package, its main, module,
  bin and exports, then the local files they require or import and the
  scripts they start with node — so a main, a bin or an export that points
  into `static/` is still read, and a Python package's browser code never is
  (its Python is). The litellm wheel's `--deps` scan finds nothing there now
  (12.6 s → 10.7 s).
- **A program written in a string literal was read as code that runs what it
  receives** (both engines; 0.1.7 too). A network call named in a
  string's text made the value bound to the string a received one:
  xmlhttprequest 1.8.0 and xmlhttprequest-ssl 2.1.2 — which socket.io's
  client installs through engine.io-client 6 — write a program for `node -e`
  that makes a request and saves the response to a file, and registry scans
  called them SUSPICIOUS ("runs code it receives over the network" at import;
  a CRITICAL SC-IMPORT-RISK with `--deps`), so `lazaret guard` blocked `npm
  install socket.io-client`; truffle's bundled copy was SC-USE-RISK. A literal's text
  is now its own code, read on its own where something in it runs (a program
  for `node -e` that runs what it fetches still is one); a template
  literal's or an f-string's interpolation is still the code around it.
- **uv fetched around the guard from an index in its settings files.** An
  index in `uv.toml` or `pyproject.toml`'s `[tool.uv]` came before the
  guard's local index (0.1.7 set only `UV_DEFAULT_INDEX`, uv's last), so
  `lazaret guard uv pip install` let uv fetch from it directly and install
  what the guard never scanned. The guard's index is now uv's first
  (`UV_INDEX`), relays those indexes itself, and answers an empty page for a
  project none of them has (uv then asks no other); a package uv plans to
  install that the index didn't serve blocks.
- **pip and uv with a private index got PyPI.** The guard relayed PyPI
  whatever pip or uv was set to use, so a package of a private index was
  looked up on PyPI instead — a failed install, or a public package of the
  same name. It now relays the tool's own indexes.
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
