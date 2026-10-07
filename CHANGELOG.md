# Changelog

All notable changes to Lazaret are recorded here. The Python (PyPI) and npm
packages share a version and are released together (see `docs/RELEASING.md`).
This log starts at 0.1.6; for earlier releases see the git history and tags.

The format is based on [Keep a Changelog](https://keepachangelog.com); the
project is pre-1.0, so the 0.x API may still change.

## [Unreleased]

### Added

- **A workflow's actions are read at the commit they run (N-4).** `python -m
  lazaret.registry.actions` now scans each action's own code, the archive the runner fetches for
  the commit its `uses:` resolves to, as the runner runs it: a JavaScript action's `pre`, `main`
  and `post` scripts and the modules they load (the import-time test), a composite action's steps
  and the action's own scripts they run (a path built from `github.action_path`), a Docker
  action's Dockerfile (base images not pinned to a digest, and the script its entrypoint runs, by
  the Dockerfile's COPY lines), and the rest of the repository (the use-time test). Judged as CI
  code: a named token sent to its service, a file uploaded or a package published is not counted;
  a script fetched and run as it arrives is MAJOR, as in a workflow; the whole environment sent, a
  decoded script written and run, a reverse shell are CRITICAL: the tj-actions/changed-files
  release of March 2025 (a script kept in base64 in its `dist/index.js`, written to a file and run)
  is CRITICAL at its commit. Each is a `code` finding with the scan's own rule;
  code not read whole leaves the action incomplete (exit 3). `--no-code` skips it. An official
  Docker image at a version tag is SC-ACTION-DOCKER-UNPINNED MINOR instead of MAJOR.
- **Lazaret's own HTTPS client, the registry's default transport (NET-1).** tiny_https, a TLS 1.3
  and HTTP library written on Rust's standard library alone (no dependencies, Apache-2.0), is in the
  repository (`rust/crates/tiny_https`, taken as it was handed over by `scripts/sync_tiny_https.py`,
  which also takes the next drop and checks the copy against its recorded hashes). Two crates sit on
  it: `lazaret-verify`, its pure part (signatures, certificate chains, transparency logs and
  attestations: no I/O, no `unsafe`, usable by the engine and in WebAssembly), and `lazaret-net`,
  the network layer the native library exports to Python (`lazaret_net_*`). `lazaret-registry`'s
  and the registry modules' requests now go through it: each caller's rule is checked on the first
  URL and on every redirect before anything connects (https only, the caller's hosts, a `*.` host
  being one DNS label on the default port, no credentials in a URL, at most 2,048 printable ASCII
  characters), with the caller's byte budget, timeouts and redirect limit. Connections are kept and
  shared: documents go over HTTP/2 where the server offers it and downloads over HTTP/1.1, as
  measured on the registries (`LAZARET_HTTP=2` or `1.1` picks one for everything). Against the real
  registries, 200 npm documents fetched by 16 threads took 0.6 s instead of 8.3 s, and 100 npm
  tarballs by 8 threads 0.4 s instead of 2.9 s. Trust anchors come from `SSL_CERT_FILE`, then the
  system's CA bundle, then what Python's `ssl` loads (the system store on Windows); the proxy is
  the one urllib would use. Python's urllib takes the request where the native library is missing,
  for a server that offers no TLS 1.3 (from then on for that host), for a proxy reached over TLS,
  and when `LAZARET_NETWORK=python` asks for it. tiny_https has not had an independent review (its
  README says so). The guard's https downloads and relays (any https host on a redirect where the
  guard allows one), the `github:` and `gitlab:` sources and the SCA feeds' downloads go through
  it too, credentials included (decision 14): a private registry's token or login, a URL's own
  `user:password@`, `GITHUB_TOKEN` and `GITLAB_TOKEN` are given hop by hop by tiny_https's hop
  hook, each to its own host (and path prefix) alone, as urllib's redirect hook gave them; the
  URL's own login goes with the request and no redirect. A request that sets `Authorization`,
  `Cookie`, `PRIVATE-TOKEN` or the like as a header is refused by the native layer, so none can
  follow a redirect to another host. A secret being verified stays on urllib, as does plain http to
  a registry on this machine and a credential outside printable ASCII. Building the native library
  now needs Rust 1.87 or later.
- **The Go checksum database's answers are checked as the go command checks them (NET-1).** A
  `go:` module's `h1:` hash comes from `sum.golang.org`'s lookup, and that answer is now verified
  through tiny_https's pure part in the native library: the signature on the database's tree head
  (the key Go pins), the head's agreement with the newest one the run has accepted, and the
  record's place in the tree, proved from the database's tiles (a partial tile the database no
  longer serves is read from the full one, as Go does). An answer that does not check out stops
  the module (fail closed). Without the native library, the lookup is as good as the TLS that
  brought it, as before.
- **npm's and PyPI's provenance as findings (NET-1).** An npm release's attestations
  (`dist.attestations`: npm's publish attestation and SLSA provenance) and each PyPI file's PEP 740
  provenance are verified by the native library against Sigstore's trusted root and npm's keys
  (shipped with the package), with the file's digest, and the release is compared with the one
  before it: SC-PROVENANCE-INVALID (CRITICAL) for an attestation that is not about the file or
  not signed by its signer's key; SC-PROVENANCE-DROPPED (MAJOR) when the release before had
  provenance and this one has none, as with ultralytics 8.3.45 and 8.3.46;
  SC-PROVENANCE-REPO-CHANGED (MAJOR) when it was built from another owner's repository (by the
  repository's and owner's IDs, which a rename keeps; INFO for a repository of the same owner);
  SC-PROVENANCE-UNCHECKED (INFO) for one that could not be checked for a reason that is not the
  file's. On the popular set's 1,205 releases, one is WARN for it (why-is-node-running 3.2.2). The result's `provenance` says who built the release, and the
  terminal shows it. `lazaret-registry` and the MCP tool; not the guard yet.
  `LAZARET_NO_PROVENANCE=1` turns it off; `LAZARET_SIGSTORE_ROOT` and `LAZARET_NPM_KEYS` name
  newer trust.
- **`lazaret guard code --install-extension` (E-1's fifth part), and `code-insiders`, `codium`, `cursor`,
  `windsurf`, `kiro` and `positron`.** The guard takes the version the editor would install, as VS Code
  chooses it (an installed extension left alone unless `--force` or a version is given; else the newest
  release, or with `--pre-release` or `@prerelease` the newest version, that has a file for the editor's
  platform and whose `engines.vscode` takes the editor's VS Code version), and every extension it brings,
  as the editor walks them (its `extensionDependencies` that are not installed, built-in ones counting as
  installed, and its `extensionPack`'s members, each at the version the editor would take, and what those
  bring). Each file comes from the registry the editor installs from (the Marketplace for VS Code, Open VSX
  for the others, each Open VSX file checked against its published SHA-256; `--gallery` chooses), and is
  scanned as `lazaret FILE.vsix` scans it, with `--min-age`, `--trust`, `--allow-new` and `--block-warn`,
  and checked against the editor's gallery's list of malicious extensions (Microsoft's for the
  Marketplace), which the editor does not apply to a file. Nothing is installed when anything is blocked
  (or under `--plan`); otherwise the editor installs exactly those files (with
  `--do-not-include-pack-dependencies` from VS Code 1.98 on; before that, each extension after what it
  brings), and what it then lists as installed is compared with what was checked. A `.vsix` on the
  command line is scanned and installed from the guard's copy. An extension installed from a file is
  pinned by the editor, so it stays at the version checked. The npm package's `lazaret guard`, which points
  to the Python package, now knows every tool the guard wraps (it knew npm, pnpm, pip and uv only, and
  took `lazaret guard cargo build` for a scan of a folder).
- **`lazaret guard code --update-extensions`, and the forks'.** It updates what the editor's own
  `--update-extensions` would update (VS Code's code read for it, MIT), checked and installed as an
  install is: each extension the editor lists that came from its gallery, to the newest version the
  editor would take for it (its newest release, or its newest version when it follows pre-releases),
  with what that version brings that is missing. Which extensions came from the gallery, and which
  follow pre-releases, is what the editor recorded when it installed them (the profile's
  `extensions.json`; with `--profile`, that profile's, found through the editor's `storage.json`, and
  the default's for extensions installed in every profile). The editor asks its gallery by the
  identifier it recorded, so an extension whose name the gallery now gives another (another
  `extensionId`, read from Open VSX's VS Code gallery or the Marketplace) is left alone and said, when
  the guard reads the gallery the editor's `product.json` names. One installed from a file (as the guard
  installs) has no identifier until the editor's window matches it to the gallery by name; the guard
  matches it by name too, so what it installed is updated by it. Under `--min-age` an update younger
  than that is held back and the newest version old enough is taken when it is newer than the one
  installed. Nothing is installed when anything is blocked, or when a lookup fails.
- **VS Code extensions named like a popular one's, and a release that brings a brand-new one (E-1's third
  part).** An extension is named `publisher.name`, and anyone can create a publisher. Its identifier, or
  one it brings (`extensionDependencies`, `extensionPack`), one change from a most-installed extension's of
  another publisher, or its publisher one change from such an extension's publisher, its separators aside,
  is SC-TYPOSQUAT (MAJOR), in `lazaret FILE.vsix`, `--extensions` and the registry's scans:
  `juanbIanco.solidity` (a capital I for the l) cloned `juanblanco.solidity` on Open VSX in 2025, and
  `juan-bianco.solidity-vlang` came next. Another publisher's extension of the same name (a fork, a build)
  is not flagged, nor one of the extension's own publisher. The targets are the Visual Studio Marketplace's
  1,000 most-installed extensions and Open VSX's 1,000 most downloaded, 1,568 in all (`popular_names.json`'s
  `vscode`, from the registries' rankings of Oct 6); `scripts/fetch-top-extensions.py` saves both rankings,
  and `update-popular-names.py --vscode` builds the list from them. No target is one change from another's
  of another publisher, and of 200 extensions sampled from Open VSX's long tail, none is flagged. And a release on Open VSX or the
  Marketplace is compared with the version published before it: an extension it brings that the one
  before did not, first published less than 7 days earlier by another publisher, is SC-NEW-DEPENDENCY
  (CRITICAL; MAJOR under 30 days), the way GlassWorm brought a malicious extension in through benign
  ones' `extensionPack` in 2026 (Open VSX's query API and the Marketplace's gallery query give the
  history; `LAZARET_NO_DEPENDENCY_HISTORY=1` turns it off).
- **VS Code extensions in `lazaret-registry` (E-1's second part): `openvsx:namespace.name[@version]`
  and `vscode:publisher.name[@version]`.** Every `.vsix` the version is published for, one per
  target platform the editor installs, is downloaded and scanned as `lazaret FILE.vsix` scans
  one; the worst platform decides. From Open VSX, each file is first checked against the
  SHA-256 Open VSX publishes beside it (never scanned when it does not match:
  SC-DIGEST-MISMATCH), and the result says whether the namespace is verified and who
  published the version. From the Visual Studio Marketplace, the extension is resolved through
  the gallery query VS Code sends (the latest release, as VS Code installs it, or the version
  asked for), and the result says whether the publisher's domain is verified and how many
  installs it has; the Marketplace publishes no digest, so its files are scanned unverified,
  and the result says that too. Both say what the extension brings and what starts it with
  the editor. The MCP server's `scan_package` takes both specs.
- **VS Code extensions: `lazaret FILE.vsix` and `lazaret --extensions` (E-1's first part).**
  An extension runs in the editor's extension host, Node with all of your access and no
  sandbox. A `.vsix`, or an extension an editor has installed, is now read as the registry
  reads an npm package, with the editor's rules for what runs and when: its `main` and
  `browser` modules and what they load get the import-time test (SC-IMPORT-RISK, which says
  when the editor starts them at every start: `*`, `onStartupFinished`); the rest of its code
  gets the use-time test; `vscode:uninstall`, the one script VS Code runs (`node` and a file,
  once the extension has been uninstalled), gets the install-hook test, and a command VS Code
  would not run is listed only. npm's scripts, a bundled package's scripts and a `binding.gyp`
  never run, so they are not hooks, and only the members VS Code writes into the
  extension's folder are the extension's: every one whose name begins with `extension`, as
  VS Code's zip reader names it. The extensions it brings (`extensionDependencies`, `extensionPack`) are
  listed. `lazaret --extensions` scans what VS Code, VS Code Insiders, VSCodium, Cursor,
  Windsurf, Kiro, Positron, code-server and the VS Code and Cursor servers have installed (and
  the folder `VSCODE_EXTENSIONS` names), or the folders and `.vsix` files given; an installed
  extension's folder reads as its `.vsix` does, and a link out of it is not followed
  (INCOMPLETE). `--ci`, `--json`, `--quiet`. `scripts/bench.py` takes `vsix` releases. The
  npm package does not scan extensions yet.
- **For contributors: the Go and Rust benign sets (N-2).** The release gate's popular set
  holds the 500 most-downloaded crates too (498: two are under licences it does not take),
  pinned by version and sha256 as its npm and PyPI releases are, and
  `scripts/popular/packaged.py` packs the Go modules and crates Ubuntu 24.04 packages (1,953
  and 2,151, licence-checked) and Go's own `std`, `cmd` and vendored modules, each as its
  registry serves it, for `scripts/bench.py`. None is SUSPICIOUS, and every WARN is read
  (`docs/TESTING.md` §4). The Go and Rust malicious set is run offline.
- **For contributors: the extensions' benign set (E-1's fourth part).**
  `scripts/popular/popular.py` pins VS Code extensions from Open VSX too (`pin --top
  0,0,0,N`): each one's newest release with a file for Linux x86-64, by the SHA-256 Open VSX
  publishes and only under the licences the crates are taken under. `--top` now pins anew
  only the ecosystems it is given a count for, and a redirect is followed only to https on
  a registry's own host (`docs/TESTING.md` §4).
- **Credentials in Go's and Rust's declarations, crates.io's tokens and a `.netrc`'s
  passwords (G-4, R-4, N-12).** S-SECRET read `name = "…"` and `name: "…"`, so Go's
  `apiKey := "…"` and `var password string = "…"` and Rust's `const API_KEY: &str = "…"`,
  `static SECRET: &'static str = "…"` and `b"…"`/`r#"…"#` literals went unreported; they are
  reported now, and so is a Python `b"…"`, `r"…"` or `rb"…"` literal given a credential's
  name, which S-SECRET skipped too (TypeScript's `apiKey: string = "…"` and Python's
  `password: str = "…"` annotations are still not read). crates.io's API tokens (`cio` and 32 letters and digits, a whole run: a `cio`
  inside base64 is chance) are S-TOKEN, in code and in config files such as
  `~/.cargo/credentials.toml`, and are redacted wherever a snippet would show one. A
  `.netrc`'s (or `_netrc`'s) password tokens, `machine HOST login USER password PASS` with
  blanks between them, are S-SECRET when the value looks like a credential, and never shown.
  The npm package and the dashboard read them the same way. Rule set 2.33.0.
- **Crate names like a popular crate's, and a crate release's brand-new dependencies (N-3's
  second part).** A crate's name, or a crate its `Cargo.toml` depends on to build (its
  `[dependencies]` and `[build-dependencies]`, per target too; not `[dev-dependencies]`,
  never built for a user), one change from one of the 5,000 crates crates.io counts the
  most downloads of in 90 days is SC-TYPOSQUAT (MAJOR), as npm's and PyPI's names are:
  `proc-macro1` for `proc-macro2`, `rustdecimal` for `rust_decimal` (2022's CrateDepression
  squat), `reqwset` for `reqwest`. Names are folded as crates.io folds them (case, and `_`
  as `-`), so `serde_json` and `serde-json` are one name. The crates the lists know are
  never flagged: the 20,000 with the most recent downloads, the 20,000 with the most
  downloads of all time and the crates Debian packages. A `crates:` scan also compares the
  release with the version crates.io published before it, from the sparse index alone (its
  lines are in publishing order, each with its `pubtime`): a crate it adds as a normal or
  build dependency, first published less than 7 days before the release, is
  SC-NEW-DEPENDENCY (CRITICAL; MAJOR under 30 days), unless an owner of the release's crate
  owns it too (crates.io's API, one request a second, as its crawler policy asks; when the
  API doesn't answer, the finding names no owner). The list comes from crates.io's API
  (`scripts/fetch-top-crates.py`, names only) and Ubuntu 24.04's source package indices;
  `scripts/update-popular-names.py --crates` rebuilds it. **Measured** before each set was
  added to the known names: Ubuntu's 2,317 packaged crates (8,186 dependencies) gave 7
  findings; the crates ranked 15,001 to 20,000 by recent downloads, 84 of 5,000; the 3,366
  of the all-time 20,000 outside the recent 20,000, 75 (21 of them gitoxide's renamed
  `git-*` crates); the 2,000 newest crates (Oct 3 to 6, 2026), 9. The API pages no further
  than 20,000 crates, so the long tail past both lists is unmeasured.
- **A crate's Rust code is read for what it does (R-1, first part).** The engine had no
  Rust detectors, so a crate's `.rs` code was never read and `lazaret guard cargo` and the
  registry marked a crate INCOMPLETE. The engine now reads it, with the test that Python's
  and JavaScript's code of the same moment gets: a build script and a procedural-macro
  crate run on the machine that builds a dependent, so they get the install-script test,
  every reason CRITICAL (`setup.py`'s analog); `#[ctor]`/`#[dtor]`, a `.init_array`-like
  section, a `#[no_mangle] extern "C" fn main` and `#![no_main]` run before a binary's
  `main`, so they get the import-time test; the rest runs when the crate is used, so it
  gets the import-time test of which only the shapes no library needs count (SC-USE-RISK).
  The reader evaluates the code rather than matching patterns over it: it follows the
  crate's own functions, closures and methods and the strings they build (`format!`,
  `concat!`, `+`, a constant, base64 or hex decoded, a byte slice read as UTF-8), and
  records a process started (`std::process::Command`, read as a shell reads its line, with
  `sh -c`/`cmd /c`/`powershell -Command` scripts pulled out), data sent (`std::net`,
  reqwest, ureq, minreq, attohttpc, curl, raw sockets), a file written and then run or
  loaded (`libloading`), and a name looked up (`ToSocketAddrs`, hickory/trust-dns, TXT
  records included — the DNS-backdoor shape). `tests/`, `benches/` and `examples/` are
  not read (a dependent never builds them). This is the engine side (`rs_crate`); nothing
  calls it yet, so no scan's verdict changes. The install-script and import-time tests take
  a crate's reading only when one is given, so Python's and JavaScript's answers are
  unchanged (the benchmark and the popular set are identical). The Go reader and the
  registry and guard wiring that clears the INCOMPLETE verdict follow. Before the Go
  reader was built on it, the reader was reviewed line by line (Oct 4): input that made it
  recurse without a bound (a chain of assignments, of `else if`s, of operators or of
  method calls, a nested pattern or function type) stops at its bounds instead of
  overflowing the stack, and its events and the text it copies are bounded; a build
  script's payload many calls deep, or behind code that spends the reading's steps, is
  read (every function of a build script or a procedural-macro crate is read, so is every
  function a start-up function calls however deep, and a reading cut short is read by the
  text test as well); `.unwrap()` on a response keeps the response; code under
  `#[cfg(all(…, test))]` is a test's; and the reverse-shell and DNS-lookup signs ask what
  the text detectors ask (a shell or an interpreter; a name built with a public domain).

- **A Go module's code is read for what it does (G-1, first part).** Go runs nothing at
  install, but a package's `init` functions and the initializers of its package-level
  variables run when any program that imports it starts, and a cgo preamble's C with a
  constructor runs then too: the engine now reads that code with the import-time test
  (SC-IMPORT-RISK), and the rest of a module's code, a command's `main` included, with the
  test of which only the strong reasons count (SC-USE-RISK). As the Rust reader does, it
  evaluates the code rather than matching patterns: it follows a package's functions,
  methods and closures across its files and into the module's other packages, every
  function init code reaches by name however deep, and the strings the code builds (`+`,
  `fmt.Sprintf`, `strings.Join`, a string array read by index, byte slices, base64 and hex,
  a loop that decodes a byte slice), and records the processes started, the data sent, the
  DNS lookups (TXT records too), the files written and run, and the plugins and DLLs
  loaded. The documented techniques are found on inert samples: the 2025 typosquats'
  `wget -O - … | /bin/bash &` built from a string array, and their Windows variant; a DNS
  TXT record's command run by an init goroutine; a base64 command; a download written,
  made executable and run; a fetched wiper script run; a reverse shell; a cgo constructor;
  credentials and the whole environment sent. Go's standard library and the modules it
  vendors give no finding. `//go:generate` and `//go:linkname` are listed, not judged; test
  files, `testdata/`, `vendor/` and files built only for `ignore` are not read. This is the
  engine side (`go_package`); nothing calls it yet, so no scan's verdict changes. A shell's
  or cmd's script is now read command by command by both readers, so a file one command
  writes and the next runs is seen.
- **Look-alike Go module paths (N-3, Go).** A Go module's own path, or one its `go.mod`
  requires, like a well-known module's is SC-TYPOSQUAT (MAJOR), as an npm or PyPI name is:
  its owner one character from that module's owner (`github.com/shopsprint/decimal` for
  `github.com/shopspring/decimal`), with its separators changed, or with a word like
  `-go` added (`github.com/boltdb-go/bolt` for `github.com/boltdb/bolt`),
  the repository the same; its host one character from the module's, the rest the same;
  a gopkg.in name one character from one (`gopkg.in/yanl.v3`). Anyone can create an owner
  on GitHub, and only its owner can add a repository to it, so the owner is where a
  squatter differs. The well-known modules are the 4,893 that awesome-go lists (MIT) or
  Debian packages (the `Go-Import-Path` of Ubuntu 24.04's indices, which carry Debian's Go
  packages), compared lower-cased and without a major version: no registry publishes Go
  downloads. An owner or host of one of them is never a look-alike, nor is a module of the
  module's own owner, nor a two- or three-character owner with a repository shorter than
  five (`lib/pq`); another owner's module of the same name is a fork, not flagged. Of the
  4,893, two would be flagged without themselves (`pions/webrtc`, pion's old name, and
  `gopkg.in/macaron.v1`, next to `macaroon.v1`); Go's own `go.mod` files and the modules it
  vendors give none. The guard and the registry read the `go.mod` in a module zip's root;
  `scripts/update-popular-names.py --go` rebuilds the list from local copies of its
  sources.
- **A Go module's and a crate's code is read where they are scanned (Part C, rule set 2.31.0).**
  `lazaret guard go`, `lazaret guard cargo` and the registry's scans of a module zip or a
  `.crate` hand its code to the engine's Go and Rust readers (above), and a module or a
  crate is OK, WARN or SUSPICIOUS for what that code does: it was INCOMPLETE whatever it
  held (SC-UNREAD-CODE, N-1), and passed by default. What a Go package's `init`
  functions, package-level initializers and cgo constructors reach is SC-IMPORT-RISK; a
  crate's build script and a procedural macro are SC-INSTALL-HOOK, CRITICAL, and a
  `#[ctor]` SC-IMPORT-RISK; the strong reasons of the rest are SC-USE-RISK, read within
  the same 24,000,000 characters as a package's JavaScript and Python. `//go:generate`
  commands are listed (SC-GO-GENERATE, INFO). Every `.go` and `.rs` file gets the file
  rules too, except test code no build of a dependent compiles (`*_test.go`, `testdata/`,
  `vendor/`, a file named with `_` or `.` first; `tests/`, `benches/`, `examples/`), which
  is not read at all: rivo/uniseg's line-break tests hold escaped URLs. A `.go` or `.rs` file
  over `--max-source-bytes` makes the scan INCOMPLETE, and a module's cgo C files are kept
  for the reader outside the text budget other files share. A module or a crate
  over 300 million characters is INCOMPLETE: a reader holds all of it at once, and the call
  now takes its text without copying each file (aws-sdk-go v1's 207 million characters
  peak at 2.4 GB, from 3.0 GB). On Ubuntu 24.04's packaged Go modules and crates whose
  licences allow reading them (1,953 and 2,120), none is SUSPICIOUS; 39 and 30 are WARN,
  for base64 and hex constants, test vectors outside test folders, archives and binaries,
  every one read; 2 are INCOMPLETE (Debian packs aws-sdk-go-v2's and azure-sdk-for-go's
  modules as one tree). The npm and PyPI scans are unchanged.
- **`lazaret-registry scan go:<module>[@version]` and `crates:<name>[@version]` (Part C).**
  `add`, `scan`, `scan-all`, `report` and the MCP server's `scan_package` take Go modules
  and crates as they take npm and PyPI packages. The registry modules resolve them (the
  module proxy's `@latest` or `.info`; crates.io's sparse index, latest being the highest
  version that is not yanked) and check the download before anything is scanned: a Go
  module zip against the `h1:` hash the Go checksum database publishes, a `.crate` against
  the SHA-256 its index lists, failing closed with SC-DIGEST-MISMATCH. Their fetches go
  only to the module's own hosts (`proxy.golang.org`, `sum.golang.org`; `index.crates.io`,
  `static.crates.io`), redirects included, through the registry's bounded, timed fetch.
  `repo.SpecError`, `FetchError`, `DigestError` and `Resolution` are now the registry
  modules' classes (X-2's first step). No `discover` and no SC-NEW-DEPENDENCY for them yet.
- **`--deps` reads a Go `vendor/` and a `cargo vendor` tree (Part C).** A vendor directory
  with a `modules.txt` (`go mod vendor`) holds the Go modules a build compiles, and one whose
  crate directories hold a `.cargo-checksum.json` (`cargo vendor`) the crates; a `--deps`
  scan, in both packages, reads them as the registry reads a module zip and a `.crate`: the
  file rules on each `.go` and `.rs` file a build compiles, the engine's Go reader on each
  module `vendor/modules.txt` lists (a file of none, with its package's directory, cgo's C
  files included) and its Rust reader on each crate. What a Go package's `init` code
  reaches is SC-IMPORT-RISK, a build script and a procedural macro SC-INSTALL-HOOK
  (CRITICAL), the strong reasons of the rest SC-USE-RISK. A crate's `Cargo.toml` is read
  by the engine (`cargo_layout`: TOML's tables, keys, strings and arrays, so a description
  holding `[lib]` is not read as one), the same answer as the registry's reading on all
  2,122 of Ubuntu's licence-checked crates. A `cargo vendor` tree is a dependency tree now:
  without `--deps` it is pruned, as `node_modules` is, where it was read as the project's
  own code.
- **The Rust crate inside a PyPI sdist is read (Part C, N-17).** A maturin or
  setuptools-rust sdist ships its crate (or a workspace of crates), and pip has cargo build
  it when it installs the sdist: each directory of the sdist with a `Cargo.toml` is a crate,
  a `.rs` file belongs to the nearest one above it, and each crate is read as a `.crate` is
  (the file rules on every `.rs` file it builds; the Rust reader on the crate). Its build
  script and procedural macros are SC-INSTALL-HOOK, CRITICAL, as `setup.py`'s code; a
  `#[ctor]` runs when the extension module is loaded (SC-IMPORT-RISK); the strong reasons of
  the rest are SC-USE-RISK, the sdist's crates sharing one use-time share. A crate's file
  that could not be kept makes the sdist INCOMPLETE. Of 72 popular PyPI sdists with a crate
  (permissive licences only), two more are WARN (a table of 200 digits; hex test vectors in
  `#[test]` functions) and none SUSPICIOUS for its Rust; their scans took 28 s instead of 11.
- **Where a run's time goes: `--timings`.** `lazaret-registry` and `lazaret guard` print on
  stderr the seconds spent in the network, reading archives, the engine (by call: the
  file scan, the import-time test, the cross-file follower, …), the package manager (the
  guard) and the rest of the Python, with the calls each took; the guard puts the same
  report in its `--json`. A scan with no `--timings` records nothing.
- **The commit-time gate: `lazaret hook`.** It checks the files being committed, as they
  are staged (read from git's index, so a partly staged file is checked as it will be
  committed), with the project scan's rules, and fails on `--ci`'s security and
  supply-chain conditions: no BLOCKER finding, no CRITICAL vulnerability, no supply-chain
  indicator, no cross-file taint flow. Duplication and maintainability are not a
  commit's business. With no file named it checks the staged files; pre-commit passes
  the files being committed. A credential in a `.env`, an install hook that pipes a
  download into a shell, or a workflow that sends out every repository secret stops
  the commit. pre-commit runs it from a mirror repository,
  github.com/lazaret-dev/lazaret-pre-commit, whose package pins the release, written
  by `scripts/make_pre_commit_mirror.py` (`docs/RELEASING.md`). The npm package
  points to the Python package for it.
- **Commands written to a shell's startup file.** An install hook's command, or a script
  it runs or starts, that writes a command that downloads or runs code (`curl … | sh`,
  `nohup node …/agent.js &`) to `~/.bashrc`, `~/.zshrc`, `~/.profile`, fish's
  `config.fish` or another shell's startup file, through the file API or the shell's
  `>>` and `tee -a`, gets SC-INSTALL-HOOK CRITICAL: "adds a command to a shell's startup
  file (.bashrc)". Every line there runs at every shell start. So does any command
  written to a startup file the script names only in strings it decodes as it runs
  (alinet 1.2.0 puts its own command first in the one its `$SHELL` reads). A variable,
  an alias or a completion is not judged: CLIs add those, and @asyncapi/cli's
  `postinstall` appends its completion script to the `.zshrc`.
- **What three of the benchmark's misses showed.**
  - The `request` client and its forks (`@cypress/request`, `postman-request`):
    `request(options, cb)`, `request.get(url, cb)`, `.post`, `.put`, `.patch`, `.del`
    and a client made with `request.defaults()` send and fetch as `axios` and `fetch`
    do, and what their callbacks are given is received (react-svg-helper-fast 1.0.0
    runs the code its server returns).
  - A parameter whose default is the script's own address (`function load(opts =
    options)`) is that address when the caller gives none. A default the caller's
    values make is still the caller's.
  - A member named by a constant (`x[N]` with `const N = 'post'`, a comma
    expression's last value included) and `require()` of a constant name are read by
    that name (react-zutils 1.0.1, once its XOR-hidden strings are decoded).

  On the benchmark, 452 of 516 malicious releases are SUSPICIOUS, up from 449: alinet,
  react-svg-helper-fast and react-zutils. The popular packages and the popular releases
  are unchanged.
- **A project's Go and Rust files are read.** `.go` and `.rs` files were classified by
  their bytes, as any data file is, so a Go or Rust repository scanned as "0 files" and
  passed whatever it held. Both packages now read them, with comments and strings as
  each language reads them (Rust's nested block comments, raw strings in both, a
  lifetime not a character): hardcoded credentials (S-SECRET, outside comments; it reads
  `name = "…"` and `name: "…"`, not yet Go's `:=` or Rust's typed constants), token
  formats (S-TOKEN, in comments too), Trojan Source characters (S-BIDI), TODO markers,
  and the checks every text gets (hex-escaped text, invisible characters, base64 blobs,
  high-entropy literals, long lines). The suppression markers work in their `//`
  comments. The MCP server's `scan_files` takes them too. Not read yet: a package's Go
  and Rust files (registry and guard scans) and a dependency tree's (`--deps`), until
  the engine has its Go and Rust detectors. Their lines count in the metrics, but the
  duplication measure is for Python, JavaScript and SQL: the gate's 10% was set on
  those, and with its six-line windows Go's standard library measures 2 to 13% and
  twenty popular crates 4 to 54%. On those crates and Go's standard library the scan
  reports test keys and vectors, base64 test data and TODO markers.
- **CI files' hardening, in project scans.** A project's GitHub Actions workflows get six
  checks: an action, reusable workflow or image not pinned to a commit or a digest
  (SC-WORKFLOW-UNPINNED), a `pull_request_target` job that checks out the pull request's
  code (SC-WORKFLOW-PR-CHECKOUT), a build cache in a release workflow (SC-WORKFLOW-CACHE),
  write permissions for every job or none set (SC-WORKFLOW-PERMISSIONS), a job that can
  request an OIDC token and installs dependencies (SC-WORKFLOW-OIDC-INSTALL), and
  `curl … | sh` (SC-WORKFLOW-PIPE-SHELL). Its GitLab CI files (`.gitlab-ci.yml`,
  `*.gitlab-ci.yml`, a `.yml` under `.gitlab/`) get five: remote, project and component
  includes not pinned (SC-GITLAB-INCLUDE), images without a digest (SC-GITLAB-IMAGE),
  `curl … | sh` (SC-GITLAB-PIPE-SHELL), a merge request's text run as code
  (SC-GITLAB-MR-TEXT), and a job with a publishing credential that installs
  dependencies (SC-GITLAB-TOKEN-INSTALL). Both packages report them, as security
  hotspots. Only a CRITICAL one fails the gate's supply-chain condition: a pull request's
  code checked out by `pull_request_target`, or a file included over plain http.
- **A repository at a commit: `lazaret scan github:owner/repo[@ref]` and
  `gitlab:group/project[@ref]`.** The ref (a branch, a tag or a commit; none means the
  default branch) is resolved to a commit, that commit's archive is read into a temporary
  directory and scanned with every option a folder's scan takes, and the directory is
  removed. The report names the commit: its `project` is `github:owner/repo@<sha>`, a
  `source` block says what was read and what was not, the report files are named for it
  and written to the current directory, and a SARIF report maps its root to the
  repository at that commit (`versionControlProvenance`). Paths the archive leaves out
  (`export-ignore` in `.gitattributes`, where many repositories put their tests and
  `.github/`) are fetched one by one, each written only if it is the blob the commit's
  tree names. A checkout not read whole is said after the report and marks the result
  `incomplete`; with `--ci` it exits 1 even when the gate passed, unless
  `--accept-incomplete`. `GITHUB_TOKEN` and `GITLAB_TOKEN` (read-only) go to the API host
  only, and `LAZARET_GITLAB_URL` names a GitLab instance. Python package only.
- **`lazaret guard go` and `lazaret guard cargo`.** The install guard for Go modules (`go
  get`, `install`, `build`, `run`, `test`, `vet`, `list`, `mod download`, `mod tidy`) and
  Cargo crates (`add`, `update`, `generate-lockfile`, `install`, `fetch`, `build`,
  `check`, `test`, `run` and the rest that fetch). For Go, the guard runs a module proxy
  on the machine for the one command, relays the proxies `GOPROXY` lists as the go
  command does, and scans each module zip before the tool gets it; go still checks
  `go.sum` and the checksum database, so what it accepts is what was scanned. For Cargo,
  it resolves first, checks every crates.io crate in `Cargo.lock` against the lock's
  checksum and scans it, and only then lets cargo fetch and build. Both take `--min-age`,
  `--plan` and `--json`, put `go.mod`, `go.sum`, `Cargo.toml` and `Cargo.lock` back when
  anything is blocked, and list what they could not check (a module go fetches straight
  from its repository through `GOPRIVATE`, a crate from git or from a registry the guard
  cannot read).
- **A Go module or a crate is never OK while its code is not read.** Lazaret has no Go
  or Rust detectors yet: `lazaret guard go` and `lazaret guard cargo` check a module's or
  a crate's checksum, age and archive, and read its other files, but not what its `.go`
  or `.rs` code does when it is built or used (init functions, package initializers and
  cgo; a build script and procedural macros). Such a module or crate is INCOMPLETE, with
  one SC-UNREAD-CODE finding that says how many files were not read, rather than OK. Test
  code the build never compiles does not count (`*_test.go`, `testdata/`; a crate's
  `tests/`, `benches/` and `examples/`). INCOMPLETE does not block an install unless
  `--block-warn` is given; a strong finding still makes it SUSPICIOUS. npm and PyPI
  releases are unchanged.
- **Dependency scanning reads Go and Rust.** `lazaret-sca` inventories `go.mod` (with its
  `replace` lines), `go.sum` for a module older than Go 1.17, `vendor/modules.txt`,
  `Cargo.lock` and `Cargo.toml`, matched against OSV's `Go` and `crates.io` advisories
  (`GO-`, `RUSTSEC-`), which `--update-bundle` now downloads. A bundle that does not carry
  them (`osv:go`, `osv:crates`) fails the gate for a project that has Go or Rust
  dependencies rather than reporting none. The standard library, the toolchain and
  RustSec's `unmaintained` and `notice` advisories are not matched.
- **An indexed CVE bundle.** `lazaret-sca --update-bundle --bundle-format index --bundle
  cve-bundle.lzx` writes a file a scan reads only the parts of that it needs. On a
  synthetic bundle the size of OSV's (120,000 advisories), opening it and matching 2,000
  dependencies takes 0.2 s and 42 MB instead of 6.9 s and 640 MB, with the same matches in
  the same order. `--bundle` takes either kind. Every part of the file is checked (its
  length, checksums, layout and order), and a damaged one is exit 4, also when the damage
  is found in the middle of matching. The JSON bundle stays the default.
- **`lazaret guard --from-plan pip install …`.** Once pip's plan has been scanned, pip
  installs the very files that were scanned, from a folder (`--no-index --find-links`),
  instead of resolving and downloading again; each file is hashed again just before pip
  runs and must be the one scanned. A plan with an sdist or a file too large to scan goes
  through the guard's index as before, with a line saying why. On `requests`, `boto3` and
  `pydantic` the guarded install took 13.5 s instead of 19.2 s (pip alone: 6.1 s).
  Opt-in.
- **`lazaret guard --keepalive`** (experimental): the guard's own requests reuse their
  connections instead of opening a connection and a TLS session for each; redirects and
  credentials follow the guard's rules as before. Off by default until it is measured on
  a direct network: with `--timings`, the network lines count the connections made and
  reused.
- **What a workflow's actions point to, checked online.** `python -m
  lazaret.registry.actions WORKFLOW…` asks GitHub about each `uses:`: a pin that is in no
  branch and at no tag of its repository, such as a fork's commit (SC-ACTION-IMPOSTOR); a
  version tag that moved since it was first seen (SC-ACTION-TAG-MOVED; what was seen is
  kept in `~/.cache/lazaret/actions-pins.json`); a tag off the branches
  (SC-ACTION-OFF-BRANCH); a pin whose `# v1.2.3` comment names another commit
  (SC-ACTION-PIN-MISMATCH); and, in the action's own `action.yml`, a Docker image without
  a digest or composite steps not pinned (SC-ACTION-DOCKER-UNPINNED,
  SC-ACTION-NESTED-UNPINNED). What it could not ask (GitHub's limit of 60 requests an hour
  without `GITHUB_TOKEN`, a private repository) is reported as not checked. A project
  scan does not run it.
- **For contributors: Go and Rust readers in the engine, and the tools that hold them to
  Go and rustc.** A Go parser (`goparse`), a port of `go/parser` that builds the same tree
  as Go's own for the Go distribution's 10,368 files and about 430,000 mutants of them
  (nesting is limited to 256, so one file of the distribution is refused), and a Rust item
  reader (`rsparse`) that finds exactly the items `rustc` finds in the 7,468 files of 186
  published crates. With them, the code that runs
  without being called: `init` functions, package-variable initializers, cgo preambles,
  `//go:linkname` and `//go:generate`; procedural macros, `#[ctor]` and `#[dtor]`,
  load-time sections, a crate's entry point, a build script's `main`. Nothing uses them
  yet: they are what the Go and Rust detectors will read. `scripts/goparse`,
  `scripts/gooracle` and `scripts/rsparse` are the differential tools; `scripts/fuzz`
  fuzzes the readers of untrusted input (34 targets: archives, XML, lockfiles, the
  registry modules, the CVE bundle; weekly in `fuzz.yml`), and `scripts/profile` holds
  the profile's scripts and a nightly check of the engine's time on eight pinned packages
  (`perf.yml`; its budgets are set after a week of runs).

### Changed

- **Code received over the network and run out of sight says so too (GR-8's follow-up; rule set 2.44.0).**
  In Go and Rust code, a shell or a program handed what a server sent and started with its window hidden,
  no console or its output sent to null: "runs code it receives over the network, out of sight (no window,
  or its output thrown away)". The reason's strength, and so every verdict, is as before.
- **A program downloaded or decoded, then run out of sight, says so (GR-8; rule set 2.40.0).** The Go and
  Rust readers note a process started with its window hidden or no console (`SysProcAttr.HideWindow`,
  `CreationFlags` or Rust's `creation_flags` with `CREATE_NO_WINDOW` or `DETACHED_PROCESS`) or with its
  output sent to null, and no reason used it. A file written and then run now says it: "downloads a file
  and then runs it, out of sight (no window, or its output thrown away)", as evm-units' per-OS payload was
  run in 2025. The reason's strength, and so every verdict, is as before.
- **SC-B64 passes over files kept as data, and a shell reads what it decodes (N-4; rule set 2.39.0).** A
  quoted base64 run that decodes to a whole WebAssembly module, a PNG, GIF or WebP image or a WAV
  sound, read by the format's structure to its end (a module's sections in order with a code section,
  an image's chunks or blocks, RIFF chunks; what a format carries beside its content at most half of
  it), is data, not a payload: undici's HTTP parser, which every JavaScript action bundling the
  Actions toolkit carries, es-module-lexer's and vite's WebAssembly, nltk's icons. A payload with a
  format's header in front of it is still SC-B64. On the popular set, @vitest/mocker, es-module-lexer,
  loader-utils, tsx and nltk go from WARN to OK. The dashboard's twin reads them the same way. And a
  shell text, a hook's command or a command line code hands a shell now says what it does when a
  pipeline decodes code and hands it to a shell or an interpreter (`echo … | base64 -d | bash`,
  `xxd -r -p | sh`, `bash -c "$(… | base64 -d)"`: "pipes code it decodes into bash", a strong reason,
  so CRITICAL in an install hook and at import time), and when a download is piped into an
  interpreter that reads its script on stdin (`curl … | sudo python3`: "downloads a script and runs
  it with python3"); the shell parser reads both through quotes and filters, where the old pattern
  stopped at a `;` inside quotes. The reviewdog/action-setup release of March 2025 (its install.sh
  decoded a script and piped it into bash) is CRITICAL at its commit.

- **The guard scans in worker processes, with limits.** Every scan runs in a worker,
  `--jobs 1` included, never in the process that downloads and talks to the package
  manager. The archive goes to the worker as a file (mode 0600) and is hashed again
  there; each worker has an address-space limit (`--worker-memory MB`, default 6144, on
  Linux) and its share of the cores, and a CPU-time limit backs the scan's own deadline. A
  worker that dies has the archives it held run again, each alone; one that kills its
  worker again blocks its package as not checked (`--trust` lets it through). With
  `--jobs 1`, six large archives took the guard's own peak memory from 2.15 GB to 0.22 GB
  in the same time. `--no-isolate` scans in the guard's process, for a platform where
  workers cannot start; the guard falls back to that by itself, and says so, when none
  can.
- **A release's files share the engine's answers.** A registry scan asks the engine once
  about content several of a release's files hold (a wheel per platform, the sdist with
  the same modules): a file's first pass, the import-time and use-time tests, the
  scripts a script starts and the cross-file follower. A hit is the engine's own
  answer, rebuilt for the member's path, so the findings and the verdict are the same;
  an answer the engine could not finish is never kept. litellm 1.104.0 (an sdist and
  seven wheels, 21,709 source files) scans in 21 s instead of 61 s on two cores, its
  engine time from 50 s to 8.5 s. `LAZARET_NO_CACHE=1` turns it off. The guard scans
  one archive at a time and keeps no memo.
- **The import-time test is faster.** Its supply-chain model parsed each Python file
  twice, once for the names that hold outside paths and once for the flow, and now
  parses it once. Its tables of names answer most names without a comparison. A call's
  text is lexed once, however many of its tests read the tokens. A list of strings to
  find is scanned at its rarest characters. A search over a long text goes to the places
  where its strings' character pairs stand, listed once per call, instead of scanning the
  text again; on a bundle the scans had read it some 40 to 60 times. A search whose
  matches all start with one of a few strings looks for them even where their
  characters are common (each place is checked for a whole string before the matcher
  tries it), one that could only look for a common first character runs its automaton
  over the text instead of trying each place, and the automaton reads two characters a
  round. On litellm's `proxy_server.py` (0.82 MB) the test runs 36% fewer instructions,
  and on playwright-core's bundles (3 to 3.5 MB, each read after the other) 47% to 48%
  fewer, with the same answers.
- **SC-USE-RISK reads the same files on every machine.** Registry and guard scans read a
  package's code that runs only when it is used, smallest files first, for at most 3
  seconds per release file: a slower machine read less, and nothing said so. The bound
  is now 24,000,000 characters per release file, which reads what 3 seconds read on two
  cores at the same cost. A registry scan's result carries what was read (`useTime`:
  files and characters, of how many, and the bound), in the JSON, the MCP server's answer
  and a line of the summary when code was left unread (next 16.3.8: 32% of 74 million
  characters).
- **Every pattern runs in linear time.** linre, the engine's linear-time regex engine,
  ran 616 of the rules' patterns in 0.1.8, and the port of CPython's backtracking
  matcher the rest. It now runs every one of them, and every pattern the engine builds
  as it scans, so no text can make a rule's pattern backtrack; a pattern it would not
  run fails the tests. It runs lookaheads of any width (`(?!\s*\()`, the rest of an
  argument list or a string), remembering what each one's walks found in a text, and a
  backreference to a quote (`(["'])…\1`) as one branch per quote. A pattern that named
  something twice (a loop's variable, a comprehension's, a string array accessor's
  parameter) or counted further than a program holds (64 strings in a constant array,
  a decoder call's 20,000 arguments) is written without it, and the engine checks the
  match instead. Two read further than before: SC-EVAL-DECODER reads a decoder's whole
  body (it stopped after 2,000 items), and a write to a shell's startup file reads
  `open()`'s arguments up to the mode however many there are (it stopped after 300).
  The other rewritten patterns answer as before: on the benchmark's 945 releases and
  the 1,205 popular ones, every verdict and every finding is the same. Scans take as
  long as before (the engine's five main calls on 1,500 installed files: 8.1 s, against
  8.2 s), and playwright-core's two bundles 4% to 6% fewer instructions. The port of
  CPython's backtracking matcher is retired, and with it the SRE library's notices in the
  engine's license files (which left any use beyond CNRI's Python 1.6 license to Secret
  Labs AB). A taint configuration's patterns must be ones linre runs: `--taint-config`
  rejects one it does not (a conditional, an atomic group or a possessive repeat, a
  repeat of what can match the empty string, a `\N{…}` escape), with the reason, as it
  already rejected patterns that could backtrack. The registry's rule set is 2.28.0, so
  stored verdicts are scanned again.
- **The native engine is Lazaret's own work.** Its last translations of CPython code are
  retired: the reading of a hook command's words is written from shlex's documentation
  and held to Python's shlex (on the hooks corpus and 30,000 random commands), the
  final-sigma rule of `str.lower()` follows the Unicode Standard's definition, and `re`'s
  extra case equivalences are derived from Unicode's case mappings. Every answer is the
  same. The engine's notice says what was CPython's. Its crates, the wheels, the sdist and
  the npm package are `Apache-2.0 AND Unicode-3.0`, and none carries CPython's license
  (`LICENSE-PYTHON`) any more: the codec names the npm package and the dashboard list, to
  read a coding cookie as Python does, are what Python's codecs answer to, facts about
  Python rather than CPython's code.

### Fixed

- **A `.vsix` is read by the names VS Code extracts, and a zip by the names its installer reads (the
  review of Oct 7; rule set 2.41.0).** VS Code writes every entry of a `.vsix` whose name begins with
  `extension` into the extension's folder, a `/` after it or not, so `extensionout/extension.js` is
  installed as `out/extension.js`; Lazaret read only `extension/…`, and an extension that hid the file
  its manifest starts that way scanned OK with the file unread. And VS Code's zip reader, like zipfile
  from Python 3.12 (so pip there), takes an entry's name from its Info-ZIP Unicode Path field when the
  field's checksum matches the header's name, which Lazaret on Python 3.10 and 3.11 did not read: an
  entry could be scanned as `notes.txt` and installed as `x.pth` or as the extension's main file. Every
  `.vsix` and zip entry is now read under the names its installer uses (both of a wheel's when pip's
  versions differ), the same on every Python; a name that begins with `extension` and no `/`, and an
  entry with two names, are SC-ARCHIVE-PATH (MAJOR); an archive zipfile from Python 3.12 refuses over a
  bad field is INCOMPLETE; and `lazaret guard code` reads the manifest the editor checks and refuses a
  file with more than one entry written as `package.json`.
- **The guard's scan workers are gone when it is done (N-22).** Closing the worker pool ended its processes
  and did not wait for them, so the interpreter waited at its exit for workers still starting up and for
  their pools' threads: under load a test process outlived its time box that way. `close` now waits for
  what it ended (5 seconds at most) and kills a worker still there.
- **Archive paths that differ only by case are one file, as macOS and Windows install them (EG-4; rule set
  2.42.0).** Their file systems ignore case and Unicode normalization, so an npm tarball, a wheel or a
  `.vsix` holding `index.js` and then `INDEX.js` installs the second one's bytes as `index.js` there; Lazaret
  read the main file as the first and the twin as a file nothing loads. Such a pair is now SC-ARCHIVE-DUP
  (MAJOR), and the twin of a file that runs gets the import-time test too. None of the benchmark's, the
  popular set's or Part F's releases holds such a pair.
- **A file an installer opens by its name is read under any case, as macOS and Windows open it (EG-4's
  leftover; rule set 2.45.0).** npm opens a package's `package.json` and `binding.gyp`, pip an sdist's
  `setup.py` and `pyproject.toml`, VS Code an extension's `package.json`; where case and Unicode
  normalization are ignored, `Package.json` is that file, whether it was written over a `package.json`
  before it or is the only one. Lazaret read such a file as an ordinary one, so the install hook a
  `Package.json` twin named and what its `main` named were not read as what runs. Now a root manifest's
  case variant is read as the manifest too (its hooks, its entry points, an extension's `vscode:uninstall`),
  a `Setup.py` is code pip runs, and a `PyProject.toml`'s build backend is too; and a path Node opens (a
  hook's script, a `main`, a `require`) that names no member exactly is the member with its name under
  another case, as there (`node Setup.js` runs `setup.js`). Of the benchmark's, the
  popular set's and Part F's releases, one holds such a name, nested, where nothing opens it
  (`pyarmor/examples/pybench/Setup.py`).
- **The code an extension's contributions name is read as code that runs (EG-5; rule set 2.43.0).** VS
  Code and the processes it starts run some of an extension's code without its `main` module: the
  TypeScript server loads a `typescriptServerPlugins` package from every installed extension's
  `node_modules` whenever a JavaScript or TypeScript file is open, whether or not the extension is
  activated; a debug adapter's `program` starts with a debug session; a notebook renderer and a Markdown
  preview script run in webviews. Lazaret gave those files the use-time test alone, which reports only
  the strongest shapes, so a download-and-run in a TypeScript server plugin was OK. They are entry
  points now, with the import-time test, and the finding says when each runs; a debug adapter's program
  outside the extension's folder is SC-UNREAD-CODE, as `main` is.
- **An extension whose `main` or `browser` names a file outside its folder is INCOMPLETE (EG-3).** VS
  Code joins the entry to the extension's folder and runs the file wherever it is, with only a warning,
  so an extension could start code from another extension's folder (a pack member's,
  `../publisher.name-1.0.0/…`); Lazaret found no entry, and could call it OK with what it runs unread.
  Such an entry is now SC-UNREAD-CODE (MAJOR), and the verdict INCOMPLETE.
- **A file over the per-file download limit that its registry declares no size for is INCOMPLETE, not an
  error (N-21).** A Go module's zip (the proxy declares no size before the download), a crate or an npm
  tarball found over the 200 MiB limit as it came made `lazaret-registry scan` fail; it is now left out
  as one declared over the limit is (SC-TRUNCATED, the verdict INCOMPLETE). The download's over-budget
  error is a type of its own (`TooLarge`), not a message. `lazaret guard code` blocks such an extension:
  it installs the files it scanned, and has none to install.
- **`lazaret guard cargo` blocks a file in cargo's cache that is not the crate the lockfile names (GR-2).**
  cargo checks a download against the index's checksum, but builds a `.crate` it finds in its cache as it
  is, so a file put there (by anything that can write to `CARGO_HOME`) was built while the guard scanned the
  registry's copy. A cached file of the crate in cargo's cache of that registry (`registry/cache/<host>-<hash>/`,
  every hash cargo's versions have used; crates.io's sparse and git indexes) whose SHA-256 is not the
  lockfile's now blocks, and the message names it.
- **A `.netrc`'s anonymous-FTP password is not a credential (N-25).** S-SECRET reported the password of an
  entry whose login is `anonymous` (or `ftp`), which by convention is an e-mail address
  (`default login anonymous password jdoe@example.org`). It now leaves out every password of such an
  entry, wherever its login sits in it, in both packages; any other entry's password is reported as before.
- **The pip and uv relay sends a private index's credentials with a file too large to scan.** Such a file
  is relayed to the tool unscanned (INCOMPLETE), and the relay made a request of its own without the
  credentials of the file's URL, so a private index that wants them for its files refused it. It now
  goes through the fetcher's request, as the scan's download does.
- **The Go guard (and the pip and uv relay) holds at most 512 MiB of archives in memory at once (GR-4).** go asks
  its proxy for about as many zips at once as the machine has cores, each up to 200 MiB, and
  the guard read each whole to scan it, all at the same time. Zips are still fetched together
  (to files), and are read and scanned within a budget of bytes held at once
  (`LAZARET_GUARD_HOLD_MB`, default 512; a zip larger than it goes alone); module zips from
  go's cache too, and the files the pip and uv relay serves (by the size the index declares).
  Eight 40 MB zips asked for at once: 320 MB held at the peak before, 80 MB with a budget of
  100 MB, in 2.2 s instead of 1.3 s.
- **The rest of the cargo guard's review (GR-3).** The guard's own runs of cargo now take the
  command's `-Z` flags, so that they resolve as the command will, and with nightly's
  `--lockfile-path` the lock that is checked and put back is that one (it was Cargo.lock, and
  cargo then built from a lock nothing had checked); `cargo install --lockfile-path` is
  refused. A crate from a plain-http registry on another machine that only the lockfile
  names, not cargo's settings, is not fetched (INCOMPLETE, not checked): the lockfile is the
  project's. A download now stops after 15 minutes in all (`LAZARET_GUARD_DOWNLOAD_SECONDS`),
  where a server sending a byte now and then kept it going for ever. Offline, an entry
  without a checksum already asked the index nothing; a test now holds it.
- **`lazaret guard --plan cargo …` runs none of the project's programs (GR-1).** When it
  updates a lock, cargo asks the compiler its version, through the wrappers and the
  compiler a project's `.cargo/config.toml` names (`build.rustc-wrapper`,
  `build.rustc-workspace-wrapper`, `build.rustc`; checked with cargo 1.95), so a dry run
  ran them. Under `--plan` the guard's cargo commands set them aside (`--config`), and
  the compiler cargo finds by itself answers; without `--plan` the command runs as the
  project configures it, as cargo would run it.
- **The cloud's and the registries' credential files are credential stores (GR-7).** A
  file read and sent is a harvest ("reads credentials or the whole environment and sends
  data over the network", and an exfiltration service's address counts as where it went)
  when the file is a credential store, and only an SSH key, `.git-credentials` and a
  browser's storage were. Now, in every language, so are the cloud's and the
  registries': `~/.aws/credentials`, `config` and the SSO cache, `~/.kube/config`,
  `~/.docker/config.json`, gcloud's `credentials.db`, `access_tokens.db`,
  `legacy_credentials` and `application_default_credentials.json`, Azure's token caches,
  `.npmrc`, `.pypirc`, `.netrc`, cargo's `credentials`, the GitHub CLI's `hosts.yml`,
  `.vault-token` and Terraform's `credentials.tfrc.json`, however the code writes the
  path (joined with `path.join` or `os.path.join`, `Path.home() / '.aws' /
  'credentials'`, concatenated or in a template). A path too long to show whole keeps
  the end that names the store, as it is shown and graded. A public key, and a file
  that holds no credential, are not stores. No release of the benchmark, the popular
  set or the Go and Rust sets changes verdict. Rule set 2.38.0.
- **A dependency's Rust test code is left out of the file rules (N-20).** What
  `#[cfg(test)]` (or `cfg(all(…, test))`), `#[test]`, `#[bench]` or `#[tokio::test]` marks
  in a crate's `src/` is compiled only for the crate's own tests, never into a dependent,
  as its `tests/` folder and Go's `*_test.go` are not. The Rust reader already left it
  out, but the file rules read it, and its test vectors and keys were WARNs. In registry
  and guard scans and `--deps`, in both packages, a line whose text is all in such an
  item, or every line of a file under its own `#![cfg(test)]`, gives no finding now; a
  line that also holds other code, and a file the parser can't read whole, are read as
  before, and a project's own tests are still read. WARN to OK: rustls among the popular
  crates, and charset, dns-parser, mailparse and rustls among Ubuntu's. Rule set 2.37.0.
- **An npm manifest inside a crate or a Go module is not npm's (N-18).** A `package.json`
  or a `binding.gyp` in a crate or a Go module (an npm wrapper of a crate's binary, an
  editor extension kept beside the code) was read for install hooks as an npm package's,
  and a plain hook counted: 2 of the 30 WARNs of Ubuntu's crates (insta's,
  tree-sitter-cli's). npm never installs a package from inside a crate or a module, so
  those hooks, the implicit `node-gyp rebuild` of a crate's root `binding.gyp` among
  them, are listed as INFO with that reason. A hostile command stays CRITICAL, and a hook
  is still followed to the script it names, which counts when that script looks hostile
  (a build script can run npm there). Rule set 2.36.0.
- **SC-B64 passes over runs that are not base64 data, and an emoji's repeated
  presentation selector is not SC-HIDDEN-UNICODE (G-5, N-23).** SC-B64 reported any
  quoted run of 200 base64 characters or more, and in Go and Rust code most such runs
  are not data: Go's `stringer` name tables (letters alone), big numbers and test
  vectors (digits alone, or hex digits, after `0x` or not) and test strings that
  repeat a short period. It was the rule behind 24 of the 39 WARNs of Ubuntu's Go
  modules and 11 of the 30 of its crates. Base64 of 150 bytes or more mixes letters
  and digits and does not repeat itself, so a run of one class of characters up to
  16,384 long and a period of up to 64 characters repeated are passed over, and a run
  after them on the line that can be data is still reported. A longer run of one class
  is reported as before: that is what a payload written in hex is (three of the
  benchmark's malicious PyPI releases carry one of 270,000 hex digits or more; the
  longest run of the benign sets is 9,327 digits). SC-HIDDEN-UNICODE took an emoji's
  presentation selector written twice (U+2622 and U+FE0F twice, in the aes crate) for
  a run of selectors carrying data; one selector repeated up to four times carries
  none, and GlassWorm's encoding, a run of many different selectors, is still found.
  WARN to OK: 12 of Ubuntu's Go modules and 8 of its crates, 3 of the popular crates
  (aes, aws-lc-rs, crc), Go's vendored x/tools, 4 popular npm and PyPI releases
  (monaco-editor, prettier, modal, notebook) and one benign release of the benchmark
  (google-adk); no malicious verdict moves. `stringer` tables of mixed case
  (`AttrSiblingAttrLocation…`) and base64 that is data (keys, certificates, test
  messages) are still SC-B64. The npm package (the engine) and the dashboard read both
  the same way. Rule set 2.35.0.
- **A library declared `crate-type = ["proc-macro"]` is a procedural macro.** Cargo builds
  a library whose crate types hold `"proc-macro"` as a procedural macro, whatever
  `proc-macro` says, and runs it inside the compiler of every crate that uses it (checked
  with cargo 1.95). The readers of a crate's `Cargo.toml` (registry and guard scans, and
  `--deps`) read only `proc-macro`, so the functions of such a crate that its
  `#[proc_macro]` entry points do not reach were read as code that runs when called
  (SC-USE-RISK, strong reasons only), not as build-time code. Both readers read
  `crate-type` now, and the Rust reader takes a crate with a `#[proc_macro]` function as a
  procedural-macro crate whatever its manifest says (rustc builds such a function in no
  other kind of crate). No crate of the Go and Rust benign sets uses that spelling. Rule
  set 2.34.0.
- **Code read back from the file itself, in Python, is read on the tree (N-19).** rumdl
  0.2.78, a popular PyPI package, was SUSPICIOUS for two maintainer scripts: each gives
  argparse its docstring as the usage text and runs `gh` with arguments
  (`subprocess.run(["gh", *args])`). The text follower behind "runs code it reads back
  from its own file" follows names across a whole file, so it took `main()`'s `args` for
  `run_gh`'s parameter of that name, and gh's arguments for code run. A Python text is now
  read on its tree, as its sends and its received code are: what it reads back from
  itself (`open(__file__)`, `Path(__file__).read_text()`, `__doc__`, its loader's source,
  a data file shipped with it, read or named by a path) is followed through its scopes and
  calls to what each call runs (`exec`, a shell, an interpreter's `-c`); a program given
  it as arguments or input runs that program, and a parser of a usage text
  (`argparse.ArgumentParser`, `optparse`, `docopt`) gives the command line, not the text.
  A text the tree can't read, and JavaScript, keep the text follower. Rule set 2.32.0, so
  stored verdicts are scanned again.
- **A download piped into a shell named by its path.** The install-script and
  import-time tests read `curl … | sh` and `wget … | bash`, but not a shell named by its
  path: `wget -O - … | /bin/bash &` (the 2025 Go typosquats' command), `| /usr/bin/env
  sh` or `| sudo /usr/local/bin/zsh`. They are now, in every language's tests (rule set
  2.30.0, so stored verdicts are scanned again).
- **The Go/Rust review (Oct 4): the guard checks what cargo and go use, and its own
  folders, servers and programs are the user's.** A review of the 0.1.9 Go and Rust
  work (`lazaret guard go` and `cargo`, the registry's Go and crates modules, the SCA
  inventory; `audits/lazaret-go-rust-code-review-2026-10-04.md` in the project) found
  ways around the guard; each is fixed with a test that failed before it:
  - **A crate's files in tar entries of an unusual type** (a device, a FIFO, a type
    letter tar does not know) were left out unread, and cargo unpacks them as regular
    files: a crate could carry its `build.rs` so and scan OK. They are read as files, as
    cargo and pip read them, and are SC-ARCHIVE-TYPE (MAJOR); an npm tarball's are still
    skipped, as npm skips them. The registry's rule set is 2.29.0, so stored verdicts are
    scanned again.
  - **The guard's scratch projects were in the shared `/tmp`** (`cargo install`, yarn 1,
    `npm install -g`, `go --plan`), where cargo, rustup, yarn, npm and go read settings
    from the folders above: another user's `rust-toolchain.toml` or `.cargo/config.toml`
    there ran their program. They are in a folder of the user's own
    (`LAZARET_GUARD_SCRATCH`, else the cache folder), a workspace of their own, and the
    package managers run from the user's folder.
  - **`guard cargo`:** `cargo install` built another graph than the one checked (its
    features, `--vers`, a release published meanwhile): it installs `NAME@=VERSION` with
    the features asked for. A crate cargo had unpacked already was never checked; every
    crate the lock names is. cargo's configuration is read as cargo reads it
    (`.cargo/config` first, `include`, `--config`, `[registries]`); a source the guard
    cannot read, a registry that asks for credentials and a git crate are INCOMPLETE,
    not a note, so `--block-warn` blocks them; the build runs with `--locked`; an
    ambiguous published lock blocks; a crate unpacked but not checked is named even when
    the build fails; and "response over" is a typed error, not words in a message.
  - **`guard go`:** the local proxy served anyone on the machine, with the user's proxy
    credentials: it answers only a secret path of the run's and its own `Host`, and only
    the checksum-database paths go asks for. A zip over 200 MiB was fetched again,
    unscanned, for go: it is fetched once, to a file, and those bytes are go's. Modules
    go takes from its module cache, or from their repositories (`GONOPROXY`), were never
    scanned and the run said nothing: they are listed (`go mod download -json`) and
    scanned where go keeps them, before a build, test, run or install and after a get or
    a tidy; a vendored build says it is not checked. `go env` no longer downloads a
    toolchain (`GOTOOLCHAIN=local`); `-C` after `mod download`, `-modfile` in `GOFLAGS`
    and a program's own arguments are read as go reads them; `GONOPROXY` alone says
    which modules come from a repository; a release whose time is unknown is said, and
    blocked under `--block-warn` (cargo's too).
  - **Programs are looked up in `PATH`'s absolute folders only**, never the current one:
    on Windows, a project's `go.exe` or `npm.cmd`, or a repository's `git.exe` for
    `lazaret hook`, ran in the real tool's place.
  - **`lazaret-sca`:** the modules of a `go.work` and the members of a Cargo workspace
    without a lock are read, and a `go.mod` or `Cargo.lock` below the root that nothing
    reads is counted in a warning. An entry with no version from a lock or the build (a
    git crate beside a crates.io one, the original of a module a fork replaces) is kept
    as unknown; only a manifest's range gives way to a known version. go.mod's quoted
    paths are read with Go's escapes, a version too long to read is an unknown, and the
    lines not read are counted. go.sum gives every version with a zip hash, its modules
    get go.mod's replacements, and a module go.sum shows replaced is unknown. An unused
    replacement in `vendor/modules.txt` is not a module. A bundle dates each ecosystem's
    advisories, and one whose newest is over 30 days old is no source of them, so the
    coverage condition fails rather than pass on a stopped mirror. go.mod's replacements
    are looked up rather than read through (20,000 of each took 12 s).
- **`lazaret-sca` and hostile manifests**, found by the new fuzzers: a NUL byte in a
  requirements file's `-r` path raised an error out of the inventory; a TOML file nested
  too deeply raised `RecursionError` past every reader that catches parse errors (the
  inventory, the guard's `uv.lock` reader, the package managers' settings); a `setup.py`
  with an invalid escape printed a `SyntaxWarning`.
- **The guard took a cut-off answer for a whole one.** A body shorter than its
  `Content-Length` was read as a shorter page; it is an error now.
- **Nine popular packages are no longer SUSPICIOUS.** 0.1.8 gave the verdict to vite
  8.3.2, vitest 5.0.3, monaco-editor 0.57.0, future 1.0.0, sympy 1.14.0, ipython 9.17.1
  and kubernetes 36.0.3, and 0.1.7 already to coverage 7.16.2 and numba 0.68.0, so
  the guard blocked them. Each was a reading that took a library's ordinary code for
  a dropper's:
  - A library's loader that fetches an address it is given or works out (Monaco's
    module loader, vitest's module runner) is not downloading code of its own: an
    address is the script's own when it is text the script writes (a literal, a
    template, a constant built from them, an item of a list of them), local data, or a
    global the page or another file defines (`axios.get(src)`, as before), and its
    caller doesn't give it (an item of a list it is given is the caller's). An object
    is no address: TypeScript's emit passes Monaco's loader a namespace, not a URL.
  - What a server is sent is received (its request handler's arguments, its
    `request`, `connection`, `upgrade` and `data` events); the server itself, its
    address and options, and what a framework keeps beside it are not.
  - A Node module's objects are Node's: `createHash('sha1').update(key)` no longer
    reaches a bundle's own `update()` methods by name (vite's MagicString), and
    `createRequire()` makes a require, through a bundler's `__require` wrapper too, so
    the modules loaded with it are known.
  - The instances of a class made in several places are each its own container: what
    one instance's methods are given stays with that instance (every MagicString of
    vite's plugins shared every other's members). What the class's methods read
    themselves is still every instance's.
  - A loop that selects the environment's variables by a test of their names (vite's
    `loadEnv`) reads a selection, not the whole environment, as `.filter()` and a
    comprehension's test already did, unless the test excludes some or names secrets;
    what the names a JavaScript test reads are given counts as its text (a stealer's
    list of `/TOKEN/i`, `/SECRET/i` patterns). An object given `os.environ` and read by
    a constant name (kubernetes' in-cluster config, future's urllib backport) reads
    that one variable.
  - A list's reversal (`names[::-1]`: sympy's `lambdify`, IPython's completer)
    reorders items and decodes nothing; a string's still decodes.
  - SC-PTH-EXEC judges a .pth file's `import` line by what its code does: CRITICAL
    when it executes or decodes a payload, reaches the network or starts another
    program (what no library does at every interpreter start: the worms' .pth files
    download Bun and start it), or does what the install-script and import-time tests
    look for, MAJOR otherwise. `exec('…')` of a plain literal (coverage's
    `a1_coverage.pth`) is judged by the literal's code; a literal in escapes is still a
    payload. The dashboard's twin, which has no engine, still reads a line by its
    pattern alone.
  - `__doc__=` as a keyword argument (numba's jitclass) is not a read of the file's own
    docstring.
  - The cross-file follower seeds a file only with the environment variables another
    file writes: vite's bundle writes and reads `process.env.BROWSER` itself.

  The registry's rule set is 2.27.0, so stored verdicts are scanned again.

## [0.1.8] — 2026-10-03

0.1.8 is two rounds of work, released together. Part 1 is the Rust-first
refactor: the native engine becomes Lazaret's only engine, and the
supply-chain detectors are rebuilt on its parsers. Part 2 is the detection
rounds prepared for October 1, which waited for it; their numbers are as
measured then. Where the numbers stand at release (the benchmark's 516
malicious releases and 429 popular packages are in-sample; the holdout is
745 other malicious releases of the same dataset, read only in aggregate):

| | 0.1.8 | 0.1.7 |
| --- | --- | --- |
| Malicious releases SUSPICIOUS (in-sample) | 87.0% (449 of 516) | 68% |
| ... SUSPICIOUS or WARN | 91.1% (470) | 77% |
| Holdout, SUSPICIOUS | 85.4% (636 of 745) | 70% |
| Holdout releases that share no code with the benchmark, SUSPICIOUS | 79.5% (395 of 497) | 74% |
| Popular packages SUSPICIOUS · SUSPICIOUS or WARN | none · 7.2% (31 of 429) | 0.7% · 7.5% |

### Part 1: the Rust-first refactor

The native engine becomes Lazaret's only engine. Until now it was held,
answer for answer, to the Python engine it was ported from: every detection
landed twice, and the engine could be no better than its twin's structure.
The refactor retires the twin. Its first phase changes no finding — the
engine answers what it answered at the baseline (tag `rust-first-baseline`,
whose outputs were recorded on the benchmark's files and on installed
packages) — and the phases that follow rebuild the detectors on the
engine's lexers and parsers (`docs/RUST_ENGINE.md` §8), each change to a
finding a reviewed difference in the recorded outputs. The lexers (phase
2) change none on real files. The registry's rule set is 2.24.0, so stored
verdicts are scanned again.

#### Changed

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

#### Added

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

#### Fixed

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

### Part 2: the detection rounds (prepared for October 1)

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

#### Added
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

#### Changed
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

#### Removed
- **The npm package's JavaScript twins of what the engine answers:**
  `js/src/lib/hooks.js`, `received.js`, `shellpipe.js` and the synced
  `received-spec.json`, `js/src/scanner/linear.js`, and the rule loop,
  families and dependency decode flow of `js/src/scanner/scan.js` (with
  `scripts/sync-received-spec.py` and `test_js_parity_hooks.py`). The
  library no longer exports `RULES` and `TEXT_RULES` (the rules live in the
  engine's rule pack); the supply-chain tests it exports are the engine's.

#### Fixed
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
