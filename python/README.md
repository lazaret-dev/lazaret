# Lazaret

Static security, supply-chain and quality analysis for Python, JavaScript and SQL, with **no dependencies**: Lazaret runs on the Python standard library and its own native engine (written in Rust, with no external crates; every wheel carries it), and even building it downloads nothing.

```bash
pip install lazaret
lazaret path/to/project                 # scan; writes lazaret-report.{html,json}
lazaret . --ci --sarif out.sarif        # quality gate for CI, SARIF for code scanning
lazaret . --deps                        # also audit node_modules and site-packages
lazaret scan github:owner/repo@v1.2.3   # a GitHub or GitLab repository at a commit
lazaret-registry scan npm:left-pad      # audit a published npm / PyPI package
lazaret guard npm install express       # check what npm, pnpm, yarn, Bun, pip, uv, go or cargo installs, before it runs
lazaret hook                            # check the files staged for commit (also a pre-commit hook)
lazaret-sca --update-bundle             # download OSV + CISA KEV + EPSS into cve-bundle.json
lazaret-sca . --bundle cve-bundle.json  # match installed npm, PyPI, Go and Rust dependencies against CVEs
lazaret-mcp                             # MCP server, so an AI assistant can scan code
```

What it finds:

- **Security:** SQL/command/code injection, SSTI, XXE, unsafe deserialization, XSS sinks, weak crypto, disabled TLS verification, hardcoded secrets (provider signatures and entropy, in code and in config files), and more, across 63 pattern rules plus supply-chain and coverage findings.
- **Taint analysis:** follows untrusted input through assignments, function calls, and across files into sinks, in Python and in JavaScript and TypeScript (read with a real parser), with Flask, Django, FastAPI and Express routes modeled, category-aware sanitizers, and a configurable source/sink/sanitizer spec.
- **Supply chain,** in your tree, in `--deps` and in published npm and PyPI packages: install hooks followed to the scripts they run and the scripts those start; code that runs at import, and in registry scans the code a package runs only when it is used; the strings a file decodes as it runs (hex, base64, its own decoding, XOR or character-code helpers, javascript-obfuscator's string arrays and proxy objects); a value received over the network in one file and run in another; data read from the machine followed to where it is sent; credential sweeps; reverse shells and miners; programs set to start at login; worms that publish themselves; code hidden off-screen; smuggled binaries and nested archives; names one change from a popular package's; and a new dependency published days before a release. On 516 real malicious npm and PyPI releases, 83% get the SUSPICIOUS verdict (GuardDog 71%), against 3 of 429 popular packages (GuardDog 18). Those releases were read while the detectors were written; of 747 others that none was written from, 78% do, and 98% of those verdicts rest on what the code does.
- **Install guard:** `lazaret guard` in front of `npm install`, `npm ci`, `pnpm add`, `yarn add`, `bun add`, `pip install`, `uv add`, `uv sync`, `uv run`, `uvx`, `go get` or `cargo build` resolves what would be installed, fetches and scans every package in memory, and installs nothing if one is SUSPICIOUS, can't be checked, or is younger than `--min-age` (2 days by default). Private registries and indexes are read with the credentials the package manager's own settings give, sent to that host only. `--plan` checks without installing; verdicts are cached by digest.
- **Before you commit:** `lazaret hook` checks the files being committed, as staged, and fails on the quality gate's security and supply-chain conditions (a credential, a critical vulnerability, a supply-chain indicator, a cross-file taint flow). pre-commit runs it from https://github.com/lazaret-dev/lazaret-pre-commit.
- **Quality:** bugs, code smells, complexity, duplication, with a quality gate and ratings.

Every command prints its version with `--version`; the scanners also name the engine. Lazaret's scanning engine is native code, written in Rust with no external crates. pip installs it with the platform wheels for Linux (x86-64 and ARM64, glibc 2.28 or later), macOS (Apple silicon, and Intel from 10.12) and Windows (x64); everywhere else pip builds a wheel from the source distribution, which compiles the engine and needs Rust (`rustup`).

Two of its building blocks are usable on their own (provisional APIs until 1.0): `lazaret.pg`, a PostgreSQL client in pure Python with SCRAM-SHA-256, channel binding and TLS; and `lazaret.safexml`, a layer that makes the stdlib XML parsers safe for untrusted input.

Licensed under Apache-2.0. The Unicode 13.0 tables the scanners pin text to are Unicode data, under the Unicode License v3. The native engine every wheel carries is Lazaret's own work since 0.1.9, so the wheels and the sdist are Apache-2.0 AND Unicode-3.0. Each carries the licenses and notices it names. Documentation, source and issue tracker: https://github.com/lazaret-dev/lazaret · https://lazaret.dev · Changes: https://github.com/lazaret-dev/lazaret/blob/main/CHANGELOG.md
