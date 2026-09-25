# Lazaret

Static security, supply-chain and quality analysis for Python, JavaScript and SQL, with **no dependencies**: Lazaret runs on the Python standard library alone, and even building it downloads nothing.

```bash
pip install lazaret
lazaret path/to/project                 # scan; writes lazaret-report.{html,json}
lazaret . --ci --sarif out.sarif        # quality gate for CI, SARIF for code scanning
lazaret-registry scan npm:left-pad      # audit a published npm / PyPI package
lazaret-sca . --bundle cve-bundle.json  # match installed dependencies against CVEs
lazaret-mcp                             # MCP server, so an AI assistant can scan code
```

What it finds:

- **Security:** SQL/command/code injection, SSTI, XXE, unsafe deserialization, XSS sinks, weak crypto, disabled TLS verification, hardcoded secrets (provider signatures and entropy), and more, across about 58 rules.
- **Taint analysis:** follows untrusted input through assignments, function calls, and across files into sinks, with category-aware sanitizers and a configurable source/sink/sanitizer spec.
- **Supply chain:** decode-then-execute patterns, packed and obfuscated JavaScript, suspicious install hooks, smuggled binaries and nested archives, both in your tree and in published npm/PyPI packages.
- **Quality:** bugs, code smells, complexity, duplication, with a quality gate and ratings.

Two of its building blocks are usable on their own (provisional APIs until 1.0): `lazaret.pg`, a PostgreSQL client in pure Python with SCRAM-SHA-256, channel binding and TLS; and `lazaret.safexml`, a layer that makes the stdlib XML parsers safe for untrusted input.

Licensed under Apache-2.0. Documentation, source and issue tracker: https://github.com/lazaret-dev/lazaret · https://lazaret.dev
