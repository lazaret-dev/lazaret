# lazaret (npm)

Quarantine for your dependencies: security & quality scanner for Python and
JavaScript projects.

The JavaScript engine is a port of Lazaret's scanner (the Python package's
`lazaret.scanner` and the browser dashboard, `lazaret/web/lazaret.html`): the
same detection rules, the taint-flow and SQL-sink analyzers, and the
obfuscation/entropy secret detection, so a dashboard scan, `npx lazaret`, and
`python -m lazaret` report the same findings for the same input. It is a
project scanner; registry auditing (`lazaret-registry`) is Python-only.

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
  CWE reference, file/line, ±2-line snippet).
- `lazaret-report.html` — the JSON report wrapped in a marker-carrying page.

Report writes are atomic (temp + rename) and never clobber a file that is not
already one of ours.

## Detection families

- **Injection**: `eval`/`exec`, shell command execution, SQL injection —
  including the flow-sensitive SQL-sink analyzer that catches SQL built into a
  variable and then passed to `execute(q)` (G12).
- **Taint flows**: request/argv input reaching command/XSS/SQL sinks without
  visible sanitization (`T-*` rules).
- **Secrets**: token signatures, high-entropy literals, credential-looking
  assignments. Flagged lines are redacted at creation time — the report
  persists `[redacted: secret rule …]`, never the credential.
- **Supply chain** (`SC-*`): install hooks, meaning the scripts npm runs on
  install (`preinstall`, `install`, `postinstall`, plus `prepare` in your own
  project; publisher-only scripts like `prepack` never run on install). A hook
  is MAJOR; one that fetches or evaluates code is CRITICAL, though
  `node -e "require('./local-file')"` is not treated as eval. Also binding.gyp
  actions; readable text hidden in hex escapes (escaped binary data is not
  flagged); base64 and char-code blobs; `javascript-obfuscator` identifier
  signatures; oversize files (declared SC-TRUNCATED, never silently skipped).
- **Quality**: function length/complexity, duplication, empty catches, and
  the rest of the code-smell set.

`node_modules`/`vendor` trees are opt-in (`--include-deps`): dependency code
is scanned with supply-chain/secret rules only — quality findings in vendored
code are noise.

## CLI

```
lazaret check <directory> [options]

  --out-dir DIR     directory for reports (default: scan root)
  --no-json / --no-html
  --include-deps    also scan dependency directories
  --quiet           suppress the per-issue terminal listing
  --ci              exit 1 when the quality gate fails
```

Exit codes: `0` clean · `1` gate failed (`--ci`) or a CRITICAL supply-chain
finding · `2` usage error · `3` report-path error (checked before scanning).

## Library

```js
import { scanFile, buildResult, run } from "lazaret";
```

Zero dependencies, ES modules, Node 22+. Tests: `npm test` (built-in
`node --test` runner).

Website: https://lazaret.dev · Source: https://github.com/lazaret-dev/lazaret
