# Lazaret documentation

This index routes readers to the smallest document that answers their question.
The repository-root [`README.md`](../README.md) remains the product overview and
quick start. Documentation contributors must follow
[`DOCUMENTATION_GUIDE.md`](DOCUMENTATION_GUIDE.md).

## Use Lazaret

- [`../README.md`](../README.md) — product overview, installation and command
  summary.
- [`../python/README.md`](../python/README.md) — the complete PyPI package.
- [`../js/README.md`](../js/README.md) — the npm project scanner and hook.
- [`../website/README.md`](../website/README.md) — reviewed `lazaret.dev`
  deployment source.

## Understand the system

- [`../STRUCTURE.md`](../STRUCTURE.md) — repository and package layout,
  boundaries and shipped contents.
- [`DESIGN.md`](DESIGN.md) — architectural invariants and detection design.
- [`RUST_ENGINE.md`](RUST_ENGINE.md) — native engine, parsers, data flow,
  packaging and recorded outputs.
- [`../rust/crates/lazaret-archive/README.md`](../rust/crates/lazaret-archive/README.md)
  — bounded native archive support.

## Develop and release

- [`TESTING.md`](TESTING.md) — verification sequence, corpus checks and
  cross-platform testing.
- [`RELEASING.md`](RELEASING.md) — promotion from private GitLab development to
  curated public GitHub, release tags and registry recovery.
- [`../SECURITY.md`](../SECURITY.md) — security and vulnerability-reporting
  policy.
- [`../security/GITLEAKS_BASELINE.md`](../security/GITLEAKS_BASELINE.md) —
  reviewed secret-scanning baseline.

## Requirements and historical evidence

- [`MAIL_GATEWAY_REQUIREMENTS.md`](MAIL_GATEWAY_REQUIREMENTS.md) — proposed
  first-party attachment-analysis requirements; not an implemented feature
  claim.
- [`0.1.9-findings.md`](0.1.9-findings.md) and
  [`0.1.9-progress.md`](0.1.9-progress.md) — historical 0.1.9 engineering
  records.
- [`ra6-deletion-review.md`](ra6-deletion-review.md) and
  [`wf-secrets-scope-snapshot-review.md`](wf-secrets-scope-snapshot-review.md)
  — bounded review records for specific detector changes.

The root `CHANGELOG.md` is the release history. Files beside fixtures, recorded
responses and tools document only those artifacts. The synchronized
`rust/crates/pratique/` documentation is maintained upstream and must not be
rewritten locally.
