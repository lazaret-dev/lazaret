# Secret-scanning baseline

This document records the reviewed Gitleaks baseline for Lazaret's public
repository. It contains no credential values. The exact accepted findings are
listed by fingerprint in the repository-root `.gitleaksignore` file.

## Baseline

| Field | Value |
| --- | --- |
| Baseline date | 2026-11-18 |
| Repository point | `5e6c634fc67c986df7cae04fb88d2026e0f13e0f` (`v0.1.10`) |
| Scanner | Gitleaks 8.30.1 |
| Commits scanned | 776 |
| Data scanned | approximately 213.82 MB |
| Reported occurrences | 216 |
| Distinct accepted fingerprints | 203 |
| Unbaselined findings after review | 0 |

The redacted report was retained outside the repository. Secret values were
not copied into this document, commit messages or review notes. No candidate
credential was sent to a provider to test whether it was live.

## Classification

| Findings | Classification | Disposition |
| ---: | --- | --- |
| 127 | Published or synthetic cryptographic vectors | Required interoperability and verification data |
| 67 | Secret-detector tests and deliberately credential-shaped fixtures | Required to prove detection and redaction behavior |
| 12 | Registry reference data with key-like identifiers | Public registry metadata; not authentication material |
| 9 | Detector source or generated dashboard examples | Literal patterns, PEM markers and deliberately vulnerable sample text |
| 1 | Documentation example | Deliberately credential-shaped explanatory text |

The largest groups are 70 QUIC vector matches and 53 synthetic TUF records.
AWS-token and curl-credential matches occur in tests. Private-key matches are
fixtures or literal PEM parsing and generation markers; they are not embedded
deployment keys. The dashboard matches are deliberately vulnerable sample
programs used to demonstrate the scanner.

No baseline finding was located in a GitHub workflow, release credential,
environment file, package manifest or deployment configuration.

## Baseline policy

1. Every line in `.gitleaksignore` must be an exact Gitleaks fingerprint.
   Broad directory, filename and rule exclusions are not permitted.
2. A new fingerprint fails CI until a maintainer reviews its value and
   provenance. CI and automation must never append fingerprints.
3. A reviewed finding may be accepted only when it is synthetic test data,
   public verification material, a detector pattern or an inert example.
4. The matched value must never be copied into a review issue or this ledger.
5. Changing Gitleaks versions requires a fresh full-history scan and review.
6. Rewriting history invalidates fingerprint identity and requires rebuilding
   this baseline.
7. A real credential is never allowlisted. Revoke or rotate it first, assess
   exposure, remove it from the public history and rebuild the bundle.

## Reproducing the gate

Install Gitleaks 8.30.1, then run from the repository root:

```sh
sh scripts/check-secrets.sh
```

The command scans all history reachable from the checkout, applies only the
fingerprints in `.gitleaksignore`, redacts any new match in its output and
returns nonzero if an unreviewed finding exists.

To review a new finding, generate a redacted report outside the repository:

```sh
gitleaks git . \
  --redact \
  --report-format json \
  --report-path /absolute/private/path/gitleaks-review.json
```

Record the classification and reviewer without recording the matched value.
Only then may the exact fingerprint be added to `.gitleaksignore`.
