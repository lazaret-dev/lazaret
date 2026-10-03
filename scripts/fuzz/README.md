# scripts/fuzz: mutation fuzzers for the readers of untrusted input

Added in 0.1.9 (X-1 of `audits/lazaret-profile-and-backlog-2026-10-03`). Standard library plus this checkout; they import
`lazaret` from the tree they sit in, so a run is of the code you have checked out.

```
python3 scripts/fuzz/fuzz.py --list
python3 scripts/fuzz/fuzz.py                                  # every target, seed 0, 200 changed inputs each
python3 scripts/fuzz/fuzz.py xml sca-uv-lock --seed 7 --seconds 60 --findings out/
python3 scripts/fuzz/fuzz.py --replay out/xml-exception-5a027f8097.bin xml
```

An input is taken from the corpus (the seeds, and the inputs that ran slower than usual), changed by `fuzz_mutate.py` (bit
flips, boundary numbers as text and as binary fields, spans copied and repeated, a dictionary of the format's words,
nesting, truncation, splices), and run. A finding is an exception the reader does not document, a broken promise
(each target checks the shape and limits of what it is given back), a warning the reader printed, or a run over the
target's time limit. Findings are de-duplicated, made smaller by deleting what is not needed, and written to
`--findings` as the input (`.bin`) and an account of it with the command to replay it (`.txt`). The same `--seed` runs the
same inputs. The exit status is 1 for a finding that is not in `fuzz_targets.KNOWN`.

To find a **hang**, which a time limit measured afterwards cannot: `--hard-limit 60 --pending pending.bin` ends the
process with every thread's stack if one input takes 60 seconds, and the input is the file left in `pending.bin`.

## Targets

| Target | Reader |
|---|---|
| `archive-tgz`, `archive-tbz2`, `archive-txz`, `archive-zip` | `registry.repo.iter_archive` on npm and sdist tarballs, bzip2 and xz tarballs, wheels and zip sdists: each member is a real size, a safe relative path, within the limits; a budget or limit stops the reading; the same bytes give the same members |
| `xml`, `xml-minidom` | `safexml.ElementTree.fromstring` and `safexml.minidom.parseString` with the options and limits the scanner can give: only the documented errors, a bounded number of elements, no amplification |
| `sca-package-lock-json`, `sca-yarn-lock`, `sca-pnpm-lock-yaml`, `sca-bun-lock`, `sca-poetry-lock`, `sca-uv-lock`, `sca-pylock-toml`, `sca-pipfile-lock`, `sca-requirements-txt`, `sca-pyproject-toml`, `sca-setup-py` | `scanner.sca.scan_all` over one file of the kind: no exception, no warning on stderr, an inventory of `(ecosystem, name, version, where)` strings no larger than the file |
| `sca-bundle-index` | `scanner.sca_index.IndexedBundle` (the CVE bundle as an indexed file), run on the bytes as given and on the same bytes with the file length and every checksum made right, so that the checks behind the checksums run: only `ValueError` for a file it refuses; a file that passes `verify()` never fails a lookup; every answer a list of `(advisory, package)` dicts with the package one of the advisory's own; two reads of one file agree |
| `sca-bundle-doc` | a JSON bundle document read as `CveBundle` and written through `dump_index` and read back: the same warnings, the same advisory count, a passing `verify()`, and the same pairs for every name the document mentions (and a few that fold to them); a document one refuses the other refuses (the index also refuses what is not JSON, NaN) |

## Findings

Fixed (regression tests in `tests/scanner/test_sca_fuzz_findings.py`): **F-3** a NUL byte in a requirements `-r` path
crashed the inventory; **F-4** a TOML file nested too deeply raised RecursionError out of `tomllib` past every caller that
catches ValueError (the inventory, the guard's `uv.lock` reader, the package-manager settings); **F-5** a `setup.py` with an
invalid escape printed a SyntaxWarning.

Known, reported and not fixed here (`fuzz_targets.KNOWN`; the test that replays them fails when one stops reproducing, so
the entry goes with the fix): **F-1** an encoding declaration the parser cannot use (`encoding="T7"`, `"UTF32"`) raises
`LookupError` or `ValueError` out of `safexml`, as the standard library does, instead of `ParseError`; `pypi_latest_from_feed`
catches neither and `registry.repo._parse_xml` does not catch the `LookupError`. **F-2** a zip whose entries start at one place
(an overlap that CPython has warned of since April 2024) makes the standard library warn on stderr from inside `iter_archive`,
which neither silences the warning nor reports the overlap as an anomaly. **F-6** (found on Python 3.10, which is why the
long job runs on both ends) a zip entry with no name raises `IndexError` out of `iter_archive`, because `ZipInfo.is_dir()` of 3.10
reads the name's last character; newer Pythons skip the entry without an anomaly. **F-7** a zip entry compressed with LZMA that declares a dictionary of about
4 GiB raises `MemoryError` out of `iter_archive` where memory is capped (an address-space limit, a small VM). `docs/0.1.9-findings.md`
has the detail and the fix.

## The nightly/weekly run

`.github/workflows/fuzz.yml` runs every target for a few minutes each on a random seed, with the hard limit, and uploads
the findings. It is read-only, takes no secrets and keeps no cache (the rules of `ci.yml`). A schedule runs only from the
default branch.

## Adding a target

Write `run(data)` in `fuzz_targets.py`: return when the reader did what it promises, whatever the bytes (catch only the
errors it documents), and call `check(condition, "rule-name", detail)` for each promise about the answer. Add seeds (valid
inputs, and the odd ones), a dictionary, and `register(...)`. Then add the target to `EXPECTED_TARGETS` and to this table, and
a case to `PromisesAreLive` in `tests/architecture/test_fuzz_scripts.py` that breaks each new promise, so that it is known to be live.
