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
| `archive-npm-diff` | the same reader on npm tarballs, against what npm writes from them (BR-4): npm's own node-tar, as pacote runs it (`npm_extract.cjs`: the first path part stripped, links dropped), with the node on PATH and the npm beside it. A file npm writes is read, under the path npm writes it at (a backslash read as Windows reads it), or the reader calls the archive corrupt; and `registry.npmtar`'s model of npm's reading says what npm writes, where it follows it. Half the inputs get every header's checksum made right first, so that a change behind a checksum is read. Without node and npm's node-tar it compares nothing |
| `archive-pip-diff` | the same reader on sdists (tar and zip), against what pip writes from them before it builds (BR-4, F-11): pip's own unpacking (`fuzz_pip_extract.py`: pip's `unpack_file`, the top folder taken off only when every member has the same one, a `..` resolved through the path), run by each Python here that has pip. A file pip writes is read, under the path pip writes it at (a backslash read as Windows reads it), or the reader calls the archive corrupt. A third of the runs are an sdist built from the input's hash (odd names: folders, `.`, `..`, slashes, another top folder), in a tar or a zip. Without a Python that has pip it compares nothing |
| `xml`, `xml-minidom` | `safexml.ElementTree.fromstring` and `safexml.minidom.parseString` with the options and limits the scanner can give: only the documented errors, a bounded number of elements, no amplification |
| `sca-package-lock-json`, `sca-yarn-lock`, `sca-pnpm-lock-yaml`, `sca-bun-lock`, `sca-poetry-lock`, `sca-uv-lock`, `sca-pylock-toml`, `sca-pipfile-lock`, `sca-requirements-txt`, `sca-pyproject-toml`, `sca-setup-py`, `sca-go-mod`, `sca-go-sum`, `sca-vendor-modules-txt`, `sca-cargo-lock`, `sca-cargo-toml` | `scanner.sca.scan_all` over one file of the kind: no exception, no warning on stderr, an inventory of `(ecosystem, name, version, where)` strings no larger than the file, of an ecosystem the inventory has; a Go module is a path Go could fetch (a dot in its first element: not `stdlib`) at a version that is SemVer with a `v`, or at none |
| `sca-bundle-index` | `scanner.sca_index.IndexedBundle` (the CVE bundle as an indexed file), run on the bytes as given and on the same bytes with the file length and every checksum made right, so that the checks behind the checksums run: only `ValueError` for a file it refuses; a file that passes `verify()` never fails a lookup; every answer a list of `(advisory, package)` dicts with the package one of the advisory's own; two reads of one file agree |
| `sca-bundle-doc` | a JSON bundle document read as `CveBundle` and written through `dump_index` and read back: the same warnings, the same advisory count, a passing `verify()`, and the same pairs for every name the document mentions (and a few that fold to them); a document one refuses the other refuses (the index also refuses what is not JSON, NaN) |
| `crates-index` | `Crates.resolve` over the index file of one crate as the registry's answer, whatever it says: only `SpecError` or `FetchError` with a short printable message; one request; a download URL on `static.crates.io`; a version that is SemVer and is the one asked for (the latest is never yanked); a lowercase SHA-256 `cksum`; the name the index spells; the archive root `name-version/`; `dependencies` sorted names that pass the name rules; `verify` agrees with SHA-256; two resolves of one file agree |
| `crates-manifest` | `run_targets` and `declared` over a `Cargo.toml`: the sets are of members that exist, nothing runs at load (`startup` is empty), the declared name and dependencies pass the name rules, sorted and bounded; each spec is a bounded text or None and each rename a crate name, both of a declared dependency; two readings agree |
| `go-zip` | `golang.zip_h1`, the `h1:` hash of a module zip: only `DigestError`; `h1:` and 43 base64 characters and `=`; the same twice; no hash for a zip with two members of one name or a newline in a name; `verify` accepts that hash and refuses another |
| `go-mod` | `parse_gomod` and `declared` over a `go.mod`: a dict of module, go version and requirements no more than the file has bytes; every requirement version canonical; the declared name and dependencies pass the module path rules and come from the requirements, each with the version of its first line as its spec; two readings agree |
| `go-sumdb` | `parse_lookup` over the checksum database's response: only `FetchError`; the record number is the first line's, and the two hashes are in the response on the lines for this module and version |
| `go-sumdb-check` | `golang.verify_lookup` (NET-1: the native library's check of the signed tree head and the record's place in the log) over the real database's answer to golang.org/x/mod v0.17.0, changed, with its tiles served as captured and, every other input, the head served before it kept as from an earlier check: only `FetchError` with a short printable message; only tiles asked for, on the database's host; an answer that is not refused is verified (not left unchecked) and its hashes and record number are the database's own; two checks agree |
| `provenance-npm` | `provenance.verify` (NET-1: the native library's check of npm's attestations) over the real registry's answer for the npm package sigstore (4.0.0 and 2.2.0), changed, with the real tarball's digest: only `Unchecked` with a short printable message; every attestation verified, invalid or unchecked, with a printable reason when not verified; a verified one is signed by sigstore/sigstore-js's CI or by one of npm's two keys, whatever the bytes; two checks agree |
| `go-resolve` | `Go.resolve` over the proxy's `.info` answer (the checksum database answers for what it is told of): only `SpecError` or `FetchError`; at most the proxy and the database are asked, on their hosts; the version is a Go version and the one asked for; the zip URL, `h1:`, root `module@version/` and time are well formed; two resolves agree |
| `ecosystem-names` | crates.io and Go: `check_name`, `identity`, `check_version`, `parse_spec` and `segment` over a name and a version: only `SpecError`; a name that is accepted is accepted again, an identity is stable, a segment has no space, `?`, `#`, `\`, control or non-ASCII character and no `..` element; a name refused is refused by `identity` and `parse_spec` too |
| `ecosystem-member-path` | crates.io and Go: `member_path` over a member name and an archive root: a relative path with no `..`, `\` or `//`, or a short printable problem, never both; under the root; no `.cargo-ok` for crates.io; `go.mod` only at the root for Go |
| `action-code` | GitHub Actions (N-4): `repo.scan_action` over an action.yml, or a Docker action's Dockerfile, in a small repository packed as GitHub's archive of a commit: a verdict of the four; what it says runs is a file of the archive, and a base image is pinned exactly when it names a digest; every issue has a rule, a known severity, a message, a file and a line; two scans of one archive agree |
| `verify-answers` | secret verification (V-1): `secretverify.interpret` and `Verifier.verify` over a provider's answer (status, body, cut short by the size limit): an outcome from the three, `live` or `rejected` only where a rule of the table has that status (and, for an answer cut short, a rule that needs no body), printable bounded `detail` and `who`, no part of the credential in either, the same answer twice, and the verifier agrees with the reader |
| `verify-credentials` | secret verification (V-1): which credentials `Verifier.verify` sends, and to where: one that is the provider's format in full is sent once, and one that is not is not sent; the host is the table's, no part is in the host or the path, no header holds a line break, and the request is one the transport sends |
| `credential-path` | decision 14: `pmsettings.Credentials.header` over a URL's path, asked of one host's npm keys: an answer (the credentials review's CR-1 was a walk up a path that never ended on one that starts with `//`); the key of the longest path that covers the path read three ways, as it is sent, with its dot segments resolved and as a server that decodes it may route it (CR-2, CR-9); `normal_path` a path with no dot segment (`%2e` spellings included) and no backslash, which it leaves as it is; the same answer twice |

## Findings

Found in the registry modules (wave 2) and fixed, with regression tests: **F-8** an error message that quotes a name or a version could be over 1,200 characters (`base.show` cut the text, not its escapes: `\udcff`, `\U0010ffff` are 6 to 10 characters each); **F-9** a Go module zip with two members that start at one place made CPython print a warning from `zip_h1` (the module now refuses such a zip).

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
