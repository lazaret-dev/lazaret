# scripts/profile: where the time goes, and a nightly check that it stays there

Added in 0.1.9 (P-10 of `audits/lazaret-profile-and-backlog-2026-10-03`). Standard library plus this checkout, and the
native engine (`cargo build --release` in `rust/`). They import `lazaret` from the tree they sit in, so a profile is of
the code you have checked out.

## The nightly check

`perf_check.py` and `packages.json`: the eight packages of the profile (litellm, botocore, requests, express,
playwright-core, typescript, next, eslint), each as the exact archives a registry scan reads, with their sha256.
`.github/workflows/perf.yml` runs it every night on the default branch.

```
python3 scripts/profile/perf_check.py fetch                 # download the pinned archives, refuse any other bytes
python3 scripts/profile/perf_check.py run --runs 3          # time the engine; --json report.json, --summary file
python3 scripts/profile/perf_check.py calibrate r1.json r2.json r3.json --write
python3 scripts/profile/perf_check.py pin npm:next@16.4.0   # add or move a package: resolve, download, hash
```

What is timed: only the engine. The archives are fetched and hashed first, then read into memory, so the network is
never in the numbers. Each run scans all the archives of a package (`repo._scan_artifact`, the call the guard makes);
the figure is the seconds spent inside the native engine summed over its threads, the median of three runs, with the
use-time step's 3-second box raised so that every run reads the same files (until P-14 bounds that step by work). One
unmeasured scan of the smallest archive comes first, for the engine's set-up.

Budgets start empty, and a package without one is reported and never failed. To calibrate: let the workflow run for a
week, download the `perf-report` artifacts of several nights, and run `calibrate` on them. It proposes each budget
as the median of the medians plus 25% (and at least 0.25 s), and with `--write` puts it in `packages.json`
together with the number of files scanned. From then on the job fails for a package over its budget, and reports "work
changed" when a scan reads a different number of files than the calibration saw. A schedule runs only from the
default branch, so the first real run is after the merge; `workflow_dispatch` runs it by hand.

## The profile harness

The scripts behind the numbers in the profile doc. Each prints what it measures, and `--help` says how to run it. A **cold**
run asks the registries and can keep their answers in `--cache DIR`; a **warm** run replays them, with no network in the
numbers.

| Script | Question it answers |
|---|---|
| `registry_scan.py` | Where does one registry scan spend its time: network, digest, archive reading, engine by call, other Python |
| `engine_replay.py hot` | Which files cost the engine the most, replayed one at a time |
| `engine_replay.py scaling` | How well does the engine scale from one thread to two on equal work |
| `thread_scaling.py` | The same on a whole scan (mind the 3-second box: `--box`) |
| `use_time_coverage.py` | How much of a package the use-time step reads before its box runs out |
| `release_overlap.py` | How much of a release (or of two versions) is the same bytes: what a cache by content could save |
| `guard_connections.py` | How many connections, and how much connect time, a guarded install costs; with and without `--keepalive` |
| `sca_bundle.py` | How much a scan pays to load `cve-bundle.json` whole against opening the indexed bundle built from it (`compare`: load and match seconds, peak memory, file size, and whether both give the same matches); `gen` makes a synthetic bundle the size of the real one |
