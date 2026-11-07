# RA-6 validation and scope

Base: DBG-STACK, `467bfbf1635b2db7a6fffd9418fe9be9b4245b94`, tree
`05b441dbe62f482b4e85a25dd457bbd2b3b50d3c`. Rule set: **2.95.0**.

The readers record deletion targets, then classify their resolved paths. Python and
JavaScript retain the path text in supply facts; Go and Rust retain `Val` in `Ev::Delete`.
Shell commands are parsed as commands, including quoted variables and local aliases.
Comments, example strings, `echo`, and `find` commands that do not delete their matches
are not deletion evidence. Command strings handed to an execution API are also read,
with source comment/string spans excluding prose that merely mentions the API.

Home and personal-file paths, filesystem/drive roots and recursive `.git` selections
produce `deletes the user's files`. Install/build/import severity is CRITICAL;
deletion-only use-time severity is MAJOR. Other strong reasons retain CRITICAL.

Ordinary relative build/dist paths, fixture trees, created temporary paths and named
application-cache subtrees are excluded. Cache-directory parents and wildcard/unknown
cache owners are not excluded. These are lexical conventions, not a claim to prove
ownership of arbitrary cache paths. Path joins, aliases, environment homes, Python
f-strings and JavaScript templates are bounded; resolution stops after eight levels
or 256 visited expressions. Unknown targets alone do not produce a finding. Dynamic
path construction and arbitrary custom traversal APIs remain subject to the existing
readers' limits. No host filesystem is consulted and no source fragment is run.

## Snapshots

Against the unmodified base, `scripts/snapshot.py` recordings gave:

| Set | Cases | Changed |
| --- | ---: | ---: |
| signs | 44,893 | 0 |
| hooks | 44,893 | 0 |
| hook_commands | 13,059 | 0 |

There are no moved cases to reclassify and no snapshot hashes to replace. New inert
regression cases are shared between Python and npm in `tests/fixtures/ra6-deletion.json`.
They cover positive paths and commands, alias/option boundaries, comments, fixture
cleanup, Unicode paths, and the negative cache/temp/build cases. Package tests cover
npm postinstall, setup.py, Python import, Go init, Rust build and use-time severities.

## Checks owed by John

The popular-set measurement (`bench.py all`) and any real malicious-package/holdout
measurements remain owed by John. None was fetched or scanned in this work. The local
checks do not establish the popular-set zero-CRITICAL acceptance criterion.

## Completed local validation

- 477 Rust engine tests passed, by module (linre individually), every invocation capped at 45 seconds.
- 18 Python modules passed (193 tests), including the three requested snapshots,
  reader snapshots, registry package moments, hook/install regressions, suppression integrity,
  rule-pack checks, native/WASM reader and signs parity, CLI hook parity and dashboard parity.
- Six npm modules passed, including the shared deletion corpus, package-hook severity cases,
  supply-chain signs, hook commands, project hooks and exfiltration regressions.
- Canonical rule pack check passed. Native release and WebAssembly builds completed; the embedded
  dashboard was rebuilt and its source/engine checks passed. Node 24.19 and Python 3.12 were used;
  a separate Node 22 run was not performed.
- The 256-expression path-resolution limit was exercised with an alias DAG that would otherwise
  expand exponentially. All test source was synthetic and inert.
