# Recorded registry responses

Real responses from public registries, kept so that a module's tests read the bytes the registry sent and not what
its author thought it sends. Nothing here is edited. A test that needs a changed document makes the change in code.

| Directory | What | Recorded |
|---|---|---|
| `crates/` | `fnv.index`: the whole sparse-index file of `fnv` (`https://index.crates.io/3/f/fnv`). `inflector.index`: the last three lines of `https://index.crates.io/in/fl/inflector`, whose `name` is `Inflector` (the file name is lowercase, the name and the download URL are not). `paste-1.0.15.index`: one line, with a dev dependency list and `rust_version`. `fnv-1.0.7.crate`: the file at `https://static.crates.io/crates/fnv/fnv-1.0.7.crate` (its SHA-256 is the `cksum` in `fnv.index`). `*.Cargo.toml`: the manifest cargo wrote into the `.crate` (`fnv` has its library at `lib.rs`; `paste` is a proc-macro crate with a `build.rs`). `*.members`: the member list of the `.crate`. | Oct 3, 2026 |

Only `fnv`'s archive is stored (its Cargo.toml says `Apache-2.0 / MIT`; the licence files are inside it); of `paste` and `Inflector` only the index lines and `paste`'s manifest and member list are kept. To record again: `curl -o <name> <the URL above>`.
