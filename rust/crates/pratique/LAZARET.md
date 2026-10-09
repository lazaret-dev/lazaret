# pratique in Lazaret

This folder is pratique 0.1.0, the HTTPS/TLS library Lazaret's network layer is built on, as it is upstream:
nothing in it is edited by hand. Its repository is https://github.com/lazaret-dev/pratique; it was called tiny_https until October 2026.

- **Taken** on 2026-10-08 by `scripts/sync_pratique.py`, from commit `7d7bc1090be6ae379daec2dcabd82a80492719c8` (its files as git holds them): 583 files, 11,981,585 bytes.
- **Licence:** Apache-2.0 (`LICENSE`), as Lazaret's is. `NOTICE` keeps the notices of what the library holds from
  elsewhere: Mozilla's root store (`roots/mozilla.pem`) is under the Mozilla Public License 2.0, as NSS is, and
  BearSSL's MIT notice goes with two of its crypto files.
- **What is here:** `Cargo.toml`, `LICENSE`, `NOTICE`, `README.md`, `BACKLOG.md`, `SECURITY_REVIEW.md` (the brief
  for the library's security review), `src/`, `tests/`, `examples/` and `roots/` (the trust roots it builds in:
  Sigstore's TUF root, always, and Mozilla's root store for the `mozilla-roots` feature, which Lazaret does not
  use and no package of Lazaret's carries).
- **What was left out:** the fuzzer and its corpus (`fuzz/`), the generators and oracles (`tools/`), the benchmarks
  against other libraries (`bench/`), the library's own `Cargo.lock`, and build output. Two of the library's
  interoperability tests use files in `tools/` when Go or aioquic is installed (`tests/h2_client_interop.rs`,
  `tests/h3_client_interop.rs`); they skip without them, and Lazaret's CI does not run them.
- **The one change:** `Cargo.toml` without its `[profile.*]` tables. A workspace member's profiles are ignored
  (the workspace's, in `rust/Cargo.toml`, apply) and cargo warns about each one.
- **Lazaret's crates on it:** `lazaret-verify` (the pure part: `default-features = false`, no I/O, no `unsafe`;
  the engine and the WebAssembly build use it) and `lazaret-net` (the network: Lazaret's host rule, URL
  limits, timeouts and byte budgets, and credentials given to each hop's own host through `Client::hop_headers`;
  linked into the native library only). `scripts/check_rust_deps.py` refuses the engine linking the network part.
- **The next take:** `python3 scripts/sync_pratique.py PATH [--rev REV]` (a checkout of https://github.com/lazaret-dev/pratique: the commit's
  files, with the commit recorded here; or a folder or tarball of the library), then the gates.
  `python3 scripts/sync_pratique.py --verify` checks this folder against `vendored.sha256` (CI does).
- **What Lazaret asks of it:** TLS 1.3, and TLS 1.2 with a server that speaks nothing newer (the library's
  default minimum: ECDHE with AEAD suites only, the extended master secret required, the downgrade check);
  HTTP/2 or HTTP/1.1; never the opt-in extras (`Content-Encoding` decoding, cookies, `Expect: 100-continue`) and
  never HTTP/3 (`rust/crates/lazaret-net`).
- **Its tests in Lazaret's CI:** `cargo test --release -p pratique --lib` and the tests that need nothing
  installed (`go_vectors`, `cms_vectors`, `sigstore_real`, `sigstore_synthetic`, `rekor_real`, `real_chains`,
  `inflate_vectors`; `real_chains` replays chains captured from real servers when `tests/data/real_chains/` is
  in the source, and skips without it).
