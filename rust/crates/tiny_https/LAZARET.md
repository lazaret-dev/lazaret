# tiny_https in Lazaret

This folder is tiny_https 0.1.0, the HTTPS/TLS library Lazaret's network layer is built on, as it was handed
over: nothing in it is edited by hand. `scripts/sync_tiny_https.py` took it on 2026-10-06 from `tiny_https-2026-10-06b.tgz`
(SHA-256 `3f12f0d386048b15134ac769020f3f4a27279ace4a8ef769508bc1b2433febe2`): 307 files, 7,515,951 bytes. Its licence is Apache-2.0 (`LICENSE`), as
Lazaret's is.

- **What is here:** `Cargo.toml`, `LICENSE`, `README.md`, `BACKLOG.md`, `src/`, `tests/` and `examples/`.
- **What was left out:** the fuzzer and its corpus (`fuzz/`), the generators and oracles (`tools/`), the
  library's own `Cargo.lock`, and build output. Two of the library's interoperability tests use files in
  `tools/` when Go or aioquic is installed (`tests/h2_client_interop.rs`, `tests/h3_client_interop.rs`); they
  skip without them, and Lazaret's CI does not run them.
- **The one change:** `Cargo.toml` without its `[profile.*]` tables. A workspace member's profiles are ignored
  (the workspace's, in `rust/Cargo.toml`, apply) and cargo warns about each one.
- **Lazaret's crates on it:** `lazaret-verify` (the pure part: `default-features = false`, no I/O, no `unsafe`;
  the engine and the WebAssembly build may use it) and `lazaret-net` (the network: Lazaret's host rule, URL
  limits, timeouts and byte budgets, and credentials given to each hop's own host through `Client::hop_headers`;
  linked into the native library only). `scripts/check_rust_deps.py` refuses the engine linking the network part.
- **The next drop:** `python3 scripts/sync_tiny_https.py PATH` (the library's folder or a tarball of it), then
  the gates. `python3 scripts/sync_tiny_https.py --verify` checks this folder against `vendored.sha256` (CI does).
- **Its tests in Lazaret's CI:** `cargo test --release -p tiny_https --lib` and the tests that need nothing
  installed (`go_vectors`, `cms_vectors`, `sigstore_real`, `sigstore_synthetic`, `rekor_real`).
