# tiny_https in Lazaret

This folder is tiny_https 0.1.0, the HTTPS/TLS library Lazaret's network layer is built on, as it was handed
over: nothing in it is edited by hand. `scripts/sync_tiny_https.py` took it on 2026-10-08 from `tiny_https-2026-10-08l.tgz`
(SHA-256 `d94f7c43411b4ee7bedc84cf569fb4487c7d770a3a9684bae624cd38b5498c0d`): 579 files, 11,828,074 bytes. Its licence is Apache-2.0 (`LICENSE`), as
Lazaret's is.

- **What is here:** `Cargo.toml`, `LICENSE`, `README.md`, `BACKLOG.md`, `src/`, `tests/`, `examples/` and `roots/`
  (the trust roots it builds in: Sigstore's TUF root, always, and Mozilla's root store for the `mozilla-roots`
  feature, which Lazaret does not use), and `SECURITY_REVIEW.md` (the brief for the library's security review) when
  the drop has one.
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
- **What Lazaret asks of it:** TLS 1.3, and TLS 1.2 with a server that speaks nothing newer (the library's
  default minimum: ECDHE with AEAD suites only, the extended master secret required, the downgrade check);
  HTTP/2 or HTTP/1.1; never the opt-in extras (`Content-Encoding` decoding, cookies, `Expect: 100-continue`) and
  never HTTP/3 (`rust/crates/lazaret-net`).
- **Its tests in Lazaret's CI:** `cargo test --release -p tiny_https --lib` and the tests that need nothing
  installed (`go_vectors`, `cms_vectors`, `sigstore_real`, `sigstore_synthetic`, `rekor_real`, `real_chains`,
  `inflate_vectors`; `real_chains` replays chains captured from real servers when `tests/data/real_chains/` is
  in the drop, and skips without it).
