# Security review brief: the verification path of tiny_https

For: a security-review agent (or a human reviewer) asked to find out whether this code can be trusted to say "yes, this is authentic" and to say "no" when it is not.
Written: 2026-10-06, against the drop that contains this file. Counts below were measured on that drop; re-measure before you quote them.

## 1. The story

`tiny_https` is an HTTPS client written from scratch in Rust with no dependencies (only `std`). It has its own TLS 1.3 (and TLS 1.2 for servers that speak nothing newer), X.509 validation, signature verification and HTTP stack. Its main consumer is **Lazaret**, a supply-chain security tool that checks Python and JavaScript packages before they are used. Lazaret asks this library to do three kinds of thing that matter:

1. **Say whether a signature, a certificate chain or an attestation is real.** An npm or PyPI package arrives with a Sigstore attestation; a Go module has a line in the Go checksum database; a Java archive has a CMS signature. The library checks the cryptography and the chain of trust, and returns facts (who signed, what, when) for Lazaret's policy to judge.
2. **Fetch things over TLS** from package registries, with an egress policy that limits which hosts a module may reach and which credentials go to which host (`Client::allowed_hosts`, `url_limits`, `hop_headers`).
3. **Stay quiet and bounded** when the bytes it is given are hostile: no panic, no unbounded memory, no unbounded time.

The worst thing this code can do is **accept something it should refuse**: a forged signature, a certificate that does not chain to a trusted root, a transparency-log proof for a record that is not in the log, an attestation whose signer was not who it says. Everything else (a wrong refusal, a slow request) is a smaller failure. A wrongly accepted artifact is the kind of failure Lazaret exists to prevent, so this library must not be the weak link.

The project's honest position, which is also what the README says: **this is unaudited, hand-written cryptography and parsing, and nobody outside the project has reviewed it** (backlog item B-23). Lazaret's rule is that it will not rely on the hand-written TLS until it has been independently reviewed. This document is the first step of that: it tells you what the code claims, what has been done to check it, what has not, and where we would attack it first.

One thing about how the evidence was produced, so you can weigh it: the code, its unit tests and the generators of its fixtures come from one development process. A test that passes shows the code agrees with the author's reading of a specification, which is weak evidence of correctness. Agreement with an implementation the project did not write (OpenSSL, Go, the JDK's `jarsigner`, Python `cryptography`, aioquic, real data from real services) is strong evidence, and most of what follows is sorted that way. Please treat the author's tests as hints about where to look, not as proof.

### What this review is, and is not

This brief asks for **Phase 1**: the *pure verification path*, 22 source files, about 9,500 lines of code and doc comments plus about 6,500 lines of in-file tests. It is the right place to start for three reasons. Its failures are the consequential kind (wrong acceptance). It is the smallest piece. And it is built with `#![forbid(unsafe_code)]`, no I/O, no threads, no clock and no dependencies, so you can read it as plain functions from bytes to verdicts, and it compiles to `wasm32-unknown-unknown`.

Phase 2 (the TLS client, the record layer, the constant-time code, the HTTP stack, the egress policy, QUIC and HTTP/3) and Phase 3 (the test server and anything that signs) are **not** in scope here; section 9 says what is in them so you can see the boundary.

## 2. What we ask of you

Deliver, in this order of importance:

1. **A list of findings.** For each: an id, a severity, `file:line`, which claim in section 5 it breaks (or "none: a new one"), a **reproducer** (a failing test, a fuzz input, or a byte string and the call that mishandles it), what the correct behaviour is, and a suggested fix. A finding without a reproducer is a hypothesis; label it so.
2. **A scorecard of the claims in section 5**: for each, *holds*, *broken (see finding N)* or *could not determine*, and in one or two sentences what you did to decide. "Could not determine" is a useful answer; please do not round it up to "holds".
3. **Answers to the questions in section 8**, even if you find nothing wrong.
4. **What you would do next**: where the evidence is thinnest, and what independent check would be cheapest to add.

Severity: **Critical** = a wrongly accepted signature, chain, proof or attestation, reachable from attacker-controlled bytes. **High** = a panic, abort, unbounded loop or unbounded allocation reachable from attacker bytes in the pure path; or a verdict that differs from the reference implementation in a way an attacker can steer (a parser differential). **Medium** = a policy gap or a check that is documented and missing. **Low** = wrong documentation, misleading error text, hardening.

Rules of engagement. Work offline: every fixture is in the repository and none of the tests below needs the network. Do not edit files under `src/`; write reproducers as new files (a new `tests/review_*.rs` can use the public API) or as patches. All fixture keys and certificates are public test data. Run test suites one at a time; the pure suite takes about 10 seconds and the whole library suite about 30 seconds on a laptop-class machine.

## 3. How the pieces fit

```
bytes from a server / a registry / a file            what the caller supplies and trusts
(untrusted)                                          (trust anchors, pinned keys, "now")
        |                                                         |
        v                                                         v
   asn1 / ber / pem / json  --parse-->  x509 (chains) ----+---> verdict
                                         revocation       |
                                         cms (signed data, time stamps)
                                         note, tlog, sumdb (transparency logs)
                                         trust_root, sigstore (attestations)
                                              |
                                              v
        crypto: sha1 sha2 bignum rsa ecdsa ed25519 (fe25519)   [verification only]
```

Trust boundaries. Everything that arrives from a network or a file is untrusted. The things the library trusts are what the caller passes in: the **trust anchors** (a `TrustStore`), the **pinned keys** (the Go checksum database key, Sigstore's `trusted_root.json`, npm's key list) and **the time** (the pure code never reads a clock; the caller says what time to validate at). Where a time comes from the data (a time stamp, a log entry), the library only believes it after the authority that vouches for it has been verified.

The pure build knows nothing about revocation *fetching*: `revocation` checks evidence it is given (a staple, a CRL), and never contacts a responder.

## 4. Threat model

**Attackers we assume.**

* One who controls every byte the library reads: a malicious or compromised registry, CDN, proxy or man-in-the-middle, and the publisher of a malicious package.
* One who can pick or craft certificates, signatures, JSON, BER/DER, tiles and proofs freely, including ones no honest tool would write (non-canonical encodings, duplicate fields, huge lengths, deep nesting).
* One who holds a certificate legitimately issued to them by a trusted CA, or a Sigstore identity of their own. The library must say *who* signed; whether that identity is acceptable is the caller's policy and not this review's concern.

**Attackers we do not assume.** One who can modify the machine running the code, the trust anchors or pinned keys the caller supplies, or the caller's clock. One who has stolen a trusted CA's or log's private key (the library cannot tell).

**Out of scope for Phase 1.** Side channels (the verification code handles public data and is variable time by design; the constant-time code is in Phase 2), the TLS handshake, the network stack, denial of service by sending a lot of data (but see claim C3 on bounded work for a given input), and Lazaret's own policy.

## 5. The claims to falsify

These are what the code promises. Each one names where it is enforced, what evidence exists, and how we would try to break it. Please try to break them.

| id | Claim | Where | Evidence so far | Where we'd push |
|---|---|---|---|---|
| C1 | A certificate chain is accepted only if every certificate is signed by the next, each is valid at the time the caller gave, the last is a trust anchor in the store, every issuing certificate is a CA whose key usage allows signing and whose extended key usage allows the purpose, `pathLenConstraint` holds, name constraints on the leaf's alternative names hold, there is no unknown critical extension, an RSA key below the store's minimum (2048 bits by default, anchors exempt) is refused, SHA-1 signatures are refused, a BOOLEAN that is not `00` or `ff` makes a certificate invalid, building the path takes at most 256 signature checks (and the answer is then a refusal), and for TLS the host name matches a subject alternative name (no common-name fallback). | `x509.rs`: `TrustStore::verify_chain`, `build_path`, `search`, `check_path`, `Certificate::from_der` | Fixture tests for each rule (OpenSSL and Python `cryptography` made them); a real Fulcio chain at its logged time and a real Apple code-signing chain; all 122 supported self-signatures among the 128 roots of the system store this was recorded on verify (`tests/system_roots.rs` reads whatever store the machine has); 52 real chains captured by OpenSSL on a normal network (47 that verify, ending at 9 different roots, and 5 that must be refused), each replayed at its capture time with every alteration (another host, a time outside the validity, flipped bits) refused (`tests/real_chains.rs`, B-97); fuzz targets `certificate`, `chain`, `purpose_chain` assert that a changed chain is never accepted; deterministic mutation fuzzers in `cargo test --lib`. | Path building with several candidates for one issuer name (it was exponential before B-93; is 256 the right budget, and can a legitimate chain with cross-signed intermediates need more?); self-issued and cross-signed intermediates; a version 1 anchor, which is a CA by being in the store (the one exemption from the `basicConstraints` rule); names in intermediates (constrained by the CAs above them since the second round, see section 7); unusual encodings of names, times and serial numbers; anything where a *later* check could be skipped because an *earlier* candidate path failed. |
| C2 | A signature verifies if and only if it is valid under the rules written in the module (RSA PKCS#1 v1.5 and PSS, ECDSA P-256 and P-384 over SHA-256/384/512, Ed25519 with the rules of Go's `crypto/ed25519`). There is no encoding that makes one signature verify in two forms, except where the module documents it. | `crypto/rsa.rs`, `crypto/ecdsa.rs`, `crypto/ed25519.rs`, `crypto/bignum.rs`, `crypto/fe25519.rs` | RFC and NIST vectors; signatures made by OpenSSL; for Ed25519, 1,048 generated vectors each with Go's verdict (OpenSSL agrees on every one) and 128 known-answer signatures; the ECDSA code is compared on random inputs with an older, simpler implementation kept under `cfg(test)`; the group arithmetic against an independent Python implementation. | **Project Wycheproof vectors have not been run.** DER-encoded ECDSA signatures (leading zeros, negative integers, trailing data, `r` or `s` equal to 0 or at or above the order), the point at infinity, points not on the curve, RSA PKCS#1 padding edge cases (the Bleichenbacher-style "short digest info" and extra-data forms), PSS salt lengths, an RSA exponent of unusual size, Montgomery reduction edge cases in `bignum`. |
| C3 | No input makes the parsers panic, abort, loop without end, recurse deeply or allocate in proportion to something other than the input's own size. | `asn1.rs`, `ber.rs`, `pem.rs`, `json.rs` and every `parse` of the others | Depth limits (BER 48, JSON 32 by default); the 19 Phase 1 coverage-guided fuzz targets (of 43; `der`, `certificate`, `hostname`, `chain`, `purpose_chain`, `ed25519`, `note`, `tlog`, `sumdb`, `ber`, `cms`, `json`, `sigstore`, `trust_root`, `pem`, `crl`, `ocsp`, `revocation_path`, `inflate`) with a counting allocator that reports an input that makes the target allocate far more than its size; deterministic mutation fuzzers; an earlier panic audit (B-13) that found two real panics. | Length fields that are almost the size of the address space; counts that multiply (a SET of many names, each with a constraint); quadratic behaviour in name-constraint checks (path building is bounded by a budget of 256 signature checks since B-93); `usize` arithmetic on 32-bit targets (the code is also built for wasm32). |
| C4 | CMS `SignedData`: a signer is accepted only if its signed attributes carry the digest of the content, the signature over them verifies for the signer's certificate, and the certificate chains at the right time (an RFC 3161 time stamp's time when there is one, else the caller's). SHA-1 is accepted only when the caller says so. | `cms.rs`, `ber.rs` | 45 messages made by OpenSSL and `jarsigner` verify; **1,886 damaged messages judged by `openssl cms -verify`** and replayed, each region of a message pinned as exactly OpenSSL's verdict, stricter, or deliberately more lenient (the leniencies are listed in the test); two fuzz targets. | The "deliberately more lenient" cases (what exactly are they?); the BER-to-DER re-encoding of the signed attributes, which is what the signature covers; certificates found by issuer-and-serial versus subject key identifier; the ESS signing-certificate attribute, which is **not** checked. |
| C5 | Revocation: OCSP and CRL evidence is used only if signed by the certificate's issuer (or a delegated responder the issuer signed that carries the OCSP-signing usage), names this certificate, and is within its window; CRLs it cannot interpret are never used. Soft-fail is the default and means missing or bad evidence is ignored; must-staple and hard-fail are stricter. | `revocation.rs` | 45 fixture files from an independent implementation; fuzz targets `crl`, `ocsp`, `revocation_path`; tests through the TLS client against `openssl s_server`. | The distance between "ignored because untrustworthy" and "ignored because forged": can a forged response ever *remove* a revocation that a good one established? CRL scope rules (issuing distribution point, delta, indirect). **Not run against real public CAs (B-65).** |
| C6 | Transparency logs: a signed note is accepted only if a signature by a key you gave verifies and no bad signature by such a key is present; an inclusion or consistency proof verifies only for the right leaf, index, size and root; tile data is trusted only after every tile has been authenticated against the signed root; two different roots for one size are a fork. | `note.rs`, `tlog.rs`, `sumdb.rs` | Real `sum.golang.org` data (tree heads, a lookup, tiles, real proofs); **2,070 valid and damaged cases judged by Go's own `sumdb` packages** and replayed; a made-up two-history log for forks; three fuzz targets. Stricter than Go in the places listed in the `sumdb` and `note` module docs (canonical Base64, plain decimals, the characters of module paths). | The "stricter than Go" list is the list of places this code could differ from the reference: is each really *only* stricter? Tile arithmetic at the right edge, partial tiles replaced by full ones, trees near 2^62 leaves. The module docs record that Go's `tlog` before x/mod 0.40.0 did not authenticate every tile (they cite CVE-2026-56865): please check that claim and that our replay of it is faithful. |
| C7 | Sigstore: an attestation verifies only if the DSSE envelope's single signature is by the signer's key (the Fulcio certificate's, or a ring key by id), every log entry in the bundle is about this envelope and is authenticated by a signed entry timestamp or an inclusion proof to a signed checkpoint from a log the trusted root lists (a present but wrong proof is an error even if the other is right), every time stamp is over the signature and from a listed authority, the only times believed are those verified, the signer was valid at one of them, and a subject of the statement has the digest the caller gave. | `sigstore.rs` (the module doc lists the six steps), `trust_root.rs`, `json.rs` | The six real npm attestations of three releases and PyPI's real provenance verify against Sigstore's production trusted root and npm's keys, and every member and string of every one, removed or changed in turn (about 1,700 changes), makes it fail unless nothing authenticates it; 86 bundles from a Sigstore of our own cover time stamps, an Ed25519 log, every key type and 62 refusals; a real attestation of Lazaret 0.1.8 is in `tests/data`; three fuzz targets. | What is **not** verified (signed certificate timestamps, `messageSignature` bundles, Rekor v2 entries, consistency between checkpoints). Whether "nothing authenticates it" is ever wrongly true. Identity extraction from the Fulcio certificate (which extension holds which fact, and whether two extensions can disagree). Validity windows read from `trusted_root.json` (rounding of fractional seconds). |
| C8 | JSON that a signature covers has one meaning: duplicate member names, lone surrogates, invalid UTF-8, leading zeros, floating-point numbers and nesting beyond the limit are refused; numbers are kept as text and read exactly; the canonical form follows RFC 8785 for the subset used. | `json.rs` | Vectors in `tests/data/json_vectors.txt`; fuzz target `json` with round-trip and canonical-form properties. | Differentials against `serde_json`, Python's `json` and V8's `JSON.parse` on the same bytes (we have not run these); the canonical form's ordering by UTF-16 code units; Protocol Buffers' string-encoded 64-bit integers. |
| C9 | The pure build has no `unsafe`, no I/O, no threads, no clock and no dependencies, and compiles for `wasm32-unknown-unknown`. | `src/lib.rs` (`#![cfg_attr(not(feature = "net"), forbid(unsafe_code))]`), `tools/check_features.sh` | The script scans the code (before the test module) of each of the 23 files for `unsafe`, `std::{fs,net,io,env,process,thread,os,ffi,path}`, clocks, printing and FFI, for `cfg` on a feature or a target, and for any mention of a `net` module; it checks that `Cargo.toml` has no dependencies; then it builds natively and for wasm32 and runs 297 tests. | That the list of pure files is complete and that the `net` feature cannot be switched on by something in the pure files; that `forbid` really covers every file listed. |
| C11 | Decompression is bounded and has one answer: `inflate` never writes a byte past `Limits::max_output` and refuses (never truncates) a stream that would pass it or the ratio limit; the bytes, or the error, do not depend on how the input and the output are cut; framing is as strict as zlib's (the zlib header and Adler-32, the gzip header, its CRC and its length, the CRC-32 and length of every member, complete Huffman codes but the single code of length one, nothing after the stream). | `inflate.rs` (`Inflater::inflate`, `room_for`, `check_ratio`, `Huff::build`), and its use for `Content-Encoding` in `http/decode.rs` (Phase 2) | 256 streams from zlib, gzip(1), zlib-flate, Go and by hand, each at 7 cuttings; 1,039 damaged copies, each with exactly zlib's verdict and bytes (Go differs only on reserved gzip flag bits, which it ignores); unit tests for every truncation, flipped bits, hand-made bad codes and both limits; a cut-invariance test of the ratio limit that fails on an earlier draft of it; a fuzz target and a mutation fuzzer. | Codes of 15 bits on the slow path with a fast table of 10; the window at its full 32 KiB and a distance of exactly 32,768; stored blocks that straddle the bit buffer; multi-member gzip with empty members; the ratio check's arithmetic near `u64::MAX`; the decoder's state after an error (it is meant to stay failed). |
| C10 | The public API makes the safe thing the easy thing: for example `verify_server_chain` requires a host name, and a verdict carries the path it took. | `x509.rs`, `cms.rs`, `sigstore.rs` public items | Doc comments and tests. | Any public function that returns `Ok` for something a caller would take as "verified" while a check is still the caller's job (revocation is a separate step; time is the caller's; identity policy is the caller's). Are those obligations stated where a caller will see them? |

## 6. The files, in the order we would read them

Line counts are the code and doc comments before the in-file tests, then the tests.

| order | file | code / tests | what it is | note |
|---|---|---|---|---|
| 1 | `src/asn1.rs` | 289 / 113 | strict DER reader | the foundation of everything that parses a certificate |
| 2 | `src/ber.rs` | 332 / 182 | BER reader for CMS | accepts indefinite lengths and constructed OCTET STRINGs; re-encodes to DER |
| 3 | `src/pem.rs`, `src/util.rs`, `src/verify_error.rs` | 130, 93, 35 | PEM and Base64, constant-time compare, errors | small |
| 4 | `src/crypto/bignum.rs` | 258 / 52 | big numbers, Montgomery arithmetic | public data only, not constant time |
| 5 | `src/crypto/sha2.rs`, `sha2_consts.rs`, `sha1.rs` | 265, 44, 71 | hashes | SHA-1 is `pub(crate)` and used only to name certificates in OCSP and to report weak CMS signatures |
| 6 | `src/crypto/rsa.rs` | 160 / 117 | PKCS#1 v1.5 and PSS verification | modulus 1024 to 8192 bits, odd exponent of 2 to 64 bits |
| 7 | `src/crypto/ecdsa.rs` | 648 / 707 | P-256 and P-384 verification | fixed-size limbs, interleaved windowed NAF, generator table, no conversion to affine for the final check; an older simple version under `cfg(test)` |
| 8 | `src/crypto/fe25519.rs`, `ed25519.rs` | 202, 273 | Ed25519 verification | the rules of Go's `crypto/ed25519`, written out in the module doc |
| 9 | `src/x509.rs` | 1,554 / 1,050 | certificates and chains | the centre of C1 |
| 10 | `src/revocation.rs` | 783 / 571 | OCSP and CRL checking | C5 |
| 11 | `src/json.rs` | 615 / 380 | strict JSON, canonical writer | C8 |
| 12 | `src/cms.rs` | 887 / 489 | CMS and RFC 3161 | C4 |
| 13 | `src/note.rs`, `src/tlog.rs`, `src/sumdb.rs` | 285, 670, 356 | signed notes, Merkle proofs and tiles, the Go checksum database | C6 |
| 14 | `src/trust_root.rs`, `src/sigstore.rs` | 592, 1,166 | the trust material and the attestation checker | C7 |
| 15 | `src/inflate.rs` | 1,251 / 1,259 | DEFLATE, zlib and gzip decompression | C11; it reads the bytes of package archives and of compressed HTTP bodies |

Entry points to start from: `x509::TrustStore::verify_chain` and `verify_server_chain`; `cms::SignedData::{parse, verify}`; `revocation` (`check_path`, `ChainEvidence`); `sumdb::Check`; `tlog::{verify_inclusion, verify_consistency, read_nodes}`; `note::open`; the three `verify(&self, trust, artifact) -> Result<Verified, _>` methods of `sigstore` (`NpmAttestation`, `Pep740Attestation` and a lone `Bundle`) with `trust_root::{TrustedRoot::parse, KeyRing::from_npm_keys}`; `crypto::rsa::RsaPublicKey::{verify_pkcs1, verify_pss, verify_pss_with}`, `crypto::ecdsa::{verify, verify_prehashed}` and `crypto::ed25519::verify` (each returns a plain `bool`).

## 7. Decisions we made on purpose, which you should challenge

Each of these is documented in the module where it lives. We would like to hear that a decision is wrong more than we would like to hear that it is documented.

* **Ed25519 follows Go and `ref10`, not RFC 8032's strictest reading.** The check is cofactorless; a non-canonical `y` of `p` or more and a zero `x` with the sign bit set are *accepted* in a public key; a small-order public key is accepted as a key (with the identity as key and `R`, `S` = 0 the equation holds for every message). The reason is that two verifiers that disagree on a signature are a danger where two parties must reach the same verdict (a log and its clients). Is that the right trade for this consumer?
* **Name constraints apply to the subject alternative names, and the `emailAddress` of the subject name (as OpenSSL does), of every certificate below the CA that carries them, intermediates included.** The rest of the subject distinguished name is not checked: a name constraint on directory names refuses the chain outright (this code does not compare names; ignoring the constraint would let a CA issue outside its subtree, which OpenSSL enforces and Go refuses as an unhandled critical extension). A constraint of another kind the code does not know, over a name of that kind, refuses the certificate; so does a name the reader had to leave out (x400Address, ediPartyName, a malformed or non-ASCII e-mail or URI) when a CA has a constraint of its kind. A DNS, e-mail or URI constraint that can never match (a trailing dot, an empty label) refuses the certificate that carries it; an empty one matches every name of its kind.
* **A trust anchor is a CA if it says so (`basicConstraints` with `cA`), or if it is a version 1 certificate**, which cannot carry the extension (some old roots are of that kind). OpenSSL and Go refuse a version 3 anchor without `basicConstraints`, and so does this code since B-93; before, any anchor without it could sign for anything. Anchors are exempt from the minimum RSA size. 
* **Names are compared as exact bytes** (anchors are found by the issuer name's DER bytes, intermediates by subject bytes), without the normalisation RFC 5280 describes. The failure mode should be a wrong refusal; please check that it cannot be a wrong acceptance.
* **Malformed extra certificates in a chain are skipped**, not fatal, so a bad intermediate cannot sink a chain that is good without it. Self-issued intermediates are never used as intermediates (a cross-signed or key-rollover certificate cannot be part of a path). Chains are at most 8 certificates, and a search for a path stops after 256 signature checks (Go stops after 100); a certificate that the server sends twice is one candidate.
* **There is no common-name fallback** for host names, and an unknown critical extension fails a certificate unless the caller says it interprets that OID.
* **Randomness: the operating system's, on every call, and no state.** On Linux `getrandom(0)`; only if the kernel refuses it (before 3.17, or a sandbox that answers ENOSYS or EPERM) `/dev/urandom`, after waiting up to a minute for `/dev/random` to report a seeded pool. Failure is an error, never a weaker source.
* **Revocation defaults to soft-fail.** Evidence that is missing or untrustworthy is ignored, except for a must-staple leaf. Hard-fail requires evidence only for the leaf.
* **Policy processing, RSA-PSS certificate signatures and SHA-1 signatures are not supported** (the last is refused on purpose). MD5, DSA and SHA-3 are refused by name in CMS.
* **CMS does not trust `signingTime`**, does not check the ESS signing-certificate attribute, and does not require the time-stamping usage to be the only one.
* **Sigstore does not verify signed certificate timestamps** (the Certificate Transparency side of Fulcio), only the Rekor entry and the time stamps; it believes a time only after the authority behind it has been verified, and needs at least one.
* **JSON and Base64 are stricter than most libraries** (canonical padded Base64; no duplicate names; no floating point), which can refuse bundles that other tools accept.
* **`sumdb` and `note` are stricter than Go in listed ways** and "none looser" is a claim you can test. One of them: a lookup whose record has no line for the module and version asked about is an error (`NoLineForVersion`), where Go's `Lookup` returns no lines and leaves it to the caller. One place where this follows Go and a reader might want it stricter: a repeated signature line by a known key is dropped before it is verified (`note::open`, as in Go's `note.Open`), so a good signature followed by a corrupted copy of one is accepted; the text is unchanged and was genuinely signed.

## 8. Questions we would like answered

1. Reading `build_path` and `check_path` as a whole: is there a way to make `verify_chain` return `Ok` with a path in which some certificate has not had *every* check applied (because it was reached on a different candidate path, as a trust anchor, or as the last element)?
2. Is there any input on which `Certificate::from_der` accepts a certificate that OpenSSL, Go's `crypto/x509` and a browser's verifier would each reject for a *security* reason (as opposed to a policy one), or the reverse?
3. Are the Ed25519 and ECDSA verifiers *complete* as well as sound, i.e. do they accept every signature the reference implementations accept that matters in practice (Sigstore's, Go's `sumdb`'s, CMS's)?
4. In `sigstore`, can an attacker who controls the whole bundle (but not the trusted root) get a `Verified` with a signer that is not the key or certificate that signed the DSSE envelope? What about two entries in one bundle, the first honest and the second not?
5. In `tlog` and `sumdb`: can any sequence of "honest log, one tile altered" or "two heads of different sizes with an inconsistent proof" be accepted?
6. What do the *errors* leak or confuse? (For example, does any error text echo attacker-controlled bytes in a way a caller might log unescaped?)
7. Which claim of section 5 is the least well supported by the evidence in section 10, and what is the cheapest independent check that would support it?

## 9. What is outside this review (and where it is)

For completeness, so you can see the boundary; none of it is Phase 1.

| phase | what | files | state of the evidence |
|---|---|---|---|
| 2 | TLS 1.3 client, record layer, KeyUpdate, HelloRetryRequest, the revocation hooks into the handshake; TLS 1.2 for servers that speak nothing newer (B-36: ECDHE with AEAD suites only, the extended master secret required, the downgrade check of RFC 8446 section 4.1.3, no renegotiation or resumption, the same chain, host-name and revocation checks; a minimum version per client and per request, which a request can only raise) | `src/tls/` (`tls12.rs` for 1.2) | interoperates with OpenSSL (47 tests, 12 of them TLS 1.2: every suite, key type and group, bulk both ways, revocation, and two men in the middle, one that takes TLS 1.3 out of the ClientHello, which the downgrade check catches, and one that takes the extended master secret out of the ServerHello, which is refused) and with Go's `crypto/tls` over TLS 1.2 (HTTP/1.1 and HTTP/2), and a third-party gateway; reproduces the RFC 8448 trace byte for byte; the TLS 1.2 PRF and records against published vectors and Python's `cryptography`; fuzz targets for records, handshake flights (1.3 and 1.2) and established connections of both versions |
| 2 | Constant-time code: X25519, P-256 and P-384 ECDH, GHASH, Poly1305, ChaCha20, AES (hardware and bitsliced), AEADs | `src/crypto/` (the rest), `src/zeroize.rs` | a dudect-style timing harness (`src/crypto/timing.rs`) with deliberately leaky positive controls and a negative control (identical classes), on x86-64 and an Apple M5 Max; a row that reads above 4.5 is repeated and fails if it comes back with the same sign (B-95); one row is flagged and unexplained on an Intel Xeon cloud VM (the 32-bit-limb Poly1305 with an all-zero key, a path 64-bit builds do not use); this is where `unsafe` lives (SIMD kernels, wiping secrets, OS randomness); an `aead` fuzz target compares vector kernels with portable code |
| 2 | HTTP/1.1, HTTP/2, HTTP/3 over QUIC, the egress policy (host rules, URL limits, per-hop credentials, the `Refused` error), and the opt-in extras of B-37: `Content-Encoding` decoding (`http/decode.rs`, over `inflate`), `Expect: 100-continue` and the cookie jar (`http/cookie.rs`, host-only) | `src/http/`, `src/quic/` | interop against Go's HTTP/2 server and aioquic; 44 fuzz targets in all; bombs, broken streams, the 100-continue wait and the cookie rules against scripted servers (47 tests); 184 deliberate bugs, all in the HTTP, QUIC and egress code and one in the ChaCha20-Poly1305 code, each caught by a test or a fuzz target |
| 3 | A TLS and HTTP/2 server, for tests only; anything that signs | `src/tls/server.rs`, `crypto/ed25519_sign.rs`, feature `server` | not a production component; not to be relied on |

## 10. The evidence, and how to rerun it

### What was done

| kind | what | independent of the author? |
|---|---|---|
| vectors | RFC and NIST vectors for hashes, RSA, ECDSA, Ed25519, ECDH, AEADs; 128 known-answer Ed25519 signatures | yes (published) |
| differential | 1,048 Ed25519 vectors with Go's verdicts; 2,070 `sumdb` cases judged by Go's packages; 1,886 damaged CMS messages judged by `openssl cms -verify`; 45 CMS messages from OpenSSL and `jarsigner`; 45 revocation fixtures from another implementation; HPACK and QPACK against Go, Python and `ls-qpack` | yes |
| real data | real `sum.golang.org` heads, tiles and proofs; six real npm attestations and one PyPI provenance, checked against production trust material; a real Fulcio chain; a real Apple chain; a real attestation of Lazaret 0.1.8; the roots of a system store | yes (the data), no (what we assert about it) |
| fixtures | certificates, CRLs, OCSP responses and Sigstore bundles generated by `tools/gen_*.py` with Python `cryptography` and OpenSSL: expiry, wrong host, non-CA issuer, `pathLen`, name constraints of four kinds, wrong purpose, a past validation time, tampering, 86 synthetic bundles with 62 refusals | partly: the generator and the checker share an author |
| fuzzing | 44 coverage-guided targets in `fuzz/` (18 of them are Phase 1: `der`, `certificate`, `hostname`, `chain`, `purpose_chain`, `ed25519`, `note`, `tlog`, `sumdb`, `ber`, `cms`, `json`, `sigstore`, `trust_root`, `pem`, `crl`, `ocsp`, `revocation_path`), each asserting something about the answer and not only "no panic"; deterministic mutation fuzzers inside `cargo test --lib` | the properties are the author's |
| deliberate bugs | `fuzz/mutate.py` breaks code on purpose and checks something notices: 184 bugs, **all in Phase 2 code (HTTP, QUIC, egress, one in an AEAD); none in Phase 1**. Some Phase 1 modules did their own one-off checks (five deliberate deviations of the Ed25519 rules each make the tests fail; every member and string of the real Sigstore bundles removed or changed in turn) | the author's |
| triage | two outside reports (6 findings on `tlog`, 11 on `x509`), each claim reproduced or refuted with a probe, the X.509 ones against `openssl verify` and Go's `crypto/x509`; the confirmed ones are fixed, with fixtures that differ in one thing each (`tools/gen_review_fixtures.py`, `tests/data/rv_fixtures.txt`; BACKLOG B-93). What it found in `x509`: an exponential search for a chain (seventeen certificates cost 63 ms, thirty-three ten seconds), a trust anchor without `basicConstraints` that could sign for anything, names the reader skipped escaping name constraints, a BOOLEAN `01` read as "not critical". | partly: OpenSSL and Go were the judges; the choice of cases was ours |
| triage, second round | three more outside reports (note, sumdb and tlog attacks; a side-channel review of `rand`, `timing`, `bignum`; the review summary), claim by claim, with Go's own `note` package as the judge for the note format and OpenSSL and Go for X.509 (BACKLOG B-94). Two claims did not hold (the duplicate signature line is Go's behaviour too; no tile width wraps), several overlapped the first round, and four things were fixed: directory-name constraints, names in intermediates, a lookup that answers a different question, and a timing harness that read a perfectly reproducible leak as none | partly, as above |
| triage, third look | a board of outside review cards (tile planning, `rand` fallback, X.509 acceptance, timing harness, `bignum`, ASN.1 times), each checked against the current tree (BACKLOG B-95, B-96). Most were findings already fixed or shown not to hold; a sweep of 1.27 million tile plans found no misshapen tile; the three bignum cards describe calls outside the contract of a module that is now crate-private, with no path from parsed input (12,000 rounds of malformed RSA and ECDSA input, no panic); the timing card on Ed25519 signing concerns a module that exists only for the test server and says it is not constant time. Fixed: a leap second (`:60`) in a certificate time; and the timing harness now repeats and fails a row that comes back above 4.5 with the same sign, which at once found a generator artifact in the AEAD row and one unexplained flagged row on an Intel Xeon VM (the 32-bit-limb Poly1305, a path 64-bit builds do not use). | the report cards; `src/asn1.rs`, `src/util.rs`, `src/crypto/timing.rs`, `src/tlog.rs` | repeat on a 32-bit host (B-58) |
| regressions | what fuzzing and tests found is listed in `fuzz/README.md`: a chunk-size overflow, a parse of `http://a:b:80/`, DER times such as 30 February, an OCSP parser that ignored parameters after the algorithm, and two remote panics on multi-byte UTF-8 | n/a |

### What has not been done

* **No systematic deliberate-bug check of Phase 1** (x509, revocation, cms, tlog, sumdb, sigstore, the signature code). Adding it is the cheapest way to learn how much the existing tests would notice; see `fuzz/mutants.py` for the format.
* **No Project Wycheproof vectors** for ECDSA, RSA or Ed25519.
* **No differential run of the JSON reader** against other parsers, and no differential run of the certificate parser and chain builder against OpenSSL or Go on a large corpus of real or generated certificates (what exists: the 128 roots, 52 real chains captured on one day from one network, and about 25 generated cases of the triage, each with one thing different; they found four real bugs, which suggests a larger run would find more).
* **Revocation has not been run against real public CAs** (B-65): 21 real OCSP responses and 46 real CRLs were captured on 2026-10-07 but are not yet replayed as fixtures, so its real-world evidence is still OpenSSL's and Python's.
* **No sanitizers.** Memory errors cannot occur in the pure build (`forbid(unsafe_code)`), but the fuzzer has no AddressSanitizer for the rest, because those need a nightly compiler.
* **Fuzz campaigns have been minutes to hours, not days**, and there is no record of a long campaign on the final code of every Phase 1 target.
* **No written threat model before this one**, and no external reader.

### Commands

```sh
# the pure build: static checks, native and wasm32 builds, 297 tests (a minute or two the first time, for the builds)
sh tools/check_features.sh
cargo test --lib --no-default-features                 # the 297 pure tests (about 15 s of testing, after the build)

# the whole library suite (about 30 s) and the integration suites, one at a time
cargo test --lib
cargo test --test go_vectors          # Ed25519 verdicts from Go
cargo test --test cms_vectors         # 1,886 damaged messages, OpenSSL's verdicts
cargo test --test sigstore_synthetic  # our own Sigstore
cargo test --test sigstore_real       # real npm and PyPI attestations (replayed offline)
cargo test --test rekor_real          # real Rekor data (replayed offline)
cargo test --test system_roots        # the 128 roots of a system store
cargo test --test real_chains         # 52 real chains, replayed at their capture time
cargo test --test inflate_vectors     # 256 streams from other compressors, 1,039 damaged ones with zlib's verdicts
TINY_HTTPS_FUZZ_SCALE=10 cargo test --lib              # ten times the deterministic mutation runs

# coverage-guided fuzzing (stable Rust; no nightly, no cargo-fuzz)
sh fuzz/run_all.sh check                                # does the coverage feedback work (2 s)
sh fuzz/run_all.sh 3600                                 # an hour, every target, all cores
sh fuzz/run_all.sh replay chain fuzz/artifacts/chain/crash-XXXX   # replay one saved input
python3 fuzz/mutate.py --list                           # the deliberate bugs (none in Phase 1)
```

The generators in `tools/` (`gen_fixtures.py`, `gen_cms_fixtures.py`, `gen_sigstore_fixtures.py`, `gen_revocation_fixtures.py`, `gen_tlog_vectors.sh`, `go_oracle.sh`, `ed25519_vectors.py`) need Python's `cryptography`, `openssl`, the JDK and Go; the committed fixtures are what the tests use, so you do not need any of them to rerun the suites. `tools/go_oracle.sh` runs Go's `sumdb` and `note` packages as an independent judge; note its warning about the `tlog` package of `x/mod` before v0.40.0.

## 11. A suggested plan

If you have a limited budget, here is the order in which we think the hours pay most.

1. **Read `asn1.rs`, then `x509.rs` end to end**, and answer question 1 of section 8. This is the code whose failure is a wrongly accepted chain, and it is where one author's misreading of RFC 5280 is most likely.
2. **Run a deliberate-bug pass over `x509.rs`, `ecdsa.rs`, `ed25519.rs`, `tlog.rs` and `sigstore.rs`** (a one-line change that makes a check weaker, then see whether any test fails). Every change that survives is a missing test, and some will be a missing check.
3. **Feed the signature code the Wycheproof vectors** for ECDSA P-256/P-384 (DER and P1363), RSA PKCS#1 v1.5 and PSS, and Ed25519, and list every disagreement with the expected verdict.
4. **Differential-test chain validation** against OpenSSL (`openssl verify`) and Go (`crypto/x509`) on generated certificates that vary one thing at a time (names, extensions, validity, key usage, path length, constraints) and on the 128 real roots, and list every disagreement for a security reason.
5. **Attack `sigstore.rs` as a whole**: take the real bundles and change each part in ways the existing "remove or change every member" pass does not (swap an entry between two bundles; two entries; a certificate chain with a different leaf; a timestamp from another envelope).
6. **Read `cms.rs` against `ber.rs`** for the re-encoding of signed attributes, and list the "more lenient than OpenSSL" cases from the test with a one-line judgement of each.
7. **Then** read the transparency-log code against Go's, and the JSON reader against two other parsers.

## 12. Glossary

* **Pure build**: `default-features = false`: the 22 verification files, no `net` feature, no `unsafe`, no I/O.
* **Trust anchor**: a root certificate the caller trusts; `TrustStore` holds them.
* **Oracle**: an implementation the project did not write, used to judge cases (OpenSSL, Go, the JDK, Python `cryptography`).
* **Tile**: a static file of consecutive hashes of a transparency log's Merkle tree; the Go checksum database serves its tree as tiles.
* **DSSE**: the signing envelope Sigstore uses (a payload type, a payload and signatures over their pre-authentication encoding).
* **Fulcio, Rekor**: Sigstore's certificate authority and its transparency log.
* **B-nn**: an item of `BACKLOG.md`. B-23 is the independent review this document prepares for; B-65 is revocation against real CAs; B-71 is Sigstore; B-70 is CMS.
