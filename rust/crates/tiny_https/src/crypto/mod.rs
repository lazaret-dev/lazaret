//! Cryptographic primitives, written from scratch using only `std`.
//!
//! None of this has been independently audited. See the crate README for caveats.
//!
//! The verification primitives (SHA-1/2, big numbers, RSA and ECDSA verification) are always built and
//! are free of `unsafe`. Everything TLS needs beyond them (HMAC and HKDF, AES and GCM, ChaCha20-
//! Poly1305, X25519, ECDH, the operating system's random numbers, the SIMD kernels, and wiping the
//! hash states) is behind the `net` feature.

// ---- pure (always built)
pub(crate) mod bignum;
pub mod ecdsa;
pub mod ed25519;
pub(crate) mod fe25519;
pub mod rsa;
pub(crate) mod sha1;
pub mod sha2;
mod sha2_consts;
#[cfg(test)]
pub(crate) mod test_vectors;

// ---- behind `net`
#[cfg(all(test, feature = "net"))]
pub(crate) mod aead_vectors;
#[cfg(feature = "net")]
pub mod aes;
#[cfg(feature = "net")]
mod aes_ct;
#[cfg(feature = "net")]
mod aes_hw;
#[cfg(feature = "net")]
pub mod chacha20poly1305;
#[cfg(feature = "net")]
pub mod ecdh;
#[cfg(any(test, feature = "server"))]
pub mod ed25519_sign;
#[cfg(all(test, feature = "net"))]
pub(crate) mod ecdh_vectors;
#[cfg(feature = "net")]
pub mod gcm;
#[cfg(feature = "net")]
pub mod hmac;
#[cfg(feature = "net")]
mod ghash;
#[cfg(feature = "net")]
mod poly1305;
#[cfg(feature = "net")]
pub mod rand;
#[cfg(feature = "net")]
mod sha2_wipe;
#[cfg(feature = "net")]
pub mod x25519;
#[cfg(all(test, feature = "net"))]
mod timing;

/// Entry points for the coverage-guided fuzzer in `fuzz/`; compiled only with `--cfg tiny_https_fuzzing`. Not part of the API.
#[cfg(all(tiny_https_fuzzing, feature = "net"))]
#[doc(hidden)]
pub mod fuzz_hooks {
    pub use super::fuzz_aead::{aead, example_inputs as aead_example_inputs};
}
#[cfg(all(tiny_https_fuzzing, feature = "net"))]
mod fuzz_aead;
