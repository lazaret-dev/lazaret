//! ChaCha20-Poly1305 AEAD (RFC 8439).
//!
//! Performance notes: the keystream is made four blocks at a time with SSE2 on x86_64 and NEON on aarch64 (baseline
//! features of those architectures, so no detection at run time); on x86_64, eight at a time with AVX2 and sixteen with
//! AVX-512 where the CPU has them (asked at run time; see the `avx2` and `avx512` modules for which CPUs); other targets
//! use a portable one-block loop. Poly1305 is in `poly1305.rs` (radix 2^64 on 64-bit targets). Encrypting and
//! authenticating in one pass, a chunk at a time, was tried (B-57) and gained nothing measurable on records of 1 to 16 KiB,
//! which stay in the L1 cache between the two passes; it would also have meant decrypting before the tag is checked.
//! Everything here is constant-time with respect to the key and data (no secret-dependent branches or table lookups).

use super::dit::Dit;
use super::poly1305::Poly1305;
use crate::util::ct_eq;
use crate::zeroize::{Zeroize, Zeroizing};

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn key_words(key: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| le32(&key[4 * i..4 * i + 4]))
}

fn nonce_words(nonce: &[u8; 12]) -> [u32; 3] {
    core::array::from_fn(|i| le32(&nonce[4 * i..4 * i + 4]))
}

// ---------------------------------------------------------------- ChaCha20, one block

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// One 64-byte keystream block.
fn chacha20_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&SIGMA);
    init[4..12].copy_from_slice(key);
    init[12] = counter;
    init[13..16].copy_from_slice(nonce);
    let mut s = init;
    for _ in 0..10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------- ChaCha20, four blocks at once
// Each backend exposes `AVAILABLE` and `xor4(key, counter, nonce, data)`, which XORs the keystream
// of blocks `counter .. counter + 4` into 256 bytes. The vector units are baseline features of
// their architectures (SSE2 on x86_64, NEON on little-endian aarch64), so there is no runtime detection; the
// cfg conditions below are exactly the guarantee the `unsafe` calls rely on. Everything else uses
// the portable one-block loop. A portable `[u32; 4]` lane version was tried first, but LLVM does
// not vectorise it (no vector rotate on SSE2) and it came out slower than the one-block loop.
//
// Build with `RUSTFLAGS="--cfg tiny_https_portable"` to force the portable path everywhere.

#[cfg(all(target_arch = "x86_64", target_feature = "sse2", not(tiny_https_portable)))]
mod simd {
    use super::SIGMA;
    use core::arch::x86_64::*;

    pub const AVAILABLE: bool = true;

    #[inline]
    #[target_feature(enable = "sse2")]
    fn rol<const L: i32, const R: i32>(x: __m128i) -> __m128i {
        _mm_or_si128(_mm_slli_epi32::<L>(x), _mm_srli_epi32::<R>(x))
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    fn quarter_round(x: &mut [__m128i; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = _mm_add_epi32(x[a], x[b]);
        x[d] = rol::<16, 16>(_mm_xor_si128(x[d], x[a]));
        x[c] = _mm_add_epi32(x[c], x[d]);
        x[b] = rol::<12, 20>(_mm_xor_si128(x[b], x[c]));
        x[a] = _mm_add_epi32(x[a], x[b]);
        x[d] = rol::<8, 24>(_mm_xor_si128(x[d], x[a]));
        x[c] = _mm_add_epi32(x[c], x[d]);
        x[b] = rol::<7, 25>(_mm_xor_si128(x[b], x[c]));
    }

    /// dst ^= v, as 16 bytes at an arbitrary alignment.
    #[inline]
    #[target_feature(enable = "sse2")]
    fn xor_into(dst: &mut [u8], v: __m128i) {
        let dst: &mut [u8; 16] = dst.try_into().unwrap();
        let p = dst.as_mut_ptr() as *mut __m128i;
        // SAFETY: `p` points to 16 valid bytes that we hold a unique reference to, and
        // `loadu`/`storeu` have no alignment requirement.
        unsafe { _mm_storeu_si128(p, _mm_xor_si128(_mm_loadu_si128(p), v)) }
    }

    #[target_feature(enable = "sse2")]
    fn xor4_sse2(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8; 256]) {
        let set = |w: u32| _mm_set1_epi32(w as i32);
        let init: [__m128i; 16] = [
            set(SIGMA[0]),
            set(SIGMA[1]),
            set(SIGMA[2]),
            set(SIGMA[3]),
            set(key[0]),
            set(key[1]),
            set(key[2]),
            set(key[3]),
            set(key[4]),
            set(key[5]),
            set(key[6]),
            set(key[7]),
            _mm_set_epi32(
                counter.wrapping_add(3) as i32,
                counter.wrapping_add(2) as i32,
                counter.wrapping_add(1) as i32,
                counter as i32,
            ),
            set(nonce[0]),
            set(nonce[1]),
            set(nonce[2]),
        ];
        let mut x = init;
        for _ in 0..10 {
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }
        // Word i of block j is lane j of x[i]. Transpose each group of four words so that one
        // register holds four consecutive words of one block, then XOR it into the data.
        for g in 0..4 {
            let a = _mm_add_epi32(x[4 * g], init[4 * g]);
            let b = _mm_add_epi32(x[4 * g + 1], init[4 * g + 1]);
            let c = _mm_add_epi32(x[4 * g + 2], init[4 * g + 2]);
            let d = _mm_add_epi32(x[4 * g + 3], init[4 * g + 3]);
            let t0 = _mm_unpacklo_epi32(a, b);
            let t1 = _mm_unpacklo_epi32(c, d);
            let t2 = _mm_unpackhi_epi32(a, b);
            let t3 = _mm_unpackhi_epi32(c, d);
            let rows = [
                _mm_unpacklo_epi64(t0, t1),
                _mm_unpackhi_epi64(t0, t1),
                _mm_unpacklo_epi64(t2, t3),
                _mm_unpackhi_epi64(t2, t3),
            ];
            for (j, row) in rows.into_iter().enumerate() {
                let off = 64 * j + 16 * g;
                xor_into(&mut data[off..off + 16], row);
            }
        }
    }

    pub fn xor4(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8; 256]) {
        // SAFETY: this module is only compiled when `target_feature = "sse2"` is enabled for the
        // whole build, so the CPU the program runs on has SSE2.
        unsafe { xor4_sse2(key, counter, nonce, data) }
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon", target_endian = "little", not(tiny_https_portable)))]
mod simd {
    use super::SIGMA;
    use core::arch::aarch64::*;

    pub const AVAILABLE: bool = true;

    /// Rotate left by `L` (and `R = 32 - L`): shift left, then shift-right-insert the original.
    #[inline]
    #[target_feature(enable = "neon")]
    fn rol<const L: i32, const R: i32>(x: uint32x4_t) -> uint32x4_t {
        vsriq_n_u32::<R>(vshlq_n_u32::<L>(x), x)
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn rol16(x: uint32x4_t) -> uint32x4_t {
        vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn quarter_round(x: &mut [uint32x4_t; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = vaddq_u32(x[a], x[b]);
        x[d] = rol16(veorq_u32(x[d], x[a]));
        x[c] = vaddq_u32(x[c], x[d]);
        x[b] = rol::<12, 20>(veorq_u32(x[b], x[c]));
        x[a] = vaddq_u32(x[a], x[b]);
        x[d] = rol::<8, 24>(veorq_u32(x[d], x[a]));
        x[c] = vaddq_u32(x[c], x[d]);
        x[b] = rol::<7, 25>(veorq_u32(x[b], x[c]));
    }

    /// dst ^= bytes of v (little-endian lane order), 16 bytes at an arbitrary alignment.
    #[inline]
    #[target_feature(enable = "neon")]
    fn xor_into(dst: &mut [u8], v: uint32x4_t) {
        let dst: &mut [u8; 16] = dst.try_into().unwrap();
        let p = dst.as_mut_ptr();
        // SAFETY: `p` points to 16 valid bytes that we hold a unique reference to; `vld1q_u8` and
        // `vst1q_u8` have no alignment requirement.
        unsafe { vst1q_u8(p, veorq_u8(vld1q_u8(p), vreinterpretq_u8_u32(v))) }
    }

    #[target_feature(enable = "neon")]
    fn xor4_neon(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8; 256]) {
        let set = |w: u32| vdupq_n_u32(w);
        let mut ctr = set(counter);
        ctr = vsetq_lane_u32::<1>(counter.wrapping_add(1), ctr);
        ctr = vsetq_lane_u32::<2>(counter.wrapping_add(2), ctr);
        ctr = vsetq_lane_u32::<3>(counter.wrapping_add(3), ctr);
        let init: [uint32x4_t; 16] = [
            set(SIGMA[0]),
            set(SIGMA[1]),
            set(SIGMA[2]),
            set(SIGMA[3]),
            set(key[0]),
            set(key[1]),
            set(key[2]),
            set(key[3]),
            set(key[4]),
            set(key[5]),
            set(key[6]),
            set(key[7]),
            ctr,
            set(nonce[0]),
            set(nonce[1]),
            set(nonce[2]),
        ];
        let mut x = init;
        for _ in 0..10 {
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }
        // Word i of block j is lane j of x[i]; transpose each group of four words (see the SSE2
        // version) so one register holds four consecutive words of one block.
        for g in 0..4 {
            let a = vaddq_u32(x[4 * g], init[4 * g]);
            let b = vaddq_u32(x[4 * g + 1], init[4 * g + 1]);
            let c = vaddq_u32(x[4 * g + 2], init[4 * g + 2]);
            let d = vaddq_u32(x[4 * g + 3], init[4 * g + 3]);
            let t0 = vreinterpretq_u64_u32(vtrn1q_u32(a, b)); // a0 b0 | a2 b2
            let t1 = vreinterpretq_u64_u32(vtrn2q_u32(a, b)); // a1 b1 | a3 b3
            let t2 = vreinterpretq_u64_u32(vtrn1q_u32(c, d)); // c0 d0 | c2 d2
            let t3 = vreinterpretq_u64_u32(vtrn2q_u32(c, d)); // c1 d1 | c3 d3
            let rows = [
                vreinterpretq_u32_u64(vtrn1q_u64(t0, t2)),
                vreinterpretq_u32_u64(vtrn1q_u64(t1, t3)),
                vreinterpretq_u32_u64(vtrn2q_u64(t0, t2)),
                vreinterpretq_u32_u64(vtrn2q_u64(t1, t3)),
            ];
            for (j, row) in rows.into_iter().enumerate() {
                let off = 64 * j + 16 * g;
                xor_into(&mut data[off..off + 16], row);
            }
        }
    }

    pub fn xor4(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8; 256]) {
        // SAFETY: this module is only compiled when `target_feature = "neon"` is enabled for the
        // whole build, so the CPU the program runs on has NEON.
        unsafe { xor4_neon(key, counter, nonce, data) }
    }
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "sse2", not(tiny_https_portable)),
    all(target_arch = "aarch64", target_feature = "neon", target_endian = "little", not(tiny_https_portable)),
)))]
mod simd {
    pub const AVAILABLE: bool = false;

    pub fn xor4(_key: &[u32; 8], _counter: u32, _nonce: &[u32; 3], _data: &mut [u8; 256]) {
        unreachable!("no vector backend on this target");
    }
}

// ---------------------------------------------------------------- ChaCha20, eight blocks at once (AVX2)
// x86-64 CPUs since 2013 (Haswell) and 2017 (Zen) have AVX2, which is not a baseline feature of the architecture: it is
// asked of the CPU at run time (`is_x86_feature_detected!`, which the standard library caches). Eight blocks are made in
// the eight 32-bit lanes of sixteen 256-bit registers; the rotations by 16 and 8 bits are byte shuffles. Constant time like
// the rest: the same instructions whatever the key and the data.

#[cfg(all(target_arch = "x86_64", not(tiny_https_portable)))]
mod avx2 {
    use super::SIGMA;
    use core::arch::x86_64::*;

    /// Whether the CPU this runs on has AVX2.
    #[inline]
    pub fn available() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn rol<const L: i32, const R: i32>(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi32::<L>(x), _mm256_srli_epi32::<R>(x))
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn quarter_round(x: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize, rot16: __m256i, rot8: __m256i) {
        x[a] = _mm256_add_epi32(x[a], x[b]);
        x[d] = _mm256_shuffle_epi8(_mm256_xor_si256(x[d], x[a]), rot16);
        x[c] = _mm256_add_epi32(x[c], x[d]);
        x[b] = rol::<12, 20>(_mm256_xor_si256(x[b], x[c]));
        x[a] = _mm256_add_epi32(x[a], x[b]);
        x[d] = _mm256_shuffle_epi8(_mm256_xor_si256(x[d], x[a]), rot8);
        x[c] = _mm256_add_epi32(x[c], x[d]);
        x[b] = rol::<7, 25>(_mm256_xor_si256(x[b], x[c]));
    }

    /// dst ^= v, as 32 bytes at an arbitrary alignment.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn xor_into(dst: &mut [u8], v: __m256i) {
        let dst: &mut [u8; 32] = dst.try_into().unwrap();
        let p = dst.as_mut_ptr() as *mut __m256i;
        // SAFETY: `p` points to 32 valid bytes that we hold a unique reference to, and `loadu`/`storeu` have no alignment
        // requirement.
        unsafe { _mm256_storeu_si256(p, _mm256_xor_si256(_mm256_loadu_si256(p), v)) }
    }

    #[target_feature(enable = "avx2")]
    fn xor8_avx2(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8; 512]) {
        let set = |w: u32| _mm256_set1_epi32(w as i32);
        // (byte shuffles that rotate each 32-bit word left by 16 and by 8 bits; the same in both 128-bit halves)
        let rot16 = _mm256_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
        let rot8 = _mm256_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
        let init: [__m256i; 16] = [
            set(SIGMA[0]),
            set(SIGMA[1]),
            set(SIGMA[2]),
            set(SIGMA[3]),
            set(key[0]),
            set(key[1]),
            set(key[2]),
            set(key[3]),
            set(key[4]),
            set(key[5]),
            set(key[6]),
            set(key[7]),
            // block j has the counter + j (wrapping, as the scalar code's)
            _mm256_add_epi32(set(counter), _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0)),
            set(nonce[0]),
            set(nonce[1]),
            set(nonce[2]),
        ];
        let mut x = init;
        for _ in 0..10 {
            quarter_round(&mut x, 0, 4, 8, 12, rot16, rot8);
            quarter_round(&mut x, 1, 5, 9, 13, rot16, rot8);
            quarter_round(&mut x, 2, 6, 10, 14, rot16, rot8);
            quarter_round(&mut x, 3, 7, 11, 15, rot16, rot8);
            quarter_round(&mut x, 0, 5, 10, 15, rot16, rot8);
            quarter_round(&mut x, 1, 6, 11, 12, rot16, rot8);
            quarter_round(&mut x, 2, 7, 8, 13, rot16, rot8);
            quarter_round(&mut x, 3, 4, 9, 14, rot16, rot8);
        }
        // Word i of block j is lane j of x[i]. A 4x4 transpose in each 128-bit half of a group of four words gives, for
        // each j < 4, a register with those words of block j in its low half and of block j + 4 in its high half; two
        // groups' halves put together make 32 consecutive bytes of one block.
        let mut rows = [[_mm256_setzero_si256(); 4]; 4];
        for (g, row) in rows.iter_mut().enumerate() {
            let a = _mm256_add_epi32(x[4 * g], init[4 * g]);
            let b = _mm256_add_epi32(x[4 * g + 1], init[4 * g + 1]);
            let c = _mm256_add_epi32(x[4 * g + 2], init[4 * g + 2]);
            let d = _mm256_add_epi32(x[4 * g + 3], init[4 * g + 3]);
            let t0 = _mm256_unpacklo_epi32(a, b);
            let t1 = _mm256_unpacklo_epi32(c, d);
            let t2 = _mm256_unpackhi_epi32(a, b);
            let t3 = _mm256_unpackhi_epi32(c, d);
            *row = [_mm256_unpacklo_epi64(t0, t1), _mm256_unpackhi_epi64(t0, t1), _mm256_unpacklo_epi64(t2, t3), _mm256_unpackhi_epi64(t2, t3)];
        }
        #[allow(clippy::needless_range_loop)] // (j picks the same register of each of the four groups)
        for j in 0..4 {
            let (lo, hi) = (64 * j, 64 * (j + 4));
            xor_into(&mut data[lo..lo + 32], _mm256_permute2x128_si256::<0x20>(rows[0][j], rows[1][j]));
            xor_into(&mut data[lo + 32..lo + 64], _mm256_permute2x128_si256::<0x20>(rows[2][j], rows[3][j]));
            xor_into(&mut data[hi..hi + 32], _mm256_permute2x128_si256::<0x31>(rows[0][j], rows[1][j]));
            xor_into(&mut data[hi + 32..hi + 64], _mm256_permute2x128_si256::<0x31>(rows[2][j], rows[3][j]));
        }
    }

    /// XORs the keystream of blocks `counter .. counter + 8` into 512 bytes. Only to be called when [`available`] said yes.
    #[inline]
    pub fn xor8(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8; 512]) {
        assert!(available());
        // SAFETY: the CPU has AVX2 (asserted just above; the standard library caches the answer)
        unsafe { xor8_avx2(key, counter, nonce, data) }
    }
}

// ---------------------------------------------------------------- ChaCha20, sixteen blocks at once (AVX-512)
// Sixteen blocks in the sixteen lanes of 512-bit registers, with the rotations done by the rotate instruction AVX-512 has.
// Only on CPUs that also have VBMI2, which is to say Intel since Ice Lake (2019) and AMD since Zen 4 (2022): the Skylake
// and Cascade Lake server CPUs before them lower the clock of a core that runs 512-bit instructions, for milliseconds and
// for whatever else it runs, which is why Linux keeps its ChaCha20 off them too; they take the AVX2 path. (On a Cascade
// Lake VM, where it was measured anyway, the keystream was 4.6 GB/s against 2.3 with AVX2, and the AEAD 1.15 to 1.3 times.)

#[cfg(all(target_arch = "x86_64", not(tiny_https_portable)))]
mod avx512 {
    use super::SIGMA;
    use core::arch::x86_64::*;

    /// Whether the CPU has AVX-512 and is of a generation that does not slow down for it (see above).
    #[inline]
    pub fn available() -> bool {
        std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512vbmi2")
    }

    /// Whether the CPU can run the code at all (the tests run it wherever it can).
    #[cfg(test)]
    pub fn runs() -> bool {
        std::is_x86_feature_detected!("avx512f")
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    fn quarter_round(x: &mut [__m512i; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = _mm512_add_epi32(x[a], x[b]);
        x[d] = _mm512_rol_epi32::<16>(_mm512_xor_si512(x[d], x[a]));
        x[c] = _mm512_add_epi32(x[c], x[d]);
        x[b] = _mm512_rol_epi32::<12>(_mm512_xor_si512(x[b], x[c]));
        x[a] = _mm512_add_epi32(x[a], x[b]);
        x[d] = _mm512_rol_epi32::<8>(_mm512_xor_si512(x[d], x[a]));
        x[c] = _mm512_add_epi32(x[c], x[d]);
        x[b] = _mm512_rol_epi32::<7>(_mm512_xor_si512(x[b], x[c]));
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    fn xor_into(dst: &mut [u8], v: __m512i) {
        let dst: &mut [u8; 64] = dst.try_into().unwrap();
        let p = dst.as_mut_ptr() as *mut __m512i;
        // SAFETY: `p` points to 64 valid bytes that we hold a unique reference to, and `loadu`/`storeu` have no alignment
        // requirement.
        unsafe { _mm512_storeu_si512(p, _mm512_xor_si512(_mm512_loadu_si512(p), v)) }
    }

    #[target_feature(enable = "avx512f")]
    fn xor16_avx512(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8; 1024]) {
        let set = |w: u32| _mm512_set1_epi32(w as i32);
        let init: [__m512i; 16] = [
            set(SIGMA[0]),
            set(SIGMA[1]),
            set(SIGMA[2]),
            set(SIGMA[3]),
            set(key[0]),
            set(key[1]),
            set(key[2]),
            set(key[3]),
            set(key[4]),
            set(key[5]),
            set(key[6]),
            set(key[7]),
            // block j has the counter + j (wrapping, as the scalar code's)
            _mm512_add_epi32(set(counter), _mm512_set_epi32(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)),
            set(nonce[0]),
            set(nonce[1]),
            set(nonce[2]),
        ];
        let mut x = init;
        for _ in 0..10 {
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }
        // As with AVX2, a 4x4 transpose in each 128-bit quarter of a group of four words; then, for each j < 4, the four
        // groups' registers hold block j + 4k's words in their quarter k, and a 4x4 transpose of quarters (`shuffle_i32x4`,
        // twice) makes one register of each block's 64 bytes.
        let mut rows = [[_mm512_setzero_si512(); 4]; 4];
        for (g, row) in rows.iter_mut().enumerate() {
            let a = _mm512_add_epi32(x[4 * g], init[4 * g]);
            let b = _mm512_add_epi32(x[4 * g + 1], init[4 * g + 1]);
            let c = _mm512_add_epi32(x[4 * g + 2], init[4 * g + 2]);
            let d = _mm512_add_epi32(x[4 * g + 3], init[4 * g + 3]);
            let t0 = _mm512_unpacklo_epi32(a, b);
            let t1 = _mm512_unpacklo_epi32(c, d);
            let t2 = _mm512_unpackhi_epi32(a, b);
            let t3 = _mm512_unpackhi_epi32(c, d);
            *row = [_mm512_unpacklo_epi64(t0, t1), _mm512_unpackhi_epi64(t0, t1), _mm512_unpacklo_epi64(t2, t3), _mm512_unpackhi_epi64(t2, t3)];
        }
        #[allow(clippy::needless_range_loop)] // (j picks the same register of each of the four groups)
        for j in 0..4 {
            let (a, b, c, d) = (rows[0][j], rows[1][j], rows[2][j], rows[3][j]);
            let t0 = _mm512_shuffle_i32x4::<0x44>(a, b);
            let t1 = _mm512_shuffle_i32x4::<0x44>(c, d);
            let t2 = _mm512_shuffle_i32x4::<0xee>(a, b);
            let t3 = _mm512_shuffle_i32x4::<0xee>(c, d);
            let out = [_mm512_shuffle_i32x4::<0x88>(t0, t1), _mm512_shuffle_i32x4::<0xdd>(t0, t1), _mm512_shuffle_i32x4::<0x88>(t2, t3), _mm512_shuffle_i32x4::<0xdd>(t2, t3)];
            for (k, v) in out.into_iter().enumerate() {
                let at = 64 * (j + 4 * k);
                xor_into(&mut data[at..at + 64], v);
            }
        }
    }

    /// XORs the keystream of blocks `counter .. counter + 16` into 1024 bytes. Only to be called when the CPU has AVX-512F
    /// ([`available`], or in tests [`runs`]).
    #[inline]
    pub fn xor16(key: &[u32; 8], counter: u32, nonce: &[u32; 3], data: &mut [u8; 1024]) {
        assert!(std::is_x86_feature_detected!("avx512f"));
        // SAFETY: the CPU has AVX-512F (asserted just above; the standard library caches the answer)
        unsafe { xor16_avx512(key, counter, nonce, data) }
    }
}

/// XORs the ChaCha20 keystream starting at block `start_counter` into `data`.
fn chacha20_xor(key: &[u32; 8], nonce: &[u32; 3], start_counter: u32, data: &mut [u8]) {
    let mut counter = start_counter;
    let mut rest = data;
    // the widest vectors the CPU has first (each leaves less than its own width), then the baseline ones
    #[cfg(all(target_arch = "x86_64", not(tiny_https_portable)))]
    if rest.len() >= 512 {
        if rest.len() >= 1024 && avx512::available() {
            let mut chunks = rest.chunks_exact_mut(1024);
            for chunk in &mut chunks {
                avx512::xor16(key, counter, nonce, <&mut [u8; 1024]>::try_from(chunk).unwrap());
                counter = counter.wrapping_add(16);
            }
            rest = chunks.into_remainder();
        }
        if rest.len() >= 512 && avx2::available() {
            let mut chunks = rest.chunks_exact_mut(512);
            for chunk in &mut chunks {
                avx2::xor8(key, counter, nonce, <&mut [u8; 512]>::try_from(chunk).unwrap());
                counter = counter.wrapping_add(8);
            }
            rest = chunks.into_remainder();
        }
    }
    if simd::AVAILABLE {
        let mut chunks = rest.chunks_exact_mut(256);
        for chunk in &mut chunks {
            simd::xor4(key, counter, nonce, <&mut [u8; 256]>::try_from(chunk).unwrap());
            counter = counter.wrapping_add(4);
        }
        rest = chunks.into_remainder();
        if rest.len() > 64 {
            // Three or four blocks' worth: one 4-block call on a scratch buffer beats up to three
            // single blocks.
            let mut tmp = Zeroizing::new([0u8; 256]);
            tmp[..rest.len()].copy_from_slice(rest);
            simd::xor4(key, counter, nonce, &mut tmp);
            rest.copy_from_slice(&tmp[..rest.len()]);
            return;
        }
    }
    for chunk in rest.chunks_mut(64) {
        let ks = Zeroizing::new(chacha20_block(key, counter, nonce));
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Poly1305 key for this (key, nonce): the first 32 bytes of keystream block 0.
fn one_time_key(key: &[u32; 8], nonce: &[u32; 3]) -> Zeroizing<[u8; 32]> {
    let block0 = Zeroizing::new(chacha20_block(key, 0, nonce));
    let mut otk = Zeroizing::new([0u8; 32]);
    otk.copy_from_slice(&block0[..32]);
    otk
}

/// Tag over aad || pad16 || ciphertext || pad16 || len(aad) || len(ciphertext).
fn compute_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(otk);
    p.update_padded(aad);
    p.update_padded(ciphertext);
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    p.block(&lens, true);
    p.finish()
}

/// The sealed message (ciphertext, then the tag) made with the scalar block function alone, whatever vector code the build has: what
/// the fuzz target `aead` holds [`ChaCha20Poly1305::seal`] to.
#[cfg(tiny_https_fuzzing)]
pub(crate) fn seal_with_scalar_code(key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(key);
    let (kw, nw) = (key_words(&k), nonce_words(nonce));
    let mut out = plaintext.to_vec();
    for (i, chunk) in out.chunks_mut(64).enumerate() {
        let ks = Zeroizing::new(chacha20_block(&kw, 1u32.wrapping_add(i as u32), &nw));
        for (d, b) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= b;
        }
    }
    let tag = compute_tag(&one_time_key(&kw, &nw), aad, &out);
    out.extend_from_slice(&tag);
    out
}

/// A ChaCha20 key used for one thing: the mask that QUIC header protection takes from a sample of the packet
/// (RFC 9001 section 5.4.4). The first four bytes of the 16-byte sample are the block counter and the other twelve the nonce,
/// both little-endian, and the mask is the first five bytes of that keystream block.
#[derive(Clone)]
pub struct ChaCha20Mask {
    key: [u32; 8],
}

impl Drop for ChaCha20Mask {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ChaCha20Mask {
    pub fn new(key: &[u8]) -> Self {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        assert_eq!(key.len(), KEY_LEN);
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(key);
        ChaCha20Mask { key: key_words(&k) }
    }

    pub fn mask(&self, sample: &[u8; 16]) -> [u8; 5] {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        let counter = le32(&sample[..4]);
        let mut n = [0u8; 12];
        n.copy_from_slice(&sample[4..]);
        let block = Zeroizing::new(chacha20_block(&self.key, counter, &nonce_words(&n)));
        [block[0], block[1], block[2], block[3], block[4]]
    }
}

#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [u32; 8],
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl ChaCha20Poly1305 {
    fn wipe(&mut self) {
        self.key.zeroize();
    }

    pub fn new(key: &[u8]) -> Self {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        assert_eq!(key.len(), KEY_LEN);
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(key);
        ChaCha20Poly1305 { key: key_words(&k) }
    }

    /// Encrypts in place. `buf` holds the plaintext followed by `TAG_LEN` bytes of room; on return
    /// it holds ciphertext || tag.
    pub fn seal_in_place(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        assert!(buf.len() >= TAG_LEN, "buffer must have room for the tag");
        let n = buf.len() - TAG_LEN;
        let nw = nonce_words(nonce);
        let otk = one_time_key(&self.key, &nw);
        let (data, tag_out) = buf.split_at_mut(n);
        chacha20_xor(&self.key, &nw, 1, data);
        tag_out.copy_from_slice(&compute_tag(&otk, aad, data));
    }

    /// Decrypts in place. `buf` holds ciphertext || tag. On success returns the plaintext length
    /// and `buf[..len]` holds the plaintext; on failure returns `None` and `buf` is untouched
    /// (the tag is verified before anything is decrypted).
    pub fn open_in_place(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> Option<usize> {
        let _dit = Dit::on(); // data-independent timing while the key and the data are in use (crypto::dit)
        if buf.len() < TAG_LEN {
            return None;
        }
        let n = buf.len() - TAG_LEN;
        let nw = nonce_words(nonce);
        let otk = one_time_key(&self.key, &nw);
        let (data, tag) = buf.split_at_mut(n);
        let expected = compute_tag(&otk, aad, data);
        if !ct_eq(&expected, tag) {
            return None;
        }
        chacha20_xor(&self.key, &nw, 1, data);
        Some(n)
    }

    /// Returns ciphertext || tag.
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        out.resize(plaintext.len() + TAG_LEN, 0);
        self.seal_in_place(nonce, aad, &mut out);
        out
    }

    pub fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext_and_tag: &[u8]) -> Option<Vec<u8>> {
        let mut buf = ciphertext_and_tag.to_vec();
        let n = self.open_in_place(nonce, aad, &mut buf)?;
        buf.truncate(n);
        Some(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    #[test]
    fn rfc8439_aead_example() {
        let key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let c = ChaCha20Poly1305::new(&key);
        let ct = c.seal(&nonce, &aad, pt);
        assert_eq!(
            hex(&ct),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        );
        assert_eq!(c.open(&nonce, &aad, &ct).unwrap(), pt.to_vec());
    }

    #[test]
    fn matches_reference_multi_block() {
        let key = unhex("090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d606366");
        let nonce: [u8; 12] = core::array::from_fn(|i| i as u8);
        let pt: Vec<u8> = (0..77u32).map(|i| ((i * 7 + 3) & 255) as u8).collect();
        let c = ChaCha20Poly1305::new(&key);
        let ct = c.seal(&nonce, b"tls13 record header", &pt);
        assert_eq!(
            hex(&ct),
            "49b97e9c8f964f35bf3813d737b63b53269d665bc241e659c1ed777be28cc061bc0b71373b0dda3cb91a616a0daeb6e1c15e739819c6890e85420794cc7859cbc1c0ec550ae7a62b3337632d07ff16505a4054bdf68fee2d541f67f8b1"
        );
    }

    #[test]
    fn rejects_tampering() {
        let c = ChaCha20Poly1305::new(&[3u8; 32]);
        let nonce = [9u8; 12];
        let mut ct = c.seal(&nonce, b"hdr", b"payload");
        assert!(c.open(&nonce, b"hdr", &ct).is_some());
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        assert!(c.open(&nonce, b"hdr", &ct).is_none());
    }

    use crate::crypto::aead_vectors::*;
    use crate::crypto::sha2::{Hash, Sha256};

    #[test]
    fn matches_independent_vectors() {
        for &(idx, klen, n, alen, ct_sha, tag) in CHACHA_VECTORS {
            assert_eq!(klen, 32);
            let c = ChaCha20Poly1305::new(&det_key(idx, klen));
            let nonce = det_nonce(idx);
            let aad = det_aad(idx, alen);
            let pt = det_pt(idx, n);
            let out = c.seal(&nonce, &aad, &pt);
            assert_eq!(out.len(), n + TAG_LEN);
            assert_eq!(hex(&Sha256::digest(&out[..n])), ct_sha, "ciphertext, vector {idx} (len {n})");
            assert_eq!(hex(&out[n..]), tag, "tag, vector {idx} (len {n})");
            assert_eq!(c.open(&nonce, &aad, &out).unwrap(), pt, "open, vector {idx}");
        }
    }

    /// Byte-at-a-time reference built from the single-block function.
    fn xor_reference(key: &[u32; 8], nonce: &[u32; 3], ctr: u32, data: &mut [u8]) {
        for (n, chunk) in data.chunks_mut(64).enumerate() {
            let ks = chacha20_block(key, ctr.wrapping_add(n as u32), nonce);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
        }
    }

    /// The wide kernels themselves, called directly wherever the CPU can run them (the dispatcher takes AVX-512 only on
    /// some of the CPUs that have it): every counter of a block that wraps around u32 in the middle, and data that is not
    /// all the same.
    #[cfg(all(target_arch = "x86_64", not(tiny_https_portable)))]
    #[test]
    fn the_wide_kernels_match_the_one_block_function() {
        let key = key_words(&det_key(9, 32).try_into().unwrap());
        let nonce = nonce_words(&det_nonce(9));
        let counters = [0u32, 1, 0x7fff_ffff, 0xffff_ffef, 0xffff_fff0, 0xffff_fff8, 0xffff_fffb, 0xffff_ffff];
        let mut ran = Vec::new();
        if avx2::available() {
            for &ctr in &counters {
                let src: [u8; 512] = det_pt(ctr as usize % 997, 512).try_into().unwrap();
                let (mut a, mut b) = (src, src);
                avx2::xor8(&key, ctr, &nonce, &mut a);
                xor_reference(&key, &nonce, ctr, &mut b);
                assert_eq!(a, b, "AVX2 from counter {ctr}");
            }
            ran.push("AVX2");
        }
        if avx512::runs() {
            for &ctr in &counters {
                let src: [u8; 1024] = det_pt(ctr as usize % 997, 1024).try_into().unwrap();
                let (mut a, mut b) = (src, src);
                avx512::xor16(&key, ctr, &nonce, &mut a);
                xor_reference(&key, &nonce, ctr, &mut b);
                assert_eq!(a, b, "AVX-512 from counter {ctr}");
            }
            ran.push(if avx512::available() { "AVX-512 (in use)" } else { "AVX-512 (not in use on this CPU)" });
        }
        eprintln!("kernels checked: {ran:?}");
    }

    #[test]
    fn bulk_keystream_matches_single_block_reference() {
        let key = key_words(&det_key(5, 32).try_into().unwrap());
        let nonce = nonce_words(&det_nonce(5));
        // Every length around the 64/256 boundaries, and counters that wrap around u32.
        for &ctr in &[0u32, 1, 7, 0xffff_fff9, 0xffff_fffe, 0xffff_ffff] {
            for len in (0..700usize).chain([767, 768, 1023, 1024, 1025, 1536, 1600, 2047, 2048, 2049, 4096, 16384]) {
                let src = det_pt(len, len);
                let mut a = src.clone();
                let mut b = src.clone();
                chacha20_xor(&key, &nonce, ctr, &mut a);
                xor_reference(&key, &nonce, ctr, &mut b);
                assert_eq!(a, b, "ctr {ctr} len {len}");
            }
        }
    }

    #[test]
    fn rfc8439_keystream_block_vector() {
        // RFC 8439 section 2.3.2.
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = unhex("000000090000004a00000000").try_into().unwrap();
        let ks = chacha20_block(&key_words(&key), 1, &nonce_words(&nonce));
        assert_eq!(
            hex(&ks),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn in_place_matches_allocating_and_failure_leaves_buffer_untouched() {
        let c = ChaCha20Poly1305::new(&det_key(9, 32));
        let nonce = det_nonce(9);
        for len in [0usize, 1, 16, 255, 256, 257, 1000, 16384] {
            let pt = det_pt(3, len);
            let aad = det_aad(4, 5);
            let mut buf = pt.clone();
            buf.resize(len + TAG_LEN, 0xaa);
            c.seal_in_place(&nonce, &aad, &mut buf);
            assert_eq!(buf, c.seal(&nonce, &aad, &pt));

            // Corrupt one byte: open must fail and must not modify the buffer.
            let mut bad = buf.clone();
            let pos = (len / 2).min(bad.len() - 1);
            bad[pos] ^= 1;
            let before = bad.clone();
            assert!(c.open_in_place(&nonce, &aad, &mut bad).is_none());
            assert_eq!(bad, before);

            // Wrong AAD fails too.
            let mut wrong = buf.clone();
            assert!(c.open_in_place(&nonce, b"other", &mut wrong).is_none());

            let n = c.open_in_place(&nonce, &aad, &mut buf).unwrap();
            assert_eq!(&buf[..n], &pt[..]);
        }
        assert!(c.open_in_place(&nonce, b"", &mut [0u8; 15]).is_none());
    }

    #[test]
    fn key_is_wiped_and_type_has_drop_glue() {
        assert!(std::mem::needs_drop::<ChaCha20Poly1305>());
        let mut c = ChaCha20Poly1305::new(&[0x42u8; 32]);
        assert!(c.key.iter().any(|&w| w != 0));
        c.wipe();
        assert_eq!(c.key, [0u32; 8]);
    }
}
