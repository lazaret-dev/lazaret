//! Poly1305 one-time authenticator (RFC 8439 section 2.5).
//!
//! Two implementations with the same interface; the one matching the pointer width is used:
//!
//! * `radix64`: two 64-bit limbs and a third of a few bits (after OpenSSL's `crypto/poly1305/poly1305.c`): four
//!   64 x 64 -> 128-bit products and two small ones per block, where three 44-bit limbs (poly1305-donna-64, used here
//!   before B-57) take nine. Fast on 64-bit CPUs, where such a product is one instruction or two: about 1.65 times the
//!   44-bit limbs on an x86-64 VM, and faster for short messages too.
//! * `limbs32`: five 26-bit limbs with 64-bit products (after poly1305-donna-32). Used on 32-bit
//!   targets, where 128-bit multiplies would be library calls.
//!
//! Both are compiled in test builds so the same vectors run against each on any host. Both are
//! constant-time: no secret-dependent branches, indices or variable-time instructions.

#[cfg(target_pointer_width = "64")]
pub(crate) use radix64::Poly1305;
#[cfg(not(target_pointer_width = "64"))]
pub(crate) use limbs32::Poly1305;

#[cfg(any(test, not(target_pointer_width = "64")))]
#[inline(always)]
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(any(test, target_pointer_width = "64"))]
#[inline(always)]
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[cfg(any(test, target_pointer_width = "64"))]
pub(crate) mod radix64 {
    use super::le64;
    use crate::zeroize::Zeroize;

    pub(crate) struct Poly1305 {
        /// r, clamped: the top four bits of each 32-bit word and the low two bits of the last three are clear, so r1 is a
        /// multiple of 4.
        r: [u64; 2],
        /// h, partly reduced: h = h0 + h1 2^64 + h2 2^128, h2 at most 4 between blocks.
        h: [u64; 3],
        pad: [u64; 2],
    }

    impl Drop for Poly1305 {
        fn drop(&mut self) {
            self.wipe();
        }
    }

    /// a + b + carry, and the carry out (0 or 1), with no branch.
    #[inline(always)]
    fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
        let t = a as u128 + b as u128 + carry as u128;
        (t as u64, (t >> 64) as u64)
    }

    impl Poly1305 {
        fn wipe(&mut self) {
            self.r.zeroize();
            self.h.zeroize();
            self.pad.zeroize();
        }

        pub(crate) fn new(key: &[u8; 32]) -> Self {
            let r0 = le64(&key[0..8]) & 0x0fff_fffc_0fff_ffff;
            let r1 = le64(&key[8..16]) & 0x0fff_fffc_0fff_fffc;
            Poly1305 { r: [r0, r1], h: [0; 3], pad: [le64(&key[16..24]), le64(&key[24..32])] }
        }

        /// Absorbs one 16-byte block. `hibit` is the 2^128 padding bit that every full block of the
        /// AEAD construction carries (it is clear only for a short final block of a plain message).
        #[inline(always)]
        pub(crate) fn block(&mut self, m: &[u8; 16], hibit: bool) {
            let [r0, r1] = self.r;
            // 2^130 = 5 mod p and r1 is a multiple of 4, so h1 r1 2^128 = h1 (r1 / 4) 2^130 = h1 (5 r1 / 4) = h1 s1 mod p
            let s1 = r1 + (r1 >> 2);
            let [h0, h1, h2] = self.h;
            // h += m: h2 at most 4 + 1 + 1
            let (h0, c) = adc(h0, le64(&m[0..8]), 0);
            let (h1, c) = adc(h1, le64(&m[8..16]), c);
            let h2 = h2 + c + u64::from(hibit);
            // h *= r, partly reduced. r0 < 2^60 and s1 < 2^61, so the sums of products are under 2^126, and h2 s1 and
            // h2 r0 (h2 at most 6) fit in 64 bits
            let mul = |a: u64, b: u64| a as u128 * b as u128;
            let d0 = mul(h0, r0) + mul(h1, s1);
            let d1 = mul(h0, r1) + mul(h1, r0) + (h2 * s1) as u128 + (d0 >> 64);
            let h2 = h2 * r0 + (d1 >> 64) as u64;
            // what is at 2^130 and above comes back times 5: (h2 >> 2) 5 = (h2 & !3) + (h2 >> 2)
            let c = (h2 & !3) + (h2 >> 2);
            let (h0, c) = adc(d0 as u64, c, 0);
            let (h1, c) = adc(d1 as u64, 0, c);
            self.h = [h0, h1, (h2 & 3) + c];
        }

        pub(crate) fn finish(self) -> [u8; 16] {
            // (the key material is wiped when `self` drops at the end of this function)
            let [h0, h1, h2] = self.h;
            // h < 5 2^128 < 2p, so h mod p is h - p if that is not below zero, which is when bit 130 of h + 5 is set
            let (g0, c) = adc(h0, 5, 0);
            let (g1, c) = adc(h1, 0, c);
            let take = 0u64.wrapping_sub((h2 + c) >> 2); // all ones when h >= p
            let h0 = (h0 & !take) | (g0 & take);
            let h1 = (h1 & !take) | (g1 & take);
            // (h + pad) mod 2^128
            let (h0, c) = adc(h0, self.pad[0], 0);
            let (h1, _) = adc(h1, self.pad[1], c);
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&h0.to_le_bytes());
            tag[8..].copy_from_slice(&h1.to_le_bytes());
            tag
        }
    }

    #[cfg(test)]
    mod wipe_test {
        use super::*;

        #[test]
        fn state_is_wiped_and_type_has_drop_glue() {
            assert!(std::mem::needs_drop::<Poly1305>());
            let mut p = Poly1305::new(&[0xa5u8; 32]);
            p.block(&[0x77; 16], true);
            assert!(p.r != [0; 2] && p.h != [0; 3]);
            p.wipe();
            assert!(p.r == [0; 2] && p.h == [0; 3] && p.pad == [0; 2]);
        }
    }
}

#[cfg(any(test, not(target_pointer_width = "64")))]
pub(crate) mod limbs32 {
    use super::le32;
    use crate::zeroize::Zeroize;

    const MASK26: u32 = 0x3ff_ffff;

    pub(crate) struct Poly1305 {
        r: [u32; 5],
        h: [u32; 5],
        s: [u32; 4],
    }

    impl Drop for Poly1305 {
        fn drop(&mut self) {
            self.wipe();
        }
    }

    impl Poly1305 {
        fn wipe(&mut self) {
            self.r.zeroize();
            self.h.zeroize();
            self.s.zeroize();
        }

        pub(crate) fn new(key: &[u8; 32]) -> Self {
            let r = [
                le32(&key[0..4]) & 0x3ff_ffff,
                (le32(&key[3..7]) >> 2) & 0x3ff_ff03,
                (le32(&key[6..10]) >> 4) & 0x3ff_c0ff,
                (le32(&key[9..13]) >> 6) & 0x3f0_3fff,
                (le32(&key[12..16]) >> 8) & 0x00f_ffff,
            ];
            let s = [le32(&key[16..20]), le32(&key[20..24]), le32(&key[24..28]), le32(&key[28..32])];
            Poly1305 { r, h: [0; 5], s }
        }

        #[inline(always)]
        pub(crate) fn block(&mut self, m: &[u8; 16], hibit: bool) {
            let [r0, r1, r2, r3, r4] = self.r;
            let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
            let hb = (hibit as u32) << 24;
            let mut h0 = self.h[0] + (le32(&m[0..4]) & MASK26);
            let mut h1 = self.h[1] + ((le32(&m[3..7]) >> 2) & MASK26);
            let mut h2 = self.h[2] + ((le32(&m[6..10]) >> 4) & MASK26);
            let mut h3 = self.h[3] + ((le32(&m[9..13]) >> 6) & MASK26);
            let mut h4 = self.h[4] + ((le32(&m[12..16]) >> 8) | hb);

            let m = |a: u32, b: u32| a as u64 * b as u64;
            let d0 = m(h0, r0) + m(h1, s4) + m(h2, s3) + m(h3, s2) + m(h4, s1);
            let mut d1 = m(h0, r1) + m(h1, r0) + m(h2, s4) + m(h3, s3) + m(h4, s2);
            let mut d2 = m(h0, r2) + m(h1, r1) + m(h2, r0) + m(h3, s4) + m(h4, s3);
            let mut d3 = m(h0, r3) + m(h1, r2) + m(h2, r1) + m(h3, r0) + m(h4, s4);
            let mut d4 = m(h0, r4) + m(h1, r3) + m(h2, r2) + m(h3, r1) + m(h4, r0);

            let mut c = (d0 >> 26) as u32;
            h0 = (d0 as u32) & MASK26;
            d1 += c as u64;
            c = (d1 >> 26) as u32;
            h1 = (d1 as u32) & MASK26;
            d2 += c as u64;
            c = (d2 >> 26) as u32;
            h2 = (d2 as u32) & MASK26;
            d3 += c as u64;
            c = (d3 >> 26) as u32;
            h3 = (d3 as u32) & MASK26;
            d4 += c as u64;
            c = (d4 >> 26) as u32;
            h4 = (d4 as u32) & MASK26;
            h0 += c * 5;
            c = h0 >> 26;
            h0 &= MASK26;
            h1 += c;
            self.h = [h0, h1, h2, h3, h4];
        }

        pub(crate) fn finish(self) -> [u8; 16] {
            let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
            let mask = MASK26;
            // fully carry h
            let mut c = h1 >> 26;
            h1 &= mask;
            h2 += c;
            c = h2 >> 26;
            h2 &= mask;
            h3 += c;
            c = h3 >> 26;
            h3 &= mask;
            h4 += c;
            c = h4 >> 26;
            h4 &= mask;
            h0 += c * 5;
            c = h0 >> 26;
            h0 &= mask;
            h1 += c;
            c = h1 >> 26;
            h1 &= mask;
            h2 += c;

            // compute h + -p
            let mut g0 = h0.wrapping_add(5);
            c = g0 >> 26;
            g0 &= mask;
            let mut g1 = h1.wrapping_add(c);
            c = g1 >> 26;
            g1 &= mask;
            let mut g2 = h2.wrapping_add(c);
            c = g2 >> 26;
            g2 &= mask;
            let mut g3 = h3.wrapping_add(c);
            c = g3 >> 26;
            g3 &= mask;
            let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

            // select h if h < p, else g (constant time)
            let sel = (g4 >> 31).wrapping_sub(1);
            let nsel = !sel;
            g0 &= sel;
            g1 &= sel;
            g2 &= sel;
            g3 &= sel;
            let g4 = g4 & sel;
            h0 = (h0 & nsel) | g0;
            h1 = (h1 & nsel) | g1;
            h2 = (h2 & nsel) | g2;
            h3 = (h3 & nsel) | g3;
            h4 = (h4 & nsel) | g4;

            // h mod 2^128
            let w0 = h0 | (h1 << 26);
            let w1 = (h1 >> 6) | (h2 << 20);
            let w2 = (h2 >> 12) | (h3 << 14);
            let w3 = (h3 >> 18) | (h4 << 8);

            // add s
            let mut f = w0 as u64 + self.s[0] as u64;
            let t0 = f as u32;
            f = w1 as u64 + self.s[1] as u64 + (f >> 32);
            let t1 = f as u32;
            f = w2 as u64 + self.s[2] as u64 + (f >> 32);
            let t2 = f as u32;
            f = w3 as u64 + self.s[3] as u64 + (f >> 32);
            let t3 = f as u32;

            let mut tag = [0u8; 16];
            tag[0..4].copy_from_slice(&t0.to_le_bytes());
            tag[4..8].copy_from_slice(&t1.to_le_bytes());
            tag[8..12].copy_from_slice(&t2.to_le_bytes());
            tag[12..16].copy_from_slice(&t3.to_le_bytes());
            tag
        }
    }

    #[cfg(test)]
    mod wipe_test {
        use super::*;

        #[test]
        fn state_is_wiped_and_type_has_drop_glue() {
            assert!(std::mem::needs_drop::<Poly1305>());
            let mut p = Poly1305::new(&[0xa5u8; 32]);
            p.block(&[0x77; 16], true);
            assert!(p.r != [0; 5] && p.h != [0; 5]);
            p.wipe();
            assert!(p.r == [0; 5] && p.s == [0; 4] && p.h == [0; 5]);
        }
    }
}

impl Poly1305 {
    /// Feeds `data` zero-padded to a multiple of 16 bytes, every block with the high bit set (the
    /// AEAD construction of RFC 8439 section 2.8).
    pub(crate) fn update_padded(&mut self, data: &[u8]) {
        let mut it = data.chunks_exact(16);
        for c in &mut it {
            self.block(<&[u8; 16]>::try_from(c).unwrap(), true);
        }
        let rem = it.remainder();
        if !rem.is_empty() {
            let mut b = [0u8; 16];
            b[..rem.len()].copy_from_slice(rem);
            self.block(&b, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::aead_vectors::POLY1305_VECTORS;
    use crate::util::{hex, unhex};

    /// RFC 8439 message semantics: a trailing partial block gets a 0x01 marker byte and no high bit.
    macro_rules! mac {
        ($imp:ident, $key:expr, $msg:expr) => {{
            let mut p = super::$imp::Poly1305::new($key);
            let mut it = $msg.chunks_exact(16);
            for c in &mut it {
                p.block(<&[u8; 16]>::try_from(c).unwrap(), true);
            }
            let rem = it.remainder();
            if !rem.is_empty() {
                let mut b = [0u8; 16];
                b[..rem.len()].copy_from_slice(rem);
                b[rem.len()] = 1;
                p.block(&b, false);
            }
            p.finish()
        }};
    }

    #[test]
    fn rfc8439_2_5_2_both_implementations() {
        let key: [u8; 32] = unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").try_into().unwrap();
        let msg = b"Cryptographic Forum Research Group";
        assert_eq!(hex(&mac!(radix64, &key, msg)), "a8061dc1305136c6c22b8baf0c0127a9");
        assert_eq!(hex(&mac!(limbs32, &key, msg)), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    /// The two implementations agree where the arithmetic is at its limits: r with every bit the clamp allows, blocks of
    /// all ones (with and without the 2^128 bit, and short final blocks), h that ends at p, just over and just under, and
    /// long runs of each, and random keys and messages.
    #[test]
    fn both_implementations_agree_at_the_limits() {
        let mut keys: Vec<[u8; 32]> = vec![[0xff; 32], [0; 32], [0x0f; 32], [0xf0; 32]];
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..40 {
            keys.push(core::array::from_fn(|_| next() as u8));
        }
        let mut messages: Vec<Vec<u8>> = Vec::new();
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 1000, 4096] {
            messages.push(vec![0xff; len]);
            messages.push(vec![0; len]);
            messages.push((0..len).map(|_| next() as u8).collect());
        }
        for key in &keys {
            for msg in &messages {
                assert_eq!(mac!(radix64, key, msg), mac!(limbs32, key, msg), "key {} length {}", hex(key), msg.len());
                // and every block with the high bit, as the AEAD feeds them
                let mut a = super::radix64::Poly1305::new(key);
                let mut b = super::limbs32::Poly1305::new(key);
                for c in msg.chunks(16) {
                    let mut block = [0u8; 16];
                    block[..c.len()].copy_from_slice(c);
                    a.block(&block, true);
                    b.block(&block, true);
                }
                assert_eq!(a.finish(), b.finish());
            }
        }
        // the last step of `finish` at its edge: with r = 1 (and s = 0) h is the sum of the blocks, and three blocks of
        // 2^128 and one of 2^128 - 5 - k make h = p - k, whose tag is h mod p
        let mut key = [0u8; 32];
        key[0] = 1;
        for (k, tag) in [(1i64, "faffffffffffffffffffffffffffffff"), (0, "00000000000000000000000000000000"), (-1, "01000000000000000000000000000000"), (-4, "04000000000000000000000000000000")] {
            let v = (u128::MAX - 4).wrapping_sub(k as u128); // 2^128 - 5 - k
            let last = v.to_le_bytes();
            let mut a = super::radix64::Poly1305::new(&key);
            let mut b = super::limbs32::Poly1305::new(&key);
            for _ in 0..3 {
                a.block(&[0; 16], true);
                b.block(&[0; 16], true);
            }
            a.block(&last, false);
            b.block(&last, false);
            assert_eq!((hex(&a.finish()), hex(&b.finish())), (tag.to_string(), tag.to_string()), "h = p - ({k})");
        }
    }

    #[test]
    fn independent_vectors_both_implementations() {
        assert!(POLY1305_VECTORS.len() > 150);
        for (i, &(key, msg, tag)) in POLY1305_VECTORS.iter().enumerate() {
            let key: [u8; 32] = unhex(key).try_into().unwrap();
            let msg = unhex(msg);
            assert_eq!(hex(&mac!(radix64, &key, msg)), tag, "radix64 vector {i}");
            assert_eq!(hex(&mac!(limbs32, &key, msg)), tag, "limbs32 vector {i}");
        }
    }
}
