//! Poly1305 one-time authenticator (RFC 8439 section 2.5).
//!
//! Two implementations with the same interface; the one matching the pointer width is used:
//!
//! * `limbs64`: three 44-bit limbs with 128-bit products (after poly1305-donna-64). Fast on 64-bit
//!   CPUs, where a 64x64 -> 128 multiply is a single instruction (or two).
//! * `limbs32`: five 26-bit limbs with 64-bit products (after poly1305-donna-32). Used on 32-bit
//!   targets, where 128-bit multiplies would be library calls.
//!
//! Both are compiled in test builds so the same vectors run against each on any host. Both are
//! constant-time: no secret-dependent branches, indices or variable-time instructions.

#[cfg(target_pointer_width = "64")]
pub(crate) use limbs64::Poly1305;
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
pub(crate) mod limbs64 {
    use super::le64;
    use crate::zeroize::Zeroize;

    const MASK44: u64 = 0xfff_ffff_ffff;
    const MASK42: u64 = 0x3ff_ffff_ffff;
    /// Bit 128 of a block, as it appears in the top limb (bit 40 of the limb at 2^88).
    const HIBIT: u64 = 1 << 40;

    pub(crate) struct Poly1305 {
        r: [u64; 3],
        /// r1 * 20 and r2 * 20 (2^132 = 4 * 2^130 = 20 mod p).
        s: [u64; 2],
        h: [u64; 3],
        pad: [u64; 2],
    }

    impl Drop for Poly1305 {
        fn drop(&mut self) {
            self.wipe();
        }
    }

    impl Poly1305 {
        fn wipe(&mut self) {
            self.r.zeroize();
            self.s.zeroize();
            self.h.zeroize();
            self.pad.zeroize();
        }

        pub(crate) fn new(key: &[u8; 32]) -> Self {
            let t0 = le64(&key[0..8]);
            let t1 = le64(&key[8..16]);
            let r0 = t0 & 0xffc_0fff_ffff;
            let r1 = ((t0 >> 44) | (t1 << 20)) & 0xfff_ffc0_ffff;
            let r2 = (t1 >> 24) & 0x00f_ffff_fc0f;
            Poly1305 { r: [r0, r1, r2], s: [r1 * 20, r2 * 20], h: [0; 3], pad: [le64(&key[16..24]), le64(&key[24..32])] }
        }

        /// Absorbs one 16-byte block. `hibit` is the 2^128 padding bit that every full block of the
        /// AEAD construction carries (it is clear only for a short final block of a plain message).
        #[inline(always)]
        pub(crate) fn block(&mut self, m: &[u8; 16], hibit: bool) {
            let [r0, r1, r2] = self.r;
            let [s1, s2] = self.s;
            let t0 = le64(&m[0..8]);
            let t1 = le64(&m[8..16]);
            let hb = if hibit { HIBIT } else { 0 };
            let h0 = self.h[0] + (t0 & MASK44);
            let h1 = self.h[1] + (((t0 >> 44) | (t1 << 20)) & MASK44);
            let h2 = self.h[2] + (((t1 >> 24) & MASK42) | hb);

            let mul = |a: u64, b: u64| a as u128 * b as u128;
            let d0 = mul(h0, r0) + mul(h1, s2) + mul(h2, s1);
            let mut d1 = mul(h0, r1) + mul(h1, r0) + mul(h2, s2);
            let mut d2 = mul(h0, r2) + mul(h1, r1) + mul(h2, r0);

            let mut c = (d0 >> 44) as u64;
            let mut h0 = d0 as u64 & MASK44;
            d1 += c as u128;
            c = (d1 >> 44) as u64;
            let mut h1 = d1 as u64 & MASK44;
            d2 += c as u128;
            c = (d2 >> 42) as u64;
            let h2 = d2 as u64 & MASK42;
            h0 += c * 5;
            c = h0 >> 44;
            h0 &= MASK44;
            h1 += c;
            self.h = [h0, h1, h2];
        }

        pub(crate) fn finish(self) -> [u8; 16] {
            // (the key material is wiped when `self` drops at the end of this function)
            let [mut h0, mut h1, mut h2] = self.h;

            // fully carry h
            let mut c = h1 >> 44;
            h1 &= MASK44;
            h2 += c;
            c = h2 >> 42;
            h2 &= MASK42;
            h0 += c * 5;
            c = h0 >> 44;
            h0 &= MASK44;
            h1 += c;
            c = h1 >> 44;
            h1 &= MASK44;
            h2 += c;
            c = h2 >> 42;
            h2 &= MASK42;
            h0 += c * 5;
            c = h0 >> 44;
            h0 &= MASK44;
            h1 += c;

            // compute h + -p
            let mut g0 = h0 + 5;
            c = g0 >> 44;
            g0 &= MASK44;
            let mut g1 = h1 + c;
            c = g1 >> 44;
            g1 &= MASK44;
            let g2 = (h2 + c).wrapping_sub(1 << 42);

            // select h if h < p, else h + -p (constant time)
            let sel = (g2 >> 63).wrapping_sub(1); // all ones when h >= p
            g0 &= sel;
            g1 &= sel;
            let g2 = g2 & sel;
            let nsel = !sel;
            h0 = (h0 & nsel) | g0;
            h1 = (h1 & nsel) | g1;
            h2 = (h2 & nsel) | g2;

            // h = (h + pad) mod 2^128
            let t0 = self.pad[0];
            let t1 = self.pad[1];
            h0 += t0 & MASK44;
            c = h0 >> 44;
            h0 &= MASK44;
            h1 += (((t0 >> 44) | (t1 << 20)) & MASK44) + c;
            c = h1 >> 44;
            h1 &= MASK44;
            h2 += ((t1 >> 24) & MASK42) + c;
            h2 &= MASK42;

            let lo = h0 | (h1 << 44);
            let hi = (h1 >> 20) | (h2 << 24);
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&lo.to_le_bytes());
            tag[8..].copy_from_slice(&hi.to_le_bytes());
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
            assert!(p.r != [0; 3] && p.h != [0; 3]);
            p.wipe();
            assert!(p.r == [0; 3] && p.s == [0; 2] && p.h == [0; 3] && p.pad == [0; 2]);
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
        assert_eq!(hex(&mac!(limbs64, &key, msg)), "a8061dc1305136c6c22b8baf0c0127a9");
        assert_eq!(hex(&mac!(limbs32, &key, msg)), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn independent_vectors_both_implementations() {
        assert!(POLY1305_VECTORS.len() > 150);
        for (i, &(key, msg, tag)) in POLY1305_VECTORS.iter().enumerate() {
            let key: [u8; 32] = unhex(key).try_into().unwrap();
            let msg = unhex(msg);
            assert_eq!(hex(&mac!(limbs64, &key, msg)), tag, "limbs64 vector {i}");
            assert_eq!(hex(&mac!(limbs32, &key, msg)), tag, "limbs32 vector {i}");
        }
    }
}
