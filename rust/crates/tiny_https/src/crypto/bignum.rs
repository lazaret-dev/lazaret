//! Variable-length unsigned integers and Montgomery modular arithmetic.
//!
//! This is only used on PUBLIC data (signature verification: RSA moduli,
//! curve points, signatures), so it is not constant time: the loops run as long as the exponent, `cmp` and
//! `is_zero` stop at the first difference, and the reductions branch on magnitudes. That is why the module is
//! private to the crate; no secret may go through its arithmetic (the constant-time code in `ecdh.rs` and
//! `x25519.rs` does its own, and uses this module for constants, conversions and public values; see the notes there).
//!
//! Numbers are little-endian `u64` limb vectors. Functions that take a modulus
//! expect operands that are already reduced and exactly as long as the modulus.

use std::cmp::Ordering;

/// Parses big-endian bytes into little-endian limbs (not trimmed).
pub fn from_be_bytes(bytes: &[u8]) -> Vec<u64> {
    let n = (bytes.len() + 7) / 8;
    let mut limbs = vec![0u64; n.max(1)];
    for (i, b) in bytes.iter().rev().enumerate() {
        limbs[i / 8] |= (*b as u64) << (8 * (i % 8));
    }
    limbs
}

/// Serialises to exactly `len` big-endian bytes (panics if the value does not fit).
pub fn to_be_bytes(limbs: &[u64], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for i in 0..limbs.len() * 8 {
        let byte = (limbs[i / 8] >> (8 * (i % 8))) as u8;
        if i < len {
            out[len - 1 - i] = byte;
        } else {
            assert!(byte == 0, "value does not fit");
        }
    }
    out
}

#[allow(dead_code)] // the constants of ecdh.rs (the `net` part) are written in hex
pub fn from_hex(s: &str) -> Vec<u64> {
    from_be_bytes(&crate::util::unhex(s))
}

pub fn trimmed_len(a: &[u64]) -> usize {
    let mut n = a.len();
    while n > 0 && a[n - 1] == 0 {
        n -= 1;
    }
    n
}

#[allow(dead_code)] // only the tests of the other modules use it
pub fn is_zero(a: &[u64]) -> bool {
    a.iter().all(|&x| x == 0)
}

pub fn bit_len(a: &[u64]) -> usize {
    let n = trimmed_len(a);
    if n == 0 {
        0
    } else {
        64 * n - a[n - 1].leading_zeros() as usize
    }
}

pub fn bit(a: &[u64], i: usize) -> bool {
    a.get(i / 64).map_or(false, |l| (l >> (i % 64)) & 1 == 1)
}

/// Compares numerically; operands may have different lengths.
pub fn cmp(a: &[u64], b: &[u64]) -> Ordering {
    let n = a.len().max(b.len());
    for i in (0..n).rev() {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
}

/// a += b (same length); returns the carry out.
fn add_in_place(a: &mut [u64], b: &[u64]) -> bool {
    let mut carry = 0u64;
    for i in 0..a.len() {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        a[i] = s2;
        carry = (c1 | c2) as u64;
    }
    carry != 0
}

/// a -= b (same length); returns the borrow out.
fn sub_in_place(a: &mut [u64], b: &[u64]) -> bool {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 | b2) as u64;
    }
    borrow != 0
}

/// Montgomery context for an odd modulus.
#[derive(Clone)]
pub struct Mont {
    m: Vec<u64>,
    n: usize,
    m0inv: u64,
    /// R mod m, i.e. the Montgomery form of 1.
    one: Vec<u64>,
    /// R^2 mod m.
    r2: Vec<u64>,
}

impl Mont {
    /// `modulus` must be odd and greater than 1.
    pub fn new(modulus: &[u64]) -> Mont {
        let n = trimmed_len(modulus);
        assert!(n > 0 && modulus[0] & 1 == 1, "Montgomery modulus must be odd");
        let m = modulus[..n].to_vec();
        // -m^-1 mod 2^64 by Newton iteration
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
        }
        let m0inv = inv.wrapping_neg();
        let mut ctx = Mont { m, n, m0inv, one: vec![0; n], r2: vec![0; n] };
        if n == 1 && ctx.m[0] == 1 {
            return ctx; // everything is 0 modulo 1
        }
        // R mod m: the highest power of two below m, doubled up to 2^(64n) (at most 64 doublings)
        let bits = bit_len(&ctx.m);
        let mut x = vec![0u64; n];
        x[(bits - 1) / 64] = 1 << ((bits - 1) % 64);
        for _ in 0..64 * n - (bits - 1) {
            x = ctx.add(&x, &x);
        }
        ctx.one = x;
        // R^2 mod m = 2^(64n) R mod m, from R (2^0 R) by the bits of 64n, high first: a Montgomery square takes 2^a R
        // to 2^(2a) R and a doubling takes it to 2^(a+1) R. A dozen multiplications instead of 64n modular doublings,
        // which made parsing an RSA-2048 key cost 0.3 ms and an RSA-4096 one over 1 ms.
        let e = 64 * n;
        let mut y = ctx.one.clone();
        for i in (0..usize::BITS - e.leading_zeros()).rev() {
            y = ctx.mul(&y, &y);
            if (e >> i) & 1 == 1 {
                y = ctx.add(&y, &y);
            }
        }
        ctx.r2 = y;
        ctx
    }

    pub fn modulus(&self) -> &[u64] {
        &self.m
    }

    #[allow(dead_code)] // used by ecdh.rs (the `net` part)
    pub fn limbs(&self) -> usize {
        self.n
    }

    /// Pads or checks a value to the modulus length.
    pub fn fit(&self, a: &[u64]) -> Vec<u64> {
        let mut v = a.to_vec();
        assert!(trimmed_len(&v) <= self.n, "value larger than modulus");
        v.resize(self.n, 0);
        v
    }

    /// Montgomery form of 1.
    pub fn one(&self) -> Vec<u64> {
        self.one.clone()
    }

    #[allow(dead_code)] // only the tests use it
    pub fn zero(&self) -> Vec<u64> {
        vec![0; self.n]
    }

    pub fn add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut r = a.to_vec();
        let carry = add_in_place(&mut r, b);
        if carry || cmp(&r, &self.m) != Ordering::Less {
            sub_in_place(&mut r, &self.m);
        }
        r
    }

    #[allow(dead_code)] // only the tests use it
    pub fn sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut r = a.to_vec();
        if sub_in_place(&mut r, b) {
            add_in_place(&mut r, &self.m);
        }
        r
    }

    /// Montgomery product: a * b * R^-1 mod m (CIOS).
    pub fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let n = self.n;
        let m = &self.m;
        let mut t = vec![0u64; n + 2];
        for i in 0..n {
            let mut carry = 0u128;
            for j in 0..n {
                let cur = t[j] as u128 + a[j] as u128 * b[i] as u128 + carry;
                t[j] = cur as u64;
                carry = cur >> 64;
            }
            let cur = t[n] as u128 + carry;
            t[n] = cur as u64;
            t[n + 1] = (cur >> 64) as u64;

            let q = t[0].wrapping_mul(self.m0inv);
            let mut carry = (t[0] as u128 + q as u128 * m[0] as u128) >> 64;
            for j in 1..n {
                let cur = t[j] as u128 + q as u128 * m[j] as u128 + carry;
                t[j - 1] = cur as u64;
                carry = cur >> 64;
            }
            let cur = t[n] as u128 + carry;
            t[n - 1] = cur as u64;
            t[n] = t[n + 1] + (cur >> 64) as u64;
        }
        let mut r = t[..n].to_vec();
        if t[n] != 0 || cmp(&r, m) != Ordering::Less {
            sub_in_place(&mut r, m);
        }
        r
    }

    pub fn sqr(&self, a: &[u64]) -> Vec<u64> {
        self.mul(a, a)
    }

    /// Converts a reduced value (< m, length n) into Montgomery form.
    pub fn to_mont(&self, a: &[u64]) -> Vec<u64> {
        self.mul(a, &self.r2)
    }

    pub fn from_mont(&self, a: &[u64]) -> Vec<u64> {
        let mut one = vec![0u64; self.n];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// base^exp where `base` is in Montgomery form; the result is in Montgomery form.
    pub fn pow(&self, base: &[u64], exp: &[u64]) -> Vec<u64> {
        let mut result = self.one();
        let bits = bit_len(exp);
        for i in (0..bits).rev() {
            result = self.sqr(&result);
            if bit(exp, i) {
                result = self.mul(&result, base);
            }
        }
        result
    }

    /// Modular inverse for a PRIME modulus via Fermat's little theorem.
    /// Input and output are in Montgomery form.
    #[allow(dead_code)] // only the tests use it
    pub fn inv(&self, a: &[u64]) -> Vec<u64> {
        let mut e = self.m.clone();
        // e = m - 2
        let mut two = vec![0u64; self.n];
        two[0] = 2;
        sub_in_place(&mut e, &two);
        self.pow(a, &e)
    }
}

/// Fixed-size Montgomery arithmetic: values are `[u64; N]` with N a const generic, so the loops unroll and nothing is
/// allocated. ECDSA verification (N = 4, 6 and 9) and RSA verification (N = 16 to 64) use it; [`Mont`] is the general case.
pub(crate) mod fixed {
    use std::cmp::Ordering;

    /// A number below a modulus of N limbs, least significant limb first.
    pub(crate) type Fe<const N: usize> = [u64; N];

    pub(crate) fn is_zero<const N: usize>(a: &Fe<N>) -> bool {
        a.iter().all(|&x| x == 0)
    }

    pub(crate) fn compare<const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Ordering {
        for i in (0..N).rev() {
            if a[i] != b[i] {
                return a[i].cmp(&b[i]);
            }
        }
        Ordering::Equal
    }

    /// a + b, and whether it carried out of the top limb.
    #[inline(always)]
    pub(crate) fn add_carry<const N: usize>(a: &Fe<N>, b: &Fe<N>) -> (Fe<N>, bool) {
        let mut r = [0u64; N];
        let mut carry = 0u64;
        for i in 0..N {
            let s = a[i] as u128 + b[i] as u128 + carry as u128;
            r[i] = s as u64;
            carry = (s >> 64) as u64;
        }
        (r, carry != 0)
    }

    /// a - b, and whether it borrowed from beyond the top limb.
    #[inline(always)]
    pub(crate) fn sub_borrow<const N: usize>(a: &Fe<N>, b: &Fe<N>) -> (Fe<N>, bool) {
        let mut r = [0u64; N];
        let mut borrow = 0u64;
        for i in 0..N {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            r[i] = d2;
            borrow = (b1 | b2) as u64;
        }
        (r, borrow != 0)
    }

    /// Big-endian bytes (at most 8 * N of them) as limbs.
    pub(crate) fn limbs_from_be<const N: usize>(bytes: &[u8]) -> Option<Fe<N>> {
        if bytes.len() > 8 * N {
            return None;
        }
        let mut r = [0u64; N];
        for (i, b) in bytes.iter().rev().enumerate() {
            r[i / 8] |= (*b as u64) << (8 * (i % 8));
        }
        Some(r)
    }

    pub(crate) fn limbs_from_hex<const N: usize>(hex: &str) -> Fe<N> {
        limbs_from_be(&crate::util::unhex(hex)).expect("constant fits")
    }

    /// The prime of P-256, 2^256 - 2^224 + 2^192 + 2^96 - 1, whose limbs make Montgomery reduction cheap: -p^-1 mod 2^64 is 1,
    /// the low limb is 2^64 - 1, the next 2^32 - 1, the third 0.
    const P256: [u64; 4] = [u64::MAX, 0x0000_0000_ffff_ffff, 0, 0xffff_ffff_0000_0001];

    /// Squaring has its own code (each product of two different limbs made once) from this many limbs to [`SQR_MAX`], RSA's
    /// sizes: there it saves a quarter of the products. Below, the curves' sizes, it was tried and gained nothing that could
    /// be told from noise (B-49): a multiplication is as quick when the modulus is P-256's, and on P-384 the doubling pass and
    /// the buffer cost about what the products saved.
    const SQR_MIN: usize = 16;
    const SQR_MAX: usize = 64;

    /// Arithmetic modulo an odd number of N limbs (the top one not zero), in Montgomery form (R = 2^(64 N)), on values below
    /// it. Variable time: for public values only (signature verification).
    pub(crate) struct Field<const N: usize> {
        pub(crate) m: Fe<N>,
        /// -m^-1 mod 2^64
        m0inv: u64,
        /// R mod m: the Montgomery form of 1
        pub(crate) one: Fe<N>,
        /// R^2 mod m
        r2: Fe<N>,
        /// m is P-256's prime (see [`P256`])
        p256: bool,
    }

    impl<const N: usize> Field<N> {
        pub(crate) fn new(modulus_hex: &str) -> Field<N> {
            Field::from_modulus(limbs_from_hex(modulus_hex))
        }

        /// For an odd modulus whose top limb is not zero.
        pub(crate) fn from_modulus(m: Fe<N>) -> Field<N> {
            assert!(m[0] & 1 == 1 && m[N - 1] != 0, "an odd modulus of N limbs");
            // -m^-1 mod 2^64 by Newton's iteration (each step doubles the bits that are right)
            let mut inv = 1u64;
            for _ in 0..6 {
                inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
            }
            let p256 = N == 4 && m[..] == P256[..];
            let mut f = Field { m, m0inv: inv.wrapping_neg(), one: [0; N], r2: [0; N], p256 };
            // R mod m: the highest power of two below m, doubled up to 2^(64 N) (at most 64 doublings: the top limb is not 0)
            let bits = 64 * N - m[N - 1].leading_zeros() as usize;
            let mut x = [0u64; N];
            x[(bits - 1) / 64] = 1 << ((bits - 1) % 64);
            for _ in 0..64 * N - (bits - 1) {
                x = f.add(&x, &x);
            }
            f.one = x;
            // R^2 mod m = 2^(64 N) R mod m, from R (2^0 R) by the bits of 64 N, high first: a Montgomery square takes 2^a R to
            // 2^(2a) R and a doubling takes it to 2^(a+1) R. A dozen products, where 64 N doublings would be 2048 for RSA-2048.
            let e = 64 * N;
            let mut y = f.one;
            for i in (0..usize::BITS - e.leading_zeros()).rev() {
                y = f.sqr(&y);
                if (e >> i) & 1 == 1 {
                    y = f.add(&y, &y);
                }
            }
            f.r2 = y;
            f
        }

        /// `t` (with the carry out of its top limb) reduced once: minus m if it is at least m.
        #[inline(always)]
        pub(crate) fn reduce_once(&self, t: Fe<N>, carry: bool) -> Fe<N> {
            let (d, borrow) = sub_borrow(&t, &self.m);
            if carry || !borrow {
                d
            } else {
                t
            }
        }

        #[inline(always)]
        pub(crate) fn add(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
            let (s, carry) = add_carry(a, b);
            self.reduce_once(s, carry)
        }

        #[inline(always)]
        pub(crate) fn sub(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
            let (d, borrow) = sub_borrow(a, b);
            if borrow {
                add_carry(&d, &self.m).0
            } else {
                d
            }
        }

        /// m - a (0 for 0).
        #[inline(always)]
        pub(crate) fn neg(&self, a: &Fe<N>) -> Fe<N> {
            if is_zero(a) {
                *a
            } else {
                sub_borrow(&self.m, a).0
            }
        }

        /// The Montgomery product a * b / R mod m (CIOS), for a and b below m.
        #[inline(always)]
        pub(crate) fn mul(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
            if N == 4 && self.p256 {
                let mut r = [0u64; N];
                r[..4].copy_from_slice(&mul_p256(a[..4].try_into().unwrap(), b[..4].try_into().unwrap()));
                return r;
            }
            let mut t = [0u64; N];
            let mut tn = 0u64; // the limb above t
            for i in 0..N {
                let bi = b[i] as u128;
                let mut c = 0u128;
                for j in 0..N {
                    let s = t[j] as u128 + a[j] as u128 * bi + c;
                    t[j] = s as u64;
                    c = s >> 64;
                }
                let s = tn as u128 + c;
                tn = s as u64;
                let tn1 = (s >> 64) as u64; // the limb above that

                let q = t[0].wrapping_mul(self.m0inv) as u128;
                let s = t[0] as u128 + q * self.m[0] as u128;
                let mut c = s >> 64;
                for j in 1..N {
                    let s = t[j] as u128 + q * self.m[j] as u128 + c;
                    t[j - 1] = s as u64;
                    c = s >> 64;
                }
                let s = tn as u128 + c;
                t[N - 1] = s as u64;
                tn = tn1 + (s >> 64) as u64;
            }
            self.reduce_once(t, tn != 0)
        }

        /// a * a / R mod m: each product of two different limbs made once and doubled (N (N + 1) / 2 products where a
        /// multiplication makes N^2), then reduced. Outside [`SQR_MIN`] to [`SQR_MAX`] limbs, a multiplication.
        #[inline(always)]
        pub(crate) fn sqr(&self, a: &Fe<N>) -> Fe<N> {
            if !(SQR_MIN..=SQR_MAX).contains(&N) {
                return self.mul(a, a);
            }
            let mut t = [0u64; 2 * SQR_MAX];
            for i in 0..N {
                let mut c = 0u128;
                for j in i + 1..N {
                    let s = t[i + j] as u128 + a[i] as u128 * a[j] as u128 + c;
                    t[i + j] = s as u64;
                    c = s >> 64;
                }
                t[i + N] = c as u64;
            }
            // twice that, plus the squares of the limbs (a^2 < 2^(128 N): nothing is left over the top)
            let mut top = 0u64;
            for v in t.iter_mut().take(2 * N) {
                let x = *v;
                *v = (x << 1) | top;
                top = x >> 63;
            }
            let mut c = 0u128;
            for i in 0..N {
                let sq = a[i] as u128 * a[i] as u128;
                let s = t[2 * i] as u128 + (sq as u64) as u128 + c;
                t[2 * i] = s as u64;
                let s = t[2 * i + 1] as u128 + (sq >> 64) + (s >> 64);
                t[2 * i + 1] = s as u64;
                c = s >> 64;
            }
            self.redc(t)
        }

        /// t / R mod m for t below m R (2 N limbs): N steps of adding the multiple of m that clears the lowest limb, then the
        /// upper half, under 2m, reduced once.
        #[inline(always)]
        fn redc(&self, mut t: [u64; 2 * SQR_MAX]) -> Fe<N> {
            // (what overflows t[i + N] at step i goes into t[i + N + 1] at step i + 1, where the next carry goes)
            let mut over = 0u64;
            for i in 0..N {
                let q = t[i].wrapping_mul(self.m0inv);
                let mut c = 0u128;
                for j in 0..N {
                    let s = t[i + j] as u128 + q as u128 * self.m[j] as u128 + c;
                    t[i + j] = s as u64;
                    c = s >> 64;
                }
                let s = t[i + N] as u128 + c + over as u128;
                t[i + N] = s as u64;
                over = (s >> 64) as u64;
            }
            let mut r = [0u64; N];
            r.copy_from_slice(&t[N..2 * N]);
            self.reduce_once(r, over != 0)
        }

        pub(crate) fn to_mont(&self, a: &Fe<N>) -> Fe<N> {
            self.mul(a, &self.r2)
        }

        #[cfg(test)]
        pub(crate) fn from_mont(&self, a: &Fe<N>) -> Fe<N> {
            let mut one = [0u64; N];
            one[0] = 1;
            self.mul(a, &one)
        }

        #[cfg(test)]
        pub(crate) fn r2_for_tests(&self) -> Fe<N> {
            self.r2
        }

        #[cfg(test)]
        pub(crate) fn is_p256_for_tests(&self) -> bool {
            self.p256
        }

        /// base^e mod m, for `base` below m (as it is, not in Montgomery form) and an odd e of at least 3: square and multiply
        /// from the top bit, the last multiplication by `base` itself, which also takes the result out of Montgomery form
        /// ((x R) b / R = x b): one product fewer than converting at the end.
        pub(crate) fn pow_odd(&self, base: &Fe<N>, e: u64) -> Fe<N> {
            assert!(e & 1 == 1 && e >= 3, "an odd exponent of at least 3");
            let bm = self.to_mont(base);
            let mut r = bm;
            let bits = 64 - e.leading_zeros();
            for i in (1..bits - 1).rev() {
                r = self.sqr(&r);
                if (e >> i) & 1 == 1 {
                    r = self.mul(&r, &bm);
                }
            }
            r = self.sqr(&r);
            self.mul(&r, base)
        }

        /// The inverse of a nonzero value (Montgomery form in, Montgomery form out) by Fermat's little theorem:
        /// a^(m-2), in windows of four bits.
        pub(crate) fn inv(&self, a: &Fe<N>) -> Fe<N> {
            let mut e = self.m;
            e[0] -= 2; // the low limb of every modulus used here is far above 2
            let mut table = [self.one; 16];
            table[1] = *a;
            for i in 2..16 {
                table[i] = self.mul(&table[i - 1], a);
            }
            let mut r = self.one;
            for limb in (0..N).rev() {
                for nibble in (0..16).rev() {
                    for _ in 0..4 {
                        r = self.sqr(&r);
                    }
                    let d = ((e[limb] >> (4 * nibble)) & 15) as usize;
                    if d != 0 {
                        r = self.mul(&r, &table[d]);
                    }
                }
            }
            r
        }
    }

    /// The Montgomery product modulo P-256's prime (CIOS, as [`Field::mul`], with the reduction of [`Field::redc`]'s P-256 case).
    #[inline(always)]
    fn mul_p256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut t = [0u64; 4];
        let mut tn = 0u64; // the limb above t
        for &bi in &b {
            let mut c = 0u128;
            for j in 0..4 {
                let s = t[j] as u128 + a[j] as u128 * bi as u128 + c;
                t[j] = s as u64;
                c = s >> 64;
            }
            let s = tn as u128 + c;
            tn = s as u64;
            let tn1 = (s >> 64) as u64;
            // t + q p with q = t[0], shifted down a limb
            let q = t[0];
            let s = t[1] as u128 + ((q as u128) << 32);
            let t0 = s as u64;
            let s = t[2] as u128 + (s >> 64);
            let t1 = s as u64;
            let s = t[3] as u128 + q as u128 * P256[3] as u128 + (s >> 64);
            let t2 = s as u64;
            let s = tn as u128 + (s >> 64);
            t = [t0, t1, t2, s as u64];
            tn = tn1 + (s >> 64) as u64;
        }
        let (d, borrow) = sub_borrow(&t, &P256);
        if tn != 0 || !borrow {
            d
        } else {
            t
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_roundtrip() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
        let l = from_be_bytes(&bytes);
        assert_eq!(l, vec![0x030405060708090a_u64, 0x0102]);
        assert_eq!(to_be_bytes(&l, 10), bytes.to_vec());
        assert_eq!(to_be_bytes(&l, 12)[..2], [0, 0]);
    }

    #[test]
    fn modpow_small() {
        // 4^13 mod 497 = 445 (classic example)
        let m = Mont::new(&[497]);
        let base = m.to_mont(&[4]);
        let r = m.from_mont(&m.pow(&base, &[13]));
        assert_eq!(r, vec![445]);
    }

    #[test]
    fn fermat_inverse_multi_limb() {
        // p = 2^127 - 1 (prime); check a * a^-1 == 1
        let p = from_hex("7fffffffffffffffffffffffffffffff");
        let m = Mont::new(&p);
        let a = m.to_mont(&m.fit(&from_hex("123456789abcdef0fedcba9876543210")));
        let inv = m.inv(&a);
        let one = m.from_mont(&m.mul(&a, &inv));
        assert_eq!(one, vec![1, 0]);
    }

    #[test]
    fn add_sub_wrap() {
        let m = Mont::new(&[97]);
        assert_eq!(m.add(&[90], &[20]), vec![13]);
        assert_eq!(m.sub(&[5], &[10]), vec![92]);
    }

    #[test]
    fn matches_python_modpow() {
        // pow(0xdeadbeefcafebabe1234567890abcdef, 65537, 2^192 - 237) computed with Python
        let modulus = from_hex("ffffffffffffffffffffffffffffffffffffffffffffff13");
        let m = Mont::new(&modulus);
        let base = m.to_mont(&m.fit(&from_hex("deadbeefcafebabe1234567890abcdef")));
        let r = m.from_mont(&m.pow(&base, &[65537]));
        assert_eq!(to_be_bytes(&r, 24), crate::util::unhex(PYTHON_RESULT));
    }

    /// The constants of the context against the definition (64n modular doublings of 1, then 64n more), for moduli of
    /// every size the library uses and some it does not, with top limbs from 1 to all ones.
    #[test]
    fn the_constants_are_r_and_r_squared_mod_m() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for n in [1usize, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 32, 33, 47, 48, 64, 65] {
            for top in [1u64, 3, 0x1ff, 0x8000_0000_0000_0000, u64::MAX, 0] {
                let mut m: Vec<u64> = (0..n).map(|_| next()).collect();
                if top != 0 {
                    m[n - 1] = top;
                }
                m[0] |= 1;
                if n == 1 && m[0] == 1 {
                    continue;
                }
                let ctx = Mont::new(&m);
                let mut x = vec![0u64; n];
                x[0] = 1;
                for _ in 0..64 * n {
                    x = ctx.add(&x, &x);
                }
                assert_eq!(ctx.one, x, "R mod m, {n} limbs, top {top:#x}");
                for _ in 0..64 * n {
                    x = ctx.add(&x, &x);
                }
                assert_eq!(ctx.r2, x, "R^2 mod m, {n} limbs, top {top:#x}");
                // and so a round trip through the Montgomery form is the identity
                let a = ctx.fit(&[next() % m[0].max(2)]);
                assert_eq!(ctx.from_mont(&ctx.to_mont(&a)), a);
            }
        }
        let one = Mont::new(&[1]);
        assert_eq!((one.one(), one.r2.clone()), (vec![0], vec![0]));
    }

    const PYTHON_RESULT: &str = "04b8399e2761eeefd31b998f36722aa31e7c257d126c1760";

    /// The fixed-size arithmetic agrees with the general code: the constants, products, squares (the dedicated squaring
    /// at RSA's sizes) and odd powers, on random moduli of every size the library uses, with top limbs of 1 and all ones,
    /// on random values and at the edges (0, 1, m - 1); and P-256's own reduction agrees with the general one.
    #[test]
    fn fixed_size_arithmetic_matches_the_general_code() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        fn check<const N: usize>(m: [u64; N], next: &mut impl FnMut() -> u64) {
            let f = fixed::Field::<N>::from_modulus(m);
            let g = Mont::new(&m);
            assert_eq!((f.one.to_vec(), f.r2_for_tests().to_vec()), (g.one.clone(), g.r2.clone()), "constants, {N} limbs");
            let below = |next: &mut dyn FnMut() -> u64| -> [u64; N] {
                let mut a: [u64; N] = core::array::from_fn(|_| next());
                a[N - 1] %= m[N - 1]; // under m's top limb, so under m
                a
            };
            let mut m_minus_1 = m;
            m_minus_1[0] -= 1;
            let mut one = [0u64; N];
            one[0] = 1;
            let mut values = vec![[0u64; N], one, m_minus_1];
            for _ in 0..6 {
                values.push(below(next));
            }
            for a in &values {
                assert_eq!(f.sqr(a).to_vec(), g.mul(a, a), "square, {N} limbs");
                for b in &values {
                    assert_eq!(f.mul(a, b).to_vec(), g.mul(a, b), "product, {N} limbs");
                }
                for e in [3u64, 65537, next() | 1 | (1 << 63)] {
                    assert_eq!(f.pow_odd(a, e).to_vec(), g.from_mont(&g.pow(&g.to_mont(a), &[e])), "power {e}, {N} limbs");
                }
            }
        }
        macro_rules! sizes {
            ($($n:literal),*) => {$(
                for top in [1u64, u64::MAX, 0] {
                    let mut m: [u64; $n] = core::array::from_fn(|_| next());
                    m[0] |= 1;
                    if top != 0 {
                        m[$n - 1] = top;
                    }
                    if m[$n - 1] == 0 {
                        m[$n - 1] = 1;
                    }
                    check::<$n>(m, &mut next);
                }
            )*};
        }
        sizes!(4, 6, 9, 16, 17, 24, 32, 48, 64);
        // P-256's prime takes its own reduction
        let p256: [u64; 4] = fixed::limbs_from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        check::<4>(p256, &mut next);
        assert!(fixed::Field::<4>::from_modulus(p256).is_p256_for_tests());
    }
}

