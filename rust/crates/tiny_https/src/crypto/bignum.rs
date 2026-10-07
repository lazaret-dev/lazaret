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
        // R mod m by repeated doubling of 1
        let mut x = vec![0u64; n];
        x[0] = 1;
        if n == 1 && ctx.m[0] == 1 {
            x[0] = 0;
        }
        for _ in 0..64 * n {
            x = ctx.add(&x, &x);
        }
        ctx.one = x.clone();
        for _ in 0..64 * n {
            x = ctx.add(&x, &x);
        }
        ctx.r2 = x;
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

    const PYTHON_RESULT: &str = "04b8399e2761eeefd31b998f36722aa31e7c257d126c1760";
}
