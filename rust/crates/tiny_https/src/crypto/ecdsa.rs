//! ECDSA signature verification over NIST P-256 and P-384.
//!
//! Verification only, so every value is public and nothing here is constant time (signing and the key
//! exchange, which do handle secrets, are in `ecdh.rs` and elsewhere and are written differently). What this
//! module is written for is speed, because a TLS handshake checks two signatures (the certificate's and the
//! server's `CertificateVerify`) and for a client that opens many connections that is most of what a handshake
//! costs:
//!
//! * field elements are fixed-size limb arrays (`[u64; N]`, N = 4 or 6, a const generic, so the loops of the
//!   Montgomery multiplication are unrolled and nothing is allocated);
//! * `u1*G + u2*Q` is computed by one interleaved pass over the width-w non-adjacent forms of the two scalars
//!   (Straus-Shamir): one doubling per bit, and an addition only at the nonzero digits (about one in w + 1);
//! * the multiples of the generator come from a table of 32 odd multiples in affine form (built once, on first
//!   use), so adding them is the cheaper mixed addition; the public key's own table (8 odd multiples) is made
//!   per signature;
//! * the final comparison `x(R) mod n == r` is made without converting R to affine coordinates (no second
//!   inversion): `X == r * Z^2`, or `X == (r + n) * Z^2` in the rare case that `r + n` is still below p.
//!
//! The old, simple implementation (a vector of limbs per value, one bit per step) is kept under `cfg(test)` as
//! the reference the new one is compared with, on random keys and signatures and on the special cases of the
//! group law (adding a point to itself, to its negative).

use super::bignum::Mont;
use super::sha2::HashAlg;
use crate::asn1::{self, Der};
use std::cmp::Ordering;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

impl Curve {
    pub fn coord_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
        }
    }
}

/// A number below a modulus of N limbs, least significant limb first.
type Fe<const N: usize> = [u64; N];

fn is_zero<const N: usize>(a: &Fe<N>) -> bool {
    a.iter().all(|&x| x == 0)
}

fn compare<const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Ordering {
    for i in (0..N).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    Ordering::Equal
}

/// a + b, and whether it carried out of the top limb.
#[inline(always)]
fn add_carry<const N: usize>(a: &Fe<N>, b: &Fe<N>) -> (Fe<N>, bool) {
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
fn sub_borrow<const N: usize>(a: &Fe<N>, b: &Fe<N>) -> (Fe<N>, bool) {
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
fn limbs_from_be<const N: usize>(bytes: &[u8]) -> Option<Fe<N>> {
    if bytes.len() > 8 * N {
        return None;
    }
    let mut r = [0u64; N];
    for (i, b) in bytes.iter().rev().enumerate() {
        r[i / 8] |= (*b as u64) << (8 * (i % 8));
    }
    Some(r)
}

fn limbs_from_hex<const N: usize>(hex: &str) -> Fe<N> {
    limbs_from_be(&crate::util::unhex(hex)).expect("constant fits")
}

/// Arithmetic modulo an odd prime of N limbs, in Montgomery form (R = 2^(64 N)).
struct Field<const N: usize> {
    m: Fe<N>,
    /// -m^-1 mod 2^64
    m0inv: u64,
    /// R mod m: the Montgomery form of 1
    one: Fe<N>,
    /// R^2 mod m
    r2: Fe<N>,
}

impl<const N: usize> Field<N> {
    fn new(modulus_hex: &str) -> Field<N> {
        let m: Fe<N> = limbs_from_hex(modulus_hex);
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
        }
        // R mod m and R^2 mod m by the generic code, which has no assumption about the form of the modulus
        let mont = Mont::new(&m);
        let one_v = mont.one();
        let r2_v = mont.to_mont(&one_v);
        let mut one = [0u64; N];
        let mut r2 = [0u64; N];
        one.copy_from_slice(&one_v);
        r2.copy_from_slice(&r2_v);
        Field { m, m0inv: inv.wrapping_neg(), one, r2 }
    }

    /// `t` (with the carry out of its top limb) reduced once: minus m if it is at least m.
    #[inline(always)]
    fn reduce_once(&self, t: Fe<N>, carry: bool) -> Fe<N> {
        let (d, borrow) = sub_borrow(&t, &self.m);
        if carry || !borrow {
            d
        } else {
            t
        }
    }

    #[inline(always)]
    fn add(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
        let (s, carry) = add_carry(a, b);
        self.reduce_once(s, carry)
    }

    #[inline(always)]
    fn sub(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
        let (d, borrow) = sub_borrow(a, b);
        if borrow {
            add_carry(&d, &self.m).0
        } else {
            d
        }
    }

    /// m - a (0 for 0).
    #[inline(always)]
    fn neg(&self, a: &Fe<N>) -> Fe<N> {
        if is_zero(a) {
            *a
        } else {
            sub_borrow(&self.m, a).0
        }
    }

    /// The Montgomery product a * b / R mod m (CIOS), for a and b below m.
    #[inline(always)]
    fn mul(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
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

    #[inline(always)]
    fn sqr(&self, a: &Fe<N>) -> Fe<N> {
        self.mul(a, a)
    }

    fn to_mont(&self, a: &Fe<N>) -> Fe<N> {
        self.mul(a, &self.r2)
    }

    #[cfg(test)]
    fn from_mont(&self, a: &Fe<N>) -> Fe<N> {
        let mut one = [0u64; N];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// The inverse of a nonzero value (Montgomery form in, Montgomery form out) by Fermat's little theorem:
    /// a^(m-2), in windows of four bits.
    fn inv(&self, a: &Fe<N>) -> Fe<N> {
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

/// A point in Jacobian coordinates (X : Y : Z), Montgomery form, meaning (X / Z^2, Y / Z^3); Z = 0 is the point at
/// infinity.
#[derive(Clone, Copy)]
struct Jac<const N: usize> {
    x: Fe<N>,
    y: Fe<N>,
    z: Fe<N>,
}

/// A point other than infinity, Montgomery form.
#[derive(Clone, Copy)]
struct Aff<const N: usize> {
    x: Fe<N>,
    y: Fe<N>,
}

/// Width of the windows over the generator's scalar: its table holds the odd multiples 1G, 3G, ... up to
/// (2^(W_G - 1) - 1) G.
const W_G: u32 = 7;
const G_TABLE: usize = 1 << (W_G - 2);
/// The same for the public key's scalar, whose table is made for each signature.
const W_Q: u32 = 5;
const Q_TABLE: usize = 1 << (W_Q - 2);
/// Digits of a width-w NAF of a number of up to 384 bits: one more than its bits, and a spare.
const MAX_DIGITS: usize = 64 * 6 + 2;

/// A curve y^2 = x^3 - 3x + b over GF(p) with a prime group order n (and cofactor 1).
struct Group<const N: usize> {
    f: Field<N>,
    n: Field<N>,
    b: Fe<N>,
    g: Aff<N>,
    /// 1G, 3G, 5G, ..., built on first use.
    g_table: OnceLock<Vec<Aff<N>>>,
}

impl<const N: usize> Group<N> {
    fn new(p: &str, b: &str, gx: &str, gy: &str, n: &str) -> Group<N> {
        let f = Field::<N>::new(p);
        let order = Field::<N>::new(n);
        let to_m = |h: &str| f.to_mont(&limbs_from_hex(h));
        let (b, gx, gy) = (to_m(b), to_m(gx), to_m(gy));
        Group { f, n: order, b, g: Aff { x: gx, y: gy }, g_table: OnceLock::new() }
    }

    fn infinity(&self) -> Jac<N> {
        Jac { x: self.f.one, y: self.f.one, z: [0; N] }
    }

    fn jac(&self, p: &Aff<N>) -> Jac<N> {
        Jac { x: p.x, y: p.y, z: self.f.one }
    }

    /// Checks y^2 = x^3 - 3x + b for Montgomery-form coordinates.
    fn on_curve(&self, p: &Aff<N>) -> bool {
        let f = &self.f;
        let lhs = f.sqr(&p.y);
        let x3 = f.mul(&f.sqr(&p.x), &p.x);
        let three_x = f.add(&f.add(&p.x, &p.x), &p.x);
        let rhs = f.add(&f.sub(&x3, &three_x), &self.b);
        lhs == rhs
    }

    /// Point doubling for a = -3 (dbl-2001-b): 3 multiplications and 5 squarings.
    fn double(&self, p: &Jac<N>) -> Jac<N> {
        let f = &self.f;
        if is_zero(&p.z) {
            return *p;
        }
        let delta = f.sqr(&p.z);
        let gamma = f.sqr(&p.y);
        let beta = f.mul(&p.x, &gamma);
        let t = f.mul(&f.sub(&p.x, &delta), &f.add(&p.x, &delta));
        let alpha = f.add(&f.add(&t, &t), &t);
        let beta2 = f.add(&beta, &beta);
        let beta4 = f.add(&beta2, &beta2);
        let x3 = f.sub(&f.sub(&f.sqr(&alpha), &beta4), &beta4);
        let z3 = f.sub(&f.sub(&f.sqr(&f.add(&p.y, &p.z)), &gamma), &delta);
        let gamma2 = f.sqr(&gamma);
        let g2x2 = f.add(&gamma2, &gamma2);
        let g2x4 = f.add(&g2x2, &g2x2);
        let g2x8 = f.add(&g2x4, &g2x4);
        let y3 = f.sub(&f.mul(&alpha, &f.sub(&beta4, &x3)), &g2x8);
        Jac { x: x3, y: y3, z: z3 }
    }

    /// p + q for an affine q (madd-2007-bl: 7 multiplications and 4 squarings), special cases included.
    fn add_affine(&self, p: &Jac<N>, q: &Aff<N>) -> Jac<N> {
        let f = &self.f;
        if is_zero(&p.z) {
            return self.jac(q);
        }
        let z1z1 = f.sqr(&p.z);
        let u2 = f.mul(&q.x, &z1z1);
        let s2 = f.mul(&f.mul(&q.y, &p.z), &z1z1);
        let h = f.sub(&u2, &p.x);
        let r0 = f.sub(&s2, &p.y);
        if is_zero(&h) {
            // the same x: the same point (double it) or its negative (infinity)
            return if is_zero(&r0) { self.double(p) } else { self.infinity() };
        }
        let hh = f.sqr(&h);
        let i = f.add(&hh, &hh);
        let i = f.add(&i, &i);
        let j = f.mul(&h, &i);
        let r = f.add(&r0, &r0);
        let v = f.mul(&p.x, &i);
        let x3 = f.sub(&f.sub(&f.sub(&f.sqr(&r), &j), &v), &v);
        let y1j = f.mul(&p.y, &j);
        let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.add(&y1j, &y1j));
        let z3 = f.sub(&f.sub(&f.sqr(&f.add(&p.z, &h)), &z1z1), &hh);
        Jac { x: x3, y: y3, z: z3 }
    }

    /// p + q (add-2007-bl: 11 multiplications and 5 squarings), special cases included.
    fn add(&self, p: &Jac<N>, q: &Jac<N>) -> Jac<N> {
        let f = &self.f;
        if is_zero(&p.z) {
            return *q;
        }
        if is_zero(&q.z) {
            return *p;
        }
        let z1z1 = f.sqr(&p.z);
        let z2z2 = f.sqr(&q.z);
        let u1 = f.mul(&p.x, &z2z2);
        let u2 = f.mul(&q.x, &z1z1);
        let s1 = f.mul(&f.mul(&p.y, &q.z), &z2z2);
        let s2 = f.mul(&f.mul(&q.y, &p.z), &z1z1);
        let h = f.sub(&u2, &u1);
        let r0 = f.sub(&s2, &s1);
        if is_zero(&h) {
            return if is_zero(&r0) { self.double(p) } else { self.infinity() };
        }
        let h2 = f.add(&h, &h);
        let i = f.sqr(&h2);
        let j = f.mul(&h, &i);
        let r = f.add(&r0, &r0);
        let v = f.mul(&u1, &i);
        let x3 = f.sub(&f.sub(&f.sub(&f.sqr(&r), &j), &v), &v);
        let s1j = f.mul(&s1, &j);
        let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.add(&s1j, &s1j));
        let zs = f.sub(&f.sub(&f.sqr(&f.add(&p.z, &q.z)), &z1z1), &z2z2);
        let z3 = f.mul(&zs, &h);
        Jac { x: x3, y: y3, z: z3 }
    }

    fn neg_jac(&self, p: &Jac<N>) -> Jac<N> {
        Jac { x: p.x, y: self.f.neg(&p.y), z: p.z }
    }

    /// The odd multiples 1G, 3G, ..., in affine form, with one inversion for all of them (Montgomery's trick).
    fn build_g_table(&self) -> Vec<Aff<N>> {
        let f = &self.f;
        let g = self.jac(&self.g);
        let g2 = self.double(&g);
        let mut pts: Vec<Jac<N>> = Vec::with_capacity(G_TABLE);
        pts.push(g);
        for i in 1..G_TABLE {
            let next = self.add(&pts[i - 1], &g2);
            pts.push(next);
        }
        // running products of the Z coordinates, one inversion, then back down
        let mut prefix: Vec<Fe<N>> = Vec::with_capacity(G_TABLE);
        let mut acc = f.one;
        for p in &pts {
            acc = f.mul(&acc, &p.z);
            prefix.push(acc);
        }
        let mut inv_acc = f.inv(&acc);
        let mut out = vec![Aff { x: [0; N], y: [0; N] }; G_TABLE];
        for i in (0..G_TABLE).rev() {
            let zinv = if i == 0 { inv_acc } else { f.mul(&inv_acc, &prefix[i - 1]) };
            inv_acc = f.mul(&inv_acc, &pts[i].z);
            let zinv2 = f.sqr(&zinv);
            out[i] = Aff { x: f.mul(&pts[i].x, &zinv2), y: f.mul(&pts[i].y, &f.mul(&zinv2, &zinv)) };
        }
        out
    }

    /// u1 * G + u2 * Q, for plain (not Montgomery) scalars: one pass over both width-w NAFs.
    fn mul_add(&self, u1: &Fe<N>, u2: &Fe<N>, q: &Aff<N>) -> Jac<N> {
        let g_table = self.g_table.get_or_init(|| self.build_g_table());
        let mut d1 = [0i8; MAX_DIGITS];
        let mut d2 = [0i8; MAX_DIGITS];
        let l1 = wnaf(u1, W_G, &mut d1);
        let l2 = wnaf(u2, W_Q, &mut d2);

        // Q, 3Q, 5Q, ...
        let mut q_table = [self.infinity(); Q_TABLE];
        q_table[0] = self.jac(q);
        let q2 = self.double(&q_table[0]);
        for i in 1..Q_TABLE {
            q_table[i] = self.add(&q_table[i - 1], &q2);
        }

        let mut r = self.infinity();
        for i in (0..l1.max(l2)).rev() {
            r = self.double(&r);
            if i < l1 && d1[i] != 0 {
                let e = &g_table[(d1[i].unsigned_abs() as usize) / 2];
                let e = if d1[i] < 0 { Aff { x: e.x, y: self.f.neg(&e.y) } } else { *e };
                r = self.add_affine(&r, &e);
            }
            if i < l2 && d2[i] != 0 {
                let e = &q_table[(d2[i].unsigned_abs() as usize) / 2];
                r = if d2[i] < 0 { self.add(&r, &self.neg_jac(e)) } else { self.add(&r, e) };
            }
        }
        r
    }

    /// The affine coordinates (plain integers) of a point, or `None` for infinity. Only the tests need it: a
    /// verification compares without it.
    #[cfg(test)]
    fn to_affine(&self, p: &Jac<N>) -> Option<(Fe<N>, Fe<N>)> {
        if is_zero(&p.z) {
            return None;
        }
        let f = &self.f;
        let zinv = f.inv(&p.z);
        let zinv2 = f.sqr(&zinv);
        let x = f.mul(&p.x, &zinv2);
        let y = f.mul(&p.y, &f.mul(&zinv2, &zinv));
        Some((f.from_mont(&x), f.from_mont(&y)))
    }

    /// The point of an uncompressed SEC1 public key (0x04 || X || Y), if it is one: right length, coordinates
    /// below the field prime, and on the curve.
    fn public_point(&self, public_key: &[u8]) -> Option<Aff<N>> {
        let cl = 8 * N;
        if public_key.len() != 1 + 2 * cl || public_key[0] != 0x04 {
            return None;
        }
        let qx: Fe<N> = limbs_from_be(&public_key[1..1 + cl])?;
        let qy: Fe<N> = limbs_from_be(&public_key[1 + cl..])?;
        if compare(&qx, &self.f.m) != Ordering::Less || compare(&qy, &self.f.m) != Ordering::Less {
            return None;
        }
        let q = Aff { x: self.f.to_mont(&qx), y: self.f.to_mont(&qy) };
        self.on_curve(&q).then_some(q)
    }

    fn verify(&self, public_key: &[u8], digest: &[u8], sig_der: &[u8]) -> bool {
        let cl = 8 * N;
        let Some(q) = self.public_point(public_key) else { return false };

        // the signature: SEQUENCE { INTEGER r, INTEGER s }, both in 1..n
        let parse = || -> Option<(Fe<N>, Fe<N>)> {
            let mut outer = Der::new(sig_der);
            let mut seq = outer.sequence().ok()?;
            outer.finish().ok()?;
            let r = asn1::unsigned_integer(&seq.expect(asn1::TAG_INTEGER).ok()?).ok()?;
            let s = asn1::unsigned_integer(&seq.expect(asn1::TAG_INTEGER).ok()?).ok()?;
            seq.finish().ok()?;
            Some((limbs_from_be(&r)?, limbs_from_be(&s)?))
        };
        let Some((r, s)) = parse() else { return false };
        for v in [&r, &s] {
            if is_zero(v) || compare(v, &self.n.m) != Ordering::Less {
                return false;
            }
        }

        // e: the leftmost bits of the digest as a number, below 2^(8 cl), so below 2 n
        let Some(mut e) = limbs_from_be::<N>(&digest[..digest.len().min(cl)]) else { return false };
        if compare(&e, &self.n.m) != Ordering::Less {
            e = sub_borrow(&e, &self.n.m).0;
        }

        // w = s^-1 in Montgomery form, so that mul(e, w) = e / s as a plain number
        let nf = &self.n;
        let w = nf.inv(&nf.to_mont(&s));
        let u1 = nf.mul(&e, &w);
        let u2 = nf.mul(&r, &w);

        let rp = self.mul_add(&u1, &u2, &q);
        if is_zero(&rp.z) {
            return false;
        }
        // x(R) mod n == r, with x = X / Z^2: X == r Z^2, or X == (r + n) Z^2 if r + n < p can be a coordinate
        let f = &self.f;
        let z2 = f.sqr(&rp.z);
        if f.mul(&f.to_mont(&r), &z2) == rp.x {
            return true;
        }
        let (r_plus_n, carry) = add_carry(&r, &self.n.m);
        if !carry && compare(&r_plus_n, &f.m) == Ordering::Less {
            return f.mul(&f.to_mont(&r_plus_n), &z2) == rp.x;
        }
        false
    }
}

/// The width-w non-adjacent form of `k`, least significant digit first, into `out`; returns how many digits.
/// Every digit is zero or odd with absolute value below 2^(w-1), and no two nonzero digits are less than w apart,
/// so a nonzero one comes about every w + 1 bits. (w is at most 7 so that a digit fits in an `i8`.)
fn wnaf(k: &[u64], w: u32, out: &mut [i8; MAX_DIGITS]) -> usize {
    debug_assert!((2..=7).contains(&w) && k.len() <= 6);
    // one limb more than k has: adding the correction for a negative digit can carry out of the top
    let mut v = [0u64; 7];
    v[..k.len()].copy_from_slice(k);
    let mask = (1u64 << w) - 1;
    let half = 1u64 << (w - 1);
    let mut len = 0;
    let mut top = k.len(); // limbs at or above this one are zero
    while top > 0 && v[top - 1] == 0 {
        top -= 1;
    }
    while top > 0 {
        let mut digit = 0i8;
        if v[0] & 1 == 1 {
            let m = v[0] & mask;
            if m >= half {
                // digit m - 2^w, below zero: add 2^w - m to make the low w bits zero
                let add = (1u64 << w) - m;
                let mut carry = add;
                for limb in v.iter_mut() {
                    let (s, c) = limb.overflowing_add(carry);
                    *limb = s;
                    carry = c as u64;
                    if carry == 0 {
                        break;
                    }
                }
                digit = -(add as i8);
                if top < 7 && v[top] != 0 {
                    top += 1;
                }
            } else {
                // digit m: subtract it
                let mut borrow = m;
                for limb in v.iter_mut() {
                    let (s, b) = limb.overflowing_sub(borrow);
                    *limb = s;
                    borrow = b as u64;
                    if borrow == 0 {
                        break;
                    }
                }
                digit = m as i8;
            }
        }
        out[len] = digit;
        len += 1;
        // shift right by one
        for i in 0..top {
            v[i] = (v[i] >> 1) | if i + 1 < 7 { v[i + 1] << 63 } else { 0 };
        }
        while top > 0 && v[top - 1] == 0 {
            top -= 1;
        }
    }
    len
}

fn p256() -> &'static Group<4> {
    static G: OnceLock<Group<4>> = OnceLock::new();
    G.get_or_init(|| {
        Group::new(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        )
    })
}

fn p384() -> &'static Group<6> {
    static G: OnceLock<Group<6>> = OnceLock::new();
    G.get_or_init(|| {
        Group::new(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        )
    })
}

/// Whether `public_key` is an uncompressed SEC1 point (0x04 || X || Y) on `curve`, which is all a public key
/// has to be for [`verify`] to use it.
pub fn is_valid_public_key(curve: Curve, public_key: &[u8]) -> bool {
    match curve {
        Curve::P256 => p256().public_point(public_key).is_some(),
        Curve::P384 => p384().public_point(public_key).is_some(),
    }
}

/// Verifies an ASN.1 DER-encoded ECDSA signature over `digest` (already hashed).
///
/// `public_key` is an uncompressed SEC1 point (0x04 || X || Y).
pub fn verify_prehashed(curve: Curve, public_key: &[u8], digest: &[u8], sig_der: &[u8]) -> bool {
    match curve {
        Curve::P256 => p256().verify(public_key, digest, sig_der),
        Curve::P384 => p384().verify(public_key, digest, sig_der),
    }
}

/// Hashes `msg` with `alg` and verifies the signature.
pub fn verify(curve: Curve, public_key: &[u8], alg: HashAlg, msg: &[u8], sig_der: &[u8]) -> bool {
    verify_prehashed(curve, public_key, &alg.digest(msg), sig_der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::bignum;
    use crate::crypto::test_vectors as tv;
    use crate::util::unhex;

    /// The old implementation: a vector of limbs per value, Jacobian coordinates, one bit per step. Slow, simple,
    /// and checked against the test vectors for years; the new code is compared with it.
    mod reference {
        use super::super::Curve;
        use crate::crypto::bignum::{self, Mont};
        use std::sync::OnceLock;

        pub(super) struct Params {
            pub(super) f: Mont, // field GF(p)
            pub(super) n: Mont, // group order
            pub(super) b: Vec<u64>,  // curve constant b (Montgomery form in f)
            pub(super) gx: Vec<u64>, // generator, Montgomery form
            pub(super) gy: Vec<u64>,
        }

        #[derive(Clone)]
        pub(super) struct Point {
            pub(super) x: Vec<u64>,
            pub(super) y: Vec<u64>,
            pub(super) z: Vec<u64>, // z == 0 means the point at infinity
        }

        pub(super) fn build(p: &str, b: &str, gx: &str, gy: &str, n: &str) -> Params {
            let f = Mont::new(&bignum::from_hex(p));
            let nn = Mont::new(&bignum::from_hex(n));
            let to_m = |h: &str| f.to_mont(&f.fit(&bignum::from_hex(h)));
            let (b, gx, gy) = (to_m(b), to_m(gx), to_m(gy));
            Params { f, n: nn, b, gx, gy }
        }

        pub(super) fn params(curve: Curve) -> &'static Params {
            static P256: OnceLock<Params> = OnceLock::new();
            static P384: OnceLock<Params> = OnceLock::new();
            match curve {
                Curve::P256 => P256.get_or_init(|| {
                    build(
                        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                        )
                }),
                Curve::P384 => P384.get_or_init(|| {
                    build(
                        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
                        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
                        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
                        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
                        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                        )
                }),
            }
        }

        impl Params {
            pub(super) fn infinity(&self) -> Point {
                Point { x: self.f.one(), y: self.f.one(), z: self.f.zero() }
            }

            pub(super) fn is_infinity(&self, p: &Point) -> bool {
                bignum::is_zero(&p.z)
            }

            pub(super) fn affine_point(&self, x: &[u64], y: &[u64]) -> Point {
                Point { x: x.to_vec(), y: y.to_vec(), z: self.f.one() }
            }

            /// Point doubling for a = -3 (dbl-2001-b).
            pub(super) fn double(&self, p: &Point) -> Point {
                let f = &self.f;
                if self.is_infinity(p) {
                    return p.clone();
                }
                let delta = f.sqr(&p.z);
                let gamma = f.sqr(&p.y);
                let beta = f.mul(&p.x, &gamma);
                let t = f.mul(&f.sub(&p.x, &delta), &f.add(&p.x, &delta));
                let alpha = f.add(&f.add(&t, &t), &t);
                let beta2 = f.add(&beta, &beta);
                let beta4 = f.add(&beta2, &beta2);
                let beta8 = f.add(&beta4, &beta4);
                let x3 = f.sub(&f.sqr(&alpha), &beta8);
                let z3 = f.sub(&f.sub(&f.sqr(&f.add(&p.y, &p.z)), &gamma), &delta);
                let gamma2 = f.sqr(&gamma);
                let g2x2 = f.add(&gamma2, &gamma2);
                let g2x4 = f.add(&g2x2, &g2x2);
                let g2x8 = f.add(&g2x4, &g2x4);
                let y3 = f.sub(&f.mul(&alpha, &f.sub(&beta4, &x3)), &g2x8);
                Point { x: x3, y: y3, z: z3 }
            }

            /// General Jacobian point addition (add-1998-cmo-2), with the special cases handled.
            pub(super) fn add(&self, p: &Point, q: &Point) -> Point {
                let f = &self.f;
                if self.is_infinity(p) {
                    return q.clone();
                }
                if self.is_infinity(q) {
                    return p.clone();
                }
                let z1z1 = f.sqr(&p.z);
                let z2z2 = f.sqr(&q.z);
                let u1 = f.mul(&p.x, &z2z2);
                let u2 = f.mul(&q.x, &z1z1);
                let s1 = f.mul(&f.mul(&p.y, &q.z), &z2z2);
                let s2 = f.mul(&f.mul(&q.y, &p.z), &z1z1);
                let h = f.sub(&u2, &u1);
                let r = f.sub(&s2, &s1);
                if bignum::is_zero(&h) {
                    return if bignum::is_zero(&r) { self.double(p) } else { self.infinity() };
                }
                let hh = f.sqr(&h);
                let hhh = f.mul(&h, &hh);
                let v = f.mul(&u1, &hh);
                let v2 = f.add(&v, &v);
                let x3 = f.sub(&f.sub(&f.sqr(&r), &hhh), &v2);
                let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.mul(&s1, &hhh));
                let z3 = f.mul(&f.mul(&p.z, &q.z), &h);
                Point { x: x3, y: y3, z: z3 }
            }

            /// Converts to affine coordinates, returned as ordinary integers.
            pub(super) fn to_affine(&self, p: &Point) -> Option<(Vec<u64>, Vec<u64>)> {
                if self.is_infinity(p) {
                    return None;
                }
                let f = &self.f;
                let zinv = f.inv(&p.z);
                let zinv2 = f.sqr(&zinv);
                let x = f.mul(&p.x, &zinv2);
                let y = f.mul(&p.y, &f.mul(&zinv2, &zinv));
                Some((f.from_mont(&x), f.from_mont(&y)))
            }

            /// Checks y^2 = x^3 - 3x + b for Montgomery-form coordinates.
            pub(super) fn on_curve(&self, x: &[u64], y: &[u64]) -> bool {
                let f = &self.f;
                let lhs = f.sqr(y);
                let x3 = f.mul(&f.sqr(x), x);
                let three_x = f.add(&f.add(x, x), x);
                let rhs = f.add(&f.sub(&x3, &three_x), &self.b);
                lhs == rhs
            }
        }
    }

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A pseudo-random number in 1..n, as limbs, for the curve of `pr`.
    fn random_scalar(pr: &reference::Params, state: &mut u64) -> Vec<u64> {
        let n = pr.n.modulus().to_vec();
        loop {
            let mut v: Vec<u64> = (0..n.len()).map(|_| splitmix(state)).collect();
            // a mix of sizes: sometimes only some of the bits, to make short and sparse scalars too
            match splitmix(state) % 4 {
                0 => {
                    let keep = (splitmix(state) % (64 * n.len() as u64)) as usize;
                    for i in 0..64 * n.len() {
                        if i >= keep {
                            v[i / 64] &= !(1u64 << (i % 64));
                        }
                    }
                }
                1 => v.iter_mut().for_each(|l| *l &= 0x8000_0000_8000_0001), // sparse
                _ => {}
            }
            if !bignum::is_zero(&v) && bignum::cmp(&v, &n) == Ordering::Less {
                return v;
            }
        }
    }

    /// k * G by the reference code, as plain affine coordinates.
    fn ref_mul_g(pr: &reference::Params, k: &[u64]) -> (Vec<u64>, Vec<u64>) {
        let g = pr.affine_point(&pr.gx, &pr.gy);
        let mut r = pr.infinity();
        for i in (0..bignum::bit_len(k)).rev() {
            r = pr.double(&r);
            if bignum::bit(k, i) {
                r = pr.add(&r, &g);
            }
        }
        pr.to_affine(&r).expect("k is in 1..n")
    }

    fn der_int(v: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = v.iter().copied().skip_while(|&b| b == 0).collect();
        if v.first().map_or(true, |&b| b & 0x80 != 0) {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend(v);
        out
    }

    fn der_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
        let (r, s) = (der_int(r), der_int(s));
        let mut out = vec![0x30, (r.len() + s.len()) as u8];
        out.extend(r);
        out.extend(s);
        out
    }

    /// Signs `digest` with private key `d` and nonce `k` using the reference arithmetic: (public key, DER signature).
    fn ref_sign(curve: Curve, d: &[u64], k: &[u64], digest: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pr = reference::params(curve);
        let cl = curve.coord_len();
        let nm = &pr.n;
        let (qx, qy) = ref_mul_g(pr, d);
        let mut public = vec![4u8];
        public.extend(bignum::to_be_bytes(&qx, cl));
        public.extend(bignum::to_be_bytes(&qy, cl));

        let (rx, _) = ref_mul_g(pr, k);
        let mut r = nm.fit(&rx);
        if bignum::cmp(&r, nm.modulus()) != Ordering::Less {
            r = nm.sub(&r, &nm.fit(nm.modulus()));
        }
        let mut e = nm.fit(&bignum::from_be_bytes(&digest[..digest.len().min(cl)]));
        if bignum::cmp(&e, nm.modulus()) != Ordering::Less {
            e = nm.sub(&e, &nm.fit(nm.modulus()));
        }
        // s = k^-1 (e + r d)
        let rd = nm.mul(&nm.to_mont(&r), &nm.to_mont(&nm.fit(d)));
        let sum = nm.add(&nm.to_mont(&e), &rd);
        let s = nm.from_mont(&nm.mul(&nm.inv(&nm.to_mont(&nm.fit(k))), &sum));
        (public, der_sig(&bignum::to_be_bytes(&r, cl), &bignum::to_be_bytes(&s, cl)))
    }

    #[test]
    fn generators_are_on_curve_and_order_is_correct() {
        for c in [Curve::P256, Curve::P384] {
            let pr = reference::params(c);
            assert!(pr.on_curve(&pr.gx, &pr.gy), "G not on curve");
            // n * G must be the point at infinity
            let n = pr.n.modulus().to_vec();
            let g = pr.affine_point(&pr.gx, &pr.gy);
            let mut r = pr.infinity();
            for i in (0..bignum::bit_len(&n)).rev() {
                r = pr.double(&r);
                if bignum::bit(&n, i) {
                    r = pr.add(&r, &g);
                }
            }
            assert!(pr.is_infinity(&r), "n*G != infinity");
        }
        assert!(p256().on_curve(&p256().g));
        assert!(p384().on_curve(&p384().g));
        // (n - 1) G + G is infinity with the new code too
        fn group_order_check<const N: usize>(g: &Group<N>) {
            let (nm1, _) = sub_borrow(&g.n.m, &{
                let mut one = [0u64; N];
                one[0] = 1;
                one
            });
            let mut one = [0u64; N];
            one[0] = 1;
            let r = g.mul_add(&nm1, &one, &g.g);
            assert!(is_zero(&r.z), "(n-1) G + G is not infinity");
        }
        group_order_check(p256());
        group_order_check(p384());
    }

    #[test]
    fn wnaf_digits_add_up_to_the_number_and_are_spaced() {
        let mut state = 7u64;
        for w in 2..=7u32 {
            for round in 0..400 {
                let limbs = 1 + round % 6;
                let k: Vec<u64> = (0..limbs).map(|_| match splitmix(&mut state) % 5 {
                    0 => 0,
                    1 => u64::MAX,
                    _ => splitmix(&mut state),
                }).collect();
                let mut digits = [0i8; MAX_DIGITS];
                let len = wnaf(&k, w, &mut digits);
                assert!(len <= 64 * limbs + 1);
                // the digits are odd or zero, below 2^(w-1), and a nonzero one is followed by w - 1 zeros
                let mut last_nonzero: Option<usize> = None;
                for (i, &d) in digits[..len].iter().enumerate() {
                    if d != 0 {
                        assert!(d % 2 != 0 && (d.unsigned_abs() as u32) < (1 << (w - 1)), "digit {d} for w {w}");
                        if let Some(l) = last_nonzero {
                            assert!(i - l >= w as usize, "digits {l} and {i} too close for w {w}");
                        }
                        last_nonzero = Some(i);
                    }
                }
                if len > 0 {
                    assert_ne!(digits[len - 1], 0, "the top digit is zero");
                }
                assert!(digits[len..].iter().all(|&d| d == 0));
                // sum of d_i 2^i == k, in a number twice as wide as needed: positives minus negatives
                let mut pos = vec![0u64; 8];
                let mut neg = vec![0u64; 8];
                for (i, &d) in digits[..len].iter().enumerate() {
                    if d == 0 {
                        continue;
                    }
                    let target = if d > 0 { &mut pos } else { &mut neg };
                    let mut carry = (d.unsigned_abs() as u128) << (i % 64);
                    let mut limb = i / 64;
                    while carry != 0 {
                        let s = target[limb] as u128 + (carry & u64::MAX as u128);
                        target[limb] = s as u64;
                        carry = (carry >> 64) + (s >> 64);
                        limb += 1;
                    }
                }
                // pos - neg == k (all limbs of k, then zeros)
                let mut borrow = 0u64;
                let mut diff = vec![0u64; 8];
                for i in 0..8 {
                    let (a, b1) = pos[i].overflowing_sub(neg[i]);
                    let (c, b2) = a.overflowing_sub(borrow);
                    diff[i] = c;
                    borrow = (b1 | b2) as u64;
                }
                assert_eq!(borrow, 0);
                let mut want = k.clone();
                want.resize(8, 0);
                assert_eq!(diff, want, "w {w} k {k:x?}");
            }
        }
    }

    fn check_mul_add<const N: usize>(g: &Group<N>, curve: Curve, rounds: usize) {
        let pr = reference::params(curve);
        let mut state = 0x1234_5678_9abc_def0 ^ N as u64;
        let to_fe = |v: &[u64]| -> Fe<N> {
            let mut a = [0u64; N];
            a.copy_from_slice(&bignum::from_be_bytes(&bignum::to_be_bytes(v, 8 * N))[..N]);
            a
        };
        for round in 0..rounds {
            let d = random_scalar(pr, &mut state);
            let u1 = random_scalar(pr, &mut state);
            let u2 = random_scalar(pr, &mut state);
            let (qx, qy) = ref_mul_g(pr, &d);
            let q = Aff { x: g.f.to_mont(&to_fe(&qx)), y: g.f.to_mont(&to_fe(&qy)) };
            assert!(g.on_curve(&q));
            // the reference: u1 G + u2 Q = (u1 + u2 d) G
            let nm = &pr.n;
            let total = nm.from_mont(&nm.add(&nm.to_mont(&nm.fit(&u1)), &nm.mul(&nm.to_mont(&nm.fit(&u2)), &nm.to_mont(&nm.fit(&d)))));
            let want = if bignum::is_zero(&total) { None } else { Some(ref_mul_g(pr, &total)) };
            let got = g.to_affine(&g.mul_add(&to_fe(&u1), &to_fe(&u2), &q));
            match (want, got) {
                (None, None) => {}
                (Some((wx, wy)), Some((gx, gy))) => {
                    assert_eq!(to_fe(&wx), gx, "x, round {round}");
                    assert_eq!(to_fe(&wy), gy, "y, round {round}");
                }
                (w, g) => panic!("round {round}: reference {:?}, new {:?}", w.is_some(), g.is_some()),
            }
        }
    }

    #[test]
    fn the_new_scalar_multiplication_matches_the_reference_p256() {
        check_mul_add(p256(), Curve::P256, 60);
    }

    #[test]
    fn the_new_scalar_multiplication_matches_the_reference_p384() {
        check_mul_add(p384(), Curve::P384, 30);
    }

    /// The special cases of the group law, which a random input never reaches: Q = G with equal scalars (the sum
    /// meets the same point, so an addition is a doubling), Q = -G (it meets the negative: infinity), zero
    /// scalars, and the largest ones.
    fn check_special_cases<const N: usize>(g: &Group<N>) {
        let f = &g.f;
        let one = {
            let mut o = [0u64; N];
            o[0] = 1;
            o
        };
        let g_aff = g.g;
        let minus_g = Aff { x: g.g.x, y: f.neg(&g.g.y) };
        let n_minus_1 = sub_borrow(&g.n.m, &one).0;
        let zero = [0u64; N];
        let affine = |p: &Jac<N>| g.to_affine(p);
        let two = {
            let mut t = [0u64; N];
            t[0] = 2;
            t
        };
        // 2G by u1 = 1, u2 = 1, Q = G, and by u1 = 2
        let a = affine(&g.mul_add(&one, &one, &g_aff));
        let b = affine(&g.mul_add(&two, &zero, &g_aff));
        let c = affine(&g.mul_add(&zero, &two, &g_aff));
        assert!(a.is_some());
        assert_eq!(a, b);
        assert_eq!(a, c);
        // Q = -G with u1 = u2: infinity; any scalar times G minus itself
        let mut state = 99u64;
        for _ in 0..20 {
            let mut k = [0u64; N];
            for l in k.iter_mut() {
                *l = splitmix(&mut state);
            }
            k[N - 1] &= 0x7fff_ffff; // below n
            assert!(affine(&g.mul_add(&k, &k, &minus_g)).is_none(), "kG - kG");
            // and u1 G + u2 G = (u1 + u2) G, whatever the digits do when they meet
            let mut k2 = k;
            k2[0] ^= 0x55;
            let sum = g.n.add(&k, &k2);
            let x = affine(&g.mul_add(&k, &k2, &g_aff));
            let y = affine(&g.mul_add(&sum, &zero, &g_aff));
            assert_eq!(x, y, "kG + k'G");
        }
        // (n - 1) G is -G
        let m = affine(&g.mul_add(&n_minus_1, &zero, &g_aff)).unwrap();
        assert_eq!(m.0, f.from_mont(&g_aff.x));
        assert_eq!(m.1, f.from_mont(&minus_g.y));
        // zero and zero: infinity
        assert!(affine(&g.mul_add(&zero, &zero, &g_aff)).is_none());
    }

    #[test]
    fn special_cases_of_the_group_law_are_right() {
        check_special_cases(p256());
        check_special_cases(p384());
    }

    #[test]
    fn signatures_made_with_the_reference_arithmetic_verify_and_tampered_ones_do_not() {
        for (curve, rounds) in [(Curve::P256, 40), (Curve::P384, 20)] {
            let pr = reference::params(curve);
            let mut state = 42u64 + rounds as u64;
            for round in 0..rounds {
                let d = random_scalar(pr, &mut state);
                let k = random_scalar(pr, &mut state);
                // digests of all the lengths the callers use (and an empty one, and one longer than the order)
                let len = [32usize, 48, 64, 20, 0, 70][round % 6];
                let digest: Vec<u8> = (0..len).map(|_| splitmix(&mut state) as u8).collect();
                let (public, sig) = ref_sign(curve, &d, &k, &digest);
                assert!(verify_prehashed(curve, &public, &digest, &sig), "{curve:?} round {round}: a good signature fails");
                assert!(is_valid_public_key(curve, &public));
                // one bit of the digest, of the signature, of the key: all refused
                if !digest.is_empty() {
                    let mut bad = digest.clone();
                    bad[round % digest.len()] ^= 1 << (round % 8);
                    // (a bit beyond the order's width, in a long digest, is not part of the number)
                    if len <= curve.coord_len() {
                        assert!(!verify_prehashed(curve, &public, &bad, &sig), "{curve:?} round {round}: bad digest");
                    }
                }
                let mut bad = sig.clone();
                let at = 4 + (round * 7) % (sig.len() - 4);
                bad[at] ^= 1 << (round % 8);
                assert!(!verify_prehashed(curve, &public, &digest, &bad), "{curve:?} round {round}: bad signature");
                let mut bad = public.clone();
                let at = 1 + (round * 5) % (public.len() - 1);
                bad[at] ^= 1 << (round % 8);
                assert!(!verify_prehashed(curve, &bad, &digest, &sig), "{curve:?} round {round}: bad key");
            }
        }
    }

    /// k * P by the reference code, in Jacobian coordinates (infinity if k is a multiple of the order).
    fn ref_mul_point(pr: &reference::Params, k: &[u64], p: &reference::Point) -> reference::Point {
        let mut r = pr.infinity();
        for i in (0..bignum::bit_len(k)).rev() {
            r = pr.double(&r);
            if bignum::bit(k, i) {
                r = pr.add(&r, p);
            }
        }
        r
    }

    /// An x coordinate between n and p is a case no random signature reaches (the chance is about 2^-64): the
    /// verifier must take x(R) mod n = x - n as r. It is made by choosing R first: a point (x, y) with x = n + t,
    /// a digest, and s; r = t; then the public key is the point that makes u1 G + u2 Q equal R.
    fn check_x_between_n_and_p(curve: Curve) {
        let pr = reference::params(curve);
        let cl = curve.coord_len();
        let f = &pr.f;
        let nm = &pr.n;
        let n = nm.modulus().to_vec();
        // (p + 1) / 4: p is 3 mod 4 for both curves, so y = rhs^((p+1)/4) is a square root when there is one
        let mut exp = f.modulus().to_vec();
        let mut carry = 1u64;
        for l in exp.iter_mut() {
            let (v, c) = l.overflowing_add(carry);
            *l = v;
            carry = c as u64;
        }
        assert_eq!(carry, 0);
        for i in 0..exp.len() {
            exp[i] = (exp[i] >> 2) | exp.get(i + 1).map_or(0, |h| h << 62);
        }
        let mut t = 0u64;
        let (x_m, y_m) = loop {
            t += 1;
            let mut small = vec![0u64; f.limbs()];
            small[0] = t;
            let x_plain = f.add(&f.fit(&n), &small);
            let x_m = f.to_mont(&x_plain);
            let three_x = f.add(&f.add(&x_m, &x_m), &x_m);
            let rhs = f.add(&f.sub(&f.mul(&f.sqr(&x_m), &x_m), &three_x), &pr.b);
            let y_m = f.pow(&rhs, &exp);
            if f.sqr(&y_m) == rhs {
                break (x_m, y_m);
            }
            assert!(t < 100, "no point with x just above n");
        };
        let big_r = pr.affine_point(&x_m, &y_m);
        let mut state = 0xabcdef ^ cl as u64;
        for round in 0..3 {
            let digest: Vec<u8> = (0..cl).map(|_| splitmix(&mut state) as u8).collect();
            let e = nm.fit(&bignum::from_be_bytes(&digest));
            assert_eq!(bignum::cmp(&e, &n), Ordering::Less, "(the chance that a random digest is not below n is 2^-32)");
            let s = random_scalar(pr, &mut state);
            let mut r = vec![0u64; nm.limbs()];
            r[0] = t;
            let w = nm.inv(&nm.to_mont(&nm.fit(&s)));
            let u1 = nm.mul(&nm.to_mont(&e), &w); // Montgomery form: e / s
            let u2 = nm.mul(&nm.to_mont(&r), &w);
            let (u1, u2) = (nm.from_mont(&u1), nm.from_mont(&u2));
            // Q = (R - u1 G) / u2
            let g = pr.affine_point(&pr.gx, &pr.gy);
            let mut u1g = ref_mul_point(pr, &u1, &g);
            u1g.y = f.sub(&f.zero(), &u1g.y);
            let diff = pr.add(&big_r, &u1g);
            let u2_inv = nm.from_mont(&nm.inv(&nm.to_mont(&nm.fit(&u2))));
            let q = ref_mul_point(pr, &u2_inv, &diff);
            let (qx, qy) = pr.to_affine(&q).expect("Q is a point");
            let mut public = vec![4u8];
            public.extend(bignum::to_be_bytes(&qx, cl));
            public.extend(bignum::to_be_bytes(&qy, cl));
            let sig = der_sig(&bignum::to_be_bytes(&r, cl), &bignum::to_be_bytes(&s, cl));
            assert!(verify_prehashed(curve, &public, &digest, &sig), "{curve:?} round {round}: x = n + {t} is not matched");
            // and not for an r that is neither x nor x - n
            let mut other = r.clone();
            other[0] += 1;
            let sig = der_sig(&bignum::to_be_bytes(&other, cl), &bignum::to_be_bytes(&s, cl));
            assert!(!verify_prehashed(curve, &public, &digest, &sig));
        }
    }

    #[test]
    fn an_x_coordinate_between_n_and_p_is_matched_by_r_equal_to_x_minus_n() {
        check_x_between_n_and_p(Curve::P256);
        check_x_between_n_and_p(Curve::P384);
    }

    #[test]
    fn digests_at_or_above_the_order_are_reduced() {
        for curve in [Curve::P256, Curve::P384] {
            let pr = reference::params(curve);
            let cl = curve.coord_len();
            let mut state = 77u64;
            let n_bytes = bignum::to_be_bytes(pr.n.modulus(), cl);
            let mut n_plus_1 = n_bytes.clone();
            *n_plus_1.last_mut().unwrap() += 1;
            let mut n_minus_1 = n_bytes.clone();
            *n_minus_1.last_mut().unwrap() -= 1;
            // all ones (above the order), the order itself, one above, one below, and a longer one (only its first cl bytes count)
            for digest in [vec![0xffu8; cl], n_bytes.clone(), n_plus_1, n_minus_1, vec![0xff; cl + 16]] {
                let d = random_scalar(pr, &mut state);
                let k = random_scalar(pr, &mut state);
                let (public, sig) = ref_sign(curve, &d, &k, &digest);
                assert!(verify_prehashed(curve, &public, &digest, &sig), "{curve:?} digest {:x?}", &digest[..4]);
            }
        }
    }

    /// Adding two Jacobian points that are the same point written with different Z (the general addition, whose
    /// special cases no scalar of the verifier reaches by chance): it doubles, and for the negative it gives infinity.
    fn check_general_add_special_cases<const N: usize>(g: &Group<N>) {
        let f = &g.f;
        let mut k = [0u64; N];
        k[0] = 0x1234_5678_9abc;
        let p = g.mul_add(&k, &[0u64; N], &g.g); // some multiple of G, with Z != 1
        assert!(!is_zero(&p.z));
        let lambda = f.to_mont(&{
            let mut l = [0u64; N];
            l[0] = 0xdead_beef;
            l[1] = 3;
            l
        });
        let l2 = f.sqr(&lambda);
        let l3 = f.mul(&l2, &lambda);
        let same = Jac { x: f.mul(&p.x, &l2), y: f.mul(&p.y, &l3), z: f.mul(&p.z, &lambda) };
        assert_eq!(g.to_affine(&p), g.to_affine(&same));
        assert_eq!(g.to_affine(&g.add(&p, &same)), g.to_affine(&g.double(&p)), "P + P by the general addition");
        assert!(g.to_affine(&g.add(&p, &g.neg_jac(&same))).is_none(), "P + (-P)");
        // the mixed addition with the same special cases
        let (ax, ay) = g.to_affine(&p).unwrap();
        let aff = Aff { x: f.to_mont(&ax), y: f.to_mont(&ay) };
        assert_eq!(g.to_affine(&g.add_affine(&p, &aff)), g.to_affine(&g.double(&p)), "P + P by the mixed addition");
        let neg = Aff { x: aff.x, y: f.neg(&aff.y) };
        assert!(g.to_affine(&g.add_affine(&p, &neg)).is_none(), "P + (-P) by the mixed addition");
        // with infinity on either side
        assert_eq!(g.to_affine(&g.add(&g.infinity(), &p)), g.to_affine(&p));
        assert_eq!(g.to_affine(&g.add(&p, &g.infinity())), g.to_affine(&p));
        assert_eq!(g.to_affine(&g.add_affine(&g.infinity(), &aff)), g.to_affine(&p));
    }

    #[test]
    fn the_general_and_mixed_additions_handle_equal_and_opposite_points() {
        check_general_add_special_cases(p256());
        check_general_add_special_cases(p384());
    }

    #[test]
    fn signatures_with_r_or_s_out_of_range_or_zero_are_refused() {
        let pr = reference::params(Curve::P256);
        let mut state = 11u64;
        let d = random_scalar(pr, &mut state);
        let k = random_scalar(pr, &mut state);
        let digest = [7u8; 32];
        let (public, sig) = ref_sign(Curve::P256, &d, &k, &digest);
        assert!(verify_prehashed(Curve::P256, &public, &digest, &sig));
        let n = bignum::to_be_bytes(pr.n.modulus(), 32);
        let zero = [0u8; 32];
        let one = {
            let mut o = [0u8; 32];
            o[31] = 1;
            o
        };
        // take r and s out of the good signature
        let r = &sig[4..4 + sig[3] as usize];
        let s_at = 4 + sig[3] as usize;
        let s = &sig[s_at + 2..];
        for (rr, ss) in [(&zero[..], s), (r, &zero[..]), (&n[..], s), (r, &n[..]), (&one[..], &one[..])] {
            let bad = der_sig(rr, ss);
            assert!(!verify_prehashed(Curve::P256, &public, &digest, &bad), "r {rr:x?} s {ss:x?}");
        }
    }

    #[test]
    fn p256_sha256_verifies() {
        let pk = unhex(tv::P256_PUBKEY);
        let sig = unhex(tv::P256_SHA256_SIG);
        assert!(verify(Curve::P256, &pk, HashAlg::Sha256, tv::EC_MSG, &sig));
        assert!(!verify(Curve::P256, &pk, HashAlg::Sha256, b"tampered", &sig));
        let mut bad = sig.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(!verify(Curve::P256, &pk, HashAlg::Sha256, tv::EC_MSG, &bad));
    }

    #[test]
    fn p256_with_sha384_truncates_digest() {
        let pk = unhex(tv::P256_PUBKEY);
        assert!(verify(Curve::P256, &pk, HashAlg::Sha384, tv::EC_MSG, &unhex(tv::P256_SHA384_SIG)));
    }

    #[test]
    fn p384_verifies() {
        let pk = unhex(tv::P384_PUBKEY);
        assert!(verify(Curve::P384, &pk, HashAlg::Sha384, tv::EC_MSG, &unhex(tv::P384_SHA384_SIG)));
        assert!(verify(Curve::P384, &pk, HashAlg::Sha256, tv::EC_MSG, &unhex(tv::P384_SHA256_SIG)));
        assert!(!verify(Curve::P384, &pk, HashAlg::Sha384, b"nope", &unhex(tv::P384_SHA384_SIG)));
    }

    #[test]
    fn rejects_wrong_curve_and_off_curve_keys() {
        let pk256 = unhex(tv::P256_PUBKEY);
        assert!(!verify(Curve::P384, &pk256, HashAlg::Sha256, tv::EC_MSG, &unhex(tv::P256_SHA256_SIG)));
        let mut off = pk256.clone();
        off[40] ^= 1;
        assert!(!verify(Curve::P256, &off, HashAlg::Sha256, tv::EC_MSG, &unhex(tv::P256_SHA256_SIG)));
    }

    #[test]
    fn keys_with_coordinates_not_below_p_or_of_the_wrong_shape_are_refused() {
        let pk = unhex(tv::P256_PUBKEY);
        assert!(is_valid_public_key(Curve::P256, &pk));
        // x + p: the same point written with an unreduced coordinate
        let mut unreduced = pk.clone();
        let p = bignum::to_be_bytes(pr_modulus(), 32);
        unreduced[1..33].copy_from_slice(&p);
        assert!(!is_valid_public_key(Curve::P256, &unreduced));
        assert!(!is_valid_public_key(Curve::P256, &pk[..64]));
        let mut compressed_prefix = pk.clone();
        compressed_prefix[0] = 2;
        assert!(!is_valid_public_key(Curve::P256, &compressed_prefix));
        assert!(!is_valid_public_key(Curve::P384, &pk));
        // the point at infinity has no encoding here: all zeros is not on the curve
        let mut zeros = vec![4u8];
        zeros.extend([0u8; 64]);
        assert!(!is_valid_public_key(Curve::P256, &zeros));
    }

    fn pr_modulus() -> &'static [u64] {
        reference::params(Curve::P256).f.modulus()
    }
}
