//! SHA-256, SHA-384 and SHA-512 (FIPS 180-4).

use super::sha2_consts::{H256, H384, H512, K256, K512};

/// Common interface for the hash functions used by HMAC, HKDF and TLS.
pub trait Hash: Clone {
    const OUTPUT_LEN: usize;
    const BLOCK_LEN: usize;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Vec<u8>;

    fn digest(data: &[u8]) -> Vec<u8> {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

// ---------------------------------------------------------------- SHA-256

#[derive(Clone)]
pub struct Sha256 {
    pub(crate) state: [u32; 8],
    pub(crate) buf: [u8; 64],
    pub(crate) buf_len: usize,
    pub(crate) total: u64,
}

impl Sha256 {
    fn compress(state: &mut [u32; 8], block: &[u8]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

impl Hash for Sha256 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;

    fn new() -> Self {
        Sha256 { state: H256, buf: [0; 64], buf_len: 0, total: 0 }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                Self::compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            Self::compress(&mut self.state, &data[..64]);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> Vec<u8> {
        let bit_len = self.total.wrapping_mul(8);
        let mut pad = vec![0x80u8];
        let rem = (self.buf_len + 1) % 64;
        let zeros = if rem <= 56 { 56 - rem } else { 120 - rem };
        pad.extend(std::iter::repeat(0).take(zeros));
        pad.extend_from_slice(&bit_len.to_be_bytes());
        let total = self.total;
        self.update(&pad);
        self.total = total;
        debug_assert_eq!(self.buf_len, 0);
        let mut out = Vec::with_capacity(32);
        for s in self.state {
            out.extend_from_slice(&s.to_be_bytes());
        }
        out
    }
}

// ------------------------------------------------------- SHA-512 / SHA-384

#[derive(Clone)]
pub(crate) struct Sha512Core {
    pub(crate) state: [u64; 8],
    pub(crate) buf: [u8; 128],
    pub(crate) buf_len: usize,
    pub(crate) total: u128,
}

impl Sha512Core {
    fn new(iv: [u64; 8]) -> Self {
        Sha512Core { state: iv, buf: [0; 128], buf_len: 0, total: 0 }
    }

    fn compress(state: &mut [u64; 8], block: &[u8]) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[8 * i..8 * i + 8]);
            w[i] = u64::from_be_bytes(b);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u128);
        if self.buf_len > 0 {
            let take = (128 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 128 {
                let block = self.buf;
                Self::compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 128 {
            Self::compress(&mut self.state, &data[..128]);
            data = &data[128..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finish(mut self, out_len: usize) -> Vec<u8> {
        let bit_len = self.total.wrapping_mul(8);
        let mut pad = vec![0x80u8];
        let rem = (self.buf_len + 1) % 128;
        let zeros = if rem <= 112 { 112 - rem } else { 240 - rem };
        pad.extend(std::iter::repeat(0).take(zeros));
        pad.extend_from_slice(&bit_len.to_be_bytes());
        let total = self.total;
        self.update(&pad);
        self.total = total;
        debug_assert_eq!(self.buf_len, 0);
        let mut out = Vec::with_capacity(64);
        for s in self.state {
            out.extend_from_slice(&s.to_be_bytes());
        }
        out.truncate(out_len);
        out
    }
}

#[derive(Clone)]
pub struct Sha512(pub(crate) Sha512Core);

impl Hash for Sha512 {
    const OUTPUT_LEN: usize = 64;
    const BLOCK_LEN: usize = 128;
    fn new() -> Self {
        Sha512(Sha512Core::new(H512))
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
    fn finalize(self) -> Vec<u8> {
        self.0.finish(64)
    }
}

#[derive(Clone)]
pub struct Sha384(pub(crate) Sha512Core);

impl Hash for Sha384 {
    const OUTPUT_LEN: usize = 48;
    const BLOCK_LEN: usize = 128;
    fn new() -> Self {
        Sha384(Sha512Core::new(H384))
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
    fn finalize(self) -> Vec<u8> {
        self.0.finish(48)
    }
}

/// Runtime selection of a SHA-2 variant (used by signature verification and TLS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(data),
            HashAlg::Sha384 => Sha384::digest(data),
            HashAlg::Sha512 => Sha512::digest(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    #[test]
    fn sha256_vectors() {
        assert_eq!(hex(&Sha256::digest(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&Sha256::digest(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex(&Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let mut h = Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(hex(&h.finalize()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    #[test]
    fn sha256_incremental_matches_oneshot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        for chunk in [1usize, 3, 63, 64, 65, 200] {
            let mut h = Sha256::new();
            for c in data.chunks(chunk) {
                h.update(c);
            }
            assert_eq!(h.finalize(), Sha256::digest(&data));
        }
    }

    #[test]
    fn sha384_vectors() {
        assert_eq!(
            hex(&Sha384::digest(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex(&Sha384::digest(b"")),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn sha512_vectors() {
        assert_eq!(
            hex(&Sha512::digest(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert_eq!(
            hex(&Sha512::digest(msg)),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
    }
}
