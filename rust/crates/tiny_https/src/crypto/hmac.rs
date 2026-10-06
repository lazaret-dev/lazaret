//! HMAC (RFC 2104) and HKDF (RFC 5869), generic over the hash function.

use super::sha2::Hash;
use crate::zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
pub struct Hmac<H: Hash + Zeroize> {
    inner: H,
    outer_key: Vec<u8>,
}

impl<H: Hash + Zeroize> Drop for Hmac<H> {
    fn drop(&mut self) {
        // Both the outer pad and the inner hash state (which has absorbed the inner pad) are
        // functions of the key.
        self.outer_key.zeroize();
        self.inner.zeroize();
    }
}

impl<H: Hash + Zeroize> Hmac<H> {
    pub fn new(key: &[u8]) -> Self {
        let mut k = Zeroizing::new(if key.len() > H::BLOCK_LEN { H::digest(key) } else { key.to_vec() });
        k.resize(H::BLOCK_LEN, 0);
        let ipad = Zeroizing::new(k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
        let mut inner = H::new();
        inner.update(&ipad);
        Hmac { inner, outer_key: opad }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> Vec<u8> {
        let ih = self.inner.clone().finalize();
        let mut outer = H::new();
        outer.update(&self.outer_key);
        outer.update(&ih);
        outer.finalize()
    }

    pub fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = Self::new(key);
        m.update(data);
        m.finalize()
    }
}

/// HKDF-Extract.
pub fn hkdf_extract<H: Hash + Zeroize>(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    if salt.is_empty() {
        Hmac::<H>::mac(&vec![0u8; H::OUTPUT_LEN], ikm)
    } else {
        Hmac::<H>::mac(salt, ikm)
    }
}

/// HKDF-Expand.
pub fn hkdf_expand<H: Hash + Zeroize>(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 255 * H::OUTPUT_LEN);
    let mut out = Vec::with_capacity(len);
    let mut t: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut counter = 1u8;
    while out.len() < len {
        let mut m = Hmac::<H>::new(prk);
        m.update(&t);
        m.update(info);
        m.update(&[counter]);
        t = Zeroizing::new(m.finalize());
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 section 7.1).
pub fn hkdf_expand_label<H: Hash + Zeroize>(secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full = format!("tls13 {}", label);
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand::<H>(secret, &info, len)
}

/// TLS 1.3 Derive-Secret: HKDF-Expand-Label over a transcript hash.
pub fn derive_secret<H: Hash + Zeroize>(secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label::<H>(secret, label, transcript_hash, H::OUTPUT_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha2::{Sha256, Sha384, Sha512};
    use crate::util::{hex, unhex};

    #[test]
    fn hmac_rfc4231() {
        // Test case 1
        let key = vec![0x0b; 20];
        assert_eq!(
            hex(&Hmac::<Sha256>::mac(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&Hmac::<Sha384>::mac(&key, b"Hi There")),
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
        );
        assert_eq!(
            hex(&Hmac::<Sha512>::mac(&key, b"Hi There")),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
        // Test case 6: key longer than block size
        let key = vec![0xaa; 131];
        assert_eq!(
            hex(&Hmac::<Sha256>::mac(&key, b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hkdf_rfc5869() {
        // Test case 1
        let ikm = vec![0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract::<Sha256>(&salt, &ikm);
        assert_eq!(hex(&prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let okm = hkdf_expand::<Sha256>(&prk, &info, 42);
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        // Test case 3: zero-length salt/info
        let okm = hkdf_expand::<Sha256>(&hkdf_extract::<Sha256>(&[], &ikm), &[], 42);
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn tls13_expand_label_rfc8448() {
        // RFC 8448 section 3: derive the "derived" secret from the early secret.
        let early = hkdf_extract::<Sha256>(&[], &[0u8; 32]);
        assert_eq!(hex(&early), "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        let empty_hash = Sha256::digest(b"");
        let derived = derive_secret::<Sha256>(&early, "derived", &empty_hash);
        assert_eq!(hex(&derived), "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
    }
}
