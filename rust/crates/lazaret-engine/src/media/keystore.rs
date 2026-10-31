//! Keystores: PKCS#12 (`.p12`, `.pfx`, `.pkcs12`: DER, a version 3 PFX whose content is PKCS#7 data or signed data),
//! Java's JKS (0xFEEDFEED) and JCEKS (0xCECECECE), Bouncy Castle's BKS (FP-OPAQUE-MEDIA, 0.1.9, John's decision of
//! Oct 21). Their bytes are near-random, so SC-OPAQUE-BLOB took them for a hidden payload; they are credential files,
//! and are reported as S-SECRET is, a finding that never sets a registry's verdict.
//!
//! A keystore is one when its structure is read to its last byte: the PFX's DER (definite or BER's indefinite
//! lengths), the bags of its unencrypted parts and a signed one's content; a Java keystore's entries (a JCEKS secret
//! key is a serialized object, read as Java's serialization writes it) and its 20-byte digest; a BKS's salt, entries,
//! end mark and MAC. Each part has its own shape: a certificate is a DER Certificate spanning its bytes, an
//! encrypted key an EncryptedPrivateKeyInfo, a key in the clear a PrivateKeyInfo (or a public key's
//! SubjectPublicKeyInfo). What it holds is what its entries say in the clear: private keys, secret keys,
//! certificates, and parts encrypted whole (a PKCS#12's encrypted data, where keytool and OpenSSL put certificates,
//! not keys).
//!
//! The bytes no structure reads (encrypted data, a key's or a secret's bytes, a signature) are counted (`largest`,
//! `opaque`): a real keystore's are small (an RSA-16384 key is under 10 KB, a JDK's trust store of certificates in
//! the clear holds none), so one past KEYSTORE_ELEMENT_MAX_BYTES or KEYSTORE_OPAQUE_MAX_BYTES in all is reported
//! as an opaque blob too (binary.rs). A certificate is read for its shape, not its fields (the re-review of Oct 27,
//! N2): every byte of it counts toward the total (a JDK's trust store of 123 certificates holds about 135 KB of them,
//! so a store of fake ones carries no more than the total allows), and its signature with its bytes past
//! CERTIFICATE_MAX, which no real certificate has, is one part; and an alias, a name or any other value nothing reads
//! (a MAC's salt, an attribute, an algorithm's parameters, a signer's names, a serialized object's strings and
//! arrays) is counted past NAME_MAX bytes, as a real one is a name or a number.

/// A certificate's bytes past this many are counted (real ones are 1 to 2 KB; one with hundreds of names, under 16).
pub const CERTIFICATE_MAX: usize = 16 * 1024;

/// A name's bytes past this many are counted (an alias, an attribute, a class name, a parameter).
pub const NAME_MAX: usize = 256;

/// What a keystore holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Keystore {
    pub kind: &'static str,
    pub keys: u64,
    pub secrets: u64,
    pub certs: u64,
    /// parts encrypted whole, whose entries are not seen
    pub sealed: u64,
    /// the largest part no structure reads (encrypted data, a key's or a secret's bytes, a signature), and all of them
    /// (certificates whole among them)
    pub largest: u64,
    pub opaque: u64,
}

impl Keystore {
    /// `n` bytes no structure reads.
    fn blob(&mut self, n: usize) {
        self.largest = self.largest.max(n as u64);
        self.opaque = self.opaque.saturating_add(n as u64);
    }

    /// A part of `n` bytes no structure reads, within `whole` bytes that count toward the total (a certificate).
    fn part(&mut self, n: usize, whole: usize) {
        self.largest = self.largest.max(n as u64);
        self.opaque = self.opaque.saturating_add(whole.max(n) as u64);
    }

    /// A name or another value of `n` bytes nothing reads: its bytes past NAME_MAX.
    fn name(&mut self, n: usize) {
        if n > NAME_MAX {
            self.blob(n - NAME_MAX);
        }
    }
}

/// The first bytes are a keystore's (read whole, then: `read`).
pub fn sniff(h: &[u8]) -> bool {
    h.starts_with(b"\xfe\xed\xfe\xed") || h.starts_with(b"\xce\xce\xce\xce") || pfx_head(h) || bks_head(h)
}

/// The keystore a file's bytes are, read to their end; or why they are not one.
pub fn read(b: &[u8]) -> Result<Keystore, String> {
    if b.starts_with(b"\xfe\xed\xfe\xed") || b.starts_with(b"\xce\xce\xce\xce") {
        return java(b);
    }
    if pfx_head(b) {
        return pfx(b);
    }
    if bks_head(b) {
        return bks(b);
    }
    Err("it is no keystore".into())
}

fn be16(b: &[u8], i: usize) -> Option<u64> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?) as u64)
}

fn be32(b: &[u8], i: usize) -> Option<u64> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?) as u64)
}

// ---- PKCS#12 -----------------------------------------------------------------------------------------------------

const OID_DATA: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01";
const OID_SIGNED: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02";
const OID_ENVELOPED: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03";
const OID_ENCRYPTED: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x06";
/// pkcs-12 bag types: 1.2.840.113549.1.12.10.1.n
const OID_BAG: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01";

/// A DER (or BER) value's header at `i`: (tag, content start, content length or None for an indefinite length).
fn tlv(b: &[u8], i: usize) -> Option<(u8, usize, Option<usize>)> {
    let tag = *b.get(i)?;
    if tag & 0x1f == 0x1f {
        return None;                                // (no tag of PKCS#12's needs the high-number form)
    }
    let l0 = *b.get(i + 1)?;
    if l0 < 0x80 {
        return Some((tag, i + 2, Some(l0 as usize)));
    }
    if l0 == 0x80 {
        return (tag & 0x20 != 0).then_some((tag, i + 2, None));
    }
    let n = (l0 & 0x7f) as usize;
    if n > 4 {
        return None;
    }
    let len = b.get(i + 2..i + 2 + n)?.iter().fold(0usize, |a, &c| (a << 8) | c as usize);
    Some((tag, i + 2 + n, Some(len)))
}

/// Where the value at `i` ends (an indefinite length's end-of-contents included), within `end`.
fn skip(b: &[u8], i: usize, end: usize, depth: u32) -> Option<usize> {
    if depth > 32 {
        return None;
    }
    let (_tag, start, len) = tlv(b, i)?;
    match len {
        Some(l) => {
            let e = start.checked_add(l)?;
            (e <= end).then_some(e)
        }
        None => {
            let mut j = start;
            loop {
                if b.get(j..j + 2)? == b"\x00\x00" {
                    return Some(j + 2);
                }
                j = skip(b, j, end, depth + 1)?;
            }
        }
    }
}

/// The values inside the constructed value at `i`: their starts, and where it ends.
fn children(b: &[u8], i: usize, end: usize, depth: u32) -> Option<(Vec<usize>, usize)> {
    let (tag, start, len) = tlv(b, i)?;
    if tag & 0x20 == 0 {
        return None;
    }
    let stop = match len {
        Some(l) => start.checked_add(l).filter(|&e| e <= end)?,
        None => end,
    };
    let mut out = Vec::new();
    let mut j = start;
    loop {
        if len.is_none() && b.get(j..j + 2) == Some(b"\x00\x00") {
            return Some((out, j + 2));
        }
        if len.is_some() && j == stop {
            return Some((out, stop));
        }
        if out.len() > 100_000 {
            return None;
        }
        out.push(j);
        j = skip(b, j, stop, depth + 1)?;
    }
}

/// An OCTET STRING's bytes (BER's constructed form: its pieces joined).
fn octets(b: &[u8], i: usize, end: usize, depth: u32) -> Option<Vec<u8>> {
    let (tag, start, len) = tlv(b, i)?;
    match tag {
        0x04 => {
            let l = len?;
            Some(b.get(start..start.checked_add(l).filter(|&e| e <= end)?)?.to_vec())
        }
        0x24 if depth < 8 => {
            let (kids, _) = children(b, i, end, depth)?;
            let mut out = Vec::new();
            for k in kids {
                out.extend(octets(b, k, end, depth + 1)?);
            }
            Some(out)
        }
        _ => None,
    }
}

fn oid_at(b: &[u8], i: usize) -> Option<&[u8]> {
    let (tag, start, len) = tlv(b, i)?;
    (tag == 0x06).then(|| b.get(start..start + len?))?
}

/// The content of a ContentInfo's [0] EXPLICIT at `i` (a ContentInfo's second value).
fn explicit(b: &[u8], i: usize, end: usize) -> Option<usize> {
    let (tag, start, _) = tlv(b, i)?;
    (tag == 0xa0 && start < end).then_some(start)
}

/// The whole of `b` is one value whose children have these tags (a signed DER structure's shape: a Certificate's
/// or a CRL's {SEQUENCE, SEQUENCE, BIT STRING}; an EncryptedPrivateKeyInfo's {SEQUENCE, OCTET STRING}, …): the
/// children's starts.
fn shaped(b: &[u8], tags: &[u8]) -> Option<Vec<usize>> {
    if skip(b, 0, b.len(), 0) != Some(b.len()) || tlv(b, 0)?.0 != 0x30 {
        return None;
    }
    let (kids, _) = children(b, 0, b.len(), 0)?;
    (kids.len() == tags.len() && kids.iter().zip(tags).all(|(&k, &t)| b[k] == t)).then_some(kids)
}

/// A DER Certificate (or CRL) spanning `b`: {tbs SEQUENCE, algorithm SEQUENCE, signature BIT STRING}, its tbs
/// starting with a version or a serial number (a CRL's with its version or its algorithm). Counted (the re-review of
/// Oct 27, N2: its fields are not read): every byte of it toward the total, and its signature with its bytes past
/// CERTIFICATE_MAX as one part.
fn signed_der(b: &[u8], k: &mut Keystore) -> Option<()> {
    let kids = shaped(b, &[0x30, 0x30, 0x03])?;
    let (tbs, _) = children(b, kids[0], b.len(), 1)?;
    if tbs.len() < 4 || ![0xa0, 0x02, 0x30].contains(&b[tbs[0]]) {
        return None;
    }
    k.part(tlv(b, kids[2])?.2? + b.len().saturating_sub(CERTIFICATE_MAX), b.len());
    Some(())
}

/// The primitive values within the value at `i` that no structure reads (a MAC's salt, an attribute, an algorithm's
/// parameters, a signer's names), each counted past NAME_MAX bytes; a constructed one whose content is not values
/// (or is nested past 32), as one.
fn loose(b: &[u8], i: usize, end: usize, k: &mut Keystore, depth: u32) -> Option<()> {
    let (tag, start, _) = tlv(b, i)?;
    if tag & 0x20 != 0 && depth <= 32 {
        if let Some((kids, _)) = children(b, i, end, depth) {
            for kid in kids {
                loose(b, kid, end, k, depth + 1)?;
            }
            return Some(());
        }
    }
    k.name(skip(b, i, end, depth.min(32))? - start);
    Some(())
}

/// An EncryptedPrivateKeyInfo spanning `b` ({algorithm {OID, …}, OCTET STRING}): its encrypted bytes counted (and
/// its algorithm's parameters past NAME_MAX).
fn encrypted_key(b: &[u8], k: &mut Keystore) -> Option<()> {
    let kids = shaped(b, &[0x30, 0x04])?;
    let (alg, _) = children(b, kids[0], b.len(), 1)?;
    oid_at(b, *alg.first()?)?;
    loose(b, kids[0], b.len(), k, 1)?;
    k.blob(tlv(b, kids[1])?.2?);
    Some(())
}

/// A PrivateKeyInfo spanning `b` ({version INTEGER, algorithm, OCTET STRING, [attributes], [public key]}): the
/// key's bytes counted (and its other values past NAME_MAX).
fn plain_key(b: &[u8], k: &mut Keystore) -> Option<()> {
    if skip(b, 0, b.len(), 0) != Some(b.len()) || tlv(b, 0)?.0 != 0x30 {
        return None;
    }
    let (kids, _) = children(b, 0, b.len(), 0)?;
    if !(3..=5).contains(&kids.len()) || b[kids[0]] != 0x02 || b[kids[1]] != 0x30 || b[kids[2]] != 0x04 {
        return None;
    }
    for &kid in kids.iter().filter(|&&kid| kid != kids[2]) {
        loose(b, kid, b.len(), k, 1)?;
    }
    k.blob(tlv(b, kids[2])?.2?);
    Some(())
}

/// A SubjectPublicKeyInfo spanning `b` ({algorithm, BIT STRING}).
fn public_key(b: &[u8]) -> bool {
    shaped(b, &[0x30, 0x03]).is_some()
}

/// An EncryptedData or EnvelopedData (at `i`): its EncryptedContentInfo's {contentType, algorithm, [0] content}, the
/// content counted (and its other values, a recipient's encrypted key among them, past NAME_MAX).
fn encrypted_content(b: &[u8], i: usize, end: usize, k: &mut Keystore) -> Option<()> {
    let (kids, _) = children(b, i, end, 1)?;
    let eci = *kids.iter().rev().find(|&&k| b[k] == 0x30)?;
    let (parts, _) = children(b, eci, end, 2)?;
    if parts.len() < 2 || oid_at(b, parts[0]).is_none() || b[parts[1]] != 0x30 {
        return None;
    }
    for &kid in kids.iter().filter(|&&kid| kid != eci).chain(&parts[..2]).chain(parts.get(3..).unwrap_or(&[])) {
        loose(b, kid, end, k, 2)?;
    }
    let n = match parts.get(2) {
        None => 0,
        Some(&c) if b[c] == 0x80 => tlv(b, c)?.2?,
        Some(&c) if b[c] == 0xa0 => {
            // (BER's constructed form: its pieces)
            let (pieces, _) = children(b, c, end, 3)?;
            pieces.iter().map(|&p| octets(b, p, end, 0).map(|o| o.len())).sum::<Option<usize>>()?
        }
        _ => return None,
    };
    k.blob(n);
    Some(())
}

fn pfx_head(h: &[u8]) -> bool {
    let Some((0x30, start, _)) = tlv(h, 0) else { return false };
    h.get(start..start + 3) == Some(b"\x02\x01\x03") && h.get(start + 3) == Some(&0x30) && {
        match tlv(h, start + 3) {
            Some((_, s, _)) => oid_at(h, s).is_some_and(|o| o == OID_DATA || o == OID_SIGNED),
            None => false,
        }
    }
}

fn pfx(b: &[u8]) -> Result<Keystore, String> {
    let not = || "its DER is not a PKCS#12 keystore's to its end".to_string();
    let end = skip(b, 0, b.len(), 0).ok_or_else(not)?;
    if end != b.len() {
        return Err(format!("bytes follow the keystore's DER at byte {end}"));
    }
    let (top, _) = children(b, 0, b.len(), 0).ok_or_else(not)?;
    if top.len() < 2 || top.len() > 3 {
        return Err(not());
    }
    let mut k = Keystore { kind: "PKCS#12 keystore", ..Keystore::default() };
    // (its MAC: a digest, a salt, a count)
    if let Some(&mac) = top.get(2) {
        loose(b, mac, b.len(), &mut k, 1).ok_or_else(not)?;
    }
    let (ci, _) = children(b, top[1], b.len(), 1).ok_or_else(not)?;
    if ci.len() != 2 {
        return Err(not());
    }
    let oid = oid_at(b, ci[0]).ok_or_else(not)?;
    let inner = explicit(b, ci[1], b.len()).ok_or_else(not)?;
    let safe = if oid == OID_SIGNED {
        // public-key integrity mode: SignedData {version, digest algorithms, the content (data: the
        // AuthenticatedSafe), [0] certificates, [1] CRLs, signer infos}
        let (parts, _) = children(b, inner, b.len(), 2).ok_or_else(not)?;
        if parts.len() < 4 || b[parts[0]] != 0x02 || b[parts[1]] != 0x31 || b[*parts.last().unwrap()] != 0x31 {
            return Err(not());
        }
        let (encap, _) = children(b, parts[2], b.len(), 3).ok_or_else(not)?;
        if encap.len() != 2 || oid_at(b, encap[0]) != Some(OID_DATA) {
            return Err(not());
        }
        let content = explicit(b, encap[1], b.len()).ok_or_else(not)?;
        loose(b, parts[1], b.len(), &mut k, 3).ok_or_else(not)?;
        for &extra in &parts[3..parts.len() - 1] {
            // certificates and CRLs: each a DER Certificate or CRL
            if !matches!(b[extra], 0xa0 | 0xa1) {
                return Err(not());
            }
            let (items, _) = children(b, extra, b.len(), 3).ok_or_else(not)?;
            for item in items {
                let end = skip(b, item, b.len(), 0).ok_or_else(not)?;
                signed_der(&b[item..end], &mut k).ok_or_else(not)?;
                k.certs += 1;
            }
        }
        let (signers, _) = children(b, *parts.last().unwrap(), b.len(), 3).ok_or_else(not)?;
        for signer in signers {
            // SignerInfo {version, sid, digest algorithm, [0] signed attributes, signature algorithm, signature, …}
            let (fields, _) = children(b, signer, b.len(), 4).ok_or_else(not)?;
            let sig = *fields.iter().find(|&&f| b[f] == 0x04).ok_or_else(not)?;
            k.blob(tlv(b, sig).and_then(|t| t.2).ok_or_else(not)?);
            for &field in fields.iter().filter(|&&f| f != sig) {
                loose(b, field, b.len(), &mut k, 5).ok_or_else(not)?;
            }
        }
        octets(b, content, b.len(), 0).ok_or_else(not)?
    } else {
        octets(b, inner, b.len(), 0).ok_or_else(not)?
    };
    // AuthenticatedSafe: SEQUENCE OF ContentInfo
    if skip(&safe, 0, safe.len(), 0) != Some(safe.len()) {
        return Err(not());
    }
    let (infos, _) = children(&safe, 0, safe.len(), 0).ok_or_else(not)?;
    for info in infos {
        let (parts, _) = children(&safe, info, safe.len(), 1).ok_or_else(not)?;
        let kind = parts.first().and_then(|&p| oid_at(&safe, p)).ok_or_else(not)?;
        if kind == OID_DATA {
            let inner = parts.get(1).and_then(|&p| explicit(&safe, p, safe.len())).ok_or_else(not)?;
            let contents = octets(&safe, inner, safe.len(), 0).ok_or_else(not)?;
            bags(&contents, &mut k, 0).ok_or_else(not)?;
        } else if kind == OID_ENCRYPTED || kind == OID_ENVELOPED {
            let inner = parts.get(1).and_then(|&p| explicit(&safe, p, safe.len())).ok_or_else(not)?;
            encrypted_content(&safe, inner, safe.len(), &mut k).ok_or_else(not)?;
            k.sealed += 1;
        } else {
            return Err(not());
        }
    }
    Ok(k)
}

/// SafeContents: SEQUENCE OF SafeBag {bagId, [0] bagValue, attributes}; each bag counted by its type.
fn bags(b: &[u8], k: &mut Keystore, depth: u32) -> Option<()> {
    if depth > 4 || skip(b, 0, b.len(), 0) != Some(b.len()) {
        return None;
    }
    let (list, _) = children(b, 0, b.len(), 0)?;
    for bag in list {
        let (parts, _) = children(b, bag, b.len(), 1)?;
        let id = oid_at(b, *parts.first()?)?;
        if id.len() != OID_BAG.len() + 1 || !id.starts_with(OID_BAG) {
            return None;
        }
        let inner = explicit(b, *parts.get(1)?, b.len())?;
        let end = skip(b, inner, b.len(), 0)?;
        let value = &b[inner..end];
        // (its attributes: a friendly name, a key's id)
        for &attrs in &parts[2..] {
            loose(b, attrs, b.len(), k, 2)?;
        }
        match id[id.len() - 1] {
            // a key in the clear (PrivateKeyInfo), an encrypted one (EncryptedPrivateKeyInfo)
            1 => plain_key(value, k)?,
            2 => encrypted_key(value, k)?,
            // a certificate or a CRL: {its type, [0] a DER Certificate or CRL in an OCTET STRING}
            3 | 4 => {
                let (kids, _) = children(value, 0, value.len(), 1)?;
                oid_at(value, *kids.first()?)?;
                let der = octets(value, explicit(value, *kids.get(1)?, value.len())?, value.len(), 0)?;
                signed_der(&der, k)?;
            }
            // a secret: {its type, [0] its value}
            5 => {
                let (kids, _) = children(value, 0, value.len(), 1)?;
                oid_at(value, *kids.first()?)?;
                let v = explicit(value, *kids.get(1)?, value.len())?;
                k.blob(skip(value, v, value.len(), 0)? - v);
            }
            6 => bags(value, k, depth + 1)?,
            _ => return None,
        }
        match id[id.len() - 1] {
            1 | 2 => k.keys += 1,
            3 | 4 => k.certs += 1,
            5 => k.secrets += 1,
            _ => {}
        }
    }
    Some(())
}

// ---- JKS and JCEKS -----------------------------------------------------------------------------------------------

/// A Java modified-UTF-8 string's length prefix and bytes, from `i`: its length.
fn utf(b: &[u8], i: &mut usize) -> Option<usize> {
    let n = be16(b, *i)? as usize;
    *i = i.checked_add(2 + n).filter(|&e| e <= b.len())?;
    Some(n)
}

/// A length (int) and that many bytes, from `i`: the bytes.
fn blob<'a>(b: &'a [u8], i: &mut usize) -> Option<&'a [u8]> {
    let n = be32(b, *i)? as usize;
    let start = i.checked_add(4)?;
    *i = start.checked_add(n).filter(|&e| e <= b.len())?;
    Some(&b[start..*i])
}

/// A certificate's type and bytes, from `i` (a JKS version 2's, a BKS's): X.509, a DER Certificate spanning them
/// (counted as signed_der counts one).
fn x509(b: &[u8], i: &mut usize, typed: bool, k: &mut Keystore) -> Option<()> {
    if typed {
        let n = be16(b, *i)? as usize;
        if b.get(*i + 2..*i + 2 + n)? != b"X.509" {
            return None;
        }
        utf(b, i)?;
    }
    signed_der(blob(b, i)?, k)
}

fn java(b: &[u8]) -> Result<Keystore, String> {
    let jceks = b.starts_with(b"\xce\xce\xce\xce");
    let mut k = Keystore { kind: if jceks { "JCEKS keystore" } else { "JKS keystore" }, ..Keystore::default() };
    let not = |at: usize| format!("its entries are not a Java keystore's (at byte {at})");
    let version = be32(b, 4).ok_or_else(|| not(4))?;
    let count = be32(b, 8).ok_or_else(|| not(8))?;
    if !(version == 1 || version == 2) || count > 100_000 {
        return Err(not(4));
    }
    let mut i = 12usize;
    for _ in 0..count {
        let at = i;
        let tag = be32(b, i).ok_or_else(|| not(at))?;
        i += 4;
        (|| -> Option<()> {
            k.name(utf(b, &mut i)?);                              // (its alias)
            i = i.checked_add(8).filter(|&e| e <= b.len())?;    // (its date)
            match tag {
                1 => {
                    // the protected key (an EncryptedPrivateKeyInfo), its certificate chain
                    encrypted_key(blob(b, &mut i)?, &mut k)?;
                    let chain = be32(b, i)?;
                    i += 4;
                    if chain > 1000 {
                        return None;
                    }
                    for _ in 0..chain {
                        x509(b, &mut i, version == 2, &mut k)?;
                    }
                    k.keys += 1;
                }
                2 => {
                    x509(b, &mut i, version == 2, &mut k)?;
                    k.certs += 1;
                }
                3 if jceks => {
                    // a SealedObject: its byte arrays (the encrypted key, the algorithm's parameters) unread
                    for n in javaser::stream(b, &mut i)? {
                        k.blob(n);
                    }
                    k.secrets += 1;
                }
                _ => return None,
            }
            Some(())
        })()
        .ok_or_else(|| not(at))?;
    }
    if i + 20 != b.len() {
        return Err(if i + 20 < b.len() {
            format!("bytes follow the keystore's digest at byte {}", i + 20)
        } else {
            "it is cut short before its digest".to_string()
        });
    }
    Ok(k)
}

/// Java's object serialization, read for where an object ends (a JCEKS secret key is a SealedObject written with
/// an ObjectOutputStream of its own): class descriptions and their handles, field values by type, strings, arrays,
/// block data, references. Nothing is run or built. Counted: byte and other primitive arrays and block data whole,
/// strings and names past NAME_MAX.
mod javaser {
    use super::{be16, be32, NAME_MAX};

    #[derive(Clone)]
    enum H {
        Desc { fields: Vec<(u8, bool)>, flags: u8, sup: Option<usize> },
        Other,
    }

    struct S<'a> {
        b: &'a [u8],
        i: usize,
        handles: Vec<H>,
        /// a class description's name, by its handle (an array's tells its elements' type)
        names: std::collections::HashMap<usize, String>,
        steps: u32,
        /// the lengths of the arrays and block data read, and of strings past NAME_MAX (bytes no structure reads)
        blobs: Vec<usize>,
    }

    /// The object at `i`, read to its end: the lengths of its byte arrays and block data.
    pub fn stream(b: &[u8], i: &mut usize) -> Option<Vec<usize>> {
        if b.get(*i..*i + 4)? != b"\xac\xed\x00\x05" {
            return None;
        }
        let mut s = S { b, i: *i + 4, handles: Vec::new(), names: Default::default(), steps: 0, blobs: Vec::new() };
        s.content(0)?;
        *i = s.i;
        Some(s.blobs)
    }

    impl S<'_> {
        fn byte(&mut self) -> Option<u8> {
            let c = *self.b.get(self.i)?;
            self.i += 1;
            Some(c)
        }

        fn take(&mut self, n: usize) -> Option<()> {
            self.i = self.i.checked_add(n).filter(|&e| e <= self.b.len())?;
            Some(())
        }

        fn utf(&mut self) -> Option<String> {
            let n = be16(self.b, self.i)? as usize;
            let s = self.b.get(self.i + 2..self.i + 2 + n)?;
            self.i += 2 + n;
            self.named(n);
            Some(String::from_utf8_lossy(s).into_owned())
        }

        /// A string or a name of `n` bytes: its bytes past NAME_MAX.
        fn named(&mut self, n: usize) {
            if n > NAME_MAX {
                self.blobs.push(n - NAME_MAX);
            }
        }

        fn tick(&mut self, depth: u32) -> Option<()> {
            self.steps += 1;
            (self.steps < 1_000_000 && depth < 64).then_some(())
        }

        /// One content: an object, a string, an array, a class, an enum, null or a reference; block data.
        fn content(&mut self, depth: u32) -> Option<Option<usize>> {
            self.tick(depth)?;
            match self.byte()? {
                0x70 => Some(None),                                   // TC_NULL
                0x71 => {                                             // TC_REFERENCE
                    let h = be32(self.b, self.i)?.checked_sub(0x7e_0000)? as usize;
                    self.take(4)?;
                    (h < self.handles.len()).then_some(Some(h))
                }
                0x72 | 0x7d => {
                    self.i -= 1;
                    self.desc(depth + 1)
                }
                0x73 => {                                             // TC_OBJECT
                    let desc = self.desc(depth + 1)??;
                    self.handles.push(H::Other);
                    let h = self.handles.len() - 1;
                    let mut chain = Vec::new();
                    let mut d = Some(desc);
                    while let Some(x) = d {
                        if chain.len() > 64 {
                            return None;
                        }
                        chain.push(x);
                        d = match self.handles.get(x)? {
                            H::Desc { sup, .. } => *sup,
                            H::Other => return None,
                        };
                    }
                    for &x in chain.iter().rev() {
                        let H::Desc { fields, flags, .. } = self.handles[x].clone() else { return None };
                        if flags & 0x04 != 0 {
                            if flags & 0x08 == 0 {
                                return None;                          // (old-style externalizable data)
                            }
                            self.annotation(depth + 1)?;
                            continue;
                        }
                        if flags & 0x02 != 0 {
                            for (code, _) in fields {
                                self.value(code, depth + 1)?;
                            }
                            if flags & 0x01 != 0 {
                                self.annotation(depth + 1)?;
                            }
                        }
                    }
                    Some(Some(h))
                }
                0x74 => {                                             // TC_STRING
                    self.utf()?;
                    self.handles.push(H::Other);
                    Some(Some(self.handles.len() - 1))
                }
                0x7c => {                                             // TC_LONGSTRING
                    let hi = be32(self.b, self.i)?;
                    let lo = be32(self.b, self.i + 4)?;
                    self.take(8)?;
                    let n = usize::try_from((hi << 32) | lo).ok()?;
                    self.take(n)?;
                    self.named(n);
                    self.handles.push(H::Other);
                    Some(Some(self.handles.len() - 1))
                }
                0x75 => {                                             // TC_ARRAY
                    let desc = self.desc(depth + 1)??;
                    let name = self.names.get(&desc).cloned()?;
                    self.handles.push(H::Other);
                    let h = self.handles.len() - 1;
                    let n = be32(self.b, self.i)? as usize;
                    self.take(4)?;
                    let code = *name.as_bytes().get(1)?;
                    match code {
                        b'B' => {
                            self.take(n)?;
                            self.blobs.push(n);
                        }
                        b'Z' | b'C' | b'S' | b'I' | b'F' | b'J' | b'D' => {
                            let size = match code { b'Z' => 1, b'C' | b'S' => 2, b'I' | b'F' => 4, _ => 8 };
                            let bytes = n.checked_mul(size)?;
                            self.take(bytes)?;
                            self.blobs.push(bytes);
                        }
                        b'L' | b'[' => {
                            for _ in 0..n {
                                self.content(depth + 1)?;
                            }
                        }
                        _ => return None,
                    }
                    Some(Some(h))
                }
                0x76 => {                                             // TC_CLASS
                    self.desc(depth + 1)?;
                    self.handles.push(H::Other);
                    Some(Some(self.handles.len() - 1))
                }
                0x7e => {                                             // TC_ENUM
                    self.desc(depth + 1)?;
                    self.handles.push(H::Other);
                    let h = self.handles.len() - 1;
                    self.content(depth + 1)?;
                    Some(Some(h))
                }
                0x77 => {                                             // TC_BLOCKDATA
                    let n = self.byte()? as usize;
                    self.take(n)?;
                    self.blobs.push(n);
                    Some(None)
                }
                0x7a => {                                             // TC_BLOCKDATALONG
                    let n = be32(self.b, self.i)? as usize;
                    self.take(4)?;
                    self.take(n)?;
                    self.blobs.push(n);
                    Some(None)
                }
                _ => None,
            }
        }

        /// A class description (new, a proxy's, null or a reference): its handle, or None for null.
        fn desc(&mut self, depth: u32) -> Option<Option<usize>> {
            self.tick(depth)?;
            match self.byte()? {
                0x70 => Some(None),
                0x71 => {
                    let h = be32(self.b, self.i)?.checked_sub(0x7e_0000)? as usize;
                    self.take(4)?;
                    matches!(self.handles.get(h)?, H::Desc { .. }).then_some(Some(h))
                }
                0x72 => {
                    let name = self.utf()?;
                    self.take(8)?;                                    // (serialVersionUID)
                    self.handles.push(H::Other);
                    let h = self.handles.len() - 1;
                    self.names.insert(h, name);
                    let flags = self.byte()?;
                    let count = be16(self.b, self.i)?;
                    self.take(2)?;
                    let mut fields = Vec::new();
                    for _ in 0..count {
                        let code = self.byte()?;
                        self.utf()?;
                        let object = code == b'L' || code == b'[';
                        if object {
                            self.content(depth + 1)?;                // (the field's class name)
                        } else if !b"BCDFIJSZ".contains(&code) {
                            return None;
                        }
                        fields.push((code, object));
                    }
                    self.annotation(depth + 1)?;
                    let sup = self.desc(depth + 1)?;
                    self.handles[h] = H::Desc { fields, flags, sup };
                    Some(Some(h))
                }
                0x7d => {
                    let n = be32(self.b, self.i)?;
                    self.take(4)?;
                    if n > 1000 {
                        return None;
                    }
                    self.handles.push(H::Other);
                    let h = self.handles.len() - 1;
                    for _ in 0..n {
                        self.utf()?;
                    }
                    self.annotation(depth + 1)?;
                    let sup = self.desc(depth + 1)?;
                    self.handles[h] = H::Desc { fields: Vec::new(), flags: 0x02, sup };
                    Some(Some(h))
                }
                _ => None,
            }
        }

        /// Contents to TC_ENDBLOCKDATA.
        fn annotation(&mut self, depth: u32) -> Option<()> {
            loop {
                self.tick(depth)?;
                if *self.b.get(self.i)? == 0x78 {
                    self.i += 1;
                    return Some(());
                }
                self.content(depth + 1)?;
            }
        }

        fn value(&mut self, code: u8, depth: u32) -> Option<()> {
            match code {
                b'B' | b'Z' => self.take(1),
                b'C' | b'S' => self.take(2),
                b'I' | b'F' => self.take(4),
                b'J' | b'D' => self.take(8),
                _ => self.content(depth).map(|_| ()),
            }
        }
    }
}

// ---- BKS ---------------------------------------------------------------------------------------------------------

fn bks_head(h: &[u8]) -> bool {
    matches!(be32(h, 0), Some(1) | Some(2)) && matches!(be32(h, 4), Some(n) if (1..=64).contains(&n))
}

/// Bouncy Castle's BKS: its version, salt and iteration count, entries (a type, an alias, a date, a certificate
/// chain, the entry's data) to a 0 type, then a 20-byte MAC.
fn bks(b: &[u8]) -> Result<Keystore, String> {
    let mut k = Keystore { kind: "BKS keystore", ..Keystore::default() };
    let not = |at: usize| format!("its entries are not a BKS keystore's (at byte {at})");
    let salt = be32(b, 4).ok_or_else(|| not(4))? as usize;
    let mut i = 8 + salt;
    let iterations = be32(b, i).ok_or_else(|| not(i))?;
    if iterations == 0 || iterations > 10_000_000 {
        return Err(not(i));
    }
    i += 4;
    for _ in 0..100_000 {
        let at = i;
        let kind = *b.get(i).ok_or_else(|| not(at))?;
        i += 1;
        if kind == 0 {
            if i + 20 != b.len() {
                return Err(if i + 20 < b.len() {
                    format!("bytes follow the keystore's MAC at byte {}", i + 20)
                } else {
                    "it is cut short before its MAC".to_string()
                });
            }
            return Ok(k);
        }
        (|| -> Option<()> {
            k.name(utf(b, &mut i)?);                              // (its alias)
            i = i.checked_add(8).filter(|&e| e <= b.len())?;
            let chain = be32(b, i)?;
            i += 4;
            if chain > 1000 {
                return None;
            }
            for _ in 0..chain {
                x509(b, &mut i, true, &mut k)?;
            }
            match kind {
                1 => {
                    x509(b, &mut i, true, &mut k)?;
                    k.certs += 1;
                }
                2 => {
                    // a key in the clear: its type (0 private, 1 public, 2 secret), format, algorithm and encoding
                    let key_type = *b.get(i)?;
                    i += 1;
                    let n = be16(b, i)? as usize;
                    let format = b.get(i + 2..i + 2 + n)?.to_vec();
                    utf(b, &mut i)?;
                    k.name(utf(b, &mut i)?);                      // (its algorithm's name)
                    let encoded = blob(b, &mut i)?;
                    match (key_type, format.as_slice()) {
                        (0, b"PKCS#8" | b"PKCS8") => plain_key(encoded, &mut k)?,
                        (1, b"X.509" | b"X509") if public_key(encoded) => loose(encoded, 0, encoded.len(), &mut k, 1)?,
                        (2, b"RAW") => k.blob(encoded.len()),
                        _ => return None,
                    }
                    k.keys += 1;
                }
                3 => {
                    k.blob(blob(b, &mut i)?.len());
                    k.secrets += 1;
                }
                4 => {
                    k.blob(blob(b, &mut i)?.len());
                    k.keys += 1;
                }
                _ => return None,
            }
            Some(())
        })()
        .ok_or_else(|| not(at))?;
    }
    Err(not(i))
}
