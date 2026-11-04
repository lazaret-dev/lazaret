use lazaret_archive::zip::{self, Bytes, Miss};
use lazaret_archive::{detect, extract, extract_as, Error, Format, Limits};

fn u16_(out: &mut Vec<u8>, n: u16) { out.extend_from_slice(&n.to_le_bytes()); }
fn u32_(out: &mut Vec<u8>, n: u32) { out.extend_from_slice(&n.to_le_bytes()); }

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn one(method: u16, compressed: &[u8], size: u32) -> Vec<u8> {
    let crc = if method == 0 { crc32(compressed) } else { 0 };
    one_with_crc(method, compressed, size, crc)
}

fn one_with_crc(method: u16, compressed: &[u8], size: u32, crc: u32) -> Vec<u8> {
    let name = b"payload.bin";
    let mut out = Vec::new();
    u32_(&mut out, 0x0403_4b50);
    for n in [20, 0, method, 0, 0] { u16_(&mut out, n); }
    u32_(&mut out, crc);
    u32_(&mut out, compressed.len() as u32);
    u32_(&mut out, size);
    u16_(&mut out, name.len() as u16);
    u16_(&mut out, 0);
    out.extend_from_slice(name);
    out.extend_from_slice(compressed);

    let directory = out.len() as u32;
    u32_(&mut out, 0x0201_4b50);
    for n in [20, 20, 0, method, 0, 0] { u16_(&mut out, n); }
    for n in [crc, compressed.len() as u32, size] { u32_(&mut out, n); }
    for n in [name.len() as u16, 0, 0, 0, 0] { u16_(&mut out, n); }
    u32_(&mut out, 0);
    u32_(&mut out, 0);
    out.extend_from_slice(name);
    let directory_size = out.len() as u32 - directory;

    u32_(&mut out, 0x0605_4b50);
    for n in [0, 0, 1, 1] { u16_(&mut out, n); }
    u32_(&mut out, directory_size);
    u32_(&mut out, directory);
    u16_(&mut out, 0);
    out
}

fn central(archive: &[u8]) -> usize {
    archive.windows(4).position(|bytes| bytes == b"PK\x01\x02").unwrap()
}

#[test]
fn archive_crate_lists_and_reads_a_stored_zip() {
    let archive = one(0, b"hello", 5);
    let bytes = Bytes::whole(&archive);
    let listing = zip::entries(&bytes, 10, 4096).unwrap();
    assert!(!listing.is_ambiguous());
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].name, b"payload.bin");
    assert_eq!(zip::read(&bytes, &listing.entries[0], 5), Ok(b"hello".to_vec()));
}

#[test]
fn zip_is_a_first_class_archive_format() {
    let archive = one(0, b"hello", 5);
    assert_eq!(detect(&archive), Ok(Format::Zip));
    let extracted = extract(&archive).unwrap();
    assert_eq!(extracted.format, Format::Zip);
    assert_eq!(extracted.entries.len(), 1);
    assert_eq!(extracted.entries[0].name, "payload.bin");
    assert_eq!(extracted.entries[0].data, b"hello");
}

#[test]
fn generic_extraction_reads_deflate_and_checks_limits_first() {
    // Raw DEFLATE for "hello".
    let archive = one_with_crc(8, &[0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], 5, crc32(b"hello"));
    let extracted = extract(&archive).unwrap();
    assert_eq!(extracted.entries[0].data, b"hello");
    assert!(extract_as(&archive, Format::Zip, Limits::new(5, 5)).is_ok());
    assert_eq!(extract_as(&archive, Format::Zip, Limits::new(4, 10)), Err(Error::Limit("member size")));
}

#[test]
fn bounded_zip_damage_never_panics_or_returns_partial_data() {
    let archive = one(0, b"hello", 5);
    for end in 0..archive.len() {
        assert!(extract(&archive[..end]).is_err());
    }
    for at in 0..archive.len() {
        let mut changed = archive.clone();
        changed[at] ^= 0x80;
        let _ = extract(&changed);
    }
}

#[test]
fn empty_zip_is_a_supported_empty_archive() {
    let mut archive = Vec::new();
    u32_(&mut archive, 0x0605_4b50);
    for n in [0, 0, 0, 0] { u16_(&mut archive, n); }
    u32_(&mut archive, 0);
    u32_(&mut archive, 0);
    u16_(&mut archive, 0);
    let extracted = extract(&archive).unwrap();
    assert_eq!(extracted.format, Format::Zip);
    assert!(extracted.entries.is_empty());
}

#[test]
fn generic_extraction_checks_the_member_crc() {
    let mut archive = one(0, b"hello", 5);
    archive[30 + b"payload.bin".len()] ^= 1;
    assert_eq!(extract(&archive), Err(Error::Checksum("ZIP member")));
}

#[test]
fn generic_extraction_refuses_unsafe_names() {
    let mut archive = one(0, b"hello", 5);
    let old = b"payload.bin";
    let new = b"../evil.txt";
    assert_eq!(old.len(), new.len());
    let directory = central(&archive);
    archive[30..30 + old.len()].copy_from_slice(new);
    archive[directory + 46..directory + 46 + old.len()].copy_from_slice(new);
    assert!(matches!(extract(&archive), Err(Error::InvalidPath(_))));
}

#[test]
fn generic_extraction_refuses_encryption() {
    let mut archive = one(0, b"hello", 5);
    let directory = central(&archive);
    archive[6..8].copy_from_slice(&1u16.to_le_bytes());
    archive[directory + 8..directory + 10].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(extract(&archive), Err(Error::Unsupported("encrypted ZIP member")));
}

#[test]
fn generic_extraction_refuses_reader_disagreement() {
    let mut archive = one(0, b"hello", 5);
    archive[30..41].copy_from_slice(b"payload.dat");
    assert!(matches!(extract(&archive), Err(Error::Ambiguous(_))));
}

#[test]
fn a_failed_prefix_reports_bytes_produced_before_the_error() {
    // A non-final stored DEFLATE block containing "hello", followed by the
    // reserved block type. The decoder must reject it, but the caller still
    // charges the five bytes already materialized.
    let deflate = [0, 5, 0, 250, 255, b'h', b'e', b'l', b'l', b'o', 7];
    let archive = one(8, &deflate, 10);
    let bytes = Bytes::whole(&archive);
    let listing = zip::entries(&bytes, 10, 4096).unwrap();
    let error = zip::read_prefix_counted(&bytes, &listing.entries[0], 10, 4096).unwrap_err();
    assert!(matches!(error.miss, Miss::Bad(_)));
    assert_eq!(error.produced, 5);
}

#[test]
fn range_backed_listing_names_the_bytes_it_needs() {
    let archive = one(0, b"hello", 5);
    let bytes = Bytes::pieces(archive.len() as u64, vec![(0, &archive[..4])], 4096);
    assert!(matches!(zip::entries(&bytes, 10, 4096), Err(Miss::Need)));
    assert!(!bytes.needs().is_empty());
}
