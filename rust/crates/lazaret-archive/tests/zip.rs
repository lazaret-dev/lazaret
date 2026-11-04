use lazaret_archive::zip::{self, Bytes, Miss};

fn u16_(out: &mut Vec<u8>, n: u16) { out.extend_from_slice(&n.to_le_bytes()); }
fn u32_(out: &mut Vec<u8>, n: u32) { out.extend_from_slice(&n.to_le_bytes()); }

fn one(method: u16, compressed: &[u8], size: u32) -> Vec<u8> {
    let name = b"payload.bin";
    let mut out = Vec::new();
    u32_(&mut out, 0x0403_4b50);
    for n in [20, 0, method, 0, 0] { u16_(&mut out, n); }
    u32_(&mut out, 0);
    u32_(&mut out, compressed.len() as u32);
    u32_(&mut out, size);
    u16_(&mut out, name.len() as u16);
    u16_(&mut out, 0);
    out.extend_from_slice(name);
    out.extend_from_slice(compressed);

    let directory = out.len() as u32;
    u32_(&mut out, 0x0201_4b50);
    for n in [20, 20, 0, method, 0, 0] { u16_(&mut out, n); }
    for n in [0, compressed.len() as u32, size] { u32_(&mut out, n); }
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
