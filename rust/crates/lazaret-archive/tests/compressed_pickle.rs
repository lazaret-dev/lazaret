use lazaret_archive::{extract, extract_with_limits, EntryKind, Error, Format, Limits};

const PICKLE: &[u8] = include_bytes!("fixtures/pickle.pkl");
const BZIP2: &[u8] = include_bytes!("fixtures/pickle.bz2");
const XZ: &[u8] = include_bytes!("fixtures/pickle.xz");
const LZMA: &[u8] = include_bytes!("fixtures/pickle.lzma");

#[test]
fn extracts_bzip2_xz_and_lzma_compressed_pickles() {
    for (bytes, format) in [(BZIP2, Format::Bzip2), (XZ, Format::Xz), (LZMA, Format::Lzma)] {
        let archive = extract(bytes).unwrap();
        assert_eq!(archive.format, format);
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, "data");
        assert_eq!(archive.entries[0].kind, EntryKind::File);
        assert_eq!(archive.entries[0].data, PICKLE);
    }
}

#[test]
fn compressed_stream_corruption_fails_closed() {
    for bytes in [BZIP2, XZ, LZMA] {
        let mut damaged = bytes.to_vec();
        let at = damaged.len() / 2;
        damaged[at] ^= 1;
        assert!(extract(&damaged).is_err());
        assert!(extract(&bytes[..bytes.len() - 1]).is_err());
    }
}

#[test]
fn compressed_pickle_limits_are_enforced() {
    for bytes in [BZIP2, XZ, LZMA] {
        assert!(matches!(extract_with_limits(bytes, Limits::new(8, 1024)), Err(Error::Limit(_))));
        assert!(matches!(extract_with_limits(bytes, Limits::new(1024, 8)), Err(Error::Limit(_))));
    }
}
