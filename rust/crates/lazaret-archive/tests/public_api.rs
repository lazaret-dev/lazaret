use lazaret_archive::{extract, extract_with_limits, EntryKind, Error, Format, Limits};

const RAR4: &[u8] = include_bytes!("fixtures/stored-rar4.rar");
const RAR5: &[u8] = include_bytes!("fixtures/stored-rar5.rar");
const TAR_GZIP: &[u8] = include_bytes!("fixtures/sample.tar.gz");

#[test]
fn extracts_independently_validated_stored_rar() {
    for (bytes, format) in [(RAR4, Format::Rar4), (RAR5, Format::Rar5)] {
        let archive = extract(bytes).unwrap();
        assert_eq!(archive.format, format);
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, "a.txt");
        assert_eq!(archive.entries[0].kind, EntryKind::File);
        assert_eq!(archive.entries[0].data, b"hello");
    }
}

#[test]
fn extracts_every_tar_gzip_member() {
    let archive = extract(TAR_GZIP).unwrap();
    assert_eq!(archive.format, Format::TarGzip);
    assert_eq!(archive.entries.len(), 2);
    assert_eq!(archive.entries[0].name, "a.txt");
    assert_eq!(archive.entries[0].data, b"hello");
    assert_eq!(archive.entries[1].name, "dir/b.txt");
    assert_eq!(archive.entries[1].data, b"world");
}

#[test]
fn member_corruption_fails_crc_validation() {
    let mut four = RAR4.to_vec();
    let at = four.len() - 12; // five payload bytes, then a seven-byte RAR4 end block
    assert_eq!(four[at], b'h');
    four[at] ^= 1;
    assert_eq!(extract(&four), Err(Error::Checksum("RAR4 member")));

    let mut five = RAR5.to_vec();
    let at = five.len() - 13; // five payload bytes, then an eight-byte RAR5 end block
    assert_eq!(five[at], b'h');
    five[at] ^= 1;
    assert_eq!(extract(&five), Err(Error::Checksum("RAR5 member")));
}

#[test]
fn truncation_is_not_a_partial_success() {
    assert_eq!(extract(&RAR4[..RAR4.len() - 1]), Err(Error::Truncated));
    assert_eq!(extract(&RAR5[..RAR5.len() - 1]), Err(Error::Truncated));
    assert!(extract(&TAR_GZIP[..TAR_GZIP.len() - 1]).is_err());
}

#[test]
fn unsafe_names_are_refused_and_duplicates_returned_as_a_collision() {
    let traversal = include_bytes!("fixtures/traversal-rar5.rar");
    assert!(matches!(extract(traversal), Err(Error::InvalidPath(_))));
    // Extractors keep one copy (the last, or the first): both are returned, and grouped, so neither is hidden.
    let duplicate = extract(include_bytes!("fixtures/duplicate-rar5.rar")).unwrap();
    assert_eq!(duplicate.entries.len(), 2);
    assert!(duplicate.entries.iter().all(|e| e.name == "a.txt" && e.collision == Some(0)));
    assert!(duplicate.collisions[0].duplicate && duplicate.is_path_ambiguous());
}

#[test]
fn compression_and_encryption_fail_closed() {
    let four = include_bytes!("fixtures/compressed-rar4.rar");
    assert_eq!(extract(four), Err(Error::Unsupported("compressed RAR4 member")));
    let five = include_bytes!("fixtures/compressed-rar5.rar");
    assert_eq!(extract(five), Err(Error::Unsupported("compressed RAR5 member")));
    let encrypted = include_bytes!("fixtures/encrypted-rar5.rar");
    assert_eq!(extract(encrypted), Err(Error::Unsupported("encrypted RAR5 member")));
}

#[test]
fn caller_limits_are_enforced() {
    assert_eq!(extract_with_limits(RAR5, Limits::new(4, 100)), Err(Error::Limit("member size")));
    assert_eq!(extract_with_limits(RAR5, Limits::new(100, 4)), Err(Error::Limit("total extracted size")));
    assert!(matches!(extract_with_limits(TAR_GZIP, Limits::new(100, 4)), Err(Error::Limit(_))));
}
