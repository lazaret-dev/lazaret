use lazaret_archive::{extract, extract_with_limits, EntryKind, Error, Format, Limits};

const COPY: &[u8] = include_bytes!("fixtures/copy.7z");
const DEFLATE: &[u8] = include_bytes!("fixtures/deflate.7z");
const LZMA1: &[u8] = include_bytes!("fixtures/lzma1.7z");
const LZMA2: &[u8] = include_bytes!("fixtures/lzma2.7z");

fn expected() -> Vec<u8> {
    let mut raw = b"7-Zip native extraction\n".repeat(100);
    raw.extend(0u8..=255);
    raw
}

#[test]
fn extracts_copy_deflate_lzma_and_lzma2() {
    for bytes in [COPY, DEFLATE, LZMA1, LZMA2] {
        let archive = extract(bytes).unwrap();
        assert_eq!(archive.format, Format::SevenZip);
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, "a.txt");
        assert_eq!(archive.entries[0].kind, EntryKind::File);
        assert_eq!(archive.entries[0].data, expected());
    }
}

#[test]
fn extracts_an_archive_from_the_system_7zip_writer() {
    let archive = extract(include_bytes!("fixtures/real-writer.7z")).unwrap();
    assert_eq!(archive.entries.len(), 1);
    assert_eq!(archive.entries[0].name, "a.txt");
    assert_eq!(archive.entries[0].data, b"Real 7-Zip writer interoperability.\n");
}

#[test]
fn extracts_multiple_files_from_one_lzma2_folder() {
    let archive = extract(include_bytes!("fixtures/lzma2-multi.7z")).unwrap();
    assert_eq!(archive.entries.len(), 2);
    assert_eq!(archive.entries[0].name, "first.txt");
    assert_eq!(archive.entries[0].data, b"first".repeat(100));
    assert_eq!(archive.entries[1].name, "second.txt");
    assert_eq!(archive.entries[1].data, b"second".repeat(100));
}

#[test]
fn lzma2_state_continues_across_compressed_chunks() {
    let archive = extract(include_bytes!("fixtures/lzma2-multichunk.7z")).unwrap();
    let expected: Vec<u8> = (0u8..=255).cycle().take(256 * 9000).collect();
    assert_eq!(archive.entries[0].data, expected);
}

#[test]
fn decodes_an_lzma2_encoded_header() {
    let archive = extract(include_bytes!("fixtures/lzma2-encoded-header.7z")).unwrap();
    assert_eq!(archive.entries.len(), 1);
    assert_eq!(archive.entries[0].name, "encoded.txt");
    assert_eq!(archive.entries[0].data, b"encoded header\n".repeat(30));
}

#[test]
fn preserves_empty_files_and_directories() {
    let archive = extract(include_bytes!("fixtures/empty-entries.7z")).unwrap();
    assert_eq!(archive.entries.len(), 2);
    assert_eq!(archive.entries[0].name, "empty-dir");
    assert_eq!(archive.entries[0].kind, EntryKind::Directory);
    assert_eq!(archive.entries[1].name, "empty.txt");
    assert_eq!(archive.entries[1].kind, EntryKind::File);
    assert!(archive.entries[1].data.is_empty());
}

#[test]
fn corruption_and_truncation_are_not_partial_successes() {
    let mut bad_member = COPY.to_vec();
    bad_member[32] ^= 1;
    assert_eq!(extract(&bad_member), Err(Error::Checksum("7-Zip member")));

    let mut bad_header = COPY.to_vec();
    *bad_header.last_mut().unwrap() ^= 1;
    assert_eq!(extract(&bad_header), Err(Error::Checksum("7-Zip header")));
    assert!(matches!(extract(&LZMA2[..LZMA2.len() - 1]), Err(Error::Corrupt(_) | Error::Truncated)));
}

#[test]
fn unsafe_and_encrypted_entries_fail_closed_and_duplicates_are_grouped() {
    assert!(matches!(extract(include_bytes!("fixtures/traversal.7z")), Err(Error::InvalidPath(_))));
    let duplicate = extract(include_bytes!("fixtures/duplicate.7z")).unwrap();
    assert!(duplicate.entries.len() == 2 && duplicate.entries.iter().all(|e| e.name == "same.txt"));
    assert!(duplicate.collisions[0].duplicate);
    assert_eq!(extract(include_bytes!("fixtures/encrypted.7z")), Err(Error::Unsupported("encrypted 7-Zip member")));
}

#[test]
fn limits_apply_before_7zip_output_is_returned() {
    assert_eq!(extract_with_limits(LZMA2, Limits::new(4, 10_000)), Err(Error::Limit("member size")));
    assert_eq!(extract_with_limits(LZMA2, Limits::new(10_000, 4)), Err(Error::Limit("total extracted size")));
}
