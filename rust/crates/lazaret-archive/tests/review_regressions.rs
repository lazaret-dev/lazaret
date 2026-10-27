use lazaret_archive::{extract, extract_with_limits, EntryKind, Error, Format, Limits};
use lazaret_verify::inflate::crc32;

#[test]
fn zero_literal_context_is_valid_in_lzma1_and_lzma2() {
    for bytes in [include_bytes!("fixtures/review/lc0-33.7z").as_slice(),
                  include_bytes!("fixtures/review/lc0-4611686018427387905.7z").as_slice()] {
        assert_eq!(extract(bytes).unwrap().entries[0].data, b"abcdefgh".repeat(500));
    }
}

#[test]
fn dictionary_reset_preserves_the_independently_encoded_output() {
    let a = extract(include_bytes!("fixtures/review/dictionary-reset.7z")).unwrap();
    let mut expected = b"abcdefghZ".repeat(500);
    expected.extend_from_slice(&b"next-context".repeat(500));
    assert_eq!(a.entries[0].data, expected);
}

#[test]
fn unknown_size_lzma_can_end_exactly_at_the_limit() {
    let bytes = include_bytes!("fixtures/pickle.lzma");
    let raw = include_bytes!("fixtures/pickle.pkl");
    let n = raw.len() as u64;
    assert_eq!(extract_with_limits(bytes, Limits::new(n, n)).unwrap().entries[0].data, raw);
    assert!(matches!(extract_with_limits(bytes, Limits::new(n-1, n)), Err(Error::Limit(_))));
    let empty = include_bytes!("fixtures/review/zero-limit.lzma");
    assert!(extract_with_limits(empty, Limits::new(0, 0)).unwrap().entries[0].data.is_empty());
}

#[test]
fn known_size_lzma_checks_the_range_coder_and_end_marker() {
    let bytes = include_bytes!("fixtures/review/known-size-cut-0.lzma");
    assert_eq!(extract(bytes).unwrap().entries[0].data, b"hello world");
    for cut in 1..=8 { assert!(extract(&bytes[..bytes.len()-cut]).is_err(), "cut={cut}"); }
    let mut trailing = bytes.to_vec(); trailing.push(0);
    assert!(extract(&trailing).is_err());
}

#[test]
fn pax_sparse_metadata_never_becomes_an_ordinary_file() {
    for bytes in [include_bytes!("fixtures/review/pax-sparse.tar").as_slice(),
                  include_bytes!("fixtures/review/pax-sparse-traversal.tar").as_slice()] {
        assert!(matches!(extract(bytes), Err(Error::Unsupported(_))));
    }
}

#[test]
fn seven_zip_symlinks_are_explicitly_unsupported() {
    assert!(matches!(extract(include_bytes!("fixtures/review/symlink.7z")), Err(Error::Unsupported(_))));
}

#[test]
fn empty_tar_and_tgz_return_empty_archives() {
    for (bytes, format) in [(include_bytes!("fixtures/review/empty.tar").as_slice(), Format::Tar),
                            (include_bytes!("fixtures/review/empty.tar.gz").as_slice(), Format::TarGzip)] {
        let archive = extract(bytes).unwrap();
        assert_eq!(archive.format, format);
        assert!(archive.entries.is_empty());
    }
}

#[test]
fn dot_slash_root_is_not_a_file_and_endings_every_reader_agrees_on_are_read() {
    let bytes = include_bytes!("fixtures/review/root-dot-slash.tar");
    let archive = extract(bytes).unwrap();
    assert_eq!(archive.entries.len(), 1);
    assert_eq!(archive.entries[0].name, "a.txt");
    assert_eq!(archive.entries[0].data, b"TEST");
    // One end block, or none, ends the archive for Python, GNU tar, bsdtar and node-tar alike (M6).
    assert_eq!(extract(&bytes[..1536 + 512]).unwrap().entries, archive.entries);
    assert_eq!(extract(&bytes[..1536]).unwrap().entries, archive.entries);
    // Zeros after a zero block are ignored by every reader, cut short or not; a cut member is not.
    assert_eq!(extract(&bytes[..bytes.len() - 1]).unwrap().entries, archive.entries);
    assert!(extract(&bytes[..1024 + 100]).is_err());
    assert!(extract(&bytes[..1024 + 512 + 100]).is_err());
}

#[test]
fn case_and_ancestor_path_collisions_are_returned_and_grouped() {
    let case = extract(include_bytes!("fixtures/review/case-collision.tar")).unwrap();
    assert_eq!(case.entries.len(), 2);
    assert!(case.collisions[0].alias && case.collisions[0].entries == [0, 1]);
    let bytes = include_bytes!("fixtures/review/ancestor-collision.tar");
    let mut reverse = bytes.to_vec();
    reverse[..1024].copy_from_slice(&bytes[1024..2048]);
    reverse[1024..2048].copy_from_slice(&bytes[..1024]);
    for archive in [extract(bytes).unwrap(), extract(&reverse).unwrap()] {
        assert_eq!(archive.entries.len(), 2);
        assert!(archive.collisions[0].file_directory && archive.collisions[0].entries == [0, 1]);
    }
}

fn rar4_mode(mode: u32) -> Vec<u8> {
    let mut bytes = include_bytes!("fixtures/stored-rar4.rar").to_vec();
    let start = 20;
    let len = u16::from_le_bytes([bytes[start+5], bytes[start+6]]) as usize;
    bytes[start+15] = 3;
    bytes[start+28..start+32].copy_from_slice(&mode.to_le_bytes());
    let crc = crc32(0, &bytes[start+2..start+len]) as u16;
    bytes[start..start+2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

#[test]
fn rar4_unix_regular_files_are_supported_and_links_are_not() {
    assert_eq!(extract(&rar4_mode(0o100644)).unwrap().entries[0].data, b"hello");
    for mode in [0o120777, 0o060644, 0o020644, 0o010644] {
        assert!(matches!(extract(&rar4_mode(mode)), Err(Error::Unsupported(_))));
    }
}

#[test]
fn rar_entry_limit_does_not_count_the_main_and_end_headers() {
    for bytes in [include_bytes!("fixtures/stored-rar4.rar").as_slice(), include_bytes!("fixtures/stored-rar5.rar").as_slice()] {
        let mut limits = Limits::default(); limits.max_entries = 1;
        assert_eq!(extract_with_limits(bytes, limits).unwrap().entries.len(), 1);
        limits.max_entries = 0;
        assert!(matches!(extract_with_limits(bytes, limits), Err(Error::Limit(_))));
    }
}

#[test]
fn many_folders_map_each_stream_once() {
    let a = extract(include_bytes!("fixtures/review/folders-2000.7z")).unwrap();
    assert_eq!(a.entries.len(), 2000);
    for (i, e) in a.entries.iter().enumerate() {
        assert_eq!(e.name, format!("f{i}"));
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.data, b"x");
    }
}

#[test]
fn independently_compressed_multiblock_data_matches() {
    let expected: Vec<u8> = (0u8..=255).rev().cycle().take(1_024_000).collect();
    for bytes in [include_bytes!("fixtures/review/differential-4.bz2").as_slice(),
                  include_bytes!("fixtures/review/differential-4.xz").as_slice(),
                  include_bytes!("fixtures/review/differential-4.lzma").as_slice()] {
        assert_eq!(extract(bytes).unwrap().entries[0].data, expected);
    }
}

#[test]
fn bounded_mutations_and_truncations_do_not_panic() {
    let fixtures: &[&[u8]] = &[
        include_bytes!("fixtures/stored-rar4.rar"), include_bytes!("fixtures/stored-rar5.rar"),
        include_bytes!("fixtures/copy.7z"), include_bytes!("fixtures/lzma1.7z"),
        include_bytes!("fixtures/lzma2.7z"), include_bytes!("fixtures/pickle.bz2"),
        include_bytes!("fixtures/pickle.xz"), include_bytes!("fixtures/pickle.lzma"),
        include_bytes!("fixtures/sample.tar.gz"),
    ];
    let mut limits = Limits::new(8192, 16384);
    limits.max_entries = 32; limits.max_metadata_size = 16384;
    let mut seed = 0x4c415a41524554u64;
    for &bytes in fixtures {
        for len in 0..bytes.len() { let _ = extract_with_limits(&bytes[..len], limits); }
        for _ in 0..512 {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            let mut mutated = bytes.to_vec();
            let i = seed as usize % mutated.len();
            mutated[i] ^= 1 << ((seed >> 32) % 8);
            // Re-sign structural CRCs so 7-Zip mutations reach the metadata
            // parser rather than stopping at the checksum gate every time.
            if mutated.starts_with(b"7z\xbc\xaf\x27\x1c") && mutated.len() >= 32 {
                let at = u64::from_le_bytes(mutated[12..20].try_into().unwrap());
                let size = u64::from_le_bytes(mutated[20..28].try_into().unwrap());
                if let Some((start, end)) = at.checked_add(32).and_then(|start| start.checked_add(size).map(|end| (start,end))) {
                    if end <= mutated.len() as u64 {
                        let crc = crc32(0, &mutated[start as usize..end as usize]);
                        mutated[28..32].copy_from_slice(&crc.to_le_bytes());
                    }
                }
                let crc = crc32(0, &mutated[12..32]);
                mutated[8..12].copy_from_slice(&crc.to_le_bytes());
            }
            let _ = extract_with_limits(&mutated, limits);
        }
    }
}
