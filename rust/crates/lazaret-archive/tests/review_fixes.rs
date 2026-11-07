//! The independent review's findings (H1-H8, M1-M6) and node-tar's rules found while fixing them (N1-N10),
//! one test each. Archives are built here from inert text the way the review's generators build them
//! (archive-review-work/gen/gen_tar.py), or are the small byte fixtures in tests/fixtures/review-fixes
//! (README, "Fixtures and tests").

use lazaret_archive::{detect, extract, extract_as, extract_with_limits, Archive, EntryKind, Error, Format, Limits, Result};
use lazaret_verify::inflate::crc32;

const B: usize = 512;
const BENIGN: &[u8] = b"benign text\n";
const HIDDEN: &[u8] = b"HIDDEN-MARKER: bytes another extractor shows as their own member\n";
const END: [u8; 2 * B] = [0; 2 * B];

fn octal(n: i64, width: usize) -> Vec<u8> { format!("{:0w$o}\0", n, w = width - 1).into_bytes() }

/// One TAR header, written as GNU tar and Python write it unless told otherwise.
#[derive(Clone)]
struct Hdr {
    name: Vec<u8>,
    size: i64,
    kind: u8,
    size_field: Option<Vec<u8>>,
    magic: Option<(Vec<u8>, Vec<u8>)>,
    prefix: Vec<u8>,
    linkname: Vec<u8>,
    uname: Vec<u8>,
    signed: bool,
    chk: Option<fn(i64) -> Vec<u8>>,
    patch: Vec<(usize, Vec<u8>)>,
}

impl Hdr {
    fn new(name: impl AsRef<[u8]>, size: usize, kind: u8) -> Hdr {
        Hdr { name: name.as_ref().to_vec(), size: size as i64, kind, size_field: None,
              magic: Some((b"ustar\0".to_vec(), b"00".to_vec())), prefix: vec![], linkname: vec![],
              uname: b"user".to_vec(), signed: false, chk: None, patch: vec![] }
    }
    fn prefix(mut self, p: &[u8]) -> Hdr { self.prefix = p.to_vec(); self }
    fn magic(mut self, m: &[u8], v: &[u8]) -> Hdr { self.magic = Some((m.to_vec(), v.to_vec())); self }
    fn v7(mut self) -> Hdr { self.magic = None; self.uname.clear(); self }
    fn size_field(mut self, f: &[u8]) -> Hdr { self.size_field = Some(f.to_vec()); self }
    fn linkname(mut self, l: &[u8]) -> Hdr { self.linkname = l.to_vec(); self }
    fn signed(mut self) -> Hdr { self.uname = b"\xff\xfe".to_vec(); self.signed = true; self }
    fn chk(mut self, f: fn(i64) -> Vec<u8>) -> Hdr { self.chk = Some(f); self }
    fn patch(mut self, at: usize, bytes: &[u8]) -> Hdr { self.patch.push((at, bytes.to_vec())); self }
    fn build(&self) -> Vec<u8> {
        let mut h = vec![0u8; B];
        h[..self.name.len()].copy_from_slice(&self.name);
        h[100..108].copy_from_slice(&octal(0o644, 8));
        h[108..116].copy_from_slice(&octal(1000, 8));
        h[116..124].copy_from_slice(&octal(1000, 8));
        h[124..136].copy_from_slice(&self.size_field.clone().unwrap_or_else(|| octal(self.size, 12)));
        h[136..148].copy_from_slice(&octal(0, 12));
        h[156] = self.kind;
        h[157..157 + self.linkname.len()].copy_from_slice(&self.linkname);
        if let Some((m, v)) = &self.magic {
            h[257..263].copy_from_slice(m);
            h[263..265].copy_from_slice(v);
        }
        h[265..265 + self.uname.len()].copy_from_slice(&self.uname);
        h[345..345 + self.prefix.len()].copy_from_slice(&self.prefix);
        for (at, bytes) in &self.patch { h[*at..*at + bytes.len()].copy_from_slice(bytes); }
        h[148..156].fill(b' ');
        let sum: i64 = if self.signed { h.iter().map(|&b| i64::from(b as i8)).sum() } else { h.iter().map(|&b| i64::from(b)).sum() };
        let field = match self.chk { Some(f) => f(sum), None => [format!("{sum:06o}").as_bytes(), b"\0 "].concat() };
        h[148..156].copy_from_slice(&field);
        h
    }
}

fn pad(data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    v.resize(v.len() + (B - v.len() % B) % B, 0);
    v
}

fn with(h: Hdr, data: &[u8]) -> Vec<u8> { [h.build(), pad(data)].concat() }
fn member(name: impl AsRef<[u8]>, data: &[u8]) -> Vec<u8> { with(Hdr::new(name, data.len(), b'0'), data) }
fn hidden() -> Vec<u8> { member("hidden.txt", HIDDEN) }

fn record(key: &str, value: &[u8]) -> Vec<u8> {
    let body = [b" ", key.as_bytes(), b"=", value, b"\n"].concat();
    let mut n = body.len() + 1;
    while n.to_string().len() + body.len() != n { n = n.to_string().len() + body.len(); }
    [n.to_string().as_bytes(), &body].concat()
}

fn pax_header(kind: u8, records: &[(&str, &[u8])], padding: &[u8]) -> Vec<u8> {
    let data: Vec<u8> = records.iter().flat_map(|(k, v)| record(k, v)).collect();
    [Hdr::new("PaxHeader", data.len(), kind).build(), pad(&[&data, padding].concat())].concat()
}

fn pax(records: &[(&str, &[u8])]) -> Vec<u8> { pax_header(b'x', records, b"") }
fn global(records: &[(&str, &[u8])]) -> Vec<u8> { pax_header(b'g', records, b"") }

fn long_name(raw: &[u8], padding: &[u8]) -> Vec<u8> {
    [Hdr::new("././@LongLink", raw.len(), b'L').build(), pad(&[raw, padding].concat())].concat()
}

fn tar(parts: &[&[u8]]) -> Vec<u8> { parts.concat() }

/// A gzip member with stored DEFLATE blocks.
fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    let chunks: Vec<&[u8]> = data.chunks(65_535).collect();
    if chunks.is_empty() { out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]); }
    for (i, chunk) in chunks.iter().enumerate() {
        out.push(u8::from(i + 1 == chunks.len()));
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&crc32(0, data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

fn ambiguous<T: std::fmt::Debug>(r: Result<T>) -> bool { matches!(r, Err(Error::Ambiguous(_))) }

fn files(a: &Archive) -> Vec<(&str, &[u8])> {
    a.entries.iter().filter(|e| e.kind == EntryKind::File).map(|e| (e.name.as_str(), e.data.as_slice())).collect()
}

#[test]
fn h1_a_size_field_that_starts_with_nul_is_refused() {
    for field in [[&b"\0"[..], format!("{:010o}\0", 2 * B).as_bytes()].concat(),
                  [&b"\0\0"[..], format!("{:09o}\0", 2 * B).as_bytes()].concat()] {
        let t = tar(&[&Hdr::new("a.txt", 0, b'0').size_field(&field).build(), &hidden(), &member("c.txt", BENIGN), &END]);
        assert!(ambiguous(extract(&t)));
    }
    // All NUL: every reader reads zero.
    let t = tar(&[&Hdr::new("a.txt", 0, b'0').size_field(&[0; 12]).build(), &member("b.txt", BENIGN), &END]);
    assert_eq!(files(&extract(&t).unwrap()), [("a.txt", &b""[..]), ("b.txt", BENIGN)]);
}

#[test]
fn h2_a_file_named_like_a_directory_is_refused() {
    for kind in [0, b'0', b'7'] {
        let t = tar(&[&Hdr::new("d/", 2 * B, kind).build(), &hidden(), &member("c.txt", BENIGN), &END]);
        assert!(ambiguous(extract(&t)), "typeflag {kind}");
    }
    assert!(ambiguous(extract(&tar(&[&pax(&[("path", b"f.txt/")]), &member("a.txt", BENIGN), &END]))));
    assert!(ambiguous(extract(&tar(&[&long_name(b"d/\0", b""), &member("a.txt", BENIGN), &END]))));
    // unrar makes "a.txt/" a directory, 7-Zip a file
    assert!(ambiguous(extract(include_bytes!("fixtures/review-fixes/r5_20_name_trailing_slash.rar"))));
    assert!(extract(&tar(&[&Hdr::new("d", 2 * B, b'5').build(), &hidden(), &END])).is_err());
}

#[test]
fn h3_the_ustar_prefix_is_read_only_in_posix_ustar_headers() {
    for h in [Hdr::new("setup.py", 12, b'0').magic(b"ustar ", b" \0").prefix(b"evil"),
              Hdr::new("setup.py", 12, b'0').v7().prefix(b"evil"),
              Hdr::new("setup.py", 12, b'0').magic(b"ustar\0", b"xx").prefix(b"evil"),
              Hdr::new("setup.py", 12, b'0').magic(b"ustar ", b" \0").patch(345, b"14567012345\0")] {
        assert!(ambiguous(extract(&tar(&[&with(h, BENIGN), &END]))));
    }
    let ok = extract(&tar(&[&with(Hdr::new("setup.py", 12, b'0').prefix(b"pkg"), BENIGN), &END])).unwrap();
    assert_eq!(files(&ok), [("pkg/setup.py", BENIGN)]);
    let gnu = extract(&tar(&[&with(Hdr::new("a.txt", 12, b'0').magic(b"ustar ", b" \0"), BENIGN), &END])).unwrap();
    assert_eq!(files(&gnu), [("a.txt", BENIGN)]);
    // xstar's times after a short prefix: every reader takes the prefix up to its NUL
    let xstar = Hdr::new("setup.py", 12, b'0').prefix(b"pkg").patch(476, b"14567012345\0");
    assert_eq!(files(&extract(&tar(&[&with(xstar, BENIGN), &END])).unwrap()), [("pkg/setup.py", BENIGN)]);
}

#[test]
fn h4_a_member_has_one_pax_header_or_one_long_name() {
    let body = [pad(BENIGN), hidden()].concat(); // what 12 bytes and 1,536 bytes of f.txt each cover
    let f = Hdr::new("f.txt", 12, b'0').build();
    for t in [
        tar(&[&pax(&[("path", b"first.txt")]), &pax(&[("path", b"second.txt")]), &member("plain.txt", BENIGN), &END]),
        tar(&[&pax(&[("size", b"12")]), &pax(&[("size", b"1536")]), &f, &body, &member("z.txt", BENIGN), &END]),
        tar(&[&pax(&[("size", b"1536")]), &pax(&[("size", b"12")]), &f, &body, &member("z.txt", BENIGN), &END]),
        tar(&[&long_name(b"from-L.txt\0", b""), &pax(&[("path", b"from-x.txt")]), &member("plain.txt", BENIGN), &END]),
        tar(&[&pax(&[("path", b"from-x.txt")]), &long_name(b"from-L.txt\0", b""), &member("plain.txt", BENIGN), &END]),
        tar(&[&long_name(b"first-L.txt\0", b""), &long_name(b"second-L.txt\0", b""), &member("plain.txt", BENIGN), &END]),
        tar(&[&pax(&[("path", b"first.txt"), ("path", b"second.txt")]), &member("plain.txt", BENIGN), &END]),
        tar(&[&pax(&[("size", b"1536")]), &f, &body, &member("z.txt", BENIGN), &END]),
    ] {
        assert!(ambiguous(extract(&t)));
    }
    let one = extract(&tar(&[&pax(&[("path", b"long/name.txt")]), &member("x.txt", BENIGN), &END])).unwrap();
    assert_eq!(files(&one), [("long/name.txt", BENIGN)]);
    let one = extract(&tar(&[&long_name(b"from-L.txt\0", b""), &member("x.txt", BENIGN), &END])).unwrap();
    assert_eq!(files(&one), [("from-L.txt", BENIGN)]);
    let sized = extract(&tar(&[&pax(&[("size", b"12")]), &Hdr::new("f.txt", 0, b'0').build(), &pad(BENIGN), &END])).unwrap();
    assert_eq!(files(&sized), [("f.txt", BENIGN)]);
}

#[test]
fn h5_a_long_name_keeps_its_newline() {
    let t = tar(&[&long_name(b"setup.py\n\0", b""), &member("plain.txt", BENIGN), &END]);
    assert!(matches!(extract(&t), Err(Error::InvalidPath(_))));
}

#[test]
fn h6_metadata_padding_holds_nothing() {
    assert!(extract(&tar(&[&long_name(b"a.txt", b"-tail.py\0"), &member("plain.txt", BENIGN), &END])).is_err());
    assert!(ambiguous(extract(&tar(&[&long_name(b"a.txt\0", b"-tail.py\0"), &member("plain.txt", BENIGN), &END]))));
    let records = pax_header(b'x', &[("path", b"declared.txt")], &record("path", b"padding.py"));
    assert!(ambiguous(extract(&tar(&[&records, &member("plain.txt", BENIGN), &END]))));
    let records = pax_header(b'x', &[("path", b"f.txt")], &record("size", b"1536"));
    let t = tar(&[&records, &Hdr::new("f.txt", 12, b'0').build(), &pad(BENIGN), &hidden(), &member("z.txt", BENIGN), &END]);
    assert!(ambiguous(extract(&t)));
}

#[test]
fn h7_a_7zip_unix_type_counts_without_the_extension_bit() {
    // (0o120777 << 16) | 0x20: 7-Zip extracts a symlink
    assert_eq!(extract(include_bytes!("fixtures/review-fixes/s04c_attr_symlink_no_ext.7z")), Err(Error::Unsupported("7-Zip special file")));
    assert_eq!(extract(include_bytes!("fixtures/review-fixes/a_fifo.7z")), Err(Error::Unsupported("7-Zip special file")));
    assert!(matches!(extract(include_bytes!("fixtures/review-fixes/z01_attr_dir_noext_file.7z")), Err(Error::Corrupt(_))));
    let regular = extract(include_bytes!("fixtures/review-fixes/z01b_attr_reg_noext.7z")).unwrap();
    assert_eq!(files(&regular), [("f.txt", BENIGN)]);
}

#[test]
fn h8_a_backslash_stays_in_the_name_and_its_windows_reading_is_reported() {
    let a = extract(&tar(&[&member("a\\b.txt", BENIGN), &END])).unwrap();
    assert_eq!(files(&a), [("a\\b.txt", BENIGN)]);
    assert_eq!(a.entries[0].windows_name.as_deref(), Some("a/b.txt"));
    assert!(a.is_path_ambiguous() && a.collisions.is_empty());
    let both = extract(&tar(&[&member("a\\b.txt", BENIGN), &member("a/b.txt", HIDDEN), &END])).unwrap();
    assert_eq!(files(&both), [("a\\b.txt", BENIGN), ("a/b.txt", HIDDEN)]);
    assert!(both.collisions[0].alias);
    for name in ["..\\x.txt", "\\x.txt", "a\\..\\..\\x.txt"] {
        assert!(matches!(extract(&tar(&[&member(name, HIDDEN), &END])), Err(Error::InvalidPath(_))), "{name}");
    }
    let seven = extract(include_bytes!("fixtures/review-fixes/s11_backslash_name.7z")).unwrap();
    assert_eq!(seven.entries[0].name, "a\\b.txt");
    assert!(matches!(extract(include_bytes!("fixtures/review-fixes/z03_backslash_traversal.7z")), Err(Error::InvalidPath(_))));
    let unix = extract(include_bytes!("fixtures/review-fixes/r5_02_backslash_unix.rar")).unwrap();
    assert_eq!((unix.entries[0].name.as_str(), unix.entries[0].windows_name.as_deref()), ("dir\\a.txt", Some("dir/a.txt")));
    // In a Windows-made RAR5 name '\' is invalid: unrar writes '_', 7-Zip keeps it.
    assert!(ambiguous(extract(include_bytes!("fixtures/review-fixes/r5_03_backslash_win.rar"))));
    // RAR4 separates with '\' everywhere, as unrar and 7-Zip read it.
    let four = extract(include_bytes!("fixtures/review-fixes/r4_02_windows_backslash.rar")).unwrap();
    assert_eq!((four.entries[0].name.as_str(), four.entries[0].windows_name.as_deref()), ("dir/a.txt", None));
}

#[test]
fn seven_zip_stream_sections_come_in_7zips_order() {
    // 7-Zip refuses unpack information before pack information; unar extracts an empty file from it.
    assert_eq!(extract(include_bytes!("fixtures/review-fixes/s07_unpack_before_pack.7z")),
               Err(Error::Corrupt("7-Zip streams information out of order")));
}

#[test]
fn m1_rar_7_archives_are_read() {
    let mut expected: Vec<(String, Vec<u8>)> = (0..4).map(|i| (format!("pkg/sub/f{i}.txt"), format!("line {i}\n").repeat(40 * i + 1).into_bytes())).collect();
    expected.push(("pkg/caf\u{e9}.txt".into(), BENIGN.to_vec()));
    expected.push(("pkg/empty.txt".into(), Vec::new()));
    expected.push(("pkg/same1.txt".into(), HIDDEN.repeat(50)));
    expected.push(("pkg/same2.txt".into(), HIDDEN.repeat(50)));
    expected.sort();
    for bytes in [include_bytes!("fixtures/review-fixes/real_store5.rar").as_slice(),
                  include_bytes!("fixtures/review-fixes/real_store5_rr.rar").as_slice()] {
        let archive = extract(bytes).unwrap();
        assert_eq!(archive.format, Format::Rar5);
        let mut got: Vec<(String, Vec<u8>)> = files(&archive).into_iter().map(|(n, d)| (n.to_string(), d.to_vec())).collect();
        got.sort();
        assert_eq!(got, expected);
        assert!(archive.entries.iter().any(|e| e.name == "pkg/emptydir" && e.kind == EntryKind::Directory));
        assert!(!archive.is_path_ambiguous());
    }
    // unrar reads headers from the quick-open copy, which this reader does not check against the archive
    assert_eq!(extract(include_bytes!("fixtures/review-fixes/real_store5_qo.rar")), Err(Error::Unsupported("RAR5 quick-open data")));
    let metadata = extract(include_bytes!("fixtures/review-fixes/r5_23_main_locator_and_metadata.rar")).unwrap();
    assert_eq!(files(&metadata), [("a.txt", BENIGN)]);
}

#[test]
fn m2_lbzip2_and_pbzip2_output_is_read() {
    let lbzip2 = extract(include_bytes!("fixtures/review-fixes/b_pattern_lbzip2.bz2")).unwrap();
    let pattern: Vec<u8> = (0u8..=255).cycle().take(256 * 5000).collect();
    assert_eq!(lbzip2.entries[0].data, pattern);
    let pbzip2 = include_bytes!("fixtures/review-fixes/b_zeros_pbzip2.bz2");
    assert_eq!(extract(pbzip2).unwrap().entries[0].data, vec![0u8; 3_000_000]);
    assert!(matches!(extract_with_limits(pbzip2, Limits::new(2_999_999, 3_000_000)), Err(Error::Limit(_))));
    assert_eq!(extract(include_bytes!("fixtures/review-fixes/b_concat.bz2")).unwrap().entries[0].data, b"first\nsecond\n");
    assert!(extract(include_bytes!("fixtures/review-fixes/b_trailing_zeros.bz2")).is_err());
}

#[test]
fn m3_common_pax_headers_are_read() {
    let sha = b"3f2a1b0c3f2a1b0c3f2a1b0c3f2a1b0c3f2a1b0c";
    for t in [
        tar(&[&global(&[("comment", sha)]), &member("a.txt", BENIGN), &END]),
        tar(&[&global(&[("mtime", b"1700000000")]), &member("a.txt", BENIGN), &END]),
        tar(&[&pax(&[("SCHILY.xattr.user.k", b"v")]), &member("a.txt", BENIGN), &END]),
        tar(&[&pax(&[("LIBARCHIVE.xattr.com.apple.provenance", b"AQ==")]), &member("a.txt", BENIGN), &END]),
        tar(&[&pax(&[("SCHILY.xattr.com.apple.provenance", b"\x01\x02\x00\xff\xfe\x80")]), &member("a.txt", BENIGN), &END]),
        tar(&[&pax(&[("hdrcharset", b"BINARY")]), &member("a.txt", BENIGN), &END]),
        tar(&[&pax(&[("LIBARCHIVE.creationtime", b"1700000000")]), &member("a.txt", BENIGN), &END]),
    ] {
        assert_eq!(files(&extract(&t).unwrap()), [("a.txt", BENIGN)]);
    }
    // what `git archive` writes
    let git = tar(&[&global(&[("comment", sha)]), &Hdr::new("pkg/", 0, b'5').build(), &member("pkg/a.txt", BENIGN), &END]);
    assert_eq!(files(&extract(&git).unwrap()), [("pkg/a.txt", BENIGN)]);
    // A global path or size: Python and GNU tar apply it to members, bsdtar ignores it, node-tar takes the size.
    for g in [global(&[("path", b"evil.txt")]), global(&[("size", b"1536")])] {
        assert!(matches!(extract(&tar(&[&g, &member("a.txt", BENIGN), &END])), Err(Error::Unsupported(_))));
    }
    let late = tar(&[&pax(&[("path", b"long/name.txt")]), &global(&[("comment", b"abc")]), &member("x.txt", BENIGN), &END]);
    assert!(ambiguous(extract(&late)));
}

#[test]
fn m4_a_signed_checksum_is_recognised_and_refused_clearly() {
    let t = tar(&[&with(Hdr::new("a", 12, b'0').signed(), BENIGN), &END]);
    assert_eq!(detect(&t), Ok(Format::Tar));
    // node-tar checks only the unsigned sum and reads on from the header's data
    assert!(ambiguous(extract(&t)));
    assert!(ambiguous(extract_as(&t, Format::Tar, Limits::default())));
    assert!(ambiguous(extract(&gzip(&t))));
    let wrong = tar(&[&with(Hdr::new("a", 12, b'0').signed().chk(|_| b"0\0      ".to_vec()), BENIGN), &END]);
    assert_eq!(extract_as(&wrong, Format::Tar, Limits::default()), Err(Error::Checksum("TAR header")));
    let control = tar(&[&with(Hdr { signed: false, ..Hdr::new("a", 12, b'0').signed() }, BENIGN), &END]);
    assert_eq!(files(&extract(&control).unwrap()), [("a", BENIGN)]);
}

#[test]
fn m5_colliding_names_are_all_returned_and_grouped_and_links_refused() {
    let nfc = "caf\u{e9}.txt";
    let nfd = "cafe\u{301}.txt";
    for (a, b, duplicate, alias, file_directory) in [
        ("Makefile", "makefile", false, true, false),
        ("a.txt", "a.txt", true, false, false),
        ("a/b.txt", "a//b.txt", true, false, false),
        (nfc, nfd, false, true, false),
        ("\u{17f}.txt", "s.txt", false, true, false),
        ("\u{212a}.txt", "k.txt", false, true, false),
        ("a\u{200d}b.txt", "ab.txt", false, true, false),
        ("stra\u{df}e.txt", "strasse.txt", false, true, false),
        ("a", "a/b.txt", false, false, true),
        ("a/b.txt", "a", false, false, true),
    ] {
        let archive = extract(&tar(&[&member(a, BENIGN), &member(b, HIDDEN), &END])).unwrap();
        assert_eq!(archive.entries.len(), 2, "{a:?} {b:?}");
        assert_eq!(archive.entries[0].data, BENIGN);
        assert_eq!(archive.entries[1].data, HIDDEN);
        let c = &archive.collisions[0];
        assert_eq!((c.entries.as_slice(), c.duplicate, c.alias, c.file_directory), (&[0, 1][..], duplicate, alias, file_directory), "{a:?} {b:?}");
    }
    let distinct = extract(&tar(&[&member(nfc, BENIGN), &member("cafe.txt", HIDDEN), &END])).unwrap();
    assert!(distinct.collisions.is_empty() && !distinct.is_path_ambiguous());
    let seven = extract(include_bytes!("fixtures/review-fixes/s11e_case_alias.7z")).unwrap();
    assert!(seven.collisions[0].alias);
    // Links still refuse the archive: which bytes land under which name is each extractor's own rule.
    let hard = tar(&[&member("a.txt", BENIGN), &Hdr::new("b.txt", 0, b'1').linkname(b"a.txt").build(), &END]);
    let soft = tar(&[&Hdr::new("b.txt", 0, b'2').linkname(b"a.txt").build(), &END]);
    for t in [hard, soft] { assert_eq!(extract(&t), Err(Error::Unsupported("TAR links"))); }
}

#[test]
fn m6_endings_every_reader_agrees_on_are_read() {
    let a = member("a.txt", BENIGN);
    for t in [a.clone(), tar(&[&a, &[0; B]]), tar(&[&a, &END, &[0; 3 * B]]), tar(&[&a, &[0; B + 100]])] {
        assert_eq!(files(&extract(&t).unwrap()), [("a.txt", BENIGN)]);
    }
    let two = extract(&tar(&[&a, &member("b.txt", HIDDEN)])).unwrap();
    assert_eq!(files(&two), [("a.txt", BENIGN), ("b.txt", HIDDEN)]);
    // node-tar reads on after a single zero block; the others stop there
    assert!(ambiguous(extract(&tar(&[&a, &[0; B], &member("b.txt", HIDDEN), &END]))));
    assert_eq!(extract(&tar(&[&Hdr::new("a.txt", 12, b'0').build(), BENIGN])), Err(Error::Truncated));
    assert!(extract(&tar(&[&a, &END, b"garbage"])).is_err());
    assert!(extract(&tar(&[&a, &pax(&[("path", b"evil.txt")])])).is_err());
}

#[test]
fn n1_no_link_name_on_a_header_that_is_not_a_link() {
    let t = tar(&[&Hdr::new("a.txt", 2 * B, b'0').linkname(b"x").build(), &hidden(), &member("c.txt", BENIGN), &END]);
    assert!(ambiguous(extract(&t)));
    let t = tar(&[&Hdr::new("././@LongLink", 9, b'L').linkname(b"x").build(), &pad(b"long.txt\0"), &member("plain.txt", BENIGN), &END]);
    assert!(ambiguous(extract(&t)));
}

#[test]
fn n2_no_line_break_after_the_nul_of_a_name() {
    assert!(ambiguous(extract(&tar(&[&member(b"setup.py\0\nx", BENIGN), &END]))));
    assert!(ambiguous(extract(&tar(&[&with(Hdr::new("setup.py", 12, b'0').prefix(b"pkg\0\nx"), BENIGN), &END]))));
    assert!(ambiguous(extract(&tar(&[&long_name(b"setup.py\0\nx\0", b""), &member("plain.txt", BENIGN), &END]))));
    assert_eq!(files(&extract(&tar(&[&member(b"setup.py\0junk", BENIGN), &END])).unwrap()), [("setup.py", BENIGN)]);
}

#[test]
fn n3_n4_n5_pax_records_node_tar_reads_differently() {
    let leading_zero = tar(&[&Hdr::new("PaxHeader", 18, b'x').build(), &pad(b"018 path=evil.txt\n"), &member("plain.txt", BENIGN), &END]);
    let split = b"30 comment=x\n17 path=evil.txt\n";
    let newline = tar(&[&Hdr::new("PaxHeader", split.len(), b'x').build(), &pad(split), &member("plain.txt", BENIGN), &END]);
    let xattr = tar(&[&pax(&[("SCHILY.xattr.user.k", b"\x01\n17 path=evil.txt")]), &member("plain.txt", BENIGN), &END]);
    for t in [leading_zero, newline, xattr] { assert!(ambiguous(extract(&t))); }
    for digits in [&b"0123"[..], b"123"] {
        assert!(ambiguous(extract(&tar(&[&pax(&[("path", digits)]), &member("plain.txt", BENIGN), &END]))));
    }
}

#[test]
fn n6_a_long_name_replaces_the_ustar_prefix_for_every_reader() {
    // node-tar writes a ustar prefix and a pax path for a long base name; its reader, like the others, takes the
    // long name alone.
    let prefixed = with(Hdr::new("x.txt", 12, b'0').prefix(b"evil"), BENIGN);
    for t in [tar(&[&pax(&[("path", b"setup.py")]), &prefixed, &END]), tar(&[&long_name(b"setup.py\0", b""), &prefixed, &END])] {
        assert_eq!(files(&extract(&t).unwrap()), [("setup.py", BENIGN)]);
    }
}

#[test]
fn n7_metadata_node_tar_would_skip_is_refused_whatever_the_limits() {
    let big = [record("comment", &vec![b'c'; 1024 * 1024]), record("path", b"evil.txt")].concat();
    let t = tar(&[&Hdr::new("PaxHeader", big.len(), b'x').build(), &pad(&big), &member("plain.txt", BENIGN), &END]);
    let limits = Limits { max_metadata_size: 4 * 1024 * 1024, ..Limits::default() };
    assert!(ambiguous(extract_with_limits(&t, limits)));
    assert!(ambiguous(extract(&t)));
}

#[test]
fn n8_n9_numbers_node_tar_reads_differently() {
    let mut c0 = vec![0u8; 12];
    c0[0] = 0xc0;
    c0[10..].copy_from_slice(&(2 * B as u16).to_be_bytes());
    let t = tar(&[&Hdr::new("a.txt", 0, b'0').size_field(&c0).build(), &hidden(), &member("c.txt", BENIGN), &END]);
    assert!(ambiguous(extract(&t)));
    let mut x80 = c0.clone();
    x80[0] = 0x80;
    let t = tar(&[&Hdr::new("a.txt", 0, b'0').size_field(&x80).build(), &hidden(), &member("c.txt", BENIGN), &END]);
    assert_eq!(extract(&t).unwrap().entries[0].data.len(), 2 * B);
    let eight = tar(&[&with(Hdr::new("a.txt", 12, b'0').chk(|s| format!("{s:08o}").into_bytes()), BENIGN), &END]);
    assert!(ambiguous(extract(&eight)));
}

#[test]
fn n10_a_non_ascii_long_name_node_tar_may_decode_in_pieces_is_refused() {
    let long = format!("{}/caf\u{e9}\u{e9}\u{e9}/setup.py", "d".repeat(600));
    assert!(ambiguous(extract(&tar(&[&pax(&[("path", long.as_bytes())]), &member("plain.txt", BENIGN), &END]))));
    assert!(ambiguous(extract(&tar(&[&long_name(&[long.as_bytes(), b"\0"].concat(), b""), &member("plain.txt", BENIGN), &END]))));
    // Within the first 512 bytes no stream splits a character: read.
    let short = "caf\u{e9}/setup.py";
    for t in [tar(&[&pax(&[("path", short.as_bytes())]), &member("caf?/setup.py", BENIGN), &END]),
              tar(&[&long_name(&[short.as_bytes(), b"\0"].concat(), b""), &member("caf/setup.py", BENIGN), &END])] {
        assert_eq!(files(&extract(&t).unwrap()), [(short, BENIGN)]);
    }
    let empty = tar(&[&Hdr::new("././@LongLink", 0, b'L').build(), &member("plain.txt", BENIGN), &END]);
    assert!(ambiguous(extract(&empty)));
}

#[test]
fn bytes_a_tar_reader_would_skip_to_are_not_read_as_another_format() {
    // GNU tar, bsdtar and node-tar skip a block that fails its checksum and read the TAR after it.
    let junk = tar(&[&[b'j'; B], &member("a.txt", BENIGN), &END]);
    assert!(matches!(detect(&junk), Err(Error::Ambiguous(_))));
    let gz = gzip(&junk);
    assert!(ambiguous(extract(&gz)));
    assert_eq!(extract_as(&gz, Format::Gzip, Limits::default()).unwrap().entries[0].data, junk);
    assert!(extract_as(&gz, Format::TarGzip, Limits::default()).is_err());
    let plain = gzip(b"just text\n");
    assert_eq!(extract(&plain).unwrap().format, Format::Gzip);
    let tgz = gzip(&tar(&[&member("a.txt", BENIGN), &END]));
    assert_eq!(files(&extract_as(&tgz, Format::TarGzip, Limits::default()).unwrap()), [("a.txt", BENIGN)]);
}

#[test]
fn the_caller_can_name_the_format() {
    let lzma = include_bytes!("fixtures/pickle.lzma");
    assert_eq!(extract_as(lzma, Format::Lzma, Limits::default()).unwrap().entries[0].data, include_bytes!("fixtures/pickle.pkl"));
    let bz2 = include_bytes!("fixtures/review-fixes/b_concat.bz2");
    assert_eq!(extract_as(bz2, Format::Xz, Limits::default()), Err(Error::Corrupt("not the named archive format")));
    assert!(extract_as(bz2, Format::Tar, Limits::default()).is_err());
}
