//! R1 from the external review of 04cb9917, ported from its `test_archive_member_bound.py` with no probe binary:
//! a solid 7-Zip folder and a bare gzip stream decode no further than the member limit allows.
//!
//! * A solid 7-Zip folder whose members are each over the member limit, while the folder fits the total, is refused
//!   with `Limit("member size")` from its metadata, before anything is decoded: a small peak, and never a partial
//!   success. Members that each fit but together pass the total are refused the same way, with
//!   `Limit("total extracted size")`.
//! * Within the limits the folder extracts completely, byte-identical to the 7-Zip CLI's own extraction.
//! * A bare gzip stream over the member limit is refused with `Limit("member size")`, and its peak stays near the
//!   member limit whatever the size of the payload. Within the limits it extracts byte-identically to `gunzip`.
//! * A TAR inside gzip still decodes up to the total.
//!
//! Peak heap is counted by this test binary's own allocator, per thread, so the tests may run in parallel. Each
//! measured case prints its peak (`cargo test --test member_bound -- --nocapture`), and every case is measured before
//! any is asserted. The inputs are inert text, built here as bytes, or written by the `7z` and `gzip` CLIs when they
//! are installed; the cases that need a CLI print that they are skipped and pass without it.

use lazaret_archive::{extract_as, extract_with_limits, Archive, EntryKind, Error, Format, Limits, Result};
use lazaret_verify::inflate::crc32;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ---------------------------------------------------------------- a counting allocator, per thread

struct Counting;

thread_local! {
    static CURRENT: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

/// `grow` bytes more are live; for a moment `transient` more than that (a realloc that copies).
fn count(grow: isize, transient: isize) {
    let _ = CURRENT.try_with(|current| {
        let now = current.get() + grow;
        current.set(now);
        let _ = PEAK.try_with(|peak| if now + transient > peak.get() { peak.set(now + transient) });
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() { count(layout.size() as isize, 0); }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() { count(layout.size() as isize, 0); }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        System.dealloc(p, layout);
        count(-(layout.size() as isize), 0);
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        let q = System.realloc(p, layout, new);
        if !q.is_null() {
            // As the review's probe counts it: a growing realloc may copy, so the old block is live for a moment too.
            let old = layout.size() as isize;
            count(new as isize - old, if new as isize > old { old } else { 0 });
        }
        q
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

fn limits(member: usize, total: usize) -> Limits { Limits::new(member as u64, total as u64) }

/// Runs `f` and returns what it returned (still alive, so counted) and the most heap this thread held during it.
fn measure<T>(label: &str, f: impl FnOnce() -> T) -> (T, usize) {
    let base = CURRENT.with(Cell::get);
    PEAK.with(|peak| peak.set(base));
    let out = f();
    let peak = (PEAK.with(Cell::get) - base).max(0) as usize;
    println!("peak {label}: {peak} bytes ({:.2} MiB)", peak as f64 / MIB as f64);
    (out, peak)
}

/// An extraction's outcome in a few words (an archive's `Debug` prints all of its bytes).
fn outcome(result: &Result<Archive>) -> String {
    match result {
        Ok(a) => format!("Ok({:?}, {} entries, {} bytes)", a.format, a.entries.len(), a.entries.iter().map(|e| e.data.len()).sum::<usize>()),
        Err(e) => format!("Err({e:?})"),
    }
}

/// The archive's files as (name, bytes), sorted by name.
fn files(archive: &Archive) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = archive.entries.iter().filter(|e| e.kind == EntryKind::File).map(|e| (e.name.clone(), e.data.clone())).collect();
    out.sort();
    out
}

fn names_and_sizes(files: &[(String, Vec<u8>)]) -> Vec<(&str, usize)> {
    files.iter().map(|(name, data)| (name.as_str(), data.len())).collect()
}

// ---------------------------------------------------------------- the CLIs, when installed

/// Whether a CLI is installed: it starts.
fn have(tool: &str) -> bool {
    Command::new(tool).arg("--help").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

fn skipped(tool: &str, what: &str) -> bool {
    if have(tool) { return false; }
    println!("skipped: {what} ({tool} is not installed)");
    true
}

/// A fresh folder under the target's temporary folder.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("member_bound-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, program: &str, args: &[&str]) -> Vec<u8> {
    let out = Command::new(program).args(args).current_dir(dir).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "{program} {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

/// Every file under `root`, as (`/`-separated relative name, bytes), sorted by name.
fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let name = path.strip_prefix(root).unwrap().components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/");
                out.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// What the 7-Zip CLI extracts from `archive`.
fn seven_zip_reads(dir: &Path, archive: &[u8]) -> Vec<(String, Vec<u8>)> {
    std::fs::write(dir.join("check.7z"), archive).unwrap();
    let _ = std::fs::remove_dir_all(dir.join("out"));
    run(dir, "7z", &["x", "-bd", "-y", "-oout", "check.7z"]);
    tree(&dir.join("out"))
}

/// What `gunzip` writes for `gz`.
fn gunzip_reads(dir: &Path, gz: &[u8]) -> Vec<u8> {
    std::fs::write(dir.join("check.gz"), gz).unwrap();
    run(dir, "gunzip", &["-c", "check.gz"])
}

// ---------------------------------------------------------------- inputs

/// The review's 7-Zip fixture: four members of 320 KiB of inert text (here each its own text), so each is over a
/// 256 KiB member limit while the folder (1.25 MiB) is under a 2 MiB total.
fn members() -> Vec<(String, Vec<u8>)> {
    (0..4).map(|i| {
        let mut data = format!("inert text line of member {i}\n").into_bytes().repeat(20_480);
        data.truncate(320 * KIB);
        (format!("s{i}.txt"), data)
    }).collect()
}

/// The 7-Zip CLI's solid folder of `files`, as the review wrote it (one LZMA2 folder, members under `tree/`).
fn seven_zip_cli(dir: &Path, files: &[(String, Vec<u8>)]) -> Vec<u8> {
    std::fs::create_dir_all(dir.join("tree")).unwrap();
    for (name, data) in files { std::fs::write(dir.join("tree").join(name), data).unwrap(); }
    run(dir, "7z", &["a", "-bd", "-m0=LZMA2", "-mx=1", "-md=1m", "-ms=on", "solid.7z", "tree"]);
    let listing = String::from_utf8_lossy(&run(dir, "7z", &["l", "-slt", "solid.7z"])).into_owned();
    assert!(listing.contains("Solid = +") && listing.contains("Blocks = 1"), "7z did not write one solid folder:\n{listing}");
    std::fs::read(dir.join("solid.7z")).unwrap()
}

/// A 7-Zip number.
fn number(value: u64) -> Vec<u8> {
    if value < 0x80 { return vec![value as u8]; }
    let used = (64 - value.leading_zeros() as usize).div_ceil(8);
    let mut out = vec![(0xff00u16 >> used) as u8];
    out.extend_from_slice(&value.to_le_bytes()[..used]);
    out
}

/// One solid 7-Zip folder of `files`, built here: LZMA2 in uncompressed chunks, a size and a CRC for every member, and
/// the names; nothing else.
fn solid_7z(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let content: Vec<u8> = files.iter().flat_map(|(_, data)| data.iter().copied()).collect();
    let mut packed = Vec::new();
    for (i, chunk) in content.chunks(64 * KIB).enumerate() {
        packed.push(if i == 0 { 1 } else { 2 }); // uncompressed, with a dictionary reset first
        packed.extend_from_slice(&((chunk.len() - 1) as u16).to_be_bytes());
        packed.extend_from_slice(chunk);
    }
    packed.push(0);

    let mut h = vec![0x01, 0x04]; // Header, MainStreamsInfo
    h.push(0x06); // PackInfo: at 0, one stream, its size
    h.extend(number(0));
    h.extend(number(1));
    h.push(0x09);
    h.extend(number(packed.len() as u64));
    h.push(0x00);
    h.extend([0x07, 0x0b]); // UnpackInfo, Folder: one, not external; one coder, LZMA2 with one property byte
    h.extend(number(1));
    h.push(0x00);
    h.extend([0x01, 0x21, 0x21, 0x01, 16]);
    h.push(0x0c); // CodersUnpackSize
    h.extend(number(content.len() as u64));
    h.push(0x00);
    h.extend([0x08, 0x0d]); // SubStreamsInfo: the member count, the sizes but the last, every CRC
    h.extend(number(files.len() as u64));
    h.push(0x09);
    for (_, data) in &files[..files.len() - 1] { h.extend(number(data.len() as u64)); }
    h.extend([0x0a, 0x01]);
    for (_, data) in files { h.extend_from_slice(&crc32(0, data).to_le_bytes()); }
    h.extend([0x00, 0x00]); // end of the substreams, of the streams
    h.push(0x05); // FilesInfo: the names, in UTF-16
    h.extend(number(files.len() as u64));
    let names: Vec<u8> = std::iter::once(0u8)
        .chain(files.iter().flat_map(|(name, _)| name.encode_utf16().chain([0]).flat_map(u16::to_le_bytes)))
        .collect();
    h.push(0x11);
    h.extend(number(names.len() as u64));
    h.extend(names);
    h.extend([0x00, 0x00]); // end of the files, of the header

    let mut start = Vec::new();
    start.extend_from_slice(&(packed.len() as u64).to_le_bytes());
    start.extend_from_slice(&(h.len() as u64).to_le_bytes());
    start.extend_from_slice(&crc32(0, &h).to_le_bytes());
    let mut out = b"7z\xbc\xaf\x27\x1c\x00\x04".to_vec();
    out.extend_from_slice(&crc32(0, &start).to_le_bytes());
    out.extend(start);
    out.extend(packed);
    out.extend(h);
    out
}

/// The review's gzip payload, 24 bytes a line: 65,536 lines are 1.5 MiB.
fn payload(lines: usize) -> Vec<u8> { b"inert gzip payload line\n".repeat(lines) }

/// One gzip member of `data` in stored DEFLATE blocks, built here.
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

/// `gzip -1 -n` of `data`.
fn gzip_cli(dir: &Path, data: &[u8]) -> Vec<u8> {
    std::fs::write(dir.join("payload.txt"), data).unwrap();
    run(dir, "gzip", &["-1", "-n", "-c", "payload.txt"])
}

/// A TAR member as GNU tar writes it (ustar), padded to its blocks.
fn ustar(name: &str, data: &[u8]) -> Vec<u8> {
    let octal = |n: usize, width: usize| format!("{:0w$o}\0", n, w = width - 1).into_bytes();
    let mut h = vec![0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(&octal(0o644, 8));
    h[108..116].copy_from_slice(&octal(1000, 8));
    h[116..124].copy_from_slice(&octal(1000, 8));
    h[124..136].copy_from_slice(&octal(data.len(), 12));
    h[136..148].copy_from_slice(&octal(0, 12));
    h[156] = b'0';
    h[257..265].copy_from_slice(b"ustar\x0000");
    h[265..269].copy_from_slice(b"user");
    h[148..156].fill(b' ');
    let sum: usize = h.iter().map(|&b| usize::from(b)).sum();
    h[148..156].copy_from_slice(&[format!("{sum:06o}").as_bytes(), b"\0 "].concat());
    let mut out = [h, data.to_vec()].concat();
    out.resize(out.len().div_ceil(512) * 512, 0);
    out
}

// ---------------------------------------------------------------- 7-Zip: a solid folder

/// The review's limits for its 7-Zip refusal: a member limit under each member, a total over the folder.
const SEVEN_MEMBER: usize = 256 * KIB;
const SEVEN_TOTAL: usize = 2 * MIB;

/// Refused before decoding: the most a refusal from the metadata may hold (the header and its decoder's tables).
const BEFORE_DECODING: usize = SEVEN_MEMBER / 4;

fn assert_refused_before_decoding(cases: &[(String, Result<Archive>, usize)], want: Error) {
    for (label, result, peak) in cases {
        assert!(matches!(result, Err(e) if *e == want), "{label}: {} (want Err({want:?}), never a partial success)", outcome(result));
        assert!(*peak < BEFORE_DECODING, "{label}: peak {peak} bytes; a refusal from the metadata decodes nothing");
    }
}

#[test]
fn seven_zip_cli_folder_over_the_member_limit_is_refused_before_decoding() {
    if skipped("7z", "the 7-Zip CLI's solid folder") { return; }
    let dir = scratch("7z-cli-over");
    let archive = seven_zip_cli(&dir, &members());
    let (member, member_peak) = measure("7z CLI folder, members over the member limit (256 KiB, total 2 MiB)", || extract_with_limits(&archive, limits(SEVEN_MEMBER, SEVEN_TOTAL)));
    let (total, total_peak) = measure("7z CLI folder, members together over the total (1 MiB, total 1 MiB)", || extract_with_limits(&archive, limits(MIB, MIB)));
    assert_refused_before_decoding(&[("member".into(), member, member_peak)], Error::Limit("member size"));
    assert_refused_before_decoding(&[("total".into(), total, total_peak)], Error::Limit("total extracted size"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seven_zip_cli_folder_within_the_limits_matches_the_7zip_cli() {
    if skipped("7z", "the 7-Zip CLI's solid folder") { return; }
    let dir = scratch("7z-cli-within");
    let archive = seven_zip_cli(&dir, &members());
    let (result, _) = measure("7z CLI folder within the limits (1 MiB, total 4 MiB)", || extract_with_limits(&archive, limits(MIB, 4 * MIB)));
    let got = result.unwrap_or_else(|e| panic!("within the limits: {e:?}"));
    assert_eq!(got.format, Format::SevenZip);
    let expected: Vec<_> = members().into_iter().map(|(name, data)| (format!("tree/{name}"), data)).collect();
    let got = files(&got);
    assert!(got == expected, "the crate read {:?}", names_and_sizes(&got));
    let cli = seven_zip_reads(&dir, &archive);
    assert!(got == cli, "the crate read {:?}, 7z {:?}", names_and_sizes(&got), names_and_sizes(&cli));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn built_solid_folder_over_the_limits_is_refused_before_decoding() {
    let archive = solid_7z(&members());
    let (member, member_peak) = measure("built folder, members over the member limit (256 KiB, total 2 MiB)", || extract_with_limits(&archive, limits(SEVEN_MEMBER, SEVEN_TOTAL)));
    let (total, total_peak) = measure("built folder, members together over the total (1 MiB, total 1 MiB)", || extract_with_limits(&archive, limits(MIB, MIB)));
    assert_refused_before_decoding(&[("member".into(), member, member_peak)], Error::Limit("member size"));
    assert_refused_before_decoding(&[("total".into(), total, total_peak)], Error::Limit("total extracted size"));
}

#[test]
fn built_solid_folder_within_the_limits_extracts_completely() {
    let archive = solid_7z(&members());
    let (result, _) = measure("built folder within the limits (1 MiB, total 4 MiB)", || extract_with_limits(&archive, limits(MIB, 4 * MIB)));
    let got = result.unwrap_or_else(|e| panic!("within the limits: {e:?}"));
    assert_eq!(got.format, Format::SevenZip);
    let got = files(&got);
    assert!(got == members(), "the crate read {:?}", names_and_sizes(&got));
    // exactly at the limits: each member at the member limit, the folder at the total
    let exact = limits(320 * KIB, 4 * 320 * KIB);
    assert_eq!(extract_with_limits(&archive, exact).map(|a| a.entries.len()), Ok(4));
    if skipped("7z", "the 7-Zip CLI's reading of the built folder") { return; }
    let dir = scratch("7z-built");
    let cli = seven_zip_reads(&dir, &archive);
    assert!(got == cli, "the crate read {:?}, 7z {:?}", names_and_sizes(&got), names_and_sizes(&cli));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------- gzip: one file

/// The review's limits for its gzip refusal.
const GZ_MEMBER: usize = 128 * KIB;
const GZ_TOTAL: usize = 4 * MIB;

/// Near the member limit: the output buffer at the limit, plus the decoder's window and chunk (64 KiB), plus a
/// growing buffer's old block while it is copied. A multiple of the member limit, never of the payload.
const NEAR_THE_MEMBER_LIMIT: usize = 3 * GZ_MEMBER;

#[test]
fn bare_gzip_over_the_member_limit_is_refused_near_the_member_limit() {
    let dir = scratch("gzip-over");
    let mut inputs = vec![("1.5 MiB in stored blocks", gzip(&payload(65_536))), ("3 MiB in stored blocks", gzip(&payload(131_072)))];
    if !skipped("gzip", "the gzip CLI's stream") {
        inputs.push(("1.5 MiB from gzip -1", gzip_cli(&dir, &payload(65_536))));
        inputs.push(("3 MiB from gzip -1", gzip_cli(&dir, &payload(131_072))));
    }
    let mut cases = Vec::new();
    for (what, gz) in &inputs {
        let (detected, peak) = measure(&format!("bare gzip {what}, over the member limit (128 KiB, total 4 MiB), detected"), || extract_with_limits(gz, limits(GZ_MEMBER, GZ_TOTAL)));
        cases.push((format!("{what}, detected"), detected, peak));
        let (named, peak) = measure(&format!("bare gzip {what}, over the member limit (128 KiB, total 4 MiB), named Gzip"), || extract_as(gz, Format::Gzip, limits(GZ_MEMBER, GZ_TOTAL)));
        cases.push((format!("{what}, named Gzip"), named, peak));
    }
    for (label, result, peak) in &cases {
        assert!(matches!(result, Err(Error::Limit("member size"))), "{label}: {} (want Err(Limit(\"member size\")), never a partial success)", outcome(result));
        assert!(*peak <= NEAR_THE_MEMBER_LIMIT, "{label}: peak {peak} bytes is not near the member limit of {GZ_MEMBER}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bare_gzip_within_the_limits_matches_gunzip() {
    let dir = scratch("gzip-within");
    let data = payload(65_536);
    let mut inputs = vec![("stored blocks", gzip(&data))];
    if !skipped("gzip", "the gzip CLI's stream") { inputs.push(("gzip -1", gzip_cli(&dir, &data))); }
    for (what, gz) in &inputs {
        let (result, _) = measure(&format!("bare gzip 1.5 MiB, {what}, within the limits (2 MiB, total 4 MiB)"), || extract_with_limits(gz, limits(2 * MIB, GZ_TOTAL)));
        let got = result.unwrap_or_else(|e| panic!("{what}, within the limits: {e:?}"));
        assert_eq!(got.format, Format::Gzip);
        assert_eq!(names_and_sizes(&files(&got)), [("data", data.len())], "{what}");
        assert!(got.entries[0].data == data, "{what}: the crate's bytes differ from the payload");
        // exactly at the member limit, it is still read
        assert_eq!(extract_as(gz, Format::Gzip, limits(data.len(), data.len())).map(|a| a.entries[0].data.len()), Ok(data.len()), "{what}");
        assert_eq!(extract_as(gz, Format::Gzip, limits(data.len() - 1, GZ_TOTAL)).err(), Some(Error::Limit("member size")), "{what}");
        if !skipped("gunzip", "gunzip's reading") {
            assert!(gunzip_reads(&dir, gz) == got.entries[0].data, "{what}: gunzip's bytes differ from the crate's");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_tar_inside_gzip_still_decodes_up_to_the_total() {
    // three members of 100 KiB: each within a 128 KiB member limit, the TAR (over 300 KiB) not
    let members: Vec<(String, Vec<u8>)> = ["a.txt", "b.txt", "c.txt"].iter()
        .map(|name| (name.to_string(), format!("inert text of {name}\n").into_bytes().repeat(8 * KIB)[..100 * KIB].to_vec()))
        .collect();
    let tar: Vec<u8> = members.iter().flat_map(|(name, data)| ustar(name, data)).chain([0; 1024]).collect();
    let gz = gzip(&tar);
    let (detected, peak) = measure("TAR in gzip, 300 KiB, members within the member limit (128 KiB, total 4 MiB)", || extract_with_limits(&gz, limits(GZ_MEMBER, GZ_TOTAL)));
    for (how, result) in [("detected", detected), ("named TarGzip", extract_as(&gz, Format::TarGzip, limits(GZ_MEMBER, GZ_TOTAL)))] {
        let got = result.unwrap_or_else(|e| panic!("{how}: {e:?}"));
        assert_eq!(got.format, Format::TarGzip, "{how}");
        assert!(files(&got) == members, "{how}: the crate read {:?}", names_and_sizes(&files(&got)));
    }
    assert!(peak < 4 * tar.len(), "peak {peak} bytes");
    // The one file gunzip writes is over the member limit; and the total still binds the TAR.
    assert_eq!(extract_as(&gz, Format::Gzip, limits(GZ_MEMBER, GZ_TOTAL)).err(), Some(Error::Limit("member size")));
    assert!(matches!(extract_with_limits(&gz, limits(GZ_MEMBER, 200 * KIB)), Err(Error::Limit(_))));
}
