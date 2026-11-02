//! Bounded archive extraction over byte slices, with no filesystem access, no `unsafe`,
//! and no dependencies outside Lazaret's pure Rust workspace.
//!
//! The initial support matrix is deliberately explicit:
//!
//! * TAR (ustar, PAX path/size records and GNU long names);
//! * GZIP as a single file, and TAR.GZ/TGZ when the inflated bytes are TAR;
//! * RAR4 and RAR5 members using the **store** method, with CRC-32 verification;
//! * 7-Zip using Copy, DEFLATE, LZMA1 or LZMA2, including encoded headers and
//!   multiple substreams, with packed and unpacked CRC-32 verification;
//! * Bzip2 (including concatenated streams), XZ (single-filter LZMA2 blocks), and
//!   LZMA-alone as single files, suitable for compressed pickle payloads.
//!
//! Compressed or encrypted RAR members, solid/multi-volume archives, links and special
//! files are refused with [`Error::Unsupported`]. Encrypted 7-Zip, coder chains and
//! external/additional streams are also refused. XZ filter chains and SHA-256 checks
//! are not implemented. Unsupported data is never returned as a partial success.
//!
//! Fail closed against real extractors: an archive is returned only in a shape that the
//! extractors people use (Python's `tarfile`, node-tar, GNU tar, bsdtar, 7-Zip, unrar)
//! read alike. Where they read it differently the error is [`Error::Ambiguous`]; where
//! only the *path* an entry lands at depends on the platform or file system (two names
//! one file system treats as one, a `\` that Windows takes as a separator), every entry
//! is still returned and the archive says so ([`Archive::collisions`],
//! [`Entry::windows_name`]), so a caller can report it.

#![forbid(unsafe_code)]

mod bzip2;
mod fold;
mod fold_table;
mod lzma;
mod path;
mod rar;
mod seven;
mod tar;
mod xz;

use lazaret_verify::inflate;

pub use fold::path_key;

/// The container selected by [`detect`], or actually returned by [`extract`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    Rar4,
    Rar5,
    Tar,
    Gzip,
    TarGzip,
    Bzip2,
    Xz,
    Lzma,
    SevenZip,
}

/// The only entry kinds the safe in-memory extractor produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

/// One fully extracted entry. Directory `data` is always empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The path as extractors on Linux and macOS write it: `/`-separated, relative, canonical
    /// (no `.` or empty segments). A `\` is part of a name there, as it is for those extractors.
    pub name: String,
    pub kind: EntryKind,
    pub data: Vec<u8>,
    /// The path an extractor that takes `\` as a separator (on Windows) writes the entry to, when
    /// that differs from `name`; it is checked as strictly as `name`.
    pub windows_name: Option<String>,
    /// The entry's index in [`Archive::collisions`], when another entry may be written to the same
    /// path on some extractor or file system.
    pub collision: Option<usize>,
}

impl Entry {
    pub fn is_file(&self) -> bool { self.kind == EntryKind::File }
    pub fn len(&self) -> usize { self.data.len() }
    pub fn is_empty(&self) -> bool { self.data.is_empty() }
}

/// Entries that some extractor or file system writes to one path, or where a file stands in place of a
/// directory another entry needs. Which copy ends up on disk depends on the extractor (last or first wins)
/// and the file system, so each entry's bytes are returned, and any name in the group may end up holding
/// any of their bytes. A caller should report the group and scan every member under every name in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collision {
    /// Indices into [`Archive::entries`], in archive order.
    pub entries: Vec<usize>,
    /// Two entries have the same name.
    pub duplicate: bool,
    /// Two names differ only in letter case, Unicode normalization, default-ignorable characters,
    /// or `\` against `/` (see [`path_key`]).
    pub alias: bool,
    /// A file stands where another entry needs a directory (the same path, or an ancestor).
    pub file_directory: bool,
}

/// A complete extraction. No entries are returned when parsing fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archive {
    pub format: Format,
    pub entries: Vec<Entry>,
    /// Groups of entries whose paths collide; empty for most archives.
    pub collisions: Vec<Collision>,
}

impl Archive {
    /// Whether the path some entry lands at depends on the extractor, platform or file system: a
    /// collision, or a name Windows extractors split at `\`. Every entry's bytes are returned either way;
    /// the caller reports this.
    pub fn is_path_ambiguous(&self) -> bool {
        !self.collisions.is_empty() || self.entries.iter().any(|e| e.windows_name.is_some())
    }
}

/// Resource limits applied before allocation or decompression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_entries: usize,
    pub max_member_size: u64,
    pub max_total_size: u64,
    pub max_name_size: usize,
    pub max_metadata_size: u64,
}

impl Limits {
    pub const fn new(max_member_size: u64, max_total_size: u64) -> Limits {
        Limits {
            max_entries: 250_000,
            max_member_size,
            max_total_size,
            max_name_size: 4096,
            max_metadata_size: 1024 * 1024,
        }
    }
}

impl Default for Limits {
    fn default() -> Limits { Limits::new(128 * 1024 * 1024, 500 * 1024 * 1024) }
}

/// Why an archive was refused. Errors contain no extracted entry data.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    UnknownFormat,
    Unsupported(&'static str),
    Corrupt(&'static str),
    Truncated,
    Checksum(&'static str),
    Limit(&'static str),
    InvalidPath(String),
    DuplicateEntry(String),
    /// Real extractors read this archive differently (different members, names or bytes), so no one
    /// reading of it can be returned. An archive built that way is worth reporting in its own right.
    Ambiguous(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownFormat => f.write_str("unknown archive format"),
            Error::Unsupported(what) => write!(f, "unsupported archive feature: {what}"),
            Error::Corrupt(what) => write!(f, "corrupt archive: {what}"),
            Error::Truncated => f.write_str("archive ends before its structure is complete"),
            Error::Checksum(what) => write!(f, "archive checksum failed: {what}"),
            Error::Limit(what) => write!(f, "archive resource limit exceeded: {what}"),
            Error::InvalidPath(what) => write!(f, "unsafe archive member path: {what}"),
            Error::DuplicateEntry(name) => write!(f, "archive contains the member twice: {name}"),
            Error::Ambiguous(what) => write!(f, "extractors read this archive differently: {what}"),
        }
    }
}

impl std::error::Error for Error {}

pub(crate) struct Builder {
    limits: Limits,
    entries: Vec<Entry>,
    total: u64,
}

impl Builder {
    pub(crate) fn new(limits: Limits) -> Builder {
        Builder { limits, entries: Vec::new(), total: 0 }
    }

    pub(crate) fn remaining(&self) -> u64 { self.limits.max_total_size - self.total }

    pub(crate) fn reserve_metadata(&self, size: u64) -> Result<()> {
        if size > self.limits.max_metadata_size { Err(Error::Limit("archive metadata")) } else { Ok(()) }
    }

    pub(crate) fn check_member_size(&self, size: u64) -> Result<usize> {
        if size > self.limits.max_member_size { return Err(Error::Limit("member size")); }
        if self.total.checked_add(size).is_none_or(|n| n > self.limits.max_total_size) {
            return Err(Error::Limit("total extracted size"));
        }
        usize::try_from(size).map_err(|_| Error::Limit("member does not fit this platform"))
    }

    /// The most a solid block of members of these sizes may decode to (R1): what its members declare, each within the
    /// member limit and all of them within what is left of the total. Checked before anything is decoded.
    pub(crate) fn block_budget(&self, sizes: &[u64]) -> Result<u64> {
        let mut sum = 0u64;
        for &size in sizes {
            self.check_member_size(size)?;
            sum = sum.checked_add(size).filter(|&n| n <= self.remaining()).ok_or(Error::Limit("total extracted size"))?;
        }
        Ok(sum)
    }

    /// Add one entry under its name as the format stores it (`\` kept: the formats that use it as a
    /// separator convert it before calling this).
    pub(crate) fn add(&mut self, raw_name: &str, kind: EntryKind, data: &[u8]) -> Result<()> {
        if self.entries.len() >= self.limits.max_entries { return Err(Error::Limit("entry count")); }
        if raw_name.len() > self.limits.max_name_size { return Err(Error::Limit("member name length")); }
        if kind == EntryKind::File && (raw_name.ends_with(['/', '\\']) || raw_name.rsplit(['/', '\\']).next() == Some(".")) {
            // Python reads such a file as a file; node-tar, bsdtar, GNU tar and unrar make it a directory
            // (and some then read the file's data as the next headers).
            return Err(Error::Ambiguous("a file whose name ends in a path separator"));
        }
        let name = path::canonical(raw_name)?;
        let windows_name = if raw_name.contains('\\') {
            Some(path::canonical(&raw_name.replace('\\', "/")).map_err(|error| match error {
                Error::InvalidPath(why) => Error::InvalidPath(format!("{why} (with '\\' as a separator, as on Windows; the name is {raw_name})")),
                other => other,
            })?)
        } else {
            None
        };
        let size = if kind == EntryKind::File { data.len() as u64 } else { 0 };
        self.check_member_size(size)?;
        self.total += size;
        self.entries.push(Entry { name, kind, data: data.to_vec(), windows_name, collision: None });
        Ok(())
    }

    pub(crate) fn finish(mut self, format: Format) -> Archive {
        let collisions = collisions(&mut self.entries);
        Archive { format, entries: self.entries, collisions }
    }
}

fn find(parent: &mut [usize], mut i: usize) -> usize {
    while parent[i] != i {
        parent[i] = parent[parent[i]];
        i = parent[i];
    }
    i
}

fn union(parent: &mut [usize], a: usize, b: usize) {
    let (a, b) = (find(parent, a), find(parent, b));
    if a != b { parent[a.max(b)] = a.min(b); }
}

/// Group the entries whose paths collide (M5): the same [`path_key`] with a file among them, or a file
/// whose key is an ancestor of another entry's. Work is bounded by sorting the keys once.
fn collisions(entries: &mut [Entry]) -> Vec<Collision> {
    const DUPLICATE: u8 = 1;
    const ALIAS: u8 = 2;
    const FILE_DIRECTORY: u8 = 4;
    let n = entries.len();
    let keys: Vec<String> = entries.iter().map(|e| path_key(e.windows_name.as_deref().unwrap_or(&e.name))).collect();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&a, &b| keys[a].cmp(&keys[b]).then(a.cmp(&b)));
    let mut parent: Vec<usize> = (0..n).collect();
    let mut flags = vec![0u8; n];
    let mut file_keys: Vec<usize> = Vec::new(); // one file per distinct key, as an index into `entries`

    let mut start = 0;
    while start < n {
        let mut end = start + 1;
        while end < n && keys[order[end]] == keys[order[start]] { end += 1; }
        let run = &order[start..end];
        if let Some(&file) = run.iter().find(|&&i| entries[i].kind == EntryKind::File) {
            file_keys.push(file);
            if run.len() > 1 {
                let mut names: Vec<&str> = run.iter().map(|&i| entries[i].name.as_str()).collect();
                names.sort_unstable();
                names.dedup();
                let mut f = 0;
                if names.len() < run.len() { f |= DUPLICATE; }
                if names.len() > 1 { f |= ALIAS; }
                if run.iter().any(|&i| entries[i].kind == EntryKind::Directory) { f |= FILE_DIRECTORY; }
                for &i in run {
                    flags[i] |= f;
                    union(&mut parent, file, i);
                }
            }
        }
        start = end;
    }
    // Everything below a file's key: the keys from `key/` up to (not including) `key0` ('0' follows '/').
    for &file in &file_keys {
        let below = format!("{}/", keys[file]);
        let after = format!("{}0", keys[file]);
        let lo = order.partition_point(|&i| keys[i].as_str() < below.as_str());
        let hi = order.partition_point(|&i| keys[i].as_str() < after.as_str());
        if lo < hi { flags[file] |= FILE_DIRECTORY; }
        for &i in &order[lo..hi] {
            flags[i] |= FILE_DIRECTORY;
            union(&mut parent, file, i);
        }
    }

    let mut groups: Vec<Collision> = Vec::new();
    let mut group_of_root = vec![usize::MAX; n];
    let mut size = vec![0usize; n];
    for i in 0..n {
        let root = find(&mut parent, i);
        size[root] += 1;
    }
    for i in 0..n {
        let root = find(&mut parent, i);
        if size[root] < 2 { continue; }
        if group_of_root[root] == usize::MAX {
            group_of_root[root] = groups.len();
            groups.push(Collision { entries: Vec::new(), duplicate: false, alias: false, file_directory: false });
        }
        let g = group_of_root[root];
        let group = &mut groups[g];
        group.entries.push(i);
        group.duplicate |= flags[i] & DUPLICATE != 0;
        group.alias |= flags[i] & ALIAS != 0;
        group.file_directory |= flags[i] & FILE_DIRECTORY != 0;
        entries[i].collision = Some(g);
    }
    groups
}

fn magic(data: &[u8]) -> Option<Format> {
    if data.starts_with(b"Rar!\x1a\x07\x00") { return Some(Format::Rar4); }
    if data.starts_with(b"Rar!\x1a\x07\x01\x00") { return Some(Format::Rar5); }
    if data.starts_with(b"\x1f\x8b") { return Some(Format::Gzip); }
    if data.starts_with(b"BZh") { return Some(Format::Bzip2); }
    if data.starts_with(b"\xfd7zXZ\x00") { return Some(Format::Xz); }
    if data.starts_with(b"7z\xbc\xaf\x27\x1c") { return Some(Format::SevenZip); }
    None
}

/// Identify a supported container, or a known container whose codec is not implemented yet.
///
/// Detection reads magic numbers, then TAR's header checksum, then LZMA-alone's properties. A caller that
/// knows which format the bytes should be (from a file name, as the extractor that will open them does)
/// should say so with [`extract_as`]: one byte string can be valid in two formats.
pub fn detect(data: &[u8]) -> Result<Format> {
    if let Some(format) = magic(data) { return Ok(format); }
    if tar::looks_like(data) { return Ok(Format::Tar); }
    // GNU tar, bsdtar and node-tar skip a block that fails its checksum and read on from the next.
    if tar::has_later_header(data) {
        return Err(Error::Ambiguous("data whose first block is not a TAR header but a later block is"));
    }
    // LZMA-alone has no magic; its properties and range-coder prefix are a
    // conservative heuristic, followed by strict decoding and size checks.
    if data.len() >= 14 && data[0] < 9 * 5 * 5 && data[13] == 0 { return Ok(Format::Lzma); }
    Err(Error::UnknownFormat)
}

/// Extract with [`Limits::default`].
pub fn extract(data: &[u8]) -> Result<Archive> { extract_with_limits(data, Limits::default()) }

/// Extract an entire archive atomically: either every supported entry is returned, or none is.
pub fn extract_with_limits(data: &[u8], limits: Limits) -> Result<Archive> {
    match detect(data)? {
        Format::Gzip | Format::TarGzip => extract_gzip(data, limits, None),
        format => extract_as(data, format, limits),
    }
}

/// Extract bytes as the named format, the one the caller's extractor would open them as: a `.tar` with a
/// TAR reader, a `.gz` with gunzip (one file, whatever it holds), a `.tar.gz` with a TAR reader after
/// gunzip, a `.lzma` without guessing. Bytes that are not that format are refused.
pub fn extract_as(data: &[u8], format: Format, limits: Limits) -> Result<Archive> {
    let expect = |want: Format| if magic(data) == Some(want) { Ok(()) } else { Err(Error::Corrupt("not the named archive format")) };
    match format {
        Format::Rar4 => { expect(Format::Rar4)?; rar::extract4(data, limits) }
        Format::Rar5 => { expect(Format::Rar5)?; rar::extract5(data, limits) }
        Format::Tar => tar::extract(data, limits, Format::Tar),
        Format::Gzip | Format::TarGzip => { expect(Format::Gzip)?; extract_gzip(data, limits, Some(format)) }
        Format::Bzip2 => { expect(Format::Bzip2)?; extract_single(data, limits, Format::Bzip2) }
        Format::Xz => { expect(Format::Xz)?; extract_single(data, limits, Format::Xz) }
        Format::Lzma => extract_single(data, limits, Format::Lzma),
        Format::SevenZip => { expect(Format::SevenZip)?; seven::extract(data, limits) }
    }
}

fn extract_single(data: &[u8], limits: Limits, format: Format) -> Result<Archive> {
    let maximum = usize::try_from(limits.max_member_size.min(limits.max_total_size)).unwrap_or(usize::MAX);
    let raw = match format {
        Format::Bzip2 => bzip2::decode(data, maximum)?,
        Format::Xz => xz::decode(data, maximum)?,
        Format::Lzma => {
            if data.len() < 14 { return Err(Error::Truncated); }
            let expected = u64::from_le_bytes([data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12]]);
            if expected == u64::MAX {
                lzma::decode_lzma_unknown(&data[13..], &data[..5], maximum)?
            } else {
                let expected = usize::try_from(expected).map_err(|_| Error::Limit("LZMA output size"))?;
                if expected > maximum { return Err(Error::Limit("LZMA output size")); }
                lzma::decode_lzma(&data[13..], &data[..5], expected)?
            }
        }
        _ => return Err(Error::Corrupt("not a single-file compressed stream")),
    };
    let mut out = Builder::new(limits);
    out.add("data", EntryKind::File, &raw)?;
    Ok(out.finish(format))
}

fn inflate_error(error: inflate::Error) -> Error {
    match error {
        inflate::Error::Corrupt(_) => Error::Corrupt("gzip stream"),
        inflate::Error::Truncated => Error::Truncated,
        inflate::Error::Checksum(_) => Error::Checksum("gzip"),
        inflate::Error::OutputLimit { .. } | inflate::Error::RatioLimit { .. } => Error::Limit("gzip output"),
        inflate::Error::Unsupported(_) => Error::Unsupported("gzip feature"),
        _ => Error::Unsupported("unknown inflate error"),
    }
}

/// The first TAR block of a gzip stream's output, or less if the stream is shorter or fails before it: enough to tell
/// a TAR from one file before the rest is decoded.
fn gzip_head(data: &[u8], max_output: u64) -> Vec<u8> {
    let mut inflater = inflate::Inflater::new(inflate::Format::Gzip, inflate::Limits::new(max_output));
    let mut head = vec![0u8; 512];
    let (mut pos, mut got) = (0, 0);
    while got < head.len() {
        let Ok(progress) = inflater.inflate(&data[pos..], &mut head[got..]) else { break };
        pos += progress.consumed;
        got += progress.produced;
        if progress.status != inflate::Status::NeedOutput || progress.consumed + progress.produced == 0 { break; }
    }
    head.truncate(got);
    head
}

/// `want`: `Some(Gzip)` reads one file as gunzip does, `Some(TarGzip)` a TAR inside; `None` decides from
/// the inflated bytes, and refuses bytes a TAR reader would find members in when they are not plainly TAR.
fn extract_gzip(data: &[u8], limits: Limits, want: Option<Format>) -> Result<Archive> {
    // R1: one file decodes no further than the member limit; only a TAR inside may take the total. Undeclared, the
    // stream is taken for a TAR when its first block is a TAR header. Any other stream is one file, unless it fits the
    // member limit and its bytes then read as a TAR after all (an empty TAR of zeros), as before.
    let tar_inside = match want {
        Some(Format::TarGzip) => true,
        Some(_) => false,
        None => tar::looks_like(&gzip_head(data, limits.max_total_size)),
    };
    let one_file = !tar_inside && limits.max_member_size <= limits.max_total_size;
    let cap = if one_file { limits.max_member_size } else { limits.max_total_size };
    let raw = inflate::decode_all(inflate::Format::Gzip, data, inflate::Limits::new(cap)).map_err(|error| match error {
        inflate::Error::OutputLimit { .. } if one_file => Error::Limit("member size"),
        error => inflate_error(error),
    })?;
    let tar = match want {
        Some(Format::TarGzip) => true,
        Some(_) => false,
        None => {
            if !tar::looks_like(&raw) && tar::has_later_header(&raw) {
                return Err(Error::Ambiguous("gzip data whose first block is not a TAR header but a later block is"));
            }
            tar::looks_like(&raw)
        }
    };
    if tar { return tar::extract(&raw, limits, Format::TarGzip); }
    let name = gzip_name(data).unwrap_or_else(|| "data".into());
    let mut out = Builder::new(limits);
    out.add(&name, EntryKind::File, &raw)?;
    Ok(out.finish(Format::Gzip))
}

/// Best-effort FNAME recovery; the strict gzip framing and checksum checks remain in pratique.
fn gzip_name(data: &[u8]) -> Option<String> {
    if data.len() < 10 { return None; }
    let flags = data[3];
    let mut pos = 10usize;
    if flags & 4 != 0 {
        let xlen = usize::from(u16::from_le_bytes([*data.get(pos)?, *data.get(pos + 1)?]));
        pos = pos.checked_add(2 + xlen)?;
    }
    if flags & 8 != 0 {
        let rest = data.get(pos..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&rest[..end]).ok()?;
        if !name.is_empty() && !name.contains(['/', '\\']) { return path::canonical(name).ok(); }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_formats() {
        assert_eq!(detect(b"Rar!\x1a\x07\x00"), Ok(Format::Rar4));
        assert_eq!(detect(b"Rar!\x1a\x07\x01\x00"), Ok(Format::Rar5));
        assert_eq!(detect(b"\x1f\x8brest"), Ok(Format::Gzip));
        assert_eq!(detect(b"BZh91AY"), Ok(Format::Bzip2));
        assert_eq!(detect(b"\xfd7zXZ\x00"), Ok(Format::Xz));
        assert_eq!(detect(b"7z\xbc\xaf\x27\x1c"), Ok(Format::SevenZip));
        assert_eq!(detect(b"not an archive"), Err(Error::UnknownFormat));
    }

    #[test]
    fn malformed_compressed_streams_fail_closed() {
        assert!(extract(b"BZh91AY").is_err());
        assert!(extract(b"\xfd7zXZ\x00").is_err());
    }

    #[test]
    fn gzip_single_file_uses_stored_name() {
        // gzip of "hello\n", with FNAME=hello.txt, generated independently by Python's gzip module.
        let data = [31,139,8,8,0,0,0,0,2,255,104,101,108,108,111,46,116,120,116,0,203,72,205,201,201,231,2,0,32,48,58,54,6,0,0,0];
        let got = extract(&data).unwrap();
        assert_eq!(got.format, Format::Gzip);
        assert_eq!(got.entries[0].name, "hello.txt");
        assert_eq!(got.entries[0].data, b"hello\n");
        assert!(!got.is_path_ambiguous());
    }

    fn file(name: &str) -> (&str, EntryKind) { (name, EntryKind::File) }

    fn build(items: &[(&str, EntryKind)]) -> Archive {
        let mut b = Builder::new(Limits::default());
        for (i, &(name, kind)) in items.iter().enumerate() {
            let data = if kind == EntryKind::File { vec![i as u8] } else { Vec::new() };
            b.add(name, kind, &data).unwrap();
        }
        b.finish(Format::Tar)
    }

    #[test]
    fn colliding_entries_are_all_returned_and_grouped() {
        let a = build(&[file("Makefile"), file("makefile"), file("other.txt")]);
        assert_eq!(a.entries.len(), 3);
        assert_eq!(a.collisions, [Collision { entries: vec![0, 1], duplicate: false, alias: true, file_directory: false }]);
        assert_eq!(a.entries[0].collision, Some(0));
        assert_eq!(a.entries[2].collision, None);

        let a = build(&[file("a.txt"), file("a.txt")]);
        assert_eq!(a.collisions, [Collision { entries: vec![0, 1], duplicate: true, alias: false, file_directory: false }]);

        // a file where a directory is needed, in either order, with an unrelated entry in between
        for items in [[file("a"), file("b"), file("a/x/y.txt")], [file("a/x/y.txt"), file("b"), file("a")]] {
            let a = build(&items);
            assert_eq!(a.collisions.len(), 1);
            assert!(a.collisions[0].file_directory && !a.collisions[0].alias);
            assert_eq!(a.entries[1].collision, None);
        }
        // directories alone never collide; a file named like a directory does
        let a = build(&[("d", EntryKind::Directory), ("D", EntryKind::Directory), ("d/x", EntryKind::File)]);
        assert!(a.collisions.is_empty());
        let a = build(&[("d", EntryKind::Directory), file("D")]);
        assert!(a.collisions[0].alias && a.collisions[0].file_directory);
    }

    #[test]
    fn backslash_names_are_kept_and_their_windows_reading_checked() {
        let a = build(&[file("a\\b.txt"), file("a/b.txt")]);
        assert_eq!(a.entries[0].name, "a\\b.txt");
        assert_eq!(a.entries[0].windows_name.as_deref(), Some("a/b.txt"));
        assert_eq!(a.entries[1].windows_name, None);
        assert!(a.collisions[0].alias && a.is_path_ambiguous());
        let mut b = Builder::new(Limits::default());
        for bad in ["..\\x", "a\\..\\..\\x", "\\x", "a\\b\\"] {
            assert!(b.add(bad, EntryKind::File, b"").is_err(), "{bad}");
        }
    }

    /// One gzip member of `data` in stored DEFLATE blocks.
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
        out.extend_from_slice(&inflate::crc32(0, data).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out
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
        h[148..156].fill(b' ');
        let sum: usize = h.iter().map(|&b| usize::from(b)).sum();
        h[148..156].copy_from_slice(&[format!("{sum:06o}").as_bytes(), b"\0 "].concat());
        let mut out = [h, data.to_vec()].concat();
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }

    const KIB: u64 = 1024;

    #[test]
    fn r1_a_solid_block_is_gated_on_its_members_before_decoding() {
        let b = Builder::new(Limits::new(100, 250));
        assert_eq!(b.block_budget(&[]), Ok(0));
        assert_eq!(b.block_budget(&[100, 100]), Ok(200));
        assert_eq!(b.block_budget(&[100, 101]), Err(Error::Limit("member size")));
        assert_eq!(b.block_budget(&[u64::MAX, 1]), Err(Error::Limit("member size")));
        assert_eq!(b.block_budget(&[100, 100, 100]), Err(Error::Limit("total extracted size")));
        // what earlier entries took counts against the total
        let mut b = Builder::new(Limits::new(100, 250));
        b.add("a", EntryKind::File, &[0; 100]).unwrap();
        assert_eq!(b.block_budget(&[100, 50]), Ok(150));
        assert_eq!(b.block_budget(&[100, 51]), Err(Error::Limit("total extracted size")));
        // a member limit over the total: the total binds
        let b = Builder::new(Limits::new(1000, 250));
        assert_eq!(b.block_budget(&[200, 51]), Err(Error::Limit("total extracted size")));
    }

    #[test]
    fn r1_one_gzip_file_decodes_no_further_than_the_member_limit() {
        let data = vec![b'x'; 64 * 1024];
        let gz = gzip(&data);
        for limits in [Limits::new(16 * KIB, 1024 * KIB), Limits::new(16 * KIB, 32 * KIB), Limits::new(32 * KIB, 32 * KIB)] {
            assert_eq!(extract_with_limits(&gz, limits), Err(Error::Limit("member size")), "{limits:?}");
            assert_eq!(extract_as(&gz, Format::Gzip, limits), Err(Error::Limit("member size")), "{limits:?}");
        }
        // a member limit over the total: the total binds, with the error it had
        assert_eq!(extract_as(&gz, Format::Gzip, Limits::new(1024 * KIB, 32 * KIB)), Err(Error::Limit("gzip output")));
        // at the member limit it is read, one byte under it is not
        let got = extract_with_limits(&gz, Limits::new(64 * KIB, 64 * KIB)).unwrap();
        assert_eq!((got.format, got.entries.len(), got.entries[0].data == data), (Format::Gzip, 1, true));
        assert_eq!(extract_as(&gz, Format::Gzip, Limits::new(64 * KIB - 1, 1024 * KIB)), Err(Error::Limit("member size")));
        // the head that decides is the first block, also across stored blocks and gzip members
        assert_eq!(gzip_head(&gz, u64::MAX), vec![b'x'; 512]);
        assert_eq!(gzip_head(&[gzip(b"ab"), gzip(&[b'c'; 600])].concat(), u64::MAX), [&b"ab"[..], &[b'c'; 510][..]].concat());
        assert_eq!(gzip_head(&gzip(b"short"), u64::MAX), b"short");
        assert_eq!(gzip_head(b"\x1f\x8bnot gzip", u64::MAX), b"");
    }

    #[test]
    fn r1_a_tar_inside_gzip_keeps_the_total_limit() {
        // three members of 24 KiB: each within a 32 KiB member limit, the TAR (over 72 KiB) not
        let tar = [ustar("a.txt", &[b'a'; 24 * 1024]), ustar("b.txt", &[b'b'; 24 * 1024]), ustar("c.txt", &[b'c'; 24 * 1024]), vec![0; 1024]].concat();
        let gz = gzip(&tar);
        let limits = Limits::new(32 * KIB, 1024 * KIB);
        for got in [extract_with_limits(&gz, limits), extract_as(&gz, Format::TarGzip, limits)] {
            let got = got.unwrap();
            assert_eq!((got.format, got.entries.len()), (Format::TarGzip, 3));
            assert_eq!(got.entries[2].data, vec![b'c'; 24 * 1024]);
        }
        // as the one file gunzip writes, it is over the member limit; and the total still binds the TAR
        assert_eq!(extract_as(&gz, Format::Gzip, limits), Err(Error::Limit("member size")));
        assert_eq!(extract_with_limits(&gz, Limits::new(32 * KIB, 64 * KIB)), Err(Error::Limit("gzip output")));
    }

    #[test]
    fn r1_gzip_that_does_not_start_with_a_tar_header_is_one_file() {
        // all zeros: an empty TAR when it fits the member limit, as before; past it, one file over the limit
        let zeros = gzip(&[0u8; 8 * 1024]);
        let got = extract_with_limits(&zeros, Limits::new(8 * KIB, 1024 * KIB)).unwrap();
        assert_eq!((got.format, got.entries.len()), (Format::TarGzip, 0));
        assert_eq!(extract_with_limits(&zeros, Limits::new(4 * KIB, 1024 * KIB)), Err(Error::Limit("member size")));
        // a TAR header after a first block that is not one: Ambiguous when it fits the member limit, as before
        let late = gzip(&[vec![b'x'; 512], ustar("a.txt", b"inert\n"), vec![0; 1024]].concat());
        assert!(matches!(extract_with_limits(&late, Limits::new(1024 * KIB, 1024 * KIB)), Err(Error::Ambiguous(_))));
        assert_eq!(extract_with_limits(&late, Limits::new(KIB, 1024 * KIB)), Err(Error::Limit("member size")));
        // a corrupt stream is still corrupt
        let mut bad = gzip(&[b'x'; 4096]);
        bad[10] = 0x07; // reserved block type
        assert_eq!(extract_with_limits(&bad, Limits::new(KIB, 1024 * KIB)), Err(Error::Corrupt("gzip stream")));
    }
}
