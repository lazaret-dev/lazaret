//! A zip archive read from its bytes (FP-MODEL-FILES): its members as every common unpacker finds them (`entries`:
//! the union of their views, and why they may not agree, `Listing`), and a member's data, stored or deflated
//! (pratique's inflate, bounded). Nothing else is decompressed: a member in another method, or encrypted, cannot be
//! read.
//!
//! The bytes are the whole file, or pieces of it (`Bytes`): a model file read by range, whatever its size, is read for
//! its end records, its central directory and the members the reader reads (its pickles; an .npy's header), never its
//! tensor storages. What a reading needs and was not given is noted (`Bytes::needs`): the host reads those ranges and
//! asks again, and the reading is the same as of the whole file.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};

use lazaret_verify::inflate::{decode_all, Format, Limits};

/// One member of the archive, as a view of it finds it (`Listing`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: Vec<u8>,
    pub flags: u16,
    pub method: u16,
    pub csize: u64,
    pub size: u64,
    /// where its local header is
    pub local: u64,
    /// its extra field's length in the central directory (a local header's is most often the same, or a little more)
    pub xlen: u16,
    /// the central directory's "version made by": its high byte the system that made it (3: Unix); 0 for a member no
    /// directory lists
    pub made_by: u16,
    /// the central directory's external file attributes (a Unix system's mode in the high 16 bits); 0 for a member no
    /// directory lists
    pub external: u32,
    /// whether a central directory lists it as it is (false: a member a local header alone shows, a streaming
    /// unpacker's; or a local header's own name, method or sizes where they are not its directory entry's)
    pub listed: bool,
}

impl Entry {
    /// Its Unix mode: the external attributes' high 16 bits, when they are not 0, whatever system made it (Info-ZIP
    /// applies them for Unix, VMS, Acorn, Atari, AtheOS, BeOS, QDOS and Tandem, and for FAT when they agree with its
    /// DOS bits: the external re-review of Oct 27 extracted a creator 16 member as 0100755).
    pub fn unix_mode(&self) -> Option<u32> {
        let m = self.external >> 16;
        (m != 0).then_some(m)
    }

    /// Whether its Unix mode lets anyone run it: a regular file (or one of no type) with an execute bit.
    pub fn executable(&self) -> bool {
        self.unix_mode().is_some_and(|m| matches!(m & 0o170000, 0 | 0o100000) && m & 0o111 != 0)
    }

    /// The kind of file its Unix mode makes it, when not a regular file (or one of no type bits): "symlink",
    /// "directory", "character device", "block device", "FIFO", "socket", or "file of type 0oNNNNNN".
    pub fn special_kind(&self) -> Option<String> {
        let m = self.unix_mode()? & 0o170000;
        match m {
            0 | 0o100000 => None,
            0o120000 => Some("symlink".into()),
            0o040000 => Some("directory".into()),
            0o020000 => Some("character device".into()),
            0o060000 => Some("block device".into()),
            0o010000 => Some("FIFO".into()),
            0o140000 => Some("socket".into()),
            t => Some(format!("file of type {t:o}")),
        }
    }
}

/// Why bytes could not be had: not given yet (noted as needed), or why the archive cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Miss {
    Need,
    Bad(String),
}

impl From<String> for Miss {
    fn from(s: String) -> Miss {
        Miss::Bad(s)
    }
}

impl From<&str> for Miss {
    fn from(s: &str) -> Miss {
        Miss::Bad(s.to_string())
    }
}

/// The bytes past a stored entry's local header the reader asks for with the header, beyond the central directory's
/// name and extra field: a local extra field may be longer (PyTorch's writer pads the data to 64 bytes there).
const LOCAL_SLACK: u64 = 1024;
/// An .npy member's stored bytes read for its header: enough for the first 64 KiB, stored or deflated.
pub const PREFIX_RAW: u64 = 1 << 17;

/// A file's bytes as a reading has them: the whole file, or pieces of it.
pub struct Bytes<'d> {
    pub size: u64,
    /// (offset, bytes), sorted, none overlapping or touching another
    pieces: Vec<(u64, Cow<'d, [u8]>)>,
    given: u64,
    /// the ranges a reading asked for that are not here
    need: RefCell<Vec<(u64, u64)>>,
    /// the bytes asked for that are not given, as disjoint ranges (start -> end), and how many: what a reading is
    /// charged, each byte once however many requests name it
    asked: RefCell<BTreeMap<u64, u64>>,
    needed: RefCell<u64>,
    /// the most bytes, given and asked for, a reading reads of the file
    cap: u64,
}

impl<'d> Bytes<'d> {
    /// The whole file.
    pub fn whole(data: &'d [u8]) -> Bytes<'d> {
        Bytes { size: data.len() as u64, pieces: vec![(0, Cow::Borrowed(data))], given: data.len() as u64,
                need: RefCell::new(Vec::new()), asked: RefCell::new(BTreeMap::new()), needed: RefCell::new(0),
                cap: u64::MAX }
    }

    /// Pieces of a file of `size` bytes ((offset, bytes), in any order, overlapping or not; a piece past the end is cut
    /// there), of which a reading reads at most `cap` bytes in all.
    pub fn pieces(size: u64, mut given: Vec<(u64, &'d [u8])>, cap: u64) -> Bytes<'d> {
        given.retain(|(off, b)| *off < size && !b.is_empty());
        given.sort_by_key(|&(off, b)| (off, std::cmp::Reverse(b.len())));
        let mut pieces: Vec<(u64, Cow<'d, [u8]>)> = Vec::new();
        for (off, b) in given {
            let b = &b[..b.len().min((size - off).min(usize::MAX as u64) as usize)];
            let end = off + b.len() as u64;
            match pieces.last_mut() {
                Some((lo, have)) if off <= *lo + have.len() as u64 => {
                    let have_end = *lo + have.len() as u64;
                    if end > have_end {
                        // (grown in place: a many-member .npz read as it streamed is one piece per member, each
                        // touching the last, and a copy of all of it per member was quadratic)
                        have.to_mut().extend_from_slice(&b[(have_end - off) as usize..]);
                    }
                }
                _ => pieces.push((off, Cow::Borrowed(b))),
            }
        }
        let total = pieces.iter().map(|(_, b)| b.len() as u64).sum();
        Bytes { size, pieces, given: total, need: RefCell::new(Vec::new()), asked: RefCell::new(BTreeMap::new()),
                needed: RefCell::new(0), cap }
    }

    /// Bytes [off, off + len) when they are here (none past the file's end).
    pub fn peek(&self, off: u64, len: u64) -> Option<&[u8]> {
        let end = off.checked_add(len).filter(|&e| e <= self.size)?;
        let k = self.pieces.partition_point(|(o, _)| *o <= off).checked_sub(1)?;
        let (o, b) = &self.pieces[k];
        if end > o + b.len() as u64 {
            return None;
        }
        let s = (off - o) as usize;
        Some(&b[s..s + len as usize])
    }

    /// Bytes [off, off + len): `past` (why the archive cannot be read) when they run past the file's end, Need when
    /// they are not here (noted), or the reading's bound when they would take it past what it reads.
    pub fn get(&self, off: u64, len: u64, past: &str) -> Result<&[u8], Miss> {
        if off.checked_add(len).is_none_or(|e| e > self.size) {
            return Err(Miss::Bad(past.to_string()));
        }
        if let Some(b) = self.peek(off, len) {
            return Ok(b);
        }
        self.note(off, len)?;
        Err(Miss::Need)
    }

    /// Ask for bytes [off, off + len) (cut at the file's end), within the reading's bound: the union of what is given
    /// and what is asked for, each byte counted once (M2, the external review of Oct 21: overlapping requests, as
    /// the local headers of a many-member .npz's neighbouring entries make, were each charged in full).
    pub fn note(&self, off: u64, len: u64) -> Result<(), Miss> {
        let len = len.min(self.size.saturating_sub(off));
        if len == 0 {
            return Ok(());
        }
        let end = off + len;
        // the parts of [off, end) neither given nor asked for already
        let mut new: Vec<(u64, u64)> = Vec::new();
        let mut cur = off;
        let k0 = self.pieces.partition_point(|(o, b)| o + b.len() as u64 <= off);
        let mut asked = self.asked.borrow_mut();
        let mut covers: Vec<(u64, u64)> = self.pieces[k0..].iter().map(|(o, b)| (*o, o + b.len() as u64))
            .take_while(|&(o, _)| o < end).collect();
        if let Some((&s, &e)) = asked.range(..=off).next_back() {
            if e > off {
                covers.push((s, e));
            }
        }
        covers.extend(asked.range(off..end).map(|(&s, &e)| (s, e)));
        covers.sort();
        for (s, e) in covers {
            if s > cur {
                new.push((cur, s.min(end)));
            }
            cur = cur.max(e);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            new.push((cur, end));
        }
        let add: u64 = new.iter().map(|(s, e)| e - s).sum();
        let mut needed = self.needed.borrow_mut();
        if self.given.saturating_add(*needed).saturating_add(add) > self.cap {
            return Err(Miss::Bad(format!("it would take reading more than the {} bytes read of a model file",
                                         super::commas(self.cap))));
        }
        *needed += add;
        for (s, e) in new {
            // (merged with the asked ranges it touches)
            let (mut lo, mut hi) = (s, e);
            if let Some((&ps, &pe)) = asked.range(..=s).next_back() {
                if pe >= s {
                    lo = ps;
                    hi = hi.max(pe);
                }
            }
            let next: Vec<u64> = asked.range(lo..=hi).map(|(&k, _)| k).collect();
            for k in next {
                if let Some(v) = asked.remove(&k) {
                    hi = hi.max(v);
                }
            }
            asked.insert(lo, hi);
        }
        self.need.borrow_mut().push((off, len));
        Ok(())
    }

    /// The ranges a reading asked for and was not given: (offset, length), sorted, merged.
    pub fn needs(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.need.borrow().iter().copied().filter(|r| r.1 > 0).collect();
        v.sort();
        let mut out: Vec<(u64, u64)> = Vec::new();
        for (off, len) in v {
            match out.last_mut() {
                Some((o, l)) if off <= *o + *l => *l = (*l).max(off + len - *o),
                _ => out.push((off, len)),
            }
        }
        out
    }
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

/// The name of the first member the local headers hold (the archive's first file as it was written; a few folder
/// entries before it, which a tool that zips a folder again writes, passed over), if the bytes start with one: what a
/// sniff of a file's first bytes can tell. A name is cut at its first NUL, as zipfile names it.
pub fn first_local_name(head: &[u8]) -> Option<&[u8]> {
    let mut at = 0usize;
    for _ in 0..8 {
        if head.get(at..at + 4) != Some(b"PK\x03\x04") {
            return None;
        }
        let n = u16_at(head, at + 26)? as usize;
        let x = u16_at(head, at + 28)? as usize;
        let name = head.get(at + 30..at + 30 + n)?;
        let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
        let size = u32_at(head, at + 18)?;
        let flags = u16_at(head, at + 6)?;
        if !(name.ends_with(b"/") && size == 0 && flags & 8 == 0) {
            return Some(name);
        }
        at += 30 + n + x;
    }
    None
}

/// What a zip's unpackers find in it (`entries`): every member any of them finds, and why they may not agree.
///
/// The views read (the external review's H2 and FP-NESTED-ARCHIVE's review of Oct 21: Python's zipfile, miniz,
/// adm-zip, yauzl, jszip, unzipper's directory reader and its streaming `Parse`, Info-ZIP's unzip):
/// - the end record: the last (zipfile's `rfind`, miniz, adm-zip), and any other whose comment runs to the file's end
///   (yauzl takes only such a one; jszip and unzipper go on to it past one they cannot use);
/// - a zip64 locator before it, looked for always (zipfile, adm-zip, yauzl, jszip and unzipper use the zip64 record
///   whenever there is one; miniz only when the end record is saturated), the record where the locator says (miniz)
///   and where zipfile reads it (just before the locator);
/// - the directory where its end record's place and size say (zipfile: `end - size`, the offsets moved by the
///   difference, its "concat") and where its offset says (adm-zip, yauzl, unzipper);
/// - every entry inside the directory's declared size (zipfile), and on while entries follow it (jszip);
/// - each member's local header (its own name, method, flags and sizes: a streaming reader's, and what adm-zip, yauzl
///   and jszip read the data by), and a walk of the local headers from the file's first byte (unzipper's `Parse`);
/// - a name cut at its first NUL (zipfile's).
pub struct Listing {
    /// Every member a view finds, once each (by its local header, name, method and sizes): the view zipfile takes
    /// first, in its order (the first entry is the archive's first, as PyTorch's reader takes it), then what the
    /// others add (`Entry::listed` false for a member no central directory lists as it is).
    pub entries: Vec<Entry>,
    /// Why the views may not all find the same members (empty: they agree): the end record's count, the directory's
    /// declared size, its offset and `end - size` disagreeing; a zip64 record (its values not the end record's, or not
    /// where zipfile reads it); more than one end record; a local header that is not its directory entry's (name,
    /// method, flags, sizes); a member no directory lists; bytes before the first member, between the members and the
    /// directory, or after the end record; members whose data overlap (a zip bomb's: each member read is charged to
    /// the reader's inflate budget); a name with a NUL.
    pub ambiguous: Vec<String>,
}

impl Listing {
    pub fn is_ambiguous(&self) -> bool {
        !self.ambiguous.is_empty()
    }
}

/// Bytes a view asks for: here, asked for (noted: the host reads them and the reading goes again), or past the end.
enum Got<'a> {
    Here(&'a [u8]),
    Asked,
    Past,
}

fn have<'a>(src: &'a Bytes, off: u64, len: u64) -> Result<Got<'a>, Miss> {
    if off.checked_add(len).is_none_or(|e| e > src.size) {
        return Ok(Got::Past);
    }
    if let Some(b) = src.peek(off, len) {
        return Ok(Got::Here(b));
    }
    src.note(off, len)?;
    Ok(Got::Asked)
}

/// One way to read the directory: its entry count, size and offset, and where it ends (zipfile's `end - size`).
#[derive(Clone, Copy, PartialEq, Eq)]
struct View {
    count: u64,
    size: u64,
    off: u64,
    end: u64,
}

/// The ways the end record at `ep` is read (zip64's first), or why it is no end record; what makes them disagree is
/// added to `amb`.
fn views_of(src: &Bytes, ep: u64, amb: &mut Vec<String>) -> Result<Vec<View>, Miss> {
    let r = src.get(ep, 22, "a truncated end of central directory record")?;
    let bad = || "a truncated end of central directory record".to_string();
    let count = u16_at(r, 10).ok_or_else(bad)? as u64;
    let size = u32_at(r, 12).ok_or_else(bad)? as u64;
    let off = u32_at(r, 16).ok_or_else(bad)? as u64;
    let saturated = count == 0xFFFF || size == 0xFFFF_FFFF || off == 0xFFFF_FFFF;
    let classic = View { count, size, off, end: ep };
    let mut out = Vec::new();
    let locator = match ep.checked_sub(20) {
        Some(at) => match have(src, at, 20)? {
            Got::Here(l) if l.starts_with(b"PK\x06\x07") => Some((at, u64_at(l, 8).unwrap_or(u64::MAX))),
            Got::Asked => return Err(Miss::Need),
            _ => None,
        },
        None => None,
    };
    if let Some((at, z)) = locator {
        let zipfile_at = at.saturating_sub(56);
        let mut z64 = None;
        let mut spots = vec![(z, "where its locator says")];
        if zipfile_at != z {
            spots.push((zipfile_at, "just before its locator"));
        }
        for (pos, whose) in spots {
            match have(src, pos, 56)? {
                Got::Here(rec) if rec.starts_with(b"PK\x06\x06") => {
                    let v = View { count: u64_at(rec, 32).unwrap_or(0), size: u64_at(rec, 40).unwrap_or(0),
                                   off: u64_at(rec, 48).unwrap_or(0), end: pos };
                    if !out.contains(&v) {
                        out.push(v);
                    }
                    z64.get_or_insert(v);
                }
                Got::Asked => return Err(Miss::Need),
                _ => amb.push(format!("its zip64 locator names no zip64 record {whose} (byte {})", super::commas(pos))),
            }
        }
        if z != zipfile_at {
            amb.push(format!("its zip64 record is at byte {}, not just before its locator, where zipfile reads it",
                             super::commas(z)));
        }
        match z64 {
            Some(v) => {
                let differ = (count != 0xFFFF && count != v.count) || (size != 0xFFFF_FFFF && size != v.size)
                    || (off != 0xFFFF_FFFF && off != v.off);
                if differ {
                    amb.push(format!("its zip64 record ({} entries, {} bytes at byte {}) and its end record ({} entries, \
                                      {} bytes at byte {}) disagree", v.count, super::commas(v.size), super::commas(v.off),
                                     count, super::commas(size), super::commas(off)));
                    if !saturated {
                        out.push(classic);              // (what a reader that takes the end record when it is not
                    }                                   // saturated reads: miniz)
                }
            }
            None if saturated => return Err("a zip64 archive without its zip64 record".into()),
            None => out.push(classic),
        }
    } else {
        if size == 0xFFFF_FFFF || off == 0xFFFF_FFFF {
            return Err("a zip64 archive without its locator".into());
        }
        out.push(classic);
    }
    Ok(out)
}

/// The Unicode Path extra fields (0x7075) of a header whose raw name is `raw`: how many there are, and the UTF-8 name
/// each valid one gives (version 1, its CRC-32 the raw name's: what Info-ZIP and Python's zipfile accept; every one,
/// as readers differ on which they take when there are several: the external re-review of Oct 27).
fn unicode_paths(extra: &[u8], raw: &[u8]) -> (usize, Vec<Vec<u8>>) {
    let crc = lazaret_verify::inflate::crc32(0, raw);
    let fields: Vec<&[u8]> = extra_fields(extra).into_iter().filter(|(id, _)| *id == 0x7075).map(|(_, b)| b).collect();
    let mut names: Vec<Vec<u8>> = Vec::new();
    for body in &fields {
        if body.len() >= 5 && body[0] == 1 && u32_at(body, 1) == Some(crc) && !names.iter().any(|n| n == &body[5..]) {
            names.push(body[5..].to_vec());
        }
    }
    (fields.len(), names)
}

/// The fields of the central directory entry at `cd[at..]`, its length and its Unicode Path extra fields (how many,
/// and the names the valid ones give), or why it is not one.
#[allow(clippy::type_complexity)]
fn cen_entry(cd: &[u8], at: usize, concat: i128) -> Result<(Option<Entry>, usize, (usize, Vec<Vec<u8>>)), String> {
    let short = || "a truncated central directory entry".to_string();
    let made_by = u16_at(cd, at + 4).ok_or_else(short)?;
    let flags = u16_at(cd, at + 8).ok_or_else(short)?;
    let method = u16_at(cd, at + 10).ok_or_else(short)?;
    let mut csize = u32_at(cd, at + 20).ok_or_else(short)? as u64;
    let mut size = u32_at(cd, at + 24).ok_or_else(short)? as u64;
    let nlen = u16_at(cd, at + 28).ok_or_else(short)? as usize;
    let xlen = u16_at(cd, at + 30).ok_or_else(short)?;
    let clen = u16_at(cd, at + 32).ok_or_else(short)? as usize;
    let external = u32_at(cd, at + 38).ok_or_else(short)?;
    let mut local = u32_at(cd, at + 42).ok_or_else(short)? as u64;
    let name = cd.get(at + 46..at + 46 + nlen).ok_or_else(short)?.to_vec();
    let extra = cd.get(at + 46 + nlen..at + 46 + nlen + xlen as usize).ok_or_else(short)?;
    // the zip64 extra field: the sizes and the offset that did not fit, in that order
    for (id, body) in extra_fields(extra) {
        if id == 1 {
            let mut k = 0;
            let mut take = |v: &mut u64| {
                if *v == 0xFFFF_FFFF {
                    if let Some(n) = u64_at(body, k) {
                        *v = n;
                        k += 8;
                    }
                }
            };
            take(&mut size);
            take(&mut csize);
            take(&mut local);
        }
    }
    let len = 46 + nlen + xlen as usize + clen;
    let upath = unicode_paths(extra, &name);
    // (an offset the concat moves before the file's start: no reader that moves it reads the member)
    let local = u64::try_from(local as i128 + concat).ok();
    Ok((local.map(|local| Entry { name, flags, method, csize, size, local, xlen, made_by, external, listed: true }), len,
        upath))
}

/// What one listing reads in all, whatever views its end records give (H5, the external re-review of Oct 27: 2,000
/// end records over one directory made 2,000 copies of it): the directory entries, and their bytes.
struct Budget {
    entries: usize,
    bytes: u64,
}

/// The most end records a listing reads views of (more is an error: SC-TRUNCATED).
const MAX_END_RECORDS: usize = 16;

fn extra_fields(extra: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut x = 0;
    while x + 4 <= extra.len() {
        let id = u16_at(extra, x).unwrap_or(0);
        let len = u16_at(extra, x + 2).unwrap_or(0) as usize;
        out.push((id, extra.get(x + 4..x + 4 + len).unwrap_or(&[])));
        x += 4 + len;
    }
    out
}

/// The entries of the directory at `at` read as `v` says (with `concat` added to their offsets): those that start
/// inside its declared size (zipfile's) and those that follow them (jszip reads on while entries do), and for an
/// entry whose Unicode Path extra names it otherwise, that name too (Info-ZIP's: not `listed`); None when there is
/// no directory there. What it reads is charged to `budget`.
fn directory(src: &Bytes, at: u64, v: View, concat: i128, budget: &mut Budget, max_dir: u64, amb: &mut Vec<String>)
             -> Result<Option<Vec<Entry>>, Miss> {
    if v.size > max_dir {
        return Err(format!("a central directory of {} bytes, more than the {} read", super::commas(v.size),
                           super::commas(max_dir)).into());
    }
    let Some(cd_end) = at.checked_add(v.size).filter(|&e| e <= src.size) else { return Ok(None) };
    src.get(at, v.size, "")?;                                  // (the declared directory, in one range)
    if v.size == 0 {
        if v.count != 0 {
            amb.push(format!("its end record counts {} entries in a directory of no bytes", v.count));
        }
        return Ok(Some(Vec::new()));
    }
    match have(src, at, 4)? {
        Got::Here(s) if s == b"PK\x01\x02" => {}
        Got::Asked => return Err(Miss::Need),
        _ => return Ok(None),
    }
    let spent = || "its central directories hold more entries or bytes than the reader reads".to_string();
    let mut out = Vec::new();
    let (mut pos, mut inside) = (at, 0u64);
    loop {
        let h = match have(src, pos, 46)? {
            Got::Here(h) if h.starts_with(b"PK\x01\x02") => h,
            Got::Asked => return Err(Miss::Need),
            _ => break,
        };
        let len = 46 + u16_at(h, 28).unwrap_or(0) as u64 + u16_at(h, 30).unwrap_or(0) as u64
            + u16_at(h, 32).unwrap_or(0) as u64;
        let whole = match have(src, pos, len)? {
            Got::Here(w) => w,
            Got::Asked => return Err(Miss::Need),
            Got::Past => {
                amb.push("a central directory entry runs past the archive's end".into());
                break;
            }
        };
        if budget.entries == 0 || budget.bytes < len {
            return Err(spent().into());
        }
        budget.entries -= 1;
        budget.bytes -= len;
        let (e, _, (fields, upaths)) = cen_entry(whole, 0, concat)?;
        if let Some(e) = e {
            if fields > 1 {
                amb.push(format!("{} has {fields} Unicode Path extra fields (readers differ on which they take)",
                                 quoted(&e.name)));
            }
            let mut aliases = Vec::new();
            for u in upaths {
                if u != e.name {
                    amb.push(format!("a Unicode Path extra field of {} names it {} (Info-ZIP's and zipfile's name)",
                                     quoted(&e.name), quoted(&u)));
                    if budget.entries == 0 || budget.bytes < u.len() as u64 {
                        return Err(spent().into());
                    }
                    budget.entries -= 1;
                    budget.bytes -= u.len() as u64;
                    aliases.push(Entry { name: u, listed: false, ..e.clone() });
                }
            }
            out.push(e);
            out.extend(aliases);
        }
        if pos < cd_end {
            inside += 1;
            if pos + len > cd_end {
                amb.push("its last central directory entry runs past the directory's declared size".into());
            }
        }
        pos += len;
    }
    let listed = out.iter().filter(|e| e.listed).count() as u64;
    if pos < cd_end {
        amb.push(format!("its central directory holds {} bytes after its {inside} entries that are not an entry",
                         super::commas(cd_end - pos)));
    }
    if listed > inside {
        amb.push(format!("{} central directory entries follow its declared size", listed - inside));
    }
    if inside != v.count {
        amb.push(format!("its end record counts {} entries and its central directory holds {inside}", v.count));
    }
    Ok(Some(out))
}

/// A local header's fields: (flags, method, csize, size, name, extra length), its zip64 sizes read.
struct Local {
    flags: u16,
    method: u16,
    csize: u64,
    size: u64,
    name: Vec<u8>,
    xlen: u16,
    /// how many Unicode Path extra fields it has, and the names the valid ones give (Info-ZIP's and zipfile's)
    ufields: usize,
    unames: Vec<Vec<u8>>,
}

/// The local header at `at`: Ok(None) when its bytes were asked for (`hint` of them, its name and extra field
/// most often among them), Err when there is none there.
fn local_at(src: &Bytes, at: u64, hint: u64) -> Result<Option<Local>, String> {
    let past = || "a local header past what is read".to_string();
    if at.checked_add(30).is_none_or(|e| e > src.size) {
        return Err("a local header past the archive's end".into());
    }
    let h = match src.peek(at, 30) {
        Some(h) => h,
        None => {
            src.note(at, hint.max(30).min(src.size - at)).map_err(|_| past())?;
            return Ok(None);
        }
    };
    if !h.starts_with(b"PK\x03\x04") {
        return Err("no local header".into());
    }
    let flags = u16_at(h, 6).unwrap_or(0);
    let method = u16_at(h, 8).unwrap_or(0);
    let mut csize = u32_at(h, 18).unwrap_or(0) as u64;
    let mut size = u32_at(h, 22).unwrap_or(0) as u64;
    let nlen = u16_at(h, 26).unwrap_or(0) as u64;
    let xlen = u16_at(h, 28).unwrap_or(0);
    let rest = match have(src, at + 30, nlen + xlen as u64).map_err(|_| past())? {
        Got::Here(r) => r,
        Got::Asked => return Ok(None),
        Got::Past => return Err("a local header past the archive's end".into()),
    };
    let name = rest[..nlen as usize].to_vec();
    let (ufields, unames) = unicode_paths(&rest[nlen as usize..], &name);
    if csize == 0xFFFF_FFFF || size == 0xFFFF_FFFF {
        // zip64: the local extra field holds the sizes that did not fit, the size first
        for (id, body) in extra_fields(&rest[nlen as usize..]) {
            if id == 1 {
                let mut k = 0;
                for v in [&mut size, &mut csize] {
                    if *v == 0xFFFF_FFFF {
                        if let Some(n) = u64_at(body, k) {
                            *v = n;
                            k += 8;
                        }
                    }
                }
            }
        }
    }
    Ok(Some(Local { flags, method, csize, size, name, xlen, ufields, unames }))
}

/// The first of reasons of one kind, with how many more there are (so that one kind does not crowd out others).
fn first_of(mut reasons: Vec<String>, more: &str) -> Option<String> {
    let n = reasons.len();
    let first = reasons.drain(..).next()?;
    Some(if n > 1 { format!("{first} (and {} more {more})", n - 1) } else { first })
}

fn quoted(name: &[u8]) -> String {
    format!("'{}'", String::from_utf8_lossy(&name[..name.len().min(120)]).escape_debug())
}

/// The members of the zip archive in `src` (at most `max`, its directory at most `max_dir` bytes; more is an error),
/// as every common unpacker finds them, and why they may not agree (`Listing`). What a view needs that is not here
/// is noted in `src` (a reading by range reads it and goes again; a directory not here is Need).
pub fn entries(src: &Bytes, max: usize, max_dir: u64) -> Result<Listing, Miss> {
    // the end records: within the last 65,535 + 22 bytes
    let lo = src.size.saturating_sub(65_535 + 22);
    let window = src.get(lo, src.size - lo, "")?;
    let mut sigs: Vec<u64> = Vec::new();
    if window.len() >= 22 {
        for i in (0..=window.len() - 22).rev() {
            if window[i..].starts_with(b"PK\x05\x06") {
                sigs.push(lo + i as u64);
            }
        }
    }
    let last = *sigs.first().ok_or("no end of central directory record")?;
    let reaches_end = |ep: u64| -> bool {
        src.peek(ep + 20, 2).and_then(|c| u16_at(c, 0)).is_some_and(|c| ep + 22 + c as u64 == src.size)
    };
    let mut amb: Vec<String> = Vec::new();
    // (the end record, its views and the directories they read: (place, view, the directory's read in `dirs_read`))
    let mut read: Vec<(u64, Vec<(u64, View, usize)>)> = Vec::new();
    // each directory read once, whatever views name it ((place, concat, size, count) -> its entries), and all of them
    // charged to one budget
    let mut dirs_read: Vec<Vec<Entry>> = Vec::new();
    let mut seen_dirs: HashMap<(u64, i128, u64, u64), Option<usize>> = HashMap::new();
    let mut budget = Budget { entries: max.saturating_mul(2), bytes: max_dir.saturating_mul(2) };
    let mut first_err: Option<Miss> = None;
    let mut need = false;
    let takes = sigs.iter().filter(|&&ep| ep == last || reaches_end(ep)).count();
    if takes > MAX_END_RECORDS {
        return Err(format!("it has {takes} end records a reader may take, more than the {MAX_END_RECORDS} read").into());
    }
    for &ep in &sigs {
        if ep != last && !reaches_end(ep) {
            continue;                               // (no reader takes it: a member's bytes, a nested zip's record)
        }
        let mut here_amb = Vec::new();
        let views = match views_of(src, ep, &mut here_amb) {
            Ok(v) => v,
            Err(Miss::Need) => {
                need = true;
                continue;
            }
            Err(e) => {
                first_err.get_or_insert(e);
                continue;
            }
        };
        let mut dirs: Vec<(u64, View, usize)> = Vec::new();
        for v in views {
            // where zipfile reads it (its offsets moved by the difference) and where its offset says
            let Some(a) = v.end.checked_sub(v.size) else { continue };
            let concat = a as i128 - v.off as i128;
            let mut places = vec![(a, concat)];
            if concat != 0 {
                places.push((v.off, 0));
            }
            for (at, concat) in places {
                if dirs.iter().any(|(p, w, _)| *p == at && *w == v) {
                    continue;
                }
                let key = (at, concat, v.size, v.count);
                let got = match seen_dirs.get(&key) {
                    Some(k) => Ok(*k),
                    None => match directory(src, at, v, concat, &mut budget, max_dir, &mut here_amb) {
                        Ok(Some(es)) => {
                            dirs_read.push(es);
                            Ok(Some(dirs_read.len() - 1))
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    },
                };
                match got {
                    Ok(k) => {
                        seen_dirs.insert(key, k);
                        if let Some(k) = k {
                            dirs.push((at, v, k));
                        }
                    }
                    Err(Miss::Need) => need = true,
                    Err(e) => {
                        if matches!(&e, Miss::Bad(m) if m.contains("more entries or bytes than the reader reads")) {
                            return Err(e);              // (the listing's budget: SC-TRUNCATED, bounded)
                        }
                        first_err.get_or_insert(e);
                    }
                }
            }
            if concat != 0 {
                here_amb.push(format!("its directory is at byte {} by its end record's place and size, and at byte \
                                       {} by its offset", super::commas(a), super::commas(v.off)));
            }
        }
        if !dirs.is_empty() {
            amb.extend(here_amb);
            read.push((ep, dirs));
        }
    }
    if need {
        return Err(Miss::Need);
    }
    let Some((primary_ep, primary)) = read.first().map(|(ep, d)| (*ep, d.clone())) else {
        return Err(first_err.unwrap_or_else(|| "no central directory where its end record says".into()));
    };
    if read.len() > 1 {
        amb.push(format!("it has {} end records whose comments run to its end", read.len()));
    }
    if primary_ep != last {
        amb.push(format!("its last end record (byte {}) is not one a reader can use", super::commas(last)));
    }
    // the union: zipfile's view first
    let mut out: Vec<Entry> = Vec::new();
    let mut keys: HashSet<(u64, Vec<u8>, u16, u16, u64, u64)> = HashSet::new();
    let mut add = |out: &mut Vec<Entry>, e: Entry| -> Result<(), Miss> {
        if keys.insert((e.local, e.name.clone(), e.method, e.flags, e.csize, e.size)) {
            if out.len() >= max {
                return Err(format!("more than the {max} entries read").into());
            }
            out.push(e);
        }
        Ok(())
    };
    let mut added = HashSet::new();
    for (_, dirs) in &read {
        for (_, _, k) in dirs {
            if added.insert(*k) {
                for e in &dirs_read[*k] {
                    add(&mut out, e.clone())?;
                }
            }
        }
    }
    drop(dirs_read);
    // each listed member's local header: its own name, method, flags and sizes
    let mut by_local: BTreeMap<u64, usize> = BTreeMap::new();
    for (k, e) in out.iter().enumerate() {
        by_local.entry(e.local).or_insert(k);
    }
    let mut locals: BTreeMap<u64, Local> = BTreeMap::new();
    for (&at, &k) in &by_local {
        let e = &out[k];
        match local_at(src, at, 30 + e.name.len() as u64 + e.xlen as u64 + 128) {
            Ok(Some(l)) => {
                locals.insert(at, l);
            }
            Ok(None) => {}
            Err(why) => amb.push(format!("{why} at byte {}, where its directory puts {}", super::commas(at),
                                         quoted(&e.name))),
        }
    }
    // (the names the directories give each member: its own and its Unicode Path extra's)
    let mut central_names: HashMap<u64, HashSet<Vec<u8>>> = HashMap::new();
    for e in &out {
        central_names.entry(e.local).or_default().insert(e.name.clone());
    }
    let mut differ = Vec::new();
    for e in out.clone() {
        if !e.listed {
            continue;
        }
        let Some(l) = locals.get(&e.local) else { continue };
        let names = &central_names[&e.local];
        let sizes = l.flags & 8 == 0 && (l.csize != e.csize || l.size != e.size);
        // its local names (its own, its Unicode Path extra fields') that no directory gives it
        let others: Vec<&Vec<u8>> = std::iter::once(&l.name).chain(l.unames.iter())
            .filter(|n| !names.contains(*n)).collect();
        if l.ufields > 1 {
            differ.push(format!("the local header of {} (byte {}) has {} Unicode Path extra fields (readers differ on \
                                 which they take)", quoted(&e.name), super::commas(e.local), l.ufields));
        }
        if !others.is_empty() || l.method != e.method || l.flags != e.flags || sizes {
            differ.push(format!("the local header of {} (byte {}) is not its directory entry's: {}", quoted(&e.name),
                                super::commas(e.local),
                                if let Some(n) = others.first() { format!("its name is {}", quoted(n)) }
                                else if sizes { format!("{} bytes, not {}", l.csize, e.csize) }
                                else { "its method or flags differ".into() }));
            let (csize, size) = if l.flags & 8 != 0 { (e.csize, e.size) } else { (l.csize, l.size) };
            let mut local_names: Vec<Vec<u8>> = others.into_iter().cloned().collect();
            if local_names.is_empty() {
                local_names.push(l.name.clone());
            }
            for name in local_names {
                add(&mut out, Entry { name, flags: l.flags, method: l.method, csize, size, local: e.local,
                                      xlen: l.xlen, made_by: e.made_by, external: e.external, listed: false })?;
            }
        }
    }
    amb.extend(first_of(differ, "members' local headers"));
    // the directories' places, and the records after them: where a walk of the local headers may stop
    let mut stops: HashSet<u64> = HashSet::new();
    for (ep, d) in &read {
        stops.insert(*ep);
        for (at, v, _) in d {
            stops.insert(*at);
            stops.insert(v.end);
        }
    }
    stops.insert(src.size);
    // the local headers walked from the file's first byte (a streaming unpacker's)
    let mut p = 0u64;
    let mut walked = 0usize;
    let mut unlisted = Vec::new();
    while !stops.contains(&p) {
        let hint = by_local.get(&p).map(|&k| 30 + out[k].name.len() as u64 + out[k].xlen as u64 + 128).unwrap_or(30 + 256);
        let fetched;
        let l = match locals.get(&p) {
            Some(l) => l,
            None => match local_at(src, p, hint) {
                Ok(Some(l)) => {
                    fetched = l;
                    &fetched
                }
                Ok(None) => break,                                     // (asked for: the next reading goes on)
                Err(_) => {
                    amb.push(if p == 0 {
                        let first = out.iter().map(|e| e.local).min().unwrap_or(primary[0].0);
                        format!("{} bytes before its first member", super::commas(first))
                    } else {
                        format!("bytes at byte {} that are neither a member nor its directory", super::commas(p))
                    });
                    break;
                }
            },
        };
        walked += 1;
        if walked > max {
            return Err(format!("more than the {max} entries read").into());
        }
        let data = p + 30 + l.name.len() as u64 + l.xlen as u64;
        let listed_here = by_local.get(&p).map(|&k| out[k].clone());
        let csize = match (&listed_here, l.flags & 8 != 0) {
            (_, false) => Some(l.csize),
            (Some(e), true) => Some(e.csize),
            // (its size only its data descriptor says: found by the descriptor's signature, when the rest is here)
            (None, true) => src.peek(data, src.size.saturating_sub(data)).and_then(|rest| {
                rest.windows(4).position(|w| w == b"PK\x07\x08").map(|k| k as u64)
            }),
        };
        if listed_here.is_none() {
            unlisted.push(format!("a member at byte {} that no central directory lists ({})", super::commas(p),
                                  quoted(&l.name)));
        }
        let Some(csize) = csize else {
            amb.push(format!("a member at byte {} whose size only its data descriptor says", super::commas(p)));
            break;
        };
        let (flags, size, wide) = (l.flags, l.size, csize >= 0xFFFF_FFFF || l.size >= 0xFFFF_FFFF);
        if listed_here.is_none() {
            add(&mut out, Entry { name: l.name.clone(), flags: l.flags, method: l.method, csize, size, local: p,
                                  xlen: l.xlen, made_by: 0, external: 0, listed: false })?;
        }
        let mut next = data.saturating_add(csize);
        if flags & 8 != 0 {
            match have(src, next, 4)? {
                Got::Here(d) => next += if d == b"PK\x07\x08" { 4 } else { 0 } + if wide { 20 } else { 12 },
                Got::Asked => break,
                Got::Past => {
                    amb.push(format!("a member at byte {} that runs past the archive's end", super::commas(p)));
                    break;
                }
            }
        }
        if next >= src.size {
            amb.push(format!("a member at byte {} that runs past the archive's end", super::commas(p)));
            break;
        }
        p = next;
    }
    amb.extend(first_of(unlisted, "such members"));
    // bytes after the primary directory, and after its end record
    let (pat, pv, _) = &primary[0];
    if pat + pv.size < pv.end {
        amb.push(format!("{} bytes between its central directory and its end record", super::commas(pv.end - pat - pv.size)));
    }
    if let Some(c) = src.peek(primary_ep + 20, 2).and_then(|c| u16_at(c, 0)) {
        let end = primary_ep + 22 + c as u64;
        if end < src.size {
            amb.push(format!("{} bytes after its end record", super::commas(src.size - end)));
        } else if end > src.size {
            amb.push("its end record's comment runs past the file's end".into());
        }
    }
    // members whose data overlap, or that share it
    let mut spans: Vec<(u64, u64, &[u8])> = out.iter().filter(|e| e.listed).map(|e| {
        let head = locals.get(&e.local)
            .map(|l| 30 + l.name.len() as u64 + l.xlen as u64).unwrap_or(30 + e.name.len() as u64 + e.xlen as u64);
        (e.local, e.local.saturating_add(head).saturating_add(e.csize), e.name.as_slice())
    }).collect();
    spans.sort();
    spans.dedup_by(|b, a| a.0 == b.0 && a.2 == b.2);
    let mut shared = 0usize;
    let mut reach = (0u64, 0u64);
    for (k, s) in spans.iter().enumerate() {
        if k > 0 && s.0 < reach.1 {
            shared += 1;
        }
        if s.1 > reach.1 {
            reach = (s.0, s.1);
        }
    }
    if shared > 0 {
        amb.push(format!("{shared} of its members' data overlap another's (each read is charged to the reader's \
                          inflate budget)"));
    }
    // a name zipfile cuts at its first NUL
    let mut nul = Vec::new();
    for e in out.clone() {
        if let Some(k) = e.name.iter().position(|&c| c == 0) {
            nul.push(format!("a member's name holds a NUL byte: zipfile names {} {}", quoted(&e.name),
                             quoted(&e.name[..k])));
            add(&mut out, Entry { name: e.name[..k].to_vec(), ..e })?;
        }
    }
    amb.extend(first_of(nul, "such names"));
    let mut seen = std::collections::HashSet::new();
    amb.retain(|a| seen.insert(a.clone()));
    amb.truncate(16);
    Ok(Listing { entries: out, ambiguous: amb })
}

/// The first `want` of an entry's stored or compressed bytes (after its local header), or why they cannot be had.
/// `fetch`: the most of them asked for when they are not here (a reading's bound: more is an error).
fn raw<'a>(src: &'a Bytes, e: &Entry, want: u64, fetch: u64, too_many: impl Fn() -> String) -> Result<&'a [u8], Miss> {
    if e.flags & 1 != 0 {
        return Err("it is encrypted".into());
    }
    let wrong = "its local header is not where the central directory says";
    if e.local >= src.size {
        return Err(wrong.into());
    }
    let room = src.size - e.local;
    let hdr = match src.peek(e.local, 30.min(room)) {
        Some(h) => h,
        None => {
            // the header and the bytes after it, in one range: the most often what it holds
            if want > fetch {
                return Err(Miss::Bad(too_many()));
            }
            src.note(e.local, (30 + e.name.len() as u64 + e.xlen as u64 + LOCAL_SLACK)
                .saturating_add(want.min(e.csize)).min(room))?;
            return Err(Miss::Need);
        }
    };
    if hdr.get(..4) != Some(b"PK\x03\x04") {
        return Err(wrong.into());
    }
    let nlen = u16_at(hdr, 26).ok_or("a truncated local header")? as u64;
    let xlen = u16_at(hdr, 28).ok_or("a truncated local header")? as u64;
    let start = e.local + 30 + nlen + xlen;
    if start > src.size || e.csize > src.size - start {
        return Err("an entry past the archive's end".into());
    }
    let want = want.min(e.csize);
    if src.peek(start, want).is_none() && want > fetch {
        return Err(Miss::Bad(too_many()));
    }
    src.get(start, want, "an entry past the archive's end")
}

/// An entry's first `n` bytes, decompressed (fewer when it is shorter). Its first PREFIX_RAW stored bytes are read
/// for them, and all of them (at most `fetch` asked for) when those hold fewer and the entry goes on: deflate's empty
/// blocks hold nothing.
pub fn read_prefix(src: &Bytes, e: &Entry, n: usize, fetch: u64) -> Result<Vec<u8>, Miss> {
    use lazaret_verify::inflate::{Inflater, Status};
    let first = PREFIX_RAW.max(n as u64);
    let more = || format!("its first {n} bytes are not in the {fetch} bytes of it read");
    match e.method {
        0 => {
            let raw = raw(src, e, first, u64::MAX, String::new)?;
            Ok(raw[..raw.len().min(n)].to_vec())
        }
        8 => {
            // (the bytes decompressed, and whether the stream ended)
            let inflate = |raw: &[u8]| -> Result<(Vec<u8>, bool), Miss> {
                let mut inf = Inflater::new(Format::Deflate, Limits::new(u64::MAX));
                let mut out = vec![0u8; n];
                let (mut got, mut pos, mut ended) = (0usize, 0usize, false);
                while got < n {
                    let pr = inf.inflate(&raw[pos..], &mut out[got..]).map_err(|err| err.to_string())?;
                    pos += pr.consumed;
                    got += pr.produced;
                    if pr.status == Status::Done {
                        ended = true;
                        break;
                    }
                    if pr.status == Status::NeedInput && pr.produced == 0 && pr.consumed == 0 {
                        break;
                    }
                }
                out.truncate(got);
                Ok((out, ended))
            };
            let raw1 = raw(src, e, first, u64::MAX, String::new)?;
            let (out, ended) = inflate(raw1)?;
            if out.len() < n && !ended && (raw1.len() as u64) < e.csize {
                return Ok(inflate(raw(src, e, e.csize, fetch, more)?)?.0);
            }
            Ok(out)
        }
        m => Err(format!("it is compressed with {} (method {m}), which the reader cannot decompress", method_name(m)).into()),
    }
}

/// An entry's bytes, decompressed (at most `limit` of them), or why they cannot be read.
pub fn read(src: &Bytes, e: &Entry, limit: u64) -> Result<Vec<u8>, Miss> {
    let more = || format!("it holds more than the {limit} bytes read");
    match e.method {
        0 => {
            let raw = raw(src, e, e.csize, limit, more)?;
            if raw.len() as u64 > limit {
                return Err(Miss::Bad(more()));
            }
            Ok(raw.to_vec())
        }
        8 => {
            // (deflate's bytes are at most about twice what they hold: more than that holds more than `limit`)
            let fetch = limit.saturating_mul(2).saturating_add(1 << 20);
            let raw = raw(src, e, e.csize, fetch, more)?;
            decode_all(Format::Deflate, raw, Limits::new(limit)).map_err(|err| Miss::Bad(err.to_string()))
        }
        m => Err(format!("it is compressed with {} (method {m}), which the reader cannot decompress", method_name(m)).into()),
    }
}

fn method_name(m: u16) -> &'static str {
    match m {
        9 => "deflate64",
        12 => "bzip2",
        14 => "LZMA",
        93 => "zstd",
        95 => "xz",
        98 => "PPMd",
        99 => "AES encryption",
        _ => "an unknown method",
    }
}
