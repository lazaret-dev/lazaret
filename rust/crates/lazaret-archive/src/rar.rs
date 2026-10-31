//! RAR4/RAR5 container parsing and stored-member extraction.
//!
//! RAR's compressed methods are separate codecs, not DEFLATE. Until those codecs are
//! implemented and differentially tested, only method 0 (store) is accepted.

use crate::{Builder, EntryKind, Error, Format, Limits, Result};
use lazaret_verify::inflate::crc32;

fn size(n: u64, what: &'static str) -> Result<usize> {
    usize::try_from(n).map_err(|_| Error::Limit(what))
}

fn u16le(data: &[u8], at: usize) -> Result<u16> {
    let b = data.get(at..at + 2).ok_or(Error::Truncated)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32le(data: &[u8], at: usize) -> Result<u32> {
    let b = data.get(at..at + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn vint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for i in 0..10 {
        let b = *data.get(*pos).ok_or(Error::Truncated)?;
        *pos += 1;
        if i == 9 && b > 1 { return Err(Error::Corrupt("RAR variable-length integer overflow")); }
        value |= u64::from(b & 0x7f) << (i * 7);
        if b & 0x80 == 0 { return Ok(value); }
    }
    Err(Error::Corrupt("unterminated RAR variable-length integer"))
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Cursor<'a> { Cursor { data, pos: 0 } }
    fn remaining(&self) -> usize { self.data.len() - self.pos }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Limit("RAR header size"))?;
        let out = self.data.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(out)
    }
    fn vint(&mut self) -> Result<u64> { vint(self.data, &mut self.pos) }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

fn utf8_name(raw: &[u8]) -> Result<&str> {
    std::str::from_utf8(raw).map_err(|_| Error::Unsupported("non-UTF-8 RAR member name"))
}

// ---------------- RAR4 ----------------

pub(crate) fn extract4(data: &[u8], limits: Limits) -> Result<crate::Archive> {
    const SIGNATURE: usize = 7;
    let mut out = Builder::new(limits);
    let mut pos = SIGNATURE;
    let mut main_seen = false;
    let mut blocks = 0usize;

    loop {
        if data.len() - pos < 7 { return Err(Error::Truncated); }
        blocks += 1;
        if blocks > limits.max_entries.saturating_add(2) { return Err(Error::Limit("RAR header count")); }
        let header_crc = u16le(data, pos)?;
        let kind = data[pos + 2];
        let flags = u16le(data, pos + 3)?;
        let header_size = usize::from(u16le(data, pos + 5)?);
        if header_size < 7 { return Err(Error::Corrupt("RAR4 header is too short")); }
        let header_end = pos.checked_add(header_size).ok_or(Error::Limit("RAR4 header size"))?;
        let header = data.get(pos..header_end).ok_or(Error::Truncated)?;
        if (crc32(0, &header[2..]) & 0xffff) != u32::from(header_crc) {
            return Err(Error::Checksum("RAR4 header"));
        }

        match kind {
            0x73 => {                                      // main archive header
                if main_seen || header_size < 13 { return Err(Error::Corrupt("invalid RAR4 main header")); }
                if flags & 0x0001 != 0 { return Err(Error::Unsupported("multi-volume RAR archive")); }
                if flags & 0x0008 != 0 { return Err(Error::Unsupported("solid RAR archive")); }
                if flags & 0x0080 != 0 || flags & 0x0200 != 0 {
                    return Err(Error::Unsupported("encrypted RAR archive"));
                }
                main_seen = true;
            }
            0x74 => {                                      // file header
                if !main_seen { return Err(Error::Corrupt("RAR4 file precedes the main header")); }
                if flags & 0x0003 != 0 { return Err(Error::Unsupported("split RAR member")); }
                if flags & 0x0004 != 0 || flags & 0x0400 != 0 {
                    return Err(Error::Unsupported("encrypted RAR member"));
                }
                if flags & 0x0010 != 0 { return Err(Error::Unsupported("solid RAR member")); }
                if flags & 0x0200 != 0 { return Err(Error::Unsupported("RAR4 encoded Unicode names")); }
                if header_size < 32 { return Err(Error::Corrupt("RAR4 file header is too short")); }
                let large = flags & 0x0100 != 0;
                let name_at = if large { 40 } else { 32 };
                if header_size < name_at { return Err(Error::Truncated); }
                let mut packed = u64::from(u32le(header, 7)?);
                let unpacked = u64::from(u32le(header, 11)?);
                out.reserve_metadata(header_size as u64)?;
                let host_os = header[15];
                let expected_crc = u32le(header, 16)?;
                let method = header[25];
                let name_size = usize::from(u16le(header, 26)?);
                let attributes = u32le(header, 28)?;
                if large {
                    packed |= u64::from(u32le(header, 32)?) << 32;
                    // Stored members cannot legitimately exceed the addressable input here;
                    // read the high unpacked field as well so all header lengths are checked.
                    let high_unpacked = u64::from(u32le(header, 36)?) << 32;
                    if high_unpacked != 0 { return Err(Error::Limit("RAR4 stored member size")); }
                }
                if method != 0x30 { return Err(Error::Unsupported("compressed RAR4 member")); }
                if packed != unpacked { return Err(Error::Corrupt("RAR4 stored member sizes differ")); }
                let name_end = name_at.checked_add(name_size).ok_or(Error::Limit("RAR4 name size"))?;
                let name = utf8_name(header.get(name_at..name_end).ok_or(Error::Truncated)?)?;
                let payload_size = out.check_member_size(unpacked)?;
                let payload_end = header_end.checked_add(payload_size).ok_or(Error::Limit("RAR4 member size"))?;
                let payload = data.get(header_end..payload_end).ok_or(Error::Truncated)?;
                if crc32(0, payload) != expected_crc { return Err(Error::Checksum("RAR4 member")); }
                let directory = flags & 0x00e0 == 0x00e0;
                match host_os {
                    3 => {
                        let file_type = attributes & 0o170000;
                        if !matches!(file_type, 0 | 0o100000 | 0o040000) { return Err(Error::Unsupported("RAR4 special file")); }
                        if file_type != 0 && (file_type == 0o040000) != directory { return Err(Error::Corrupt("RAR4 file type mismatch")); }
                    }
                    0..=2 => {
                        if (attributes & 0x10 != 0) != directory { return Err(Error::Corrupt("RAR4 directory attributes")); }
                    }
                    _ => return Err(Error::Unsupported("RAR4 host OS")),
                }
                if directory && !payload.is_empty() { return Err(Error::Corrupt("RAR4 directory has data")); }
                // RAR4 separates path segments with '\' on every host: unrar and 7-Zip split there.
                out.add(&name.replace('\\', "/"), if directory { EntryKind::Directory } else { EntryKind::File },
                        if directory { &[] } else { payload })?;
                pos = payload_end;
                continue;
            }
            0x7b => {                                      // end of archive
                if !main_seen { return Err(Error::Corrupt("RAR4 main header is missing")); }
                if flags & 1 != 0 { return Err(Error::Unsupported("multi-volume RAR archive")); }
                if data[header_end..].iter().any(|&b| b != 0) {
                    return Err(Error::Corrupt("data after RAR4 end marker"));
                }
                return Ok(out.finish(Format::Rar4));
            }
            0x75 => {}                                     // bounded archive comment
            0x7a => return Err(Error::Unsupported("RAR4 service headers")),
            _ => return Err(Error::Unsupported("unknown RAR4 header")),
        }

        let data_size = if flags & 0x8000 != 0 { u64::from(u32le(header, 7)?) } else { 0 };
        out.reserve_metadata((header_size as u64).saturating_add(data_size))?;
        pos = header_end.checked_add(size(data_size, "RAR4 metadata size")?).ok_or(Error::Limit("RAR4 metadata size"))?;
        if pos > data.len() { return Err(Error::Truncated); }
    }
}

// ---------------- RAR5 ----------------

/// The main archive header's extra records: 1 is the locator (RAR 7 writes one in every archive),
/// 2 the archive's original name and time.
fn main_extra(cursor: &mut Cursor<'_>, extra_size: usize) -> Result<()> {
    if cursor.remaining() != extra_size { return Err(Error::Corrupt("RAR5 extra-area size mismatch")); }
    while cursor.remaining() > 0 {
        let record_size = size(cursor.vint()?, "RAR5 extra record size")?;
        if record_size == 0 { return Err(Error::Corrupt("empty RAR5 extra record")); }
        let mut record = Cursor::new(cursor.take(record_size)?);
        match record.vint()? {
            1 => {
                let flags = record.vint()?;
                let quick_open = if flags & 1 != 0 { record.vint()? } else { 0 };
                if flags & 2 != 0 { record.vint()?; }          // recovery record offset
                // unrar reads headers from the quick-open copy in place of the archive's own.
                if quick_open != 0 { return Err(Error::Unsupported("RAR5 quick-open data")); }
            }
            2 => {}
            _ => return Err(Error::Unsupported("unknown RAR5 main header record")),
        }
    }
    Ok(())
}

/// The fields file and service headers share.
struct FileHeader<'a> {
    file_flags: u64,
    unpacked: u64,
    attributes: u64,
    crc: Option<u32>,
    compression: u64,
    host_os: u64,
    name: &'a [u8],
}

fn file_header<'a>(cursor: &mut Cursor<'a>) -> Result<FileHeader<'a>> {
    let file_flags = cursor.vint()?;
    let unpacked = cursor.vint()?;
    let attributes = cursor.vint()?;
    if file_flags & 2 != 0 { cursor.u32()?; }   // Unix mtime
    let crc = if file_flags & 4 != 0 { Some(cursor.u32()?) } else { None };
    if file_flags & 8 != 0 { return Err(Error::Unsupported("unknown RAR5 unpacked size")); }
    let compression = cursor.vint()?;
    let host_os = cursor.vint()?;
    let name_size = size(cursor.vint()?, "RAR5 name size")?;
    let name = cursor.take(name_size)?;
    Ok(FileHeader { file_flags, unpacked, attributes, crc, compression, host_os, name })
}

/// A service header's extra records: hash, time, owner and service data.
fn service_extra(cursor: &mut Cursor<'_>, extra_size: usize) -> Result<()> {
    if cursor.remaining() != extra_size { return Err(Error::Corrupt("RAR5 extra-area size mismatch")); }
    while cursor.remaining() > 0 {
        let record_size = size(cursor.vint()?, "RAR5 extra record size")?;
        if record_size == 0 { return Err(Error::Corrupt("empty RAR5 extra record")); }
        let mut record = Cursor::new(cursor.take(record_size)?);
        match record.vint()? {
            2 | 3 | 6 | 7 => {}
            1 => return Err(Error::Unsupported("encrypted RAR5 service header")),
            _ => return Err(Error::Unsupported("unknown RAR5 service header record")),
        }
    }
    Ok(())
}

fn extra(cursor: &mut Cursor<'_>, extra_size: usize) -> Result<()> {
    if cursor.remaining() != extra_size { return Err(Error::Corrupt("RAR5 extra-area size mismatch")); }
    let end = cursor.data.len();
    while cursor.pos < end {
        let record_size = size(cursor.vint()?, "RAR5 extra record size")?;
        if record_size == 0 { return Err(Error::Corrupt("empty RAR5 extra record")); }
        let mut record = Cursor::new(cursor.take(record_size)?);
        let record_type = record.vint()?;
        match record_type {
            1 => return Err(Error::Unsupported("encrypted RAR5 member")),
            5 => return Err(Error::Unsupported("RAR5 link redirection")),
            2 | 3 | 6 => {}                              // hash, time, owner (not extraction semantics)
            4 | 7 => return Err(Error::Unsupported("RAR5 version or service metadata")),
            _ => return Err(Error::Unsupported("unknown RAR5 extra record")),
        }
    }
    Ok(())
}

pub(crate) fn extract5(data: &[u8], limits: Limits) -> Result<crate::Archive> {
    const SIGNATURE: usize = 8;
    let mut out = Builder::new(limits);
    let mut pos = SIGNATURE;
    let mut main_seen = false;
    let mut blocks = 0usize;

    loop {
        if data.len() - pos < 5 { return Err(Error::Truncated); }
        blocks += 1;
        if blocks > limits.max_entries.saturating_add(2) { return Err(Error::Limit("RAR header count")); }
        let expected_header_crc = u32le(data, pos)?;
        let size_at = pos + 4;
        let mut start = size_at;
        let header_size = vint(data, &mut start)?;
        out.reserve_metadata(header_size)?;
        let header_end = start.checked_add(size(header_size, "RAR5 header size")?).ok_or(Error::Limit("RAR5 header size"))?;
        if header_end > data.len() { return Err(Error::Truncated); }
        if crc32(0, &data[size_at..header_end]) != expected_header_crc {
            return Err(Error::Checksum("RAR5 header"));
        }
        let mut cursor = Cursor::new(&data[start..header_end]);
        let kind = cursor.vint()?;
        let flags_at = cursor.pos;
        let flags = cursor.vint()?;
        let flags_width = cursor.pos - flags_at;
        let extra_size = if flags & 1 != 0 { size(cursor.vint()?, "RAR5 extra size")? } else { 0 };
        let data_size = if flags & 2 != 0 { cursor.vint()? } else { 0 };
        let payload_end = header_end.checked_add(size(data_size, "RAR5 member size")?).ok_or(Error::Limit("RAR5 member size"))?;
        if payload_end > data.len() { return Err(Error::Truncated); }

        match kind {
            1 => {                                         // main
                if main_seen { return Err(Error::Corrupt("duplicate RAR5 main header")); }
                let archive_flags = cursor.vint()?;
                if archive_flags & 0x0003 != 0 { return Err(Error::Unsupported("multi-volume RAR archive")); }
                if archive_flags & 0x0004 != 0 { return Err(Error::Unsupported("solid RAR archive")); }
                main_extra(&mut cursor, extra_size)?;
                main_seen = true;
                pos = payload_end;
                continue;
            }
            2 => {                                         // file
                if !main_seen { return Err(Error::Corrupt("RAR5 file precedes the main header")); }
                if flags & 0x0018 != 0 { return Err(Error::Unsupported("split RAR member")); }
                let FileHeader { file_flags, unpacked, attributes, crc: expected_crc, compression, host_os, name } =
                    file_header(&mut cursor)?;
                let name = utf8_name(name)?;
                // RAR5 separates with '/'. In a Unix-made name '\' is a character, which unrar and 7-Zip keep;
                // in a Windows-made one it is invalid, and they disagree (unrar writes '_', 7-Zip keeps it).
                if host_os == 0 && name.contains('\\') {
                    return Err(Error::Ambiguous("a backslash in a Windows-made RAR5 name (unrar writes '_', 7-Zip keeps it)"));
                }
                extra(&mut cursor, extra_size)?;
                if compression & 0x3f != 0 { return Err(Error::Unsupported("RAR5 compression version")); }
                if compression & 0x40 != 0 { return Err(Error::Unsupported("solid RAR5 member")); }
                if compression & !0x3fff != 0 { return Err(Error::Corrupt("reserved RAR5 compression bits")); }
                if (compression >> 7) & 7 != 0 { return Err(Error::Unsupported("compressed RAR5 member")); }
                let directory = file_flags & 1 != 0;
                if directory && (unpacked != 0 || data_size != 0) { return Err(Error::Corrupt("RAR5 directory has data")); }
                if host_os == 1 {
                    let file_type = attributes & 0o170000;
                    if !matches!(file_type, 0 | 0o100000 | 0o040000) { return Err(Error::Unsupported("RAR5 special file")); }
                    if file_type != 0 && (file_type == 0o040000) != directory { return Err(Error::Corrupt("RAR5 file type mismatch")); }
                } else if host_os != 0 { return Err(Error::Unsupported("RAR5 host OS")); }
                if !directory && unpacked != data_size { return Err(Error::Corrupt("RAR5 stored member sizes differ")); }
                out.check_member_size(unpacked)?;
                let payload = &data[header_end..payload_end];
                if !directory {
                    let expected = expected_crc.ok_or(Error::Corrupt("RAR5 file has no CRC-32"))?;
                    if crc32(0, payload) != expected { return Err(Error::Checksum("RAR5 member")); }
                }
                out.add(name, if directory { EntryKind::Directory } else { EntryKind::File },
                        if directory { &[] } else { payload })?;
                pos = payload_end;
                continue;
            }
            3 => {                                         // service header
                if !main_seen { return Err(Error::Corrupt("RAR5 service header precedes the main header")); }
                if flags & 0x0018 != 0 { return Err(Error::Unsupported("split RAR service header")); }
                let service = file_header(&mut cursor)?;
                service_extra(&mut cursor, extra_size)?;
                match service.name {
                    // A comment, and the recovery record unrar reads only to repair: no file is written.
                    b"CMT" | b"RR" => {}
                    b"QO" => return Err(Error::Unsupported("RAR5 quick-open data")),
                    // NTFS streams (STM) and ACLs are data and metadata a Windows unrar writes.
                    _ => return Err(Error::Unsupported("RAR5 service headers other than comments and recovery records")),
                }
                pos = payload_end;
                continue;
            }
            4 => return Err(Error::Unsupported("encrypted RAR5 archive")),
            5 => {                                         // end of archive
                if !main_seen { return Err(Error::Corrupt("RAR5 main header is missing")); }
                let end_flags = cursor.vint()?;
                if end_flags & 1 != 0 { return Err(Error::Unsupported("multi-volume RAR archive")); }
                extra(&mut cursor, extra_size)?;
                if data[payload_end..].iter().any(|&b| b != 0) {
                    return Err(Error::Corrupt("data after RAR5 end marker"));
                }
                return Ok(out.finish(Format::Rar5));
            }
            // Any other type. unrar and unar skip the header and its data area, its fields unread, whether
            // or not it carries HFL_SKIPIFUNKNOWN (0x0004), a flag that tells an archiver what to do with the
            // block when updating the archive. 7-Zip stops there with an error, having written only the
            // members before it. The crate skips it too, except where some extractor reads it otherwise:
            // - unrar keeps a header's type in 32 bits, so a type over that is read as its low 32 bits
            //   (2^32 + 2 is a file header it writes; 2^32 + 5 ends the archive);
            // - libarchive (bsdtar) takes type 0 for its end marker and stops there without an error;
            // - libarchive skips a header with HFL_SKIPIFUNKNOWN by reading the next block right after its
            //   flags field, so sizes, fields or an extra area after it are read as headers (a file block
            //   there is written);
            // - libarchive ends the archive, without an error, at a header with HFL_SKIPIFUNKNOWN whose
            //   flags field takes ten bytes (a non-minimal encoding, or bit 63 set), so the members after
            //   it are not written by bsdtar.
            _ if kind > u64::from(u32::MAX) => {
                return Err(Error::Ambiguous("a RAR5 header type over 32 bits (unrar reads its low 32 bits)"));
            }
            0 => return Err(Error::Ambiguous("a RAR5 header of type 0 (libarchive ends the archive there)")),
            _ if flags & 4 != 0 && (flags & 3 != 0 || cursor.remaining() > 0) => {
                return Err(Error::Ambiguous("an unknown RAR5 header that libarchive reads into and unrar skips"));
            }
            _ if flags & 4 != 0 && flags_width == 10 => {
                return Err(Error::Ambiguous(
                    "an unknown RAR5 header whose flags take ten bytes (libarchive ends the archive there)"));
            }
            _ => {
                // An extra area that does not fit in the header is refused. unrar refuses one only when it
                // is at least the whole header's size, so this is stricter than unrar, and a refusal.
                if extra_size > cursor.remaining() { return Err(Error::Corrupt("RAR5 extra-area size mismatch")); }
                out.reserve_metadata(header_size.saturating_add(data_size))?;
            }
        }
        pos = payload_end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vi(mut n: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 { b |= 0x80; }
            out.push(b);
            if n == 0 { break; }
        }
    }

    fn rar4_block(kind: u8, flags: u16, body: &[u8], payload: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        out.resize(out.len() + 7, 0);
        out.extend_from_slice(body);
        let header_size = out.len() - start;
        out[start + 2] = kind;
        out[start + 3..start + 5].copy_from_slice(&flags.to_le_bytes());
        out[start + 5..start + 7].copy_from_slice(&(header_size as u16).to_le_bytes());
        let crc = (crc32(0, &out[start + 2..start + header_size]) & 0xffff) as u16;
        out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(payload);
    }

    fn rar4_file(name: &str, payload: &[u8], method: u8, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        body.push(0);
        body.extend_from_slice(&crc32(0, payload).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(20);
        body.push(method);
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        rar4_block(0x74, 0x8000, &body, payload, out);
    }

    fn rar4(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"Rar!\x1a\x07\x00".to_vec();
        rar4_block(0x73, 0, &[0; 6], &[], &mut out);
        for &(name, data) in entries { rar4_file(name, data, 0x30, &mut out); }
        rar4_block(0x7b, 0, &[], &[], &mut out);
        out
    }

    fn rar5_block(kind: u64, specific: &[u8], extra_data: &[u8], payload: &[u8], out: &mut Vec<u8>) {
        rar5_block_flags(kind, 0, specific, extra_data, payload, out);
    }

    fn rar5_block_flags(kind: u64, flags: u64, specific: &[u8], extra_data: &[u8], payload: &[u8], out: &mut Vec<u8>) {
        let mut body = Vec::new();
        vi(kind, &mut body);
        let flags = flags | if extra_data.is_empty() { 0 } else { 1 } | if payload.is_empty() { 0 } else { 2 };
        vi(flags, &mut body);
        if !extra_data.is_empty() { vi(extra_data.len() as u64, &mut body); }
        if !payload.is_empty() { vi(payload.len() as u64, &mut body); }
        body.extend_from_slice(specific);
        body.extend_from_slice(extra_data);
        let mut framed = Vec::new();
        vi(body.len() as u64, &mut framed);
        framed.extend_from_slice(&body);
        out.extend_from_slice(&crc32(0, &framed).to_le_bytes());
        out.extend_from_slice(&framed);
        out.extend_from_slice(payload);
    }

    fn rar5_file(name: &str, payload: &[u8], compression: u64, extra_data: &[u8], out: &mut Vec<u8>) {
        let mut specific = Vec::new();
        vi(4, &mut specific);                              // CRC32 present
        vi(payload.len() as u64, &mut specific);
        vi(0, &mut specific);                              // attributes
        specific.extend_from_slice(&crc32(0, payload).to_le_bytes());
        vi(compression, &mut specific);
        vi(0, &mut specific);                              // host OS
        vi(name.len() as u64, &mut specific);
        specific.extend_from_slice(name.as_bytes());
        rar5_block(2, &specific, extra_data, payload, out);
    }

    fn rar5(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
        rar5_block(1, &[0], &[], &[], &mut out);
        for &(name, data) in entries { rar5_file(name, data, 0, &[], &mut out); }
        rar5_block(5, &[0], &[], &[], &mut out);
        out
    }

    #[test]
    fn rar4_stored_file() {
        let got = extract4(&rar4(&[("a.txt", b"hello")]), Limits::default()).unwrap();
        assert_eq!(got.entries[0].name, "a.txt");
        assert_eq!(got.entries[0].data, b"hello");
    }

    #[test]
    fn rar5_stored_file() {
        let got = extract5(&rar5(&[("a.txt", b"hello")]), Limits::default()).unwrap();
        assert_eq!(got.entries[0].name, "a.txt");
        assert_eq!(got.entries[0].data, b"hello");
    }

    #[test]
    fn compressed_members_are_explicitly_unsupported() {
        let mut four = b"Rar!\x1a\x07\x00".to_vec();
        rar4_block(0x73, 0, &[0; 6], &[], &mut four);
        rar4_file("a", b"hello", 0x33, &mut four);
        rar4_block(0x7b, 0, &[], &[], &mut four);
        assert_eq!(extract4(&four, Limits::default()), Err(Error::Unsupported("compressed RAR4 member")));

        let mut five = b"Rar!\x1a\x07\x01\x00".to_vec();
        rar5_block(1, &[0], &[], &[], &mut five);
        rar5_file("a", b"hello", 1 << 7, &[], &mut five);
        rar5_block(5, &[0], &[], &[], &mut five);
        assert_eq!(extract5(&five, Limits::default()), Err(Error::Unsupported("compressed RAR5 member")));
    }

    #[test]
    fn member_crc_is_enforced() {
        let mut good = rar5(&[("a", b"hello")]);
        // Five payload bytes precede the eight-byte end block. Do not search for
        // the payload's first byte: it could also occur inside a header CRC.
        let at = good.len() - 13;
        assert_eq!(good[at], b'h');
        good[at] ^= 1;
        assert_eq!(extract5(&good, Limits::default()), Err(Error::Checksum("RAR5 member")));
    }

    /// An archive of a.txt and b.txt with `block` between them.
    fn rar5_around(block: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
        let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
        rar5_block(1, &[0], &[], &[], &mut out);
        rar5_file("a.txt", b"benign a", 0, &[], &mut out);
        block(&mut out);
        rar5_file("b.txt", b"benign b", 0, &[], &mut out);
        rar5_block(5, &[0], &[], &[], &mut out);
        out
    }

    fn names(archive: &crate::Archive) -> Vec<&str> {
        archive.entries.iter().map(|e| e.name.as_str()).collect()
    }

    #[test]
    fn unknown_rar5_headers_are_skipped_as_unrar_skips_them() {
        // unrar 7.00 and unar write a.txt and b.txt for each of these; 7-Zip stops at the header with an
        // error after a.txt; bsdtar stops with an error at an unknown header without HFL_SKIPIFUNKNOWN (4).
        let hidden: &[u8] = b"bytes in the unknown header's data area";
        let mut record = Vec::new();
        vi(3, &mut record);
        vi(9, &mut record);                                // an unknown extra record type
        record.extend_from_slice(b"xy");
        for kind in [6, 127, 200, u64::from(u32::MAX)] {
            // Without the flag: any body, extra area or data area.
            for flags in [0, 0x08, 0x10, 0x20, 0x40] {
                for (specific, extra_data, payload) in [
                    (&b""[..], &[][..], &[][..]),
                    (&b""[..], &[][..], hidden),
                    (&b"\x05\x00junk"[..], &[][..], &[][..]),
                    (&b""[..], &record[..], &[][..]),
                    (&b"\x07\x01zz"[..], &record[..], hidden),
                ] {
                    let input = rar5_around(|out| rar5_block_flags(kind, flags, specific, extra_data, payload, out));
                    let got = extract5(&input, Limits::default())
                        .unwrap_or_else(|e| panic!("kind {kind} flags {flags:#x}: {e:?}"));
                    assert_eq!(names(&got), ["a.txt", "b.txt"], "kind {kind} flags {flags:#x}");
                    assert_eq!(got.entries[1].data, b"benign b");
                }
            }
            // With the flag and nothing after the flags field, where libarchive reads on from too.
            for flags in [4, 4 | 0x08, 4 | 0x10, 4 | 0x20, 4 | 0x40] {
                let input = rar5_around(|out| rar5_block_flags(kind, flags, &[], &[], &[], out));
                assert_eq!(names(&extract5(&input, Limits::default()).unwrap()), ["a.txt", "b.txt"]);
            }
        }
        // Before the main header, and twice in a row.
        let mut early = b"Rar!\x1a\x07\x01\x00".to_vec();
        rar5_block_flags(6, 4, &[], &[], &[], &mut early);
        early.extend_from_slice(&rar5(&[("a.txt", b"benign a")])[8..]);
        assert_eq!(names(&extract5(&early, Limits::default()).unwrap()), ["a.txt"]);
        let twice = rar5_around(|out| {
            rar5_block_flags(6, 0, &[], &[], &[], out);
            rar5_block_flags(7, 4, &[], &[], &[], out);
        });
        assert_eq!(names(&extract5(&twice, Limits::default()).unwrap()), ["a.txt", "b.txt"]);
    }

    #[test]
    fn unknown_rar5_headers_other_extractors_read_are_ambiguous() {
        let ambiguous = |input: &[u8]| matches!(extract5(input, Limits::default()), Err(Error::Ambiguous(_)));
        // unrar reads a type of 2^32 or more by its low 32 bits: 2^32 + 2 is a file header it writes,
        // 2^32 + 5 ends the archive.
        for kind in [1u64 << 32, (1 << 32) + 2, (1 << 32) + 5, (1 << 34) + 2, u64::MAX] {
            for flags in [0, 4] {
                let input = rar5_around(|out| rar5_block_flags(kind, flags, &[], &[], &[], out));
                assert!(ambiguous(&input), "kind {kind:#x} flags {flags:#x}");
            }
        }
        // libarchive ends the archive at type 0.
        for flags in [0, 4] {
            assert!(ambiguous(&rar5_around(|out| rar5_block_flags(0, flags, &[], &[], &[], out))));
        }
        // With HFL_SKIPIFUNKNOWN, libarchive reads on right after the flags field: a file block in the
        // header's body, or in its data area after the size field, is written by bsdtar.
        let mut inner = Vec::new();
        rar5_file("hidden.txt", b"not skipped by bsdtar", 0, &[], &mut inner);
        let mut record = Vec::new();
        vi(2, &mut record);
        vi(2, &mut record);
        record.extend_from_slice(&[0; 1]);
        for (specific, extra_data, payload) in [
            (&inner[..], &[][..], &[][..]),
            (&b""[..], &[][..], &inner[..]),
            (&b""[..], &record[..], &[][..]),
            (&b"\x05\x00junk"[..], &[][..], &[][..]),
        ] {
            let input = rar5_around(|out| rar5_block_flags(6, 4, specific, extra_data, payload, out));
            assert!(ambiguous(&input));
        }
        // libarchive ends the archive without an error (bsdtar writes a.txt only) at a flagged header whose
        // flags field takes ten bytes: the value 4 in a non-minimal encoding, or 4 with bit 63 set. These
        // are the external review's fe_flags_nonminimal10 and fe_flags_hi63; unrar and unar write both.
        for flags in [[0x84, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
                      [0x84, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]] {
            for kind in [6, 127, 200, u64::from(u32::MAX)] {
                let mut body = Vec::new();
                vi(kind, &mut body);
                body.extend_from_slice(&flags);
                assert!(ambiguous(&rar5_around(|out| rar5_raw(&body, out))), "kind {kind} flags {flags:x?}");
            }
        }
    }

    /// A RAR5 block of `body` (its type, flags and the rest, as given), framed with its size and CRC.
    fn rar5_raw(body: &[u8], out: &mut Vec<u8>) {
        let mut framed = Vec::new();
        vi(body.len() as u64, &mut framed);
        framed.extend_from_slice(body);
        out.extend_from_slice(&crc32(0, &framed).to_le_bytes());
        out.extend_from_slice(&framed);
    }

    #[test]
    fn wide_flags_without_the_ten_byte_skip_shape_are_still_skipped() {
        // Controls for the ten-byte case above. A flagged header whose flags take nine bytes (bit 56 set),
        // and an unflagged one whose flags take ten (0 non-minimal, or bit 63 alone), are skipped as unrar
        // and unar skip them. bsdtar writes both members from the first and stops with an error at the others.
        let around = |body: &[u8]| rar5_around(|out| rar5_raw(body, out));
        let mut nine = Vec::new();
        vi(6, &mut nine);
        vi(4 | (1 << 56), &mut nine);
        assert_eq!(nine.len(), 10);                        // one byte of type, nine of flags
        assert_eq!(names(&extract5(&around(&nine), Limits::default()).unwrap()), ["a.txt", "b.txt"]);
        for flags in [[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
                      [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]] {
            let mut body = Vec::new();
            vi(6, &mut body);
            body.extend_from_slice(&flags);
            assert_eq!(names(&extract5(&around(&body), Limits::default()).unwrap()), ["a.txt", "b.txt"]);
        }
    }

    #[test]
    fn a_skipped_header_s_data_area_is_not_read_as_headers() {
        // A whole file block inside an unflagged unknown header's data area: unrar, unar and the crate skip
        // it; 7-Zip and bsdtar stop with an error at the header.
        let mut inner = Vec::new();
        rar5_file("hidden.txt", b"not a member", 0, &[], &mut inner);
        let input = rar5_around(|out| rar5_block_flags(6, 0, &[], &[], &inner, out));
        assert_eq!(names(&extract5(&input, Limits::default()).unwrap()), ["a.txt", "b.txt"]);
    }

    #[test]
    fn unknown_rar5_headers_stay_bounded_and_checked() {
        // An extra area that does not fit in the header is refused.
        let mut body = Vec::new();
        vi(6, &mut body);
        vi(1, &mut body);
        vi(50, &mut body);
        let mut framed = Vec::new();
        vi(body.len() as u64, &mut framed);
        framed.extend_from_slice(&body);
        let input = rar5_around(|out| {
            out.extend_from_slice(&crc32(0, &framed).to_le_bytes());
            out.extend_from_slice(&framed);
        });
        assert_eq!(extract5(&input, Limits::default()), Err(Error::Corrupt("RAR5 extra-area size mismatch")));

        // The header CRC is still checked.
        let mut bad = rar5_around(|out| rar5_block_flags(6, 4, &[], &[], &[], out));
        let a_end = 8 + {
            let mut probe = Vec::new();
            rar5_block(1, &[0], &[], &[], &mut probe);
            rar5_file("a.txt", b"benign a", 0, &[], &mut probe);
            probe.len()
        };
        bad[a_end] ^= 1;
        assert_eq!(extract5(&bad, Limits::default()), Err(Error::Checksum("RAR5 header")));

        // Skipped headers and their data count against the metadata budget and the header count.
        let big = vec![b'z'; 4096];
        let input = rar5_around(|out| rar5_block_flags(6, 0, &[], &[], &big, out));
        let tight = Limits { max_metadata_size: 1024, ..Limits::default() };
        assert!(matches!(extract5(&input, tight), Err(Error::Limit(_))));
        let flood = rar5_around(|out| for _ in 0..64 { rar5_block_flags(6, 4, &[], &[], &[], out) });
        let few = Limits { max_entries: 16, ..Limits::default() };
        assert_eq!(extract5(&flood, few), Err(Error::Limit("RAR header count")));
    }

    #[test]
    fn paths_and_encryption_fail_closed() {
        assert!(matches!(extract5(&rar5(&[("../x", b"x")]), Limits::default()), Err(Error::InvalidPath(_))));
        let mut encrypted = b"Rar!\x1a\x07\x01\x00".to_vec();
        rar5_block(1, &[0], &[], &[], &mut encrypted);
        rar5_file("a", b"hello", 0, &[2, 1, 0], &mut encrypted);
        assert_eq!(extract5(&encrypted, Limits::default()), Err(Error::Unsupported("encrypted RAR5 member")));
    }
}
