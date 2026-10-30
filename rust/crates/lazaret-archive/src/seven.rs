//! 7-Zip container parsing with Copy, DEFLATE, LZMA1 and LZMA2 coders.
//!
//! Simple one-input/one-output folders are supported, including encoded headers
//! and multiple files in a folder. Coder chains, encryption, external metadata,
//! additional streams and special entries are refused rather than guessed.

use crate::{lzma, Builder, EntryKind, Error, Format, Limits, Result};
use lazaret_verify::inflate::{self, crc32};

const SIGNATURE_SIZE: usize = 32;
const END: u8 = 0x00;
const HEADER: u8 = 0x01;
const MAIN_STREAMS: u8 = 0x04;
const FILES_INFO: u8 = 0x05;
const PACK_INFO: u8 = 0x06;
const UNPACK_INFO: u8 = 0x07;
const SUBSTREAMS_INFO: u8 = 0x08;
const SIZE: u8 = 0x09;
const CRC: u8 = 0x0a;
const FOLDER: u8 = 0x0b;
const CODERS_UNPACK_SIZE: u8 = 0x0c;
const NUM_UNPACK_STREAM: u8 = 0x0d;
const EMPTY_STREAM: u8 = 0x0e;
const EMPTY_FILE: u8 = 0x0f;
const ANTI: u8 = 0x10;
const NAME: u8 = 0x11;
const ENCODED_HEADER: u8 = 0x17;

fn usize64(value: u64, what: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::Limit(what))
}

fn count(value: u64, maximum: usize, what: &'static str) -> Result<usize> {
    let value = usize64(value, what)?;
    if value > maximum { return Err(Error::Limit(what)); }
    Ok(value)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Cursor<'a> { Cursor { data, pos: 0 } }
    fn done(&self) -> bool { self.pos == self.data.len() }
    fn byte(&mut self) -> Result<u8> {
        let byte = *self.data.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(byte)
    }
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(size).ok_or(Error::Limit("7-Zip field size"))?;
        let out = self.data.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(out)
    }
    fn uint(&mut self) -> Result<u64> {
        let first = self.byte()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                value |= u64::from(first & (mask - 1)) << (i * 8);
                return Ok(value);
            }
            value |= u64::from(self.byte()?) << (i * 8);
            mask >>= 1;
        }
        Ok(value)
    }
    fn external(&mut self) -> Result<()> {
        if self.byte()? == 0 { Ok(()) } else { Err(Error::Unsupported("external 7-Zip metadata")) }
    }
}

fn bitset(cursor: &mut Cursor<'_>, count: usize) -> Result<Vec<bool>> {
    let bytes = count.checked_add(7).ok_or(Error::Limit("7-Zip bit set"))? / 8;
    let raw = cursor.take(bytes)?;
    Ok((0..count).map(|i| raw[i / 8] & (0x80 >> (i % 8)) != 0).collect())
}

fn digests(cursor: &mut Cursor<'_>, count: usize) -> Result<Vec<Option<u32>>> {
    let defined = if cursor.byte()? != 0 {
        vec![true; count]
    } else {
        bitset(cursor, count)?
    };
    let mut out = Vec::with_capacity(count);
    for present in defined {
        if present {
            let b = cursor.take(4)?;
            out.push(Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]])));
        } else {
            out.push(None);
        }
    }
    Ok(out)
}

#[derive(Clone, Copy)]
enum Method {
    Copy,
    Deflate,
    Lzma,
    Lzma2,
}

struct Folder {
    method: Method,
    properties: Vec<u8>,
    unpack_size: u64,
    crc: Option<u32>,
    sub_sizes: Vec<u64>,
    sub_crcs: Vec<Option<u32>>,
}

struct Pack {
    position: u64,
    sizes: Vec<u64>,
    offsets: Vec<u64>,
    crcs: Vec<Option<u32>>,
}

struct Streams {
    pack: Pack,
    folders: Vec<Folder>,
}

impl Streams {
    fn empty() -> Streams {
        Streams { pack: Pack { position: 0, sizes: Vec::new(), offsets: Vec::new(), crcs: Vec::new() }, folders: Vec::new() }
    }
}

fn parse_pack(cursor: &mut Cursor<'_>, limits: Limits) -> Result<Pack> {
    let position = cursor.uint()?;
    let count = count(cursor.uint()?, limits.max_entries, "7-Zip packed stream count")?;
    let mut sizes = None;
    let mut crcs = None;
    loop {
        match cursor.byte()? {
            SIZE => {
                if sizes.is_some() { return Err(Error::Corrupt("duplicate 7-Zip packed sizes")); }
                let mut values = Vec::with_capacity(count);
                for _ in 0..count { values.push(cursor.uint()?); }
                sizes = Some(values);
            }
            CRC => {
                if crcs.is_some() { return Err(Error::Corrupt("duplicate 7-Zip packed CRCs")); }
                crcs = Some(digests(cursor, count)?);
            }
            END => break,
            _ => return Err(Error::Unsupported("7-Zip pack information")),
        }
    }
    let sizes = sizes.ok_or(Error::Corrupt("7-Zip packed sizes are missing"))?;
    let mut offset = 0u64;
    let mut offsets = Vec::with_capacity(sizes.len());
    for &size in &sizes {
        offsets.push(offset);
        offset = offset.checked_add(size).ok_or(Error::Limit("7-Zip packed position"))?;
    }
    Ok(Pack {
        position,
        sizes,
        offsets,
        crcs: crcs.unwrap_or_else(|| vec![None; count]),
    })
}

fn method(id: &[u8]) -> Result<Method> {
    match id {
        [0] => Ok(Method::Copy),
        [3, 1, 1] => Ok(Method::Lzma),
        [0x21] => Ok(Method::Lzma2),
        [4, 1, 8] => Ok(Method::Deflate),
        [6, 0xf1, 7, 1] => Err(Error::Unsupported("encrypted 7-Zip member")),
        _ => Err(Error::Unsupported("7-Zip codec or filter")),
    }
}

fn parse_folder(cursor: &mut Cursor<'_>, limits: Limits) -> Result<Folder> {
    let coder_count = cursor.uint()?;
    if coder_count != 1 { return Err(Error::Unsupported("7-Zip coder chains")); }
    let flags = cursor.byte()?;
    if flags & 0xc0 != 0 { return Err(Error::Unsupported("alternative 7-Zip coders")); }
    if flags & 0x10 != 0 { return Err(Error::Unsupported("multi-stream 7-Zip coders")); }
    let id_size = usize::from(flags & 0x0f);
    if id_size == 0 { return Err(Error::Corrupt("empty 7-Zip codec ID")); }
    let codec = method(cursor.take(id_size)?)?;
    let properties = if flags & 0x20 != 0 {
        let size = count(cursor.uint()?, usize64(limits.max_metadata_size, "7-Zip properties")?, "7-Zip properties")?;
        cursor.take(size)?.to_vec()
    } else {
        Vec::new()
    };
    Ok(Folder {
        method: codec,
        properties,
        unpack_size: 0,
        crc: None,
        sub_sizes: Vec::new(),
        sub_crcs: Vec::new(),
    })
}

fn parse_unpack(cursor: &mut Cursor<'_>, limits: Limits) -> Result<Vec<Folder>> {
    if cursor.byte()? != FOLDER { return Err(Error::Corrupt("7-Zip folders are missing")); }
    let folder_count = count(cursor.uint()?, limits.max_entries, "7-Zip folder count")?;
    cursor.external()?;
    let mut folders = Vec::with_capacity(folder_count);
    for _ in 0..folder_count { folders.push(parse_folder(cursor, limits)?); }
    if cursor.byte()? != CODERS_UNPACK_SIZE { return Err(Error::Corrupt("7-Zip unpack sizes are missing")); }
    for folder in &mut folders { folder.unpack_size = cursor.uint()?; }
    let mut crcs = vec![None; folder_count];
    let mut have_crcs = false;
    loop {
        match cursor.byte()? {
            CRC => {
                if have_crcs { return Err(Error::Corrupt("duplicate 7-Zip folder CRCs")); }
                have_crcs = true;
                crcs = digests(cursor, folder_count)?;
            }
            END => break,
            _ => return Err(Error::Unsupported("7-Zip unpack information")),
        }
    }
    for (folder, crc) in folders.iter_mut().zip(crcs) { folder.crc = crc; }
    Ok(folders)
}

fn parse_substreams(cursor: &mut Cursor<'_>, folders: &mut [Folder], limits: Limits) -> Result<()> {
    let mut counts = vec![1u64; folders.len()];
    let mut have_sizes = false;
    let mut have_crcs = false;
    let mut have_counts = false;
    loop {
        match cursor.byte()? {
            NUM_UNPACK_STREAM => {
                if have_counts || have_sizes || have_crcs { return Err(Error::Corrupt("duplicate or late 7-Zip substream counts")); }
                have_counts = true;
                for value in &mut counts { *value = cursor.uint()?; }
                let total = counts.iter().try_fold(0u64, |sum, &n| sum.checked_add(n))
                    .ok_or(Error::Limit("7-Zip substream count"))?;
                count(total, limits.max_entries, "7-Zip substream count")?;
            }
            SIZE => {
                if have_sizes || have_crcs { return Err(Error::Corrupt("duplicate or late 7-Zip substream sizes")); }
                have_sizes = true;
                for (folder, &count) in folders.iter_mut().zip(&counts) {
                    let count = usize64(count, "7-Zip substream count")?;
                    if count == 0 { continue; }
                    folder.sub_sizes = Vec::with_capacity(count);
                    let mut sum = 0u64;
                    for _ in 0..count - 1 {
                        let size = cursor.uint()?;
                        sum = sum.checked_add(size).ok_or(Error::Limit("7-Zip substream size"))?;
                        folder.sub_sizes.push(size);
                    }
                    let last = folder.unpack_size.checked_sub(sum).ok_or(Error::Corrupt("7-Zip substream sizes exceed the folder"))?;
                    folder.sub_sizes.push(last);
                }
            }
            CRC => {
                if have_crcs { return Err(Error::Corrupt("duplicate 7-Zip substream CRCs")); }
                have_crcs = true;
                let digest_count = folders.iter().zip(&counts).try_fold(0usize, |sum, (folder, &count)| {
                    if count == 1 && folder.crc.is_some() { Ok(sum) } else { sum.checked_add(count as usize).ok_or(Error::Limit("7-Zip digest count")) }
                })?;
                let values = digests(cursor, digest_count)?;
                let mut at = 0usize;
                for (folder, &count) in folders.iter_mut().zip(&counts) {
                    if count == 1 && folder.crc.is_some() {
                        folder.sub_crcs = vec![folder.crc];
                    } else {
                        let end = at + count as usize;
                        folder.sub_crcs = values[at..end].to_vec();
                        at = end;
                    }
                }
            }
            END => break,
            _ => return Err(Error::Unsupported("7-Zip substream information")),
        }
    }
    for (folder, &count) in folders.iter_mut().zip(&counts) {
        let count = usize64(count, "7-Zip substream count")?;
        if count == 0 {
            if folder.unpack_size != 0 { return Err(Error::Corrupt("empty 7-Zip folder has data")); }
            folder.sub_sizes.clear();
        } else if folder.sub_sizes.is_empty() {
            if count != 1 { return Err(Error::Corrupt("7-Zip substream sizes are missing")); }
            folder.sub_sizes.push(folder.unpack_size);
        }
        if folder.sub_sizes.iter().try_fold(0u64, |sum, &n| sum.checked_add(n)) != Some(folder.unpack_size) {
            return Err(Error::Corrupt("7-Zip substream size mismatch"));
        }
        if folder.sub_sizes.len() != count { return Err(Error::Corrupt("7-Zip substream count mismatch")); }
        if folder.sub_crcs.is_empty() { folder.sub_crcs = vec![None; count]; }
    }
    Ok(())
}

fn parse_streams(cursor: &mut Cursor<'_>, limits: Limits) -> Result<Streams> {
    // In 7-Zip's one order: pack, unpack, substreams, each at most once (7-Zip refuses any other; unar reads
    // some of them differently).
    let mut pack = None;
    let mut folders = None;
    let mut substreams_seen = false;
    let mut id = cursor.byte()?;
    if id == PACK_INFO {
        pack = Some(parse_pack(cursor, limits)?);
        id = cursor.byte()?;
    }
    if id == UNPACK_INFO {
        folders = Some(parse_unpack(cursor, limits)?);
        id = cursor.byte()?;
    }
    if id == SUBSTREAMS_INFO {
        substreams_seen = true;
        let folders = folders.as_mut().ok_or(Error::Corrupt("7-Zip substreams precede folders"))?;
        parse_substreams(cursor, folders, limits)?;
        id = cursor.byte()?;
    }
    match id {
        END => {}
        PACK_INFO | UNPACK_INFO | SUBSTREAMS_INFO => return Err(Error::Corrupt("7-Zip streams information out of order")),
        _ => return Err(Error::Unsupported("7-Zip streams information")),
    }
    let pack = pack.unwrap_or(Pack { position: 0, sizes: Vec::new(), offsets: Vec::new(), crcs: Vec::new() });
    let mut folders = folders.unwrap_or_default();
    if !substreams_seen {
        // Default: one substream per folder, inheriting any folder CRC.
        for folder in &mut folders {
            folder.sub_sizes = vec![folder.unpack_size];
            folder.sub_crcs = vec![folder.crc];
        }
    }
    if pack.sizes.len() != folders.len() { return Err(Error::Corrupt("7-Zip folder/packed-stream mismatch")); }
    Ok(Streams { pack, folders })
}

struct File {
    name: String,
    empty_stream: bool,
    empty_file: bool,
}

fn names(data: &[u8], count: usize) -> Result<Vec<String>> {
    let mut cursor = Cursor::new(data);
    cursor.external()?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut units = Vec::new();
        loop {
            let b = cursor.take(2)?;
            let unit = u16::from_le_bytes([b[0], b[1]]);
            if unit == 0 { break; }
            units.push(unit);
        }
        out.push(String::from_utf16(&units).map_err(|_| Error::Corrupt("7-Zip name is not UTF-16"))?);
    }
    if !cursor.done() { return Err(Error::Corrupt("data follows 7-Zip names")); }
    Ok(out)
}

fn parse_files(cursor: &mut Cursor<'_>, limits: Limits) -> Result<Vec<File>> {
    let file_count = count(cursor.uint()?, limits.max_entries, "7-Zip file count")?;
    let mut file_names = None;
    let mut empty_streams = None;
    let mut empty_files = None;
    let mut anti = None;
    let mut attributes = None;
    loop {
        let property = cursor.byte()?;
        if property == END { break; }
        let size = count(cursor.uint()?, usize64(limits.max_metadata_size, "7-Zip file property")?, "7-Zip file property")?;
        let data = cursor.take(size)?;
        match property {
            NAME => {
                if file_names.is_some() { return Err(Error::Corrupt("duplicate 7-Zip names")); }
                file_names = Some(names(data, file_count)?);
            }
            EMPTY_STREAM => {
                if empty_streams.is_some() { return Err(Error::Corrupt("duplicate 7-Zip empty streams")); }
                let mut property_cursor = Cursor::new(data);
                empty_streams = Some(bitset(&mut property_cursor, file_count)?);
                if !property_cursor.done() { return Err(Error::Corrupt("7-Zip empty-stream bit set")) }
            }
            EMPTY_FILE | ANTI => {
                if (property == EMPTY_FILE && empty_files.is_some()) || (property == ANTI && anti.is_some()) {
                    return Err(Error::Corrupt("duplicate 7-Zip empty-file or anti property"));
                }
                let empty_count = empty_streams.as_ref().ok_or(Error::Corrupt("7-Zip empty files precede empty streams"))?
                    .iter().filter(|&&empty| empty).count();
                let mut property_cursor = Cursor::new(data);
                let values = bitset(&mut property_cursor, empty_count)?;
                if !property_cursor.done() { return Err(Error::Corrupt("7-Zip empty-file bit set")); }
                if property == EMPTY_FILE { empty_files = Some(values); } else { anti = Some(values); }
            }
            0x15 => { // Attributes can encode symlinks, devices and reparse points.
                if attributes.is_some() { return Err(Error::Corrupt("duplicate 7-Zip attributes")); }
                let values = fixed_properties(data, file_count, 4)?;
                attributes = Some(values.into_iter().map(|v| v.map(|v| v as u32)).collect::<Vec<_>>());
            }
            0x12..=0x14 => { fixed_properties(data, file_count, 8)?; } // creation/access/modification time
            0x19 if data.iter().all(|&b| b == 0) => {} // padding
            _ => return Err(Error::Unsupported("7-Zip file property")),
        }
    }
    let file_names = file_names.ok_or(Error::Corrupt("7-Zip names are missing"))?;
    let empty_streams = empty_streams.unwrap_or_else(|| vec![false; file_count]);
    let empty_files = empty_files.unwrap_or_else(|| vec![false; empty_streams.iter().filter(|&&empty| empty).count()]);
    let anti = anti.unwrap_or_else(|| vec![false; empty_files.len()]);
    if anti.iter().any(|&value| value) { return Err(Error::Unsupported("7-Zip anti entries")); }
    let mut files = Vec::with_capacity(file_count);
    let mut empty_at = 0usize;
    for (index, (name, empty_stream)) in file_names.into_iter().zip(empty_streams).enumerate() {
        let empty_file = if empty_stream {
            let value = empty_files.get(empty_at).copied().ok_or(Error::Corrupt("7-Zip empty-file count"))?;
            empty_at += 1;
            value
        } else {
            false
        };
        if let Some(attr) = attributes.as_ref().and_then(|a| a[index]) {
            if attr & 0x400 != 0 { return Err(Error::Unsupported("7-Zip reparse point")); }
            // 7-Zip takes a Unix file type from the high 16 bits whether or not FILE_ATTRIBUTE_UNIX_EXTENSION
            // (0x8000) is set: S_IFLNK there is extracted as a symlink. So the type is read either way.
            let unix_type = (attr >> 16) & 0o170000;
            if !matches!(unix_type, 0 | 0o100000 | 0o040000) { return Err(Error::Unsupported("7-Zip special file")); }
            let directory = empty_stream && !empty_file;
            if (unix_type != 0 && (unix_type == 0o040000) != directory) || (attr & 0x10 != 0) != directory {
                return Err(Error::Corrupt("7-Zip file attributes disagree with entry type"));
            }
        }
        files.push(File { name, empty_stream, empty_file });
    }
    Ok(files)
}

fn fixed_properties(data: &[u8], count: usize, width: usize) -> Result<Vec<Option<u64>>> {
    let mut cursor = Cursor::new(data);
    let defined = match cursor.byte()? {
        0 => bitset(&mut cursor, count)?,
        1 => vec![true; count],
        _ => return Err(Error::Corrupt("7-Zip property definition flag")),
    };
    cursor.external()?;
    let mut values = Vec::with_capacity(count);
    for present in defined {
        if present {
            let raw = cursor.take(width)?;
            let mut bytes = [0u8; 8];
            bytes[..width].copy_from_slice(raw);
            values.push(Some(u64::from_le_bytes(bytes)));
        } else { values.push(None); }
    }
    if !cursor.done() { return Err(Error::Corrupt("data follows 7-Zip property")); }
    Ok(values)
}

fn parse_header(data: &[u8], limits: Limits) -> Result<(Streams, Vec<File>)> {
    let mut cursor = Cursor::new(data);
    if cursor.byte()? != HEADER { return Err(Error::Corrupt("7-Zip header is missing")); }
    let mut streams = None;
    let mut files = None;
    loop {
        match cursor.byte()? {
            MAIN_STREAMS => {
                if streams.is_some() { return Err(Error::Corrupt("duplicate 7-Zip main streams")); }
                streams = Some(parse_streams(&mut cursor, limits)?);
            }
            FILES_INFO => {
                if files.is_some() { return Err(Error::Corrupt("duplicate 7-Zip file information")); }
                files = Some(parse_files(&mut cursor, limits)?);
            }
            END => break,
            _ => return Err(Error::Unsupported("7-Zip header feature")),
        }
    }
    if !cursor.done() { return Err(Error::Corrupt("data follows the 7-Zip header")); }
    Ok((streams.unwrap_or_else(Streams::empty), files.ok_or(Error::Corrupt("7-Zip file information is missing"))?))
}

fn inflate_error(error: inflate::Error) -> Error {
    match error {
        inflate::Error::Corrupt(_) => Error::Corrupt("7-Zip DEFLATE stream"),
        inflate::Error::Truncated => Error::Truncated,
        inflate::Error::Checksum(_) => Error::Checksum("7-Zip DEFLATE"),
        inflate::Error::OutputLimit { .. } | inflate::Error::RatioLimit { .. } => Error::Limit("7-Zip output"),
        inflate::Error::Unsupported(_) => Error::Unsupported("7-Zip DEFLATE feature"),
        _ => Error::Unsupported("unknown inflate error"),
    }
}

fn decode_folder(data: &[u8], region_end: usize, streams: &Streams, index: usize, output_limit: u64) -> Result<Vec<u8>> {
    let folder = streams.folders.get(index).ok_or(Error::Corrupt("7-Zip folder index"))?;
    if folder.unpack_size > output_limit { return Err(Error::Limit("7-Zip output")); }
    let expected = usize64(folder.unpack_size, "7-Zip output")?;
    let previous = streams.pack.offsets[index];
    let relative = streams.pack.position.checked_add(previous).ok_or(Error::Limit("7-Zip packed position"))?;
    let start = SIGNATURE_SIZE.checked_add(usize64(relative, "7-Zip packed position")?).ok_or(Error::Limit("7-Zip packed position"))?;
    let packed_size = usize64(streams.pack.sizes[index], "7-Zip packed size")?;
    let end = start.checked_add(packed_size).ok_or(Error::Limit("7-Zip packed size"))?;
    if end > region_end { return Err(Error::Corrupt("7-Zip packed data overlaps its header")); }
    let packed = data.get(start..end).ok_or(Error::Truncated)?;
    if let Some(crc) = streams.pack.crcs[index] {
        if crc32(0, packed) != crc { return Err(Error::Checksum("7-Zip packed stream")); }
    }
    let decoded = match folder.method {
        Method::Copy => {
            if !folder.properties.is_empty() { return Err(Error::Corrupt("7-Zip Copy properties")); }
            if packed.len() != expected { return Err(Error::Corrupt("7-Zip Copy size mismatch")); }
            packed.to_vec()
        }
        Method::Deflate => {
            if !folder.properties.is_empty() { return Err(Error::Corrupt("7-Zip DEFLATE properties")); }
            inflate::decode_all(inflate::Format::Deflate, packed, inflate::Limits::new(folder.unpack_size)).map_err(inflate_error)?
        }
        Method::Lzma => lzma::decode_lzma(packed, &folder.properties, expected)?,
        Method::Lzma2 => lzma::decode_lzma2(packed, &folder.properties, expected)?,
    };
    if decoded.len() != expected { return Err(Error::Corrupt("7-Zip unpacked size mismatch")); }
    if let Some(crc) = folder.crc {
        if crc32(0, &decoded) != crc { return Err(Error::Checksum("7-Zip folder")); }
    }
    Ok(decoded)
}

fn encoded_header(data: &[u8], region_end: usize, header: &[u8], limits: Limits) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(header);
    if cursor.byte()? != ENCODED_HEADER { return Err(Error::Corrupt("7-Zip encoded header")); }
    let streams = parse_streams(&mut cursor, limits)?;
    if !cursor.done() { return Err(Error::Corrupt("data follows the 7-Zip encoded header")); }
    if streams.folders.len() != 1 || streams.folders[0].sub_sizes.len() != 1 {
        return Err(Error::Unsupported("multi-stream 7-Zip encoded header"));
    }
    let decoded = decode_folder(data, region_end, &streams, 0, limits.max_metadata_size)?;
    if let Some(crc) = streams.folders[0].sub_crcs[0] {
        if crc32(0, &decoded) != crc { return Err(Error::Checksum("7-Zip encoded header")); }
    }
    Ok(decoded)
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    let b = data.get(at..at + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(data: &[u8], at: usize) -> Result<u64> {
    let b = data.get(at..at + 8).ok_or(Error::Truncated)?;
    Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

pub(crate) fn extract(data: &[u8], limits: Limits) -> Result<crate::Archive> {
    if data.len() < SIGNATURE_SIZE { return Err(Error::Truncated); }
    if data[6] != 0 { return Err(Error::Unsupported("7-Zip major version")); }
    if crc32(0, &data[12..32]) != u32_at(data, 8)? { return Err(Error::Checksum("7-Zip start header")); }
    let next_at = SIGNATURE_SIZE.checked_add(usize64(u64_at(data, 12)?, "7-Zip header position")?)
        .ok_or(Error::Limit("7-Zip header position"))?;
    let next_size = count(u64_at(data, 20)?, usize64(limits.max_metadata_size, "7-Zip header")?, "7-Zip header")?;
    let next_end = next_at.checked_add(next_size).ok_or(Error::Limit("7-Zip header size"))?;
    if next_end != data.len() { return Err(Error::Corrupt("data follows the 7-Zip header")); }
    let next = data.get(next_at..next_end).ok_or(Error::Truncated)?;
    if crc32(0, next) != u32_at(data, 28)? { return Err(Error::Checksum("7-Zip header")); }
    let decoded;
    let header = match next.first().copied() {
        Some(HEADER) => next,
        Some(ENCODED_HEADER) => {
            decoded = encoded_header(data, next_at, next, limits)?;
            &decoded
        }
        _ => return Err(Error::Corrupt("unknown 7-Zip next header")),
    };
    let (streams, files) = parse_header(header, limits)?;
    let nonempty = files.iter().filter(|file| !file.empty_stream).count();
    let substreams = streams.folders.iter().try_fold(0usize, |sum, folder| sum.checked_add(folder.sub_sizes.len()))
        .ok_or(Error::Limit("7-Zip substream count"))?;
    if nonempty != substreams { return Err(Error::Corrupt("7-Zip file/substream mismatch")); }

    let mut out = Builder::new(limits);
    let mut file_at = 0usize;
    for folder_at in 0..streams.folders.len() {
        let folder = &streams.folders[folder_at];
        // R1: a solid folder decodes no further than its members may hold, each within the member limit and all
        // within what is left of the total; a member over either is refused from the metadata, before decoding.
        let budget = out.block_budget(&folder.sub_sizes)?;
        let decoded = decode_folder(data, next_at, &streams, folder_at, budget)?;
        let mut data_at = 0usize;
        for (sub_at, &size) in folder.sub_sizes.iter().enumerate() {
            while files.get(file_at).is_some_and(|file| file.empty_stream) {
                let file = &files[file_at];
                out.add(&file.name, if file.empty_file { EntryKind::File } else { EntryKind::Directory }, &[])?;
                file_at += 1;
            }
            let file = files.get(file_at).ok_or(Error::Corrupt("7-Zip file mapping"))?;
            let size = usize64(size, "7-Zip member size")?;
            let end = data_at.checked_add(size).ok_or(Error::Limit("7-Zip member size"))?;
            let payload = decoded.get(data_at..end).ok_or(Error::Corrupt("7-Zip substream bounds"))?;
            if let Some(crc) = folder.sub_crcs.get(sub_at).copied().flatten() {
                if crc32(0, payload) != crc { return Err(Error::Checksum("7-Zip member")); }
            }
            out.add(&file.name, EntryKind::File, payload)?;
            file_at += 1;
            data_at = end;
        }
    }
    while file_at < files.len() {
        let file = &files[file_at];
        if !file.empty_stream { return Err(Error::Corrupt("7-Zip file mapping")); }
        out.add(&file.name, if file.empty_file { EntryKind::File } else { EntryKind::Directory }, &[])?;
        file_at += 1;
    }
    Ok(out.finish(Format::SevenZip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(value: u64) -> Vec<u8> {
        if value < 0x80 { return vec![value as u8]; }
        let bytes = value.to_le_bytes();
        let used = ((64 - value.leading_zeros() as usize) + 7) / 8;
        let mut out = vec![0u8; used + 1];
        out[0] = (0xff00u16 >> used) as u8;
        if used < 8 {
            out[0] |= ((value >> (used * 8)) & ((1 << (7 - used)) - 1)) as u8;
        }
        out[1..=used].copy_from_slice(&bytes[..used]);
        out
    }

    #[test]
    fn uint64_round_trips() {
        for value in [0, 1, 127, 128, 255, 256, 16_384, u32::MAX as u64, u64::MAX] {
            let bytes = encoded(value);
            let mut cursor = Cursor::new(&bytes);
            assert_eq!(cursor.uint().unwrap(), value, "encoding {bytes:02x?}");
            assert!(cursor.done());
        }
    }

    #[test]
    fn bit_sets_are_most_significant_bit_first() {
        let mut cursor = Cursor::new(&[0b1010_0101]);
        assert_eq!(bitset(&mut cursor, 8).unwrap(), [true, false, true, false, false, true, false, true]);
    }
}
