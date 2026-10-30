//! XZ streams containing single-filter LZMA2 blocks, with index and integrity checks.

use crate::{lzma, Error, Result};
use lazaret_verify::inflate::crc32;

fn crc64(data: &[u8]) -> u64 {
    let mut crc = u64::MAX;
    for &byte in data {
        crc ^= u64::from(byte);
        for _ in 0..8 { crc = if crc & 1 != 0 { (crc >> 1) ^ 0xc96c_5795_d787_0f42 } else { crc >> 1 }; }
    }
    !crc
}

struct Cursor<'a> { data: &'a [u8], pos: usize }

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Cursor<'a> { Cursor { data, pos: 0 } }
    fn byte(&mut self) -> Result<u8> {
        let value = *self.data.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(value)
    }
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(size).ok_or(Error::Limit("XZ field size"))?;
        let out = self.data.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(out)
    }
    fn uint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for i in 0..9 {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << (i * 7);
            if byte & 0x80 == 0 {
                if i > 0 && byte == 0 { return Err(Error::Corrupt("non-canonical XZ integer")); }
                return Ok(value);
            }
        }
        Err(Error::Corrupt("XZ integer overflow"))
    }
}

fn usize64(value: u64) -> Result<usize> { usize::try_from(value).map_err(|_| Error::Limit("XZ size")) }
fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    let b = data.get(at..at + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[derive(Clone, Copy)]
enum Check { None, Crc32, Crc64 }

impl Check {
    fn from_flags(flags: u8) -> Result<Check> {
        match flags & 0x0f {
            0 => Ok(Check::None),
            1 => Ok(Check::Crc32),
            4 => Ok(Check::Crc64),
            10 => Err(Error::Unsupported("XZ SHA-256 integrity check")),
            _ => Err(Error::Unsupported("XZ integrity check")),
        }
    }
    fn size(self) -> usize {
        match self { Check::None => 0, Check::Crc32 => 4, Check::Crc64 => 8 }
    }
    fn verify(self, data: &[u8], expected: &[u8]) -> Result<()> {
        let valid = match self {
            Check::None => true,
            Check::Crc32 => expected.len() == 4 && crc32(0, data).to_le_bytes() == expected,
            Check::Crc64 => expected.len() == 8 && crc64(data).to_le_bytes() == expected,
        };
        if valid { Ok(()) } else { Err(Error::Checksum("XZ block")) }
    }
}

fn padding(data: &[u8], position: &mut usize, compressed_size: usize) -> Result<()> {
    let count = (4 - compressed_size % 4) % 4;
    let end = position.checked_add(count).ok_or(Error::Limit("XZ padding"))?;
    let bytes = data.get(*position..end).ok_or(Error::Truncated)?;
    if bytes.iter().any(|&byte| byte != 0) { return Err(Error::Corrupt("nonzero XZ padding")); }
    *position = end;
    Ok(())
}

pub(crate) fn decode(data: &[u8], maximum: usize) -> Result<Vec<u8>> {
    if data.len() < 24 || !data.starts_with(b"\xfd7zXZ\x00") { return Err(Error::Corrupt("XZ header")); }
    if data[6] != 0 || data[7] & 0xf0 != 0 { return Err(Error::Unsupported("XZ stream flags")); }
    if crc32(0, &data[6..8]) != u32_at(data, 8)? { return Err(Error::Checksum("XZ stream header")); }
    let check = Check::from_flags(data[7])?;
    let mut position = 12usize;
    let mut out = Vec::new();
    let mut records: Vec<(u64, u64)> = Vec::new();

    while *data.get(position).ok_or(Error::Truncated)? != 0 {
        let block_start = position;
        let header_size = (usize::from(data[position]) + 1) * 4;
        let header_end = position.checked_add(header_size).ok_or(Error::Limit("XZ block header"))?;
        let header = data.get(position..header_end).ok_or(Error::Truncated)?;
        if crc32(0, &header[..header.len() - 4]) != u32_at(header, header.len() - 4)? {
            return Err(Error::Checksum("XZ block header"));
        }
        let mut cursor = Cursor::new(&header[..header.len() - 4]);
        cursor.byte()?;
        let flags = cursor.byte()?;
        if flags & 0x3c != 0 { return Err(Error::Unsupported("XZ block flags")); }
        if flags & 3 != 0 { return Err(Error::Unsupported("XZ filter chains")); }
        let compressed_declared = if flags & 0x40 != 0 { Some(usize64(cursor.uint()?)?) } else { None };
        let uncompressed_declared = if flags & 0x80 != 0 { Some(usize64(cursor.uint()?)?) } else { None };
        if cursor.uint()? != 0x21 { return Err(Error::Unsupported("XZ filter")); }
        let properties_size = usize64(cursor.uint()?)?;
        let properties = cursor.take(properties_size)?;
        if cursor.data[cursor.pos..].iter().any(|&byte| byte != 0) { return Err(Error::Corrupt("nonzero XZ header padding")); }
        position = header_end;
        let packed_size = match compressed_declared {
            Some(size) => size,
            None => lzma::lzma2_packed_size(&data[position..])?,
        };
        let packed_end = position.checked_add(packed_size).ok_or(Error::Limit("XZ compressed size"))?;
        let packed = data.get(position..packed_end).ok_or(Error::Truncated)?;
        let remaining = maximum.checked_sub(out.len()).ok_or(Error::Limit("XZ output"))?;
        let decoded = lzma::decode_lzma2_bounded(packed, properties, uncompressed_declared, remaining)?;
        if let Some(expected) = compressed_declared {
            if lzma::lzma2_packed_size(packed)? != expected { return Err(Error::Corrupt("XZ compressed size")); }
        }
        position = packed_end;
        padding(data, &mut position, packed_size)?;
        let check_end = position.checked_add(check.size()).ok_or(Error::Limit("XZ check size"))?;
        let expected_check = data.get(position..check_end).ok_or(Error::Truncated)?;
        check.verify(&decoded, expected_check)?;
        position = check_end;
        let unpadded = (header_size as u64).checked_add(packed_size as u64).and_then(|n| n.checked_add(check.size() as u64))
            .ok_or(Error::Limit("XZ block size"))?;
        records.push((unpadded, decoded.len() as u64));
        out.extend_from_slice(&decoded);
        if position <= block_start { return Err(Error::Corrupt("XZ block position")); }
    }

    let index_start = position;
    position += 1; // Index indicator.
    let record_count = Cursor::new(&data[position..]).uint()?;
    // Reparse with a shared cursor so the count and records consume exactly once.
    let mut index = Cursor::new(&data[index_start..]);
    index.byte()?;
    if index.uint()? != record_count || record_count != records.len() as u64 {
        return Err(Error::Corrupt("XZ index record count"));
    }
    for &(unpadded, uncompressed) in &records {
        if index.uint()? != unpadded || index.uint()? != uncompressed { return Err(Error::Corrupt("XZ index record")); }
    }
    position = index_start.checked_add(index.pos).ok_or(Error::Limit("XZ index size"))?;
    while (position - index_start) % 4 != 0 {
        if *data.get(position).ok_or(Error::Truncated)? != 0 { return Err(Error::Corrupt("nonzero XZ index padding")); }
        position += 1;
    }
    let index_crc = u32_at(data, position)?;
    if crc32(0, &data[index_start..position]) != index_crc { return Err(Error::Checksum("XZ index")); }
    position += 4;
    let index_size = position - index_start;

    let footer = data.get(position..position + 12).ok_or(Error::Truncated)?;
    if crc32(0, &footer[4..10]) != u32_at(footer, 0)? { return Err(Error::Checksum("XZ footer")); }
    let backward = u32_at(footer, 4)?;
    if backward != (index_size / 4 - 1) as u32 { return Err(Error::Corrupt("XZ backward index size")); }
    if footer[8] != data[6] || footer[9] != data[7] { return Err(Error::Corrupt("XZ footer flags")); }
    if &footer[10..] != b"YZ" { return Err(Error::Corrupt("XZ footer magic")); }
    position += 12;
    let padding = data.get(position..).ok_or(Error::Truncated)?;
    if padding.len() % 4 != 0 || padding.iter().any(|&byte| byte != 0) { return Err(Error::Corrupt("XZ stream padding")); }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crc64_matches_standard_vector() { assert_eq!(crc64(b"123456789"), 0x995d_c9bb_df19_39fa); }
    #[test]
    fn variable_integers_are_canonical() {
        assert_eq!(Cursor::new(&[0x80, 0x01]).uint().unwrap(), 128);
        assert!(Cursor::new(&[0x80, 0]).uint().is_err());
    }
}
