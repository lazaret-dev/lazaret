//! Bzip2 decoding with bounded blocks and verified block/stream CRC-32 values.

use crate::{Error, Result};

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_MAGIC: u64 = 0x1772_4538_5090;
/// bzip2 1.0.8's BZ_MAX_SELECTORS: 2 + 900,000 / 50.
const MAX_SELECTORS: usize = 18_002;

struct Bits<'a> { data: &'a [u8], position: usize }

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Bits<'a> { Bits { data, position: 0 } }
    fn bit(&mut self) -> Result<u32> {
        let byte = *self.data.get(self.position / 8).ok_or(Error::Truncated)?;
        let bit = u32::from((byte >> (7 - self.position % 8)) & 1);
        self.position += 1;
        Ok(bit)
    }
    fn bits(&mut self, count: u32) -> Result<u32> {
        let mut value = 0u32;
        for _ in 0..count { value = (value << 1) | self.bit()?; }
        Ok(value)
    }
    fn magic(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for _ in 0..6 { value = (value << 8) | u64::from(self.bits(8)?); }
        Ok(value)
    }
    fn align(&mut self) -> Result<()> {
        while self.position % 8 != 0 {
            if self.bit()? != 0 { return Err(Error::Corrupt("nonzero bzip2 padding")); }
        }
        Ok(())
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte) << 24;
        for _ in 0..8 { crc = if crc & 0x8000_0000 != 0 { (crc << 1) ^ 0x04c1_1db7 } else { crc << 1 }; }
    }
    !crc
}

struct Huffman {
    counts: [u32; 21],
    first_code: [u32; 21],
    first_index: [u32; 21],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Huffman> {
        let mut counts = [0u32; 21];
        for &length in lengths {
            if !(1..=20).contains(&length) { return Err(Error::Corrupt("bzip2 Huffman length")); }
            counts[usize::from(length)] += 1;
        }
        let mut symbols = Vec::with_capacity(lengths.len());
        for length in 1..=20 {
            for (symbol, &actual) in lengths.iter().enumerate() {
                if actual == length { symbols.push(symbol as u16); }
            }
        }
        let mut first_code = [0u32; 21];
        let mut first_index = [0u32; 21];
        let mut code = 0u32;
        let mut index = 0u32;
        for length in 1..=20 {
            code = code.checked_add(counts[length - 1]).and_then(|n| n.checked_shl(1))
                .ok_or(Error::Corrupt("bzip2 Huffman tree"))?;
            if code + counts[length] > (1u32 << length) { return Err(Error::Corrupt("overfull bzip2 Huffman tree")); }
            first_code[length] = code;
            first_index[length] = index;
            index += counts[length];
        }
        Ok(Huffman { counts, first_code, first_index, symbols })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16> {
        let mut code = 0u32;
        for length in 1..=20 {
            code = (code << 1) | bits.bit()?;
            let first = self.first_code[length];
            if code >= first && code - first < self.counts[length] {
                let index = (self.first_index[length] + code - first) as usize;
                return self.symbols.get(index).copied().ok_or(Error::Corrupt("bzip2 Huffman symbol"));
            }
        }
        Err(Error::Corrupt("invalid bzip2 Huffman code"))
    }
}

fn inverse_bwt(data: &[u8], original: usize) -> Result<Vec<u8>> {
    if original >= data.len() { return Err(Error::Corrupt("bzip2 BWT origin")); }
    let mut counts = [0usize; 256];
    for &byte in data { counts[usize::from(byte)] += 1; }
    let mut offsets = [0usize; 256];
    let mut sum = 0usize;
    for i in 0..256 { offsets[i] = sum; sum += counts[i]; }
    let mut next = vec![0u32; data.len()];
    for (i, &byte) in data.iter().enumerate() {
        let slot = &mut offsets[usize::from(byte)];
        next[*slot] = u32::try_from(i).map_err(|_| Error::Limit("bzip2 block size"))?;
        *slot += 1;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut position = original;
    for _ in 0..data.len() { position = next[position] as usize; out.push(data[position]); }
    Ok(out)
}

fn rle1(data: &[u8], maximum: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        let byte = data[at];
        at += 1;
        let mut run = 1usize;
        while run < 4 && at < data.len() && data[at] == byte { at += 1; run += 1; }
        if run == 4 {
            let extra = usize::from(*data.get(at).ok_or(Error::Truncated)?);
            at += 1;
            run = run.checked_add(extra).ok_or(Error::Limit("bzip2 run length"))?;
        }
        let end = out.len().checked_add(run).ok_or(Error::Limit("bzip2 output"))?;
        if end > maximum { return Err(Error::Limit("bzip2 output")); }
        out.resize(end, byte);
    }
    Ok(out)
}

fn tables(bits: &mut Bits<'_>, groups: usize, alphabet: usize) -> Result<Vec<Huffman>> {
    let mut out = Vec::with_capacity(groups);
    for _ in 0..groups {
        let mut current = bits.bits(5)? as u8;
        let mut lengths = Vec::with_capacity(alphabet);
        for _ in 0..alphabet {
            loop {
                if bits.bit()? == 0 { break; }
                if bits.bit()? == 0 { current = current.checked_add(1).ok_or(Error::Corrupt("bzip2 Huffman length"))?; }
                else { current = current.checked_sub(1).ok_or(Error::Corrupt("bzip2 Huffman length"))?; }
                if !(1..=20).contains(&current) { return Err(Error::Corrupt("bzip2 Huffman length")); }
            }
            lengths.push(current);
        }
        out.push(Huffman::new(&lengths)?);
    }
    Ok(out)
}

fn block(bits: &mut Bits<'_>, block_maximum: usize, output_maximum: usize) -> Result<Vec<u8>> {
    let expected_crc = bits.bits(32)?;
    if bits.bit()? != 0 { return Err(Error::Unsupported("randomized bzip2 blocks")); }
    let original = bits.bits(24)? as usize;
    let mut map = Vec::new();
    let used_groups = bits.bits(16)?;
    for group in 0..16 {
        if used_groups & (1 << (15 - group)) != 0 {
            let symbols = bits.bits(16)?;
            for symbol in 0..16 {
                if symbols & (1 << (15 - symbol)) != 0 { map.push((group * 16 + symbol) as u8); }
            }
        }
    }
    if map.is_empty() { return Err(Error::Corrupt("empty bzip2 symbol map")); }
    let group_count = bits.bits(3)? as usize;
    if !(2..=6).contains(&group_count) { return Err(Error::Corrupt("bzip2 Huffman group count")); }
    let selector_count = bits.bits(15)? as usize;
    if selector_count == 0 { return Err(Error::Corrupt("bzip2 selector count")); }
    // As bzip2 1.0.8: every selector is read and checked, the first MAX_SELECTORS are kept, and more than a
    // block uses is fine (lbzip2 writes extra ones).
    let mut selectors = Vec::with_capacity(selector_count.min(MAX_SELECTORS));
    let mut mtf_groups: Vec<u8> = (0..group_count as u8).collect();
    for i in 0..selector_count {
        let mut index = 0usize;
        while bits.bit()? != 0 {
            index += 1;
            if index >= group_count { return Err(Error::Corrupt("bzip2 selector")); }
        }
        if i < MAX_SELECTORS {
            let group = mtf_groups.remove(index);
            mtf_groups.insert(0, group);
            selectors.push(group);
        }
    }
    let alphabet = map.len() + 2;
    let huffman = tables(bits, group_count, alphabet)?;
    let end_of_block = alphabet - 1;
    let mut mtf: Vec<u8> = (0..map.len()).map(|index| index as u8).collect();
    let mut transformed = Vec::new();
    let mut selector = 0usize;
    let mut group_remaining = 0usize;
    let mut group = 0usize;
    let mut next = |bits: &mut Bits<'_>| -> Result<u16> {
        if group_remaining == 0 {
            group = usize::from(*selectors.get(selector).ok_or(Error::Corrupt("bzip2 selectors are exhausted"))?);
            selector += 1;
            group_remaining = 50;
        }
        group_remaining -= 1;
        huffman[group].decode(bits)
    };
    let mut symbol = next(bits)?;
    loop {
        if symbol <= 1 {
            let mut run = 0u64;
            let mut weight = 1u64;
            loop {
                run = run.checked_add(if symbol == 0 { weight } else { weight * 2 })
                    .ok_or(Error::Limit("bzip2 run length"))?;
                if run > block_maximum as u64 { return Err(Error::Limit("bzip2 block size")); }
                symbol = next(bits)?;
                if symbol > 1 { break; }
                weight = weight.checked_mul(2).ok_or(Error::Limit("bzip2 run length"))?;
            }
            let byte = map[usize::from(mtf[0])];
            let end = transformed.len().checked_add(run as usize).ok_or(Error::Limit("bzip2 block size"))?;
            if end > block_maximum { return Err(Error::Limit("bzip2 block size")); }
            transformed.resize(end, byte);
        }
        if usize::from(symbol) == end_of_block { break; }
        if symbol < 2 { return Err(Error::Corrupt("bzip2 run state")); }
        let index = usize::from(symbol - 1);
        if index >= mtf.len() { return Err(Error::Corrupt("bzip2 MTF index")); }
        let value = mtf.remove(index);
        mtf.insert(0, value);
        if transformed.len() >= block_maximum { return Err(Error::Limit("bzip2 block size")); }
        transformed.push(map[usize::from(value)]);
        symbol = next(bits)?;
    }
    let transformed = inverse_bwt(&transformed, original)?;
    let decoded = rle1(&transformed, output_maximum)?;
    if crc32(&decoded) != expected_crc { return Err(Error::Checksum("bzip2 block")); }
    Ok(decoded)
}

/// One stream at the start of `data`, appended to `out`; returns the bytes it takes.
fn stream(data: &[u8], maximum: usize, out: &mut Vec<u8>) -> Result<usize> {
    if data.len() < 4 || &data[..3] != b"BZh" { return Err(Error::Corrupt("bzip2 header")); }
    if !(b'1'..=b'9').contains(&data[3]) { return Err(Error::Corrupt("bzip2 block size")); }
    let block_maximum = usize::from(data[3] - b'0') * 100_000;
    let mut bits = Bits::new(&data[4..]);
    let mut combined = 0u32;
    loop {
        match bits.magic()? {
            BLOCK_MAGIC => {
                let decoded = block(&mut bits, block_maximum, maximum.saturating_sub(out.len()))?;
                combined = combined.rotate_left(1) ^ crc32(&decoded);
                out.extend_from_slice(&decoded);
            }
            END_MAGIC => {
                if bits.bits(32)? != combined { return Err(Error::Checksum("bzip2 stream")); }
                bits.align()?;
                return Ok(4 + bits.position / 8);
            }
            _ => return Err(Error::Corrupt("bzip2 block marker")),
        }
    }
}

/// Every stream in `data`, concatenated, as bzip2 1.0.8 and Python's bz2 decode them (pbzip2 writes one
/// stream per block). Anything after the last stream that is not another stream is refused.
pub(crate) fn decode(data: &[u8], maximum: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = stream(data, maximum, &mut out)?;
    while at < data.len() {
        if !data[at..].starts_with(b"BZh") { return Err(Error::Corrupt("data follows the bzip2 stream")); }
        at += stream(&data[at..], maximum, &mut out)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crc_matches_standard_bzip2_vector() { assert_eq!(crc32(b"123456789"), 0xfc89_1918); }
    #[test]
    fn rle1_decodes_long_runs() {
        assert_eq!(rle1(b"aaaa\x02", 20).unwrap(), b"aaaaaa");
        assert!(rle1(b"aaaa", 20).is_err());
        assert_eq!(rle1(b"aaaa\x02", 5), Err(Error::Limit("bzip2 output")));
    }
}
