//! LZMA1 and LZMA2 decoding over bounded, caller-owned byte slices.
//!
//! The complete output doubles as the history window, so dictionary properties
//! never cause a separate dictionary-sized allocation. Matches may not reach
//! before the latest dictionary reset or beyond the declared dictionary size.

use crate::{Error, Result};

const STATES: usize = 12;
const POS_STATES: usize = 16;
const TOP: u32 = 1 << 24;
const BIT_MODEL_TOTAL: u32 = 1 << 11;
const MOVE_BITS: u32 = 5;

fn probability() -> u16 { (BIT_MODEL_TOTAL / 2) as u16 }

struct Range<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> Range<'a> {
    fn new(data: &'a [u8]) -> Result<Range<'a>> {
        let first = data.get(..5).ok_or(Error::Truncated)?;
        if first[0] != 0 { return Err(Error::Corrupt("LZMA range-coder prefix")); }
        let range = Range {
            data,
            pos: 5,
            range: u32::MAX,
            code: u32::from_be_bytes([first[1], first[2], first[3], first[4]]),
        };
        Ok(range)
    }

    fn normalize(&mut self) -> Result<()> {
        if self.range < TOP {
            let byte = *self.data.get(self.pos).ok_or(Error::Truncated)?;
            self.pos += 1;
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(byte);
        }
        Ok(())
    }

    fn bit(&mut self, probability: &mut u16) -> Result<u32> {
        let bound = (self.range >> 11) * u32::from(*probability);
        let bit;
        if self.code < bound {
            self.range = bound;
            *probability += ((BIT_MODEL_TOTAL - u32::from(*probability)) >> MOVE_BITS) as u16;
            bit = 0;
        } else {
            self.range -= bound;
            self.code -= bound;
            *probability -= *probability >> MOVE_BITS;
            bit = 1;
        }
        self.normalize()?;
        Ok(bit)
    }

    fn direct(&mut self, count: u32) -> Result<u32> {
        let mut value = 0u32;
        for _ in 0..count {
            self.range >>= 1;
            let bit = if self.code >= self.range {
                self.code -= self.range;
                1
            } else {
                0
            };
            value = (value << 1) | bit;
            self.normalize()?;
        }
        Ok(value)
    }

    fn finish(&self) -> Result<()> {
        if self.pos != self.data.len() || self.code != 0 {
            Err(Error::Corrupt("unfinished LZMA range coder or trailing data"))
        } else { Ok(()) }
    }
}

fn tree(range: &mut Range<'_>, probabilities: &mut [u16], bits: u32) -> Result<u32> {
    let mut node = 1usize;
    for _ in 0..bits {
        let bit = range.bit(probabilities.get_mut(node).ok_or(Error::Corrupt("LZMA probability index"))?)?;
        node = (node << 1) | bit as usize;
    }
    Ok((node - (1usize << bits)) as u32)
}

fn reverse_tree(range: &mut Range<'_>, probabilities: &mut [u16], offset: usize, bits: u32) -> Result<u32> {
    let mut node = 1usize;
    let mut value = 0u32;
    for i in 0..bits {
        let index = offset.checked_add(node).ok_or(Error::Limit("LZMA probability index"))?;
        let bit = range.bit(probabilities.get_mut(index).ok_or(Error::Corrupt("LZMA probability index"))?)?;
        node = (node << 1) | bit as usize;
        value |= bit << i;
    }
    Ok(value)
}

struct Length {
    choice: [u16; 2],
    low: Vec<u16>,
    mid: Vec<u16>,
    high: Vec<u16>,
}

impl Length {
    fn new() -> Length {
        Length {
            choice: [probability(); 2],
            low: vec![probability(); POS_STATES * 8],
            mid: vec![probability(); POS_STATES * 8],
            high: vec![probability(); 256],
        }
    }

    fn decode(&mut self, range: &mut Range<'_>, pos_state: usize) -> Result<u32> {
        if range.bit(&mut self.choice[0])? == 0 {
            return tree(range, &mut self.low[pos_state * 8..pos_state * 8 + 8], 3);
        }
        if range.bit(&mut self.choice[1])? == 0 {
            return Ok(8 + tree(range, &mut self.mid[pos_state * 8..pos_state * 8 + 8], 3)?);
        }
        Ok(16 + tree(range, &mut self.high, 8)?)
    }
}

struct Models {
    is_match: Vec<u16>,
    is_rep: [u16; STATES],
    is_rep_g0: [u16; STATES],
    is_rep_g1: [u16; STATES],
    is_rep_g2: [u16; STATES],
    is_rep0_long: Vec<u16>,
    pos_slot: Vec<u16>,
    // Three reserved prefix slots accommodate the negative spec-pos offsets
    // used by the smallest distance slots in the original probability layout.
    pos_special: Vec<u16>,
    align: [u16; 16],
    literal: Vec<u16>,
    len: Length,
    rep_len: Length,
}

impl Models {
    fn new(lc: u32, lp: u32) -> Result<Models> {
        let literal_len = 0x300usize.checked_shl(lc + lp).ok_or(Error::Limit("LZMA literal model"))?;
        Ok(Models {
            is_match: vec![probability(); STATES * POS_STATES],
            is_rep: [probability(); STATES],
            is_rep_g0: [probability(); STATES],
            is_rep_g1: [probability(); STATES],
            is_rep_g2: [probability(); STATES],
            is_rep0_long: vec![probability(); STATES * POS_STATES],
            pos_slot: vec![probability(); 4 * 64],
            pos_special: vec![probability(); 128],
            align: [probability(); 16],
            literal: vec![probability(); literal_len],
            len: Length::new(),
            rep_len: Length::new(),
        })
    }
}

#[derive(Clone, Copy)]
struct Properties {
    lc: u32,
    lp: u32,
    pb: u32,
}

fn properties(byte: u8) -> Result<Properties> {
    if byte >= 9 * 5 * 5 { return Err(Error::Corrupt("LZMA properties")); }
    let value = u32::from(byte);
    let lc = value % 9;
    let remainder = value / 9;
    let lp = remainder % 5;
    let pb = remainder / 5;
    if lc + lp > 12 { return Err(Error::Unsupported("LZMA literal context size")); }
    Ok(Properties { lc, lp, pb })
}

struct Decoder {
    out: Vec<u8>,
    dict_start: usize,
    dict_size: u64,
    properties: Properties,
    models: Models,
    state: usize,
    reps: [u32; 4],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EndMarker { Required, Optional, Forbidden }

impl Decoder {
    fn new(dict_size: u64, properties: Properties) -> Result<Decoder> {
        if dict_size == 0 { return Err(Error::Corrupt("LZMA dictionary size")); }
        Ok(Decoder {
            out: Vec::new(),
            dict_start: 0,
            dict_size,
            properties,
            models: Models::new(properties.lc, properties.lp)?,
            state: 0,
            reps: [0; 4],
        })
    }

    fn set_properties(&mut self, properties: Properties) {
        self.properties = properties;
    }

    fn reset_state(&mut self) -> Result<()> {
        self.models = Models::new(self.properties.lc, self.properties.lp)?;
        self.state = 0;
        self.reps = [0; 4];
        Ok(())
    }

    fn reset_dictionary(&mut self) { self.dict_start = self.out.len(); }

    fn distance(&self, distance: u32) -> Result<usize> {
        let distance = u64::from(distance).checked_add(1).ok_or(Error::Corrupt("LZMA end marker"))?;
        let history = (self.out.len() - self.dict_start) as u64;
        if distance > history || distance > self.dict_size { return Err(Error::Corrupt("LZMA match distance")); }
        Ok(distance as usize)
    }

    fn literal(&mut self, range: &mut Range<'_>) -> Result<u8> {
        let position = (self.out.len() - self.dict_start) as u64;
        let previous = if self.out.len() == self.dict_start { 0 } else { self.out.last().copied().unwrap_or(0) };
        let lc = self.properties.lc;
        let lp_mask = (1u64 << self.properties.lp) - 1;
        let literal_state = (((position & lp_mask) << lc) as usize)
            .checked_add((u32::from(previous) >> (8 - lc)) as usize)
            .ok_or(Error::Limit("LZMA literal state"))?;
        let start = literal_state.checked_mul(0x300).ok_or(Error::Limit("LZMA literal state"))?;
        let matched_distance = if self.state >= 7 { Some(self.distance(self.reps[0])?) } else { None };
        let probabilities = self.models.literal.get_mut(start..start + 0x300)
            .ok_or(Error::Corrupt("LZMA literal state"))?;
        let mut symbol = 1usize;
        if self.state >= 7 {
            let distance = matched_distance.unwrap();
            let mut match_byte = self.out[self.out.len() - distance];
            while symbol < 0x100 {
                let match_bit = usize::from(match_byte >> 7);
                match_byte <<= 1;
                let index = 0x100 + (match_bit << 8) + symbol;
                let bit = range.bit(&mut probabilities[index])? as usize;
                symbol = (symbol << 1) | bit;
                if bit != match_bit {
                    while symbol < 0x100 {
                        let bit = range.bit(&mut probabilities[symbol])? as usize;
                        symbol = (symbol << 1) | bit;
                    }
                    break;
                }
            }
        } else {
            while symbol < 0x100 {
                let bit = range.bit(&mut probabilities[symbol])? as usize;
                symbol = (symbol << 1) | bit;
            }
        }
        Ok((symbol - 0x100) as u8)
    }

    fn copy_match(&mut self, distance: usize, len: usize, target: usize) -> Result<()> {
        let end = self.out.len().checked_add(len).ok_or(Error::Limit("LZMA output size"))?;
        if end > target { return Err(Error::Corrupt("LZMA match exceeds its output size")); }
        for _ in 0..len {
            let byte = self.out[self.out.len() - distance];
            self.out.push(byte);
        }
        Ok(())
    }

    fn decode_chunk(&mut self, input: &[u8], unpacked: usize, target_limit: usize, end_marker: EndMarker) -> Result<()> {
        let target = self.out.len().checked_add(unpacked).ok_or(Error::Limit("LZMA output size"))?;
        if target > target_limit { return Err(Error::Limit("LZMA output size")); }
        let mut range = Range::new(input)?;
        loop {
            if self.out.len() == target {
                if end_marker == EndMarker::Forbidden { return range.finish(); }
                if end_marker == EndMarker::Optional && range.finish().is_ok() { return Ok(()); }
                // An unknown-size stream may end exactly at the caller's limit.
                // Decode its end marker without permitting another output byte.
            }
            let position = (self.out.len() - self.dict_start) as u64;
            let pos_state = (position & ((1u64 << self.properties.pb) - 1)) as usize;
            let match_index = self.state * POS_STATES + pos_state;
            if range.bit(&mut self.models.is_match[match_index])? == 0 {
                if self.out.len() == target {
                    return Err(if end_marker == EndMarker::Required { Error::Limit("LZMA output size") }
                               else { Error::Corrupt("LZMA literal exceeds declared size") });
                }
                let byte = self.literal(&mut range)?;
                self.out.push(byte);
                self.state = if self.state < 4 { 0 } else if self.state < 10 { self.state - 3 } else { self.state - 6 };
                continue;
            }

            let len;
            if range.bit(&mut self.models.is_rep[self.state])? != 0 {
                if range.bit(&mut self.models.is_rep_g0[self.state])? == 0 {
                    if range.bit(&mut self.models.is_rep0_long[match_index])? == 0 {
                        if self.out.len() == target && end_marker == EndMarker::Required { return Err(Error::Limit("LZMA output size")); }
                        self.state = if self.state < 7 { 9 } else { 11 };
                        let distance = self.distance(self.reps[0])?;
                        self.copy_match(distance, 1, target)?;
                        continue;
                    }
                } else {
                    let distance;
                    if range.bit(&mut self.models.is_rep_g1[self.state])? == 0 {
                        distance = self.reps[1];
                    } else {
                        if range.bit(&mut self.models.is_rep_g2[self.state])? == 0 {
                            distance = self.reps[2];
                        } else {
                            distance = self.reps[3];
                            self.reps[3] = self.reps[2];
                        }
                        self.reps[2] = self.reps[1];
                    }
                    self.reps[1] = self.reps[0];
                    self.reps[0] = distance;
                }
                len = self.models.rep_len.decode(&mut range, pos_state)? as usize + 2;
                self.state = if self.state < 7 { 8 } else { 11 };
            } else {
                self.reps[3] = self.reps[2];
                self.reps[2] = self.reps[1];
                self.reps[1] = self.reps[0];
                len = self.models.len.decode(&mut range, pos_state)? as usize + 2;
                self.state = if self.state < 7 { 7 } else { 10 };
                let len_state = (len - 2).min(3);
                let pos_slot = tree(&mut range, &mut self.models.pos_slot[len_state * 64..len_state * 64 + 64], 6)?;
                self.reps[0] = if pos_slot < 4 {
                    pos_slot
                } else {
                    let direct_bits = (pos_slot >> 1) - 1;
                    let base = (2u64 | u64::from(pos_slot & 1)) << direct_bits;
                    let distance = if pos_slot < 14 {
                        let offset = 3usize.checked_add(base as usize)
                            .and_then(|n| n.checked_sub(pos_slot as usize + 1))
                            .ok_or(Error::Corrupt("LZMA distance model"))?;
                        base + u64::from(reverse_tree(&mut range, &mut self.models.pos_special, offset, direct_bits)?)
                    } else {
                        base + (u64::from(range.direct(direct_bits - 4)?) << 4)
                            + u64::from(reverse_tree(&mut range, &mut self.models.align, 0, 4)?)
                    };
                    u32::try_from(distance).map_err(|_| Error::Corrupt("LZMA match distance"))?
                };
                if self.reps[0] == u32::MAX {
                    if end_marker == EndMarker::Forbidden || (end_marker == EndMarker::Optional && self.out.len() != target) {
                        return Err(Error::Corrupt("unexpected LZMA end marker"));
                    }
                    range.finish()?;
                    return Ok(());
                }
            }
            if end_marker == EndMarker::Required && len > target - self.out.len() {
                return Err(Error::Limit("LZMA output size"));
            }
            let distance = self.distance(self.reps[0])?;
            self.copy_match(distance, len, target)?;
        }
    }
}

fn decoder(props: &[u8]) -> Result<Decoder> {
    if props.len() != 5 { return Err(Error::Corrupt("LZMA properties size")); }
    let properties = properties(props[0])?;
    let dict_size = u64::from(u32::from_le_bytes([props[1], props[2], props[3], props[4]]));
    Decoder::new(dict_size, properties)
}

pub(crate) fn decode_lzma(input: &[u8], props: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut decoder = decoder(props)?;
    decoder.decode_chunk(input, expected, expected, EndMarker::Optional)?;
    Ok(decoder.out)
}

pub(crate) fn decode_lzma_unknown(input: &[u8], props: &[u8], maximum: usize) -> Result<Vec<u8>> {
    let mut decoder = decoder(props)?;
    decoder.decode_chunk(input, maximum, maximum, EndMarker::Required)?;
    Ok(decoder.out)
}

fn dictionary_size(encoded: u8) -> Result<u64> {
    if encoded > 40 { return Err(Error::Corrupt("LZMA2 dictionary property")); }
    if encoded == 40 { return Ok(u64::from(u32::MAX)); }
    Ok(u64::from(2 | (encoded & 1)) << (u32::from(encoded) / 2 + 11))
}

pub(crate) fn decode_lzma2_bounded(input: &[u8], props: &[u8], expected: Option<usize>, maximum: usize) -> Result<Vec<u8>> {
    if props.len() != 1 { return Err(Error::Corrupt("LZMA2 properties size")); }
    if expected.is_some_and(|size| size > maximum) { return Err(Error::Limit("LZMA2 output size")); }
    let dict_size = dictionary_size(props[0])?;
    let initial = properties(0)?; // Replaced by the first compressed chunk.
    let mut decoder = Decoder::new(dict_size, initial)?;
    let mut pos = 0usize;
    let mut need_dictionary = true;
    let mut need_properties = true;
    let mut need_state = true;

    loop {
        let control = *input.get(pos).ok_or(Error::Truncated)?;
        pos += 1;
        if control == 0 {
            if pos != input.len() { return Err(Error::Corrupt("data follows the LZMA2 end marker")); }
            if expected.is_some_and(|size| decoder.out.len() != size) { return Err(Error::Truncated); }
            return Ok(decoder.out);
        }
        if control == 1 || control == 2 {
            if need_dictionary && control != 1 { return Err(Error::Corrupt("LZMA2 dictionary is not initialized")); }
            let size = input.get(pos..pos + 2).ok_or(Error::Truncated)?;
            pos += 2;
            let unpacked = usize::from(u16::from_be_bytes([size[0], size[1]])) + 1;
            let end = pos.checked_add(unpacked).ok_or(Error::Limit("LZMA2 chunk size"))?;
            let bytes = input.get(pos..end).ok_or(Error::Truncated)?;
            let new_len = decoder.out.len().checked_add(unpacked).ok_or(Error::Limit("LZMA2 output size"))?;
            if new_len > maximum { return Err(Error::Limit("LZMA2 output size")); }
            if control == 1 {
                decoder.reset_dictionary();
                need_dictionary = false;
                need_properties = true;
            }
            decoder.out.extend_from_slice(bytes);
            pos = end;
            need_state = true;
            continue;
        }
        if control < 0x80 { return Err(Error::Corrupt("LZMA2 chunk control")); }
        let sizes = input.get(pos..pos + 4).ok_or(Error::Truncated)?;
        pos += 4;
        let unpacked = (((usize::from(control) & 0x1f) << 16)
            | (usize::from(sizes[0]) << 8) | usize::from(sizes[1])) + 1;
        let packed = ((usize::from(sizes[2]) << 8) | usize::from(sizes[3])) + 1;
        if need_dictionary && control < 0xe0 { return Err(Error::Corrupt("LZMA2 dictionary is not initialized")); }
        if control >= 0xe0 {
            decoder.reset_dictionary();
            need_dictionary = false;
        }
        if control >= 0xc0 {
            let encoded = *input.get(pos).ok_or(Error::Truncated)?;
            pos += 1;
            let props = properties(encoded)?;
            if props.lc + props.lp > 4 { return Err(Error::Corrupt("LZMA2 literal context size")); }
            decoder.set_properties(props);
            need_properties = false;
        } else if need_properties {
            return Err(Error::Corrupt("LZMA2 properties are not initialized"));
        }
        if control >= 0xa0 {
            decoder.reset_state()?;
            need_state = false;
        } else if need_state {
            return Err(Error::Corrupt("LZMA2 state is not initialized"));
        }
        let end = pos.checked_add(packed).ok_or(Error::Limit("LZMA2 chunk size"))?;
        let chunk = input.get(pos..end).ok_or(Error::Truncated)?;
        decoder.decode_chunk(chunk, unpacked, maximum, EndMarker::Forbidden)?;
        pos = end;
    }
}

pub(crate) fn decode_lzma2(input: &[u8], props: &[u8], expected: usize) -> Result<Vec<u8>> {
    decode_lzma2_bounded(input, props, Some(expected), expected)
}

/// Locate the end of one raw LZMA2 stream without decompressing it. XZ blocks
/// normally omit their compressed size, so their chunk framing supplies it.
pub(crate) fn lzma2_packed_size(input: &[u8]) -> Result<usize> {
    let mut pos = 0usize;
    loop {
        let control = *input.get(pos).ok_or(Error::Truncated)?;
        pos += 1;
        if control == 0 { return Ok(pos); }
        if control == 1 || control == 2 {
            let size = input.get(pos..pos + 2).ok_or(Error::Truncated)?;
            let unpacked = usize::from(u16::from_be_bytes([size[0], size[1]])) + 1;
            pos = pos.checked_add(2 + unpacked).ok_or(Error::Limit("LZMA2 chunk size"))?;
        } else {
            if control < 0x80 { return Err(Error::Corrupt("LZMA2 chunk control")); }
            let sizes = input.get(pos..pos + 4).ok_or(Error::Truncated)?;
            let packed = ((usize::from(sizes[2]) << 8) | usize::from(sizes[3])) + 1;
            let properties = if control >= 0xc0 { 1 } else { 0 };
            pos = pos.checked_add(4 + properties + packed).ok_or(Error::Limit("LZMA2 chunk size"))?;
        }
        if pos > input.len() { return Err(Error::Truncated); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_properties_are_decoded() {
        assert_eq!(dictionary_size(0).unwrap(), 4096);
        assert_eq!(dictionary_size(1).unwrap(), 6144);
        assert_eq!(dictionary_size(16).unwrap(), 1024 * 1024);
        assert_eq!(dictionary_size(40).unwrap(), u64::from(u32::MAX));
        assert!(dictionary_size(41).is_err());
    }

    #[test]
    fn invalid_properties_are_refused() {
        assert!(properties(9 * 5 * 5).is_err());
        assert!(decode_lzma(&[], &[0; 4], 0).is_err());
        assert!(decode_lzma2(&[], &[41], 0).is_err());
    }
}
