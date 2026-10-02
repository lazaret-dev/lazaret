//! A quick hash for maps keyed by the engine's own numbers (node, name and
//! function ids, and tuples of them): each word xored into the state, which
//! is then multiplied by a constant and the 128-bit product folded (its two
//! halves xored, as foldhash does), so every bit of a key reaches the low
//! bits a table takes its index from.
//!
//! Only for keys the engine numbers itself: an input cannot choose them, so
//! it cannot make them collide. Keys an input chooses (its texts) keep the
//! standard library's keyed hash.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

#[derive(Clone, Copy)]
pub struct QuickHash(u64);

const K: u64 = 0xf135_7aea_2e62_a9c5;
const SEED: u64 = 0x2d35_8dcc_aa6c_78a5;

impl Default for QuickHash {
    #[inline]
    fn default() -> QuickHash {
        QuickHash(SEED)
    }
}

impl QuickHash {
    #[inline]
    fn add(&mut self, v: u64) {
        let full = ((self.0 ^ v) as u128) * (K as u128);
        self.0 = (full as u64) ^ ((full >> 64) as u64);
    }
}

impl Hasher for QuickHash {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks {
            self.add(u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]));
        }
        for &b in chunks.remainder() {
            self.add(b as u64);
        }
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

pub type QuickMap<K, V> = HashMap<K, V, BuildHasherDefault<QuickHash>>;
pub type QuickSet<K> = HashSet<K, BuildHasherDefault<QuickHash>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::BuildHasher;

    #[test]
    fn keys_that_differ_high_or_low_spread_over_a_table() {
        let b = BuildHasherDefault::<QuickHash>::default();
        // a table of 1024 slots takes the low 10 bits: ids, and pairs that
        // differ only in their high word, both spread
        let mut low = HashSet::new();
        let mut high = HashSet::new();
        for k in 0u64..1024 {
            low.insert(b.hash_one(k) & 1023);
            high.insert(b.hash_one(((k + 1) << 32) | 7) & 1023);
        }
        assert!(low.len() > 600 && high.len() > 600, "{} {}", low.len(), high.len());
        let mut m: QuickMap<(u32, u32), u32> = QuickMap::default();
        for k in 0..100 {
            m.insert((k, k + 1), k);
        }
        assert_eq!(m.get(&(5, 6)), Some(&5));
        assert_eq!(m.get(&(6, 5)), None);
    }
}
