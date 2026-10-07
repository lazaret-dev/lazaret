//! The texts a caller hands the engine once and names by id after (0.1.9, FE-1).
//!
//! A registry scan reads each file of a package three to five times, once per step that reads it (the rules, the
//! import-time test, the scripts it starts, the agent check, the cross-file follower), and each step used to send the
//! file's text again: in a batch, escaped into the arguments' JSON and parsed back on one thread before the batch's
//! threads started. Now a scan puts each text here once, as the bytes of its region (`texts.put`: the lengths in the
//! arguments, the texts one after another in the text region, no JSON), and a call names it with `"text_id"` in its
//! arguments, in a batch or alone; `cross_file` takes its files' texts by id too (`"text_ids"`). The scan lets them go
//! when it ends (`texts.drop`, in a `finally`).
//!
//! A text is kept as the bytes it came as, UTF-8 with surrogates passed through (WTF-8: what Python's
//! `str.encode("utf-8", "surrogatepass")` writes), checked when it is put, and read into the engine's code points by
//! each call that asks for it, on that call's thread: kept as code points it would take four times the room, and the
//! scan holds its own copy of each text in the caller already. The store is the process's, behind a lock (a batch's
//! threads read it at once, and a process may run several scans on threads), and bounded: a put that would hold more
//! than MAX_BYTES is refused whole, and the caller then sends those texts as before.
//!
//! The engine still reads only what it is handed: this is the text it was handed, kept until the caller lets it go.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// The bytes the store holds at most (of every caller's texts at once). A registry scan holds at most an archive's
/// decompressed size of text (500 MiB: repo.MAX_ARCHIVE_TOTAL).
pub const MAX_BYTES: usize = 1 << 30;

/// UTF-8 with surrogates passed through (CPython's "surrogatepass"): the code points of a Python str (or of a JS
/// string, lone surrogates included). None for bytes no such encoder writes.
pub fn decode_wtf8(b: &[u8]) -> Option<Vec<u32>> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let (c, n) = next(b, i)?;
        out.push(c);
        i += n;
    }
    Some(out)
}

/// `region` (WTF-8) cut into texts of `lengths` code points each, checked as it is cut: the pieces, or why not.
fn split<'a>(lengths: &[usize], region: &'a [u8]) -> Result<Vec<&'a [u8]>, PutError> {
    let mut pieces = Vec::with_capacity(lengths.len());
    let mut at = 0usize;
    for (k, &n) in lengths.iter().enumerate() {
        let start = at;
        let mut left = n;
        while left > 0 {
            if at >= region.len() {
                return Err(PutError::Bad("the lengths run past the texts".into()));
            }
            // (ASCII, eight bytes at a time: most of a source file)
            if left >= 8 && at + 8 <= region.len() {
                let b = &region[at..at + 8];
                let w = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if w & 0x8080_8080_8080_8080 == 0 {
                    at += 8;
                    left -= 8;
                    continue;
                }
            }
            let (_c, width) = next(region, at).ok_or_else(|| PutError::Bad(format!("text {k} is not UTF-8")))?;
            at += width;
            left -= 1;
        }
        pieces.push(&region[start..at]);
    }
    if at != region.len() {
        return Err(PutError::Bad("the lengths do not add up to the texts".into()));
    }
    Ok(pieces)
}

/// The code point at `b[i]` and its length in bytes.
#[inline]
fn next(b: &[u8], i: usize) -> Option<(u32, usize)> {
    let c = b[i] as u32;
    if c < 0x80 {
        return Some((c, 1));
    }
    let (n, min, init) = if c & 0xE0 == 0xC0 {
        (1, 0x80, c & 0x1F)
    } else if c & 0xF0 == 0xE0 {
        (2, 0x800, c & 0x0F)
    } else if c & 0xF8 == 0xF0 {
        (3, 0x10000, c & 0x07)
    } else {
        return None;
    };
    let mut v = init;
    for k in 1..=n {
        let x = *b.get(i + k)? as u32;
        if x & 0xC0 != 0x80 {
            return None;
        }
        v = (v << 6) | (x & 0x3F);
    }
    if v < min || v > 0x10FFFF {
        return None;
    }
    Some((v, n + 1))
}

/// Code points as WTF-8 (decode_wtf8's inverse; a lone surrogate is written as itself).
pub fn encode_wtf8(text: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for &c in text {
        match c {
            0..=0x7F => out.push(c as u8),
            0x80..=0x7FF => out.extend_from_slice(&[0xC0 | (c >> 6) as u8, 0x80 | (c & 0x3F) as u8]),
            0x800..=0xFFFF => out.extend_from_slice(&[0xE0 | (c >> 12) as u8, 0x80 | ((c >> 6) & 0x3F) as u8,
                                                      0x80 | (c & 0x3F) as u8]),
            _ => out.extend_from_slice(&[0xF0 | ((c >> 18) & 0x07) as u8, 0x80 | ((c >> 12) & 0x3F) as u8,
                                         0x80 | ((c >> 6) & 0x3F) as u8, 0x80 | (c & 0x3F) as u8]),
        }
    }
    out
}

struct Store {
    texts: HashMap<u64, Arc<[u8]>>,
    bytes: usize,
}

static STORE: Mutex<Option<Store>> = Mutex::new(None);
static NEXT: AtomicU64 = AtomicU64::new(1);

fn store() -> MutexGuard<'static, Option<Store>> {
    // (a thread that panicked while holding it left the map whole: every change below is one insert or remove)
    STORE.lock().unwrap_or_else(|p| p.into_inner())
}

/// Why a put was refused.
#[derive(Debug, PartialEq)]
pub enum PutError {
    /// The arguments do not describe the region (a bug in the caller).
    Bad(String),
    /// The store would hold more than MAX_BYTES: the caller sends these texts with its calls instead.
    Full { held: usize, asked: usize },
}

impl PutError {
    pub fn message(&self) -> String {
        match self {
            PutError::Bad(m) => format!("texts.put: {m}"),
            PutError::Full { held, asked } => format!(
                "texts.put: the text store is full ({held} bytes held, {asked} more asked, {MAX_BYTES} at most)"),
        }
    }
}

/// Keep the texts of `region` (WTF-8: the texts one after another, `lengths` code points each, as a Python str's
/// `"".join(texts).encode("utf-8", "surrogatepass")` writes them) and answer their ids, in order. All or none: a text
/// that is not WTF-8, lengths that do not add up to the region, or a store that would pass MAX_BYTES keeps nothing.
pub fn put(lengths: &[usize], region: &[u8]) -> Result<Vec<u64>, PutError> {
    put_within(lengths, region, MAX_BYTES)
}

fn put_within(lengths: &[usize], region: &[u8], max_bytes: usize) -> Result<Vec<u64>, PutError> {
    let pieces = split(lengths, region)?;
    let mut guard = store();
    let st = guard.get_or_insert_with(|| Store { texts: HashMap::new(), bytes: 0 });
    if st.bytes.saturating_add(region.len()) > max_bytes {
        return Err(PutError::Full { held: st.bytes, asked: region.len() });
    }
    let mut ids = Vec::with_capacity(pieces.len());
    for piece in pieces {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        st.texts.insert(id, Arc::from(piece));
        st.bytes += piece.len();
        ids.push(id);
    }
    Ok(ids)
}

/// The bytes of text `id`, if the store holds it.
pub fn get(id: u64) -> Option<Arc<[u8]>> {
    store().as_ref().and_then(|st| st.texts.get(&id).cloned())
}

/// Text `id` as the engine's code points (read on the calling thread, outside the lock), if the store holds it.
pub fn decoded(id: u64) -> Option<Vec<u32>> {
    let bytes = get(id)?;
    decode_wtf8(&bytes)                      // (checked when it was put)
}

/// Let texts go: the number the store held (an id it does not hold is passed over).
pub fn release(ids: &[u64]) -> usize {
    let mut guard = store();
    let Some(st) = guard.as_mut() else { return 0 };
    let mut n = 0;
    for id in ids {
        if let Some(t) = st.texts.remove(id) {
            st.bytes -= t.len();
            n += 1;
        }
    }
    n
}

/// (texts, bytes) the store holds.
pub fn held() -> (usize, usize) {
    store().as_ref().map_or((0, 0), |st| (st.texts.len(), st.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wtf8_both_ways() {
        assert_eq!(decode_wtf8("a\u{e9}\u{1F600}".as_bytes()), Some(vec![0x61, 0xE9, 0x1F600]));
        assert_eq!(decode_wtf8(&[0xED, 0xA0, 0x80]), Some(vec![0xD800]));
        assert_eq!(decode_wtf8(&[0xC0, 0x80]), None);
        assert_eq!(decode_wtf8(&[0xE2, 0x82]), None);
        assert_eq!(decode_wtf8(&[0xF4, 0x90, 0x80, 0x80]), None, "past U+10FFFF");
        let all = vec![0x61, 0xE9, 0x1F600, 0xD800, 0xDFFF, 0x7F, 0x80, 0x7FF, 0x800, 0xFFFF, 0x10000, 0x10FFFF];
        assert_eq!(decode_wtf8(&encode_wtf8(&all)), Some(all.clone()));
        assert_eq!(encode_wtf8(&[]), Vec::<u8>::new());
    }

    #[test]
    fn a_region_is_cut_by_code_points() {
        // ASCII runs past eight bytes, then two- to four-byte code points and a lone surrogate
        let a = "abcdefghijklmnopq\u{e9}xyz";
        let b = "\u{1F600}\u{7FF}";
        let mut region = format!("{a}{b}").into_bytes();
        region.extend_from_slice(&[0xED, 0xA0, 0x80]);         // (U+D800 alone)
        let pieces = split(&[a.chars().count(), b.chars().count(), 1], &region).unwrap();
        assert_eq!(pieces, vec![a.as_bytes(), b.as_bytes(), &[0xED, 0xA0, 0x80][..]]);
        assert_eq!(split(&[0, 0], b"").unwrap(), vec![&b""[..], &b""[..]]);
        assert!(matches!(split(&[9], b"abcdefgh"), Err(PutError::Bad(_))));
        assert!(matches!(split(&[7], b"abcdefgh"), Err(PutError::Bad(_))));
        assert!(matches!(split(&[1], &[0xE2, 0x82]), Err(PutError::Bad(_))));
    }

    #[test]
    fn put_get_release() {
        let ids = put(&[3, 0, 2], b"abc\xc3\xa9\xc3\xa9").unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(decoded(ids[0]), Some(vec![0x61, 0x62, 0x63]));
        assert_eq!(decoded(ids[1]), Some(vec![]));
        assert_eq!(decoded(ids[2]), Some(vec![0xE9, 0xE9]));
        assert_eq!(release(&[ids[0], ids[0], 0]), 1);
        assert_eq!(decoded(ids[0]), None);
        assert_eq!(release(&ids), 2);
        // all or none
        assert!(matches!(put(&[2, 2], b"ab\xff\xff"), Err(PutError::Bad(_))));
        assert!(matches!(put(&[5], b"abc"), Err(PutError::Bad(_))));
        assert!(matches!(put(&[1], b"abc"), Err(PutError::Bad(_))));
        assert!(matches!(put(&[usize::MAX, 2], b"ab"), Err(PutError::Bad(_))));
        assert!(matches!(put(&[1, 1], b"a\xff"), Err(PutError::Bad(_))));
        // past the bound: refused whole (the store is the process's: other tests' texts may be in it)
        assert!(matches!(put_within(&[2, 2], b"abcd", 3), Err(PutError::Full { asked: 4, .. })));
    }
}
