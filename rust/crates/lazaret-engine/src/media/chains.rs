//! The formats that are a chain of parts, each naming its length: ISO media's boxes (MP4, MOV, M4A, 3GP, HEIC, AVIF,
//! JPEG 2000), RIFF's chunks (WAV, AVI, WebP, …) and AIFF's, Matroska's and WebM's elements, PNG's chunks with their
//! checksums, GIF's blocks, JPEG's segments and entropy-coded scans, an Apple icon's elements.

use super::{be16, be32, be64, fourcc, free, le16, le32, le64, name4, need, pad, raw_samples, switch, Fmt, Step, Walker};

// ---- ISO base media (MP4, MOV, M4A, 3GP, HEIC, AVIF, JPEG 2000) --------------------------------------------------
//
// The top-level boxes, each its size and a four-character name, to the end (a size of 0: to the end, the media data
// alone). The first is `ftyp` or `styp` (or a JPEG 2000 file's signature box); a QuickTime file's older first boxes
// (`moov`, `mdat`, `free`, `skip`, `wide`, `pnot`) only in a file that has a movie box. Free space and boxes of no
// kind defined at the top level are free-form. n[0]: boxes. x[0]: 1 while a movie box is required and not read.

/// The boxes defined at a file's top level (ISO/IEC 14496-12, HEIF, JPEG 2000's, QuickTime's), but free space.
const TOP_BOXES: &[&[u8; 4]] = &[
    b"ftyp", b"styp", b"moov", b"mdat", b"moof", b"mfra", b"meta", b"pdin", b"sidx", b"ssix", b"prft", b"emsg",
    b"meco", b"pnot", b"PICT", b"jP  ", b"jp2h", b"jp2c", b"jp2i", b"xml ", b"uinf", b"rreq", b"res ", b"asoc",
    b"cgrp", b"nlst", b"lbl ", b"ftbl", b"jpch", b"jplh", b"dtbl", b"udta",
];

pub fn bmff(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    let no_movie = |w: &Walker| (w.x[0] == 1).then(|| Step::Fail("it has no file type box and no movie box".into()));
    if w.phase == 1 {
        // the last box, of size 0: to the end
        return if eof { no_movie(w).unwrap_or(Step::Done) } else { Step::Used(b.len()) };
    }
    if b.is_empty() && eof {
        return if w.n[0] > 0 { no_movie(w).unwrap_or(Step::Done) } else { Step::Fail("it holds no box".into()) };
    }
    if b.len() < 16 && !eof {
        return Step::More(16);
    }
    let first = w.n[0] == 0;
    // (n[7]: what the file is was said before this box chain began: a motion photo's JPEG)
    let label = first && w.n[7] == 0;
    if b.len() < 8 || !fourcc(&b[4..8]) {
        return if first {
            Step::Fail("its first box is not one".into())
        } else if let Some(s) = no_movie(w) {
            s
        } else {
            pad(w, format!("the bytes at {} are not a box", w.at))
        };
    }
    let kind = &b[4..8];
    if first {
        let ok = match kind {
            b"ftyp" | b"styp" => true,
            b"jP  " => b.len() >= 12 && be32(b, 0) == 12 && &b[8..12] == b"\r\n\x87\n",
            b"moov" | b"mdat" | b"free" | b"skip" | b"wide" | b"pnot" => {
                w.x[0] = 1;
                true
            }
            _ => false,
        };
        if !ok {
            return Step::Fail("its first box is not a file type box".into());
        }
        if label {
            w.kind = if (kind == b"ftyp" || kind == b"styp") && b.len() >= 12 {
                brand(&b[8..12])
            } else if kind == b"jP  " {
                "JPEG 2000 image".into()
            } else {
                "QuickTime movie".into()
            };
        }
    }
    if kind == b"moov" {
        w.x[0] = 0;
    }
    let small = be32(b, 0);
    let (size, header) = match small {
        0 => {
            // (to the end: the media data alone runs so)
            if kind != b"mdat" {
                return Step::Fail(format!("the box at byte {} runs to the end and is not media data ('mdat')", w.at));
            }
            w.n[0] += 1;
            w.phase = 1;
            return Step::Used(8);
        }
        1 => {
            if b.len() < 16 {
                return Step::Fail(format!("it is cut short inside a box's header at byte {}", w.at));
            }
            (be64(b, 8), 16)
        }
        s => (s, 8),
    };
    if size < header {
        return if first {
            Step::Fail("its first box is not one".into())
        } else if let Some(s) = no_movie(w) {
            s
        } else {
            pad(w, format!("the box at byte {} is not one", w.at))
        };
    }
    if !TOP_BOXES.iter().any(|t| &t[..] == kind) {
        // free space (`free`, `skip`, `wide`), a `uuid` box, a box of no kind defined here
        if let Some(s) = free(w, size, "ISO media free-space, uuid and unknown boxes") {
            return s;
        }
    }
    w.n[0] += 1;
    Step::Skip(size)
}

/// What an ISO media file is, by its major brand.
fn brand(b: &[u8]) -> String {
    let name = match &b[..4] {
        b"qt  " => "QuickTime movie",
        b"M4A " | b"M4B " | b"M4P " => "MPEG-4 audio",
        b"heic" | b"heix" | b"heim" | b"heis" | b"hevc" | b"hevx" | b"mif1" | b"msf1" => "HEIF image",
        b"avif" | b"avis" => "AVIF image",
        b"3gp4" | b"3gp5" | b"3gp6" | b"3g2a" => "3GPP media",
        b"crx " => "Canon raw image",
        b"jp2 " | b"jpx " | b"jpm " => "JPEG 2000 image",
        _ => "MPEG-4 media",
    };
    format!("{name} (ISO media, {})", name4(b))
}

// ---- RIFF and AIFF -----------------------------------------------------------------------------------------------
//
// RIFF (little-endian; WAV, AVI, WebP, MIDI, animated cursors, …; RF64 and BW64, whose sizes are in a ds64 chunk;
// RIFX, its big-endian form) and
// AIFF (big-endian FORM): a header, then chunks, each its name, its size and its bytes, padded to an even length,
// to the end the header declares. An AVI past 1 GB is RIFF 'AVI ' then RIFF 'AVIX' parts.
// Phases: 0 a header, 1 a chunk, 2 a chunk's pad byte, 3 after the form. n[0]: the form's end (u64::MAX: its size
// a placeholder, to the end), n[1]: 1 for RF64 / BW64, n[2]: the ds64 chunk's data size, n[3]: forms read, n[4]: the
// first form's type, n[5]: chunks in this form, n[6]: the chunk's pad byte is due. x[0]: a sound's samples, by its
// format chunk (1: stored raw, PCM; 2: coded). JUNK, padding, application and unknown chunks are free-form, and so
// is a LIST of no type defined here; a sound's raw samples must follow one another (raw_samples).

/// The chunks defined in a RIFF form (WAV's, Broadcast Wave's, AVI's, WebP's, MIDI's, animated cursors', DLS's) and
/// in AIFF; LIST by its type (LIST_TYPES).
const IFF_CHUNKS: &[&[u8; 4]] = &[
    b"fmt ", b"data", b"fact", b"cue ", b"plst", b"smpl", b"inst", b"bext", b"iXML", b"axml", b"ds64", b"id3 ",
    b"ID3 ", b"acid", b"strc", b"umid", b"cart", b"labl", b"note", b"ltxt", b"DISP", b"PEAK", b"levl", b"chna",
    b"MD5 ", b"cset", b"wavl", b"slnt", b"idx1", b"indx", b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ANIM", b"ANMF",
    b"ICCP", b"EXIF", b"XMP ", b"anih", b"rate", b"seq ", b"colh", b"vers", b"dlid", b"ptbl", b"COMM", b"SSND",
    b"FVER", b"MARK", b"INST", b"MIDI", b"AESD", b"COMT", b"NAME", b"AUTH", b"(c) ", b"ANNO", b"CHAN", b"basc",
    b"trns", b"cate",
];

const LIST_TYPES: &[&[u8; 4]] = &[
    b"INFO", b"adtl", b"hdrl", b"strl", b"movi", b"odml", b"rec ", b"sdta", b"pdta", b"fram", b"wvpl", b"lins",
    b"ins ", b"lrgn", b"rgn ", b"rgn2", b"lart", b"lar2", b"wave",
];

/// An AIFF-C file's compression types that store their samples raw.
const AIFC_RAW: &[&[u8; 4]] = &[b"NONE", b"sowt", b"twos", b"raw ", b"fl32", b"FL32", b"fl64", b"FL64", b"in24", b"in32"];

pub fn iff(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    let aiff = w.fmt == Fmt::Aiff as u8;
    // (n[7]: RIFX, RIFF's big-endian form)
    let be = aiff || w.n[7] == 1;
    let size_at = |b: &[u8], i: usize| if be { be32(b, i) } else { le32(b, i) };
    let wave = w.n[4] == u32::from_be_bytes(*b"WAVE") as u64;
    match w.phase {
        0 => {
            if let Some(s) = need(b, 12, eof, w.at, "a header") {
                return s;
            }
            let id = &b[..4];
            let form = &b[8..12];
            let ok = if aiff {
                id == b"FORM" && (form == b"AIFF" || form == b"AIFC")
            } else if be {
                id == b"RIFX" && fourcc(form)
            } else {
                (id == b"RIFF" || (w.n[3] == 0 && (id == b"RF64" || id == b"BW64"))) && fourcc(form)
            };
            if !ok || (w.n[3] > 0 && !(form == b"AVIX" && w.n[4] == u32::from_be_bytes(*b"AVI ") as u64)) {
                return if w.n[3] == 0 {
                    Step::Fail("its header is not one".into())
                } else {
                    pad(w, format!("bytes follow the {} at byte {}", w.kind, w.at))
                };
            }
            if w.n[3] == 0 {
                w.n[4] = be32(form, 0);
                if !aiff {
                    w.kind = format!("{} {} file", if be { "RIFX" } else { "RIFF" }, name4(form).trim_end());
                }
            }
            let size = size_at(b, 4);
            w.n[1] = (id == b"RF64" || id == b"BW64") as u64;
            w.n[0] = if w.n[1] == 1 || (!aiff && (size == 0 || size == 0xffff_ffff)) {
                u64::MAX
            } else {
                w.at + 8 + size
            };
            w.n[3] += 1;
            w.n[5] = 0;
            w.phase = 1;
            Step::Used(12)
        }
        1 => {
            if w.at == w.n[0] {
                w.phase = 3;
                return Step::Used(0);
            }
            if w.at > w.n[0] {
                return Step::Fail(format!("a chunk runs past the {}'s declared end at byte {}", w.kind, w.n[0]));
            }
            if b.is_empty() && eof {
                return if w.n[0] == u64::MAX && w.n[5] > 0 {
                    Step::Done
                } else {
                    Step::Fail(format!("it is cut short: its header declares {} bytes, it has {}", w.n[0], w.at))
                };
            }
            if let Some(s) = need(b, 8, eof, w.at, "a chunk's header") {
                return s;
            }
            if !fourcc(b) {
                return Step::Fail(format!("the bytes at {} are not a chunk", w.at));
            }
            let mut size = size_at(b, 4);
            if w.n[1] == 1 && w.n[5] == 0 {
                // RF64's ds64 chunk: the form's and the data chunk's sizes
                if &b[..4] != b"ds64" || size < 24 {
                    return Step::Fail("an RF64 file's first chunk is not ds64".into());
                }
                if let Some(s) = need(b, 32, eof, w.at, "the ds64 chunk") {
                    return s;
                }
                let riff = le64(b, 8);
                w.n[2] = le64(b, 16);
                w.n[0] = match (w.at - 12).checked_add(8).and_then(|x| x.checked_add(riff)) {
                    Some(end) => end,
                    None => return Step::Fail("the ds64 chunk's size is not one".into()),
                };
            } else if !aiff && &b[..4] == b"data" && size == 0xffff_ffff {
                if w.n[1] == 1 {
                    size = w.n[2];
                } else if w.n[0] == u64::MAX {
                    if wave && w.x[0] != 2 {
                        if let Some(s) = raw_samples(w, b, 8, u64::MAX, eof) {
                            return s;
                        }
                    }
                    w.n[5] += 1;
                    w.phase = 4;                  // (its size a placeholder: the data runs to the end)
                    return Step::Used(8);
                }
            }
            let name = &b[..4];
            if wave && name == b"fmt " && w.x[0] == 0 {
                // the sound's format: PCM, IEEE float, A-law, mu-law and WAVE_FORMAT_EXTENSIBLE store samples raw,
                // and so, for this walk, does a format of no name (0); a sound has channels, a rate and a block size
                if let Some(s) = need(b, 24, eof, w.at, "the format chunk") {
                    return s;
                }
                let (h, l): (fn(&[u8], usize) -> u64, fn(&[u8], usize) -> u64) = if be { (be16, be32) } else { (le16, le32) };
                if size < 16 || h(b, 10) == 0 || l(b, 12) == 0 || h(b, 20) == 0 {
                    return Step::Fail(format!("its format chunk at byte {} names no channels, rate or block size: no \
                                               sound's is so", w.at));
                }
                w.x[0] = if [0, 1, 3, 6, 7, 0xfffe].contains(&h(b, 8)) { 1 } else { 2 };
            }
            if aiff && name == b"COMM" && w.x[0] == 0 {
                if let Some(s) = need(b, 26, eof, w.at, "the common chunk") {
                    return s;
                }
                if size < 18 || be16(b, 8) == 0 || be16(b, 14) == 0 || b[16..26].iter().all(|&c| c == 0) {
                    return Step::Fail(format!("its common chunk at byte {} names no channels, sample size or rate: no \
                                               sound's is so", w.at));
                }
                w.x[0] = if w.n[4] == u32::from_be_bytes(*b"AIFF") as u64 {
                    1
                } else {
                    if let Some(s) = need(b, 30, eof, w.at, "the common chunk") {
                        return s;
                    }
                    if AIFC_RAW.iter().any(|t| &t[..] == &b[26..30]) { 1 } else { 2 }
                };
            }
            if (wave && name == b"data" || aiff && name == b"SSND") && w.x[0] != 2 {
                // (an AIFF's sound data starts after its offset and block size, and the offset's bytes)
                let skip = if aiff {
                    if let Some(s) = need(b, 16, eof, w.at, "the sound data chunk") {
                        return s;
                    }
                    16u64.saturating_add(be32(b, 8))
                } else {
                    8
                };
                if skip < 8 + size && skip <= super::RAW_SAMPLE as u64 {
                    if let Some(s) = raw_samples(w, b, skip as usize, 8 + size - skip, eof) {
                        return s;
                    }
                }
            }
            let listed = if name == b"LIST" {
                if let Some(s) = need(b, 12, eof, w.at, "a list's type") {
                    return s;
                }
                LIST_TYPES.iter().any(|t| &t[..] == &b[8..12])
            } else {
                IFF_CHUNKS.iter().any(|t| &t[..] == name)
            };
            if !listed {
                if let Some(s) = free(w, size, "JUNK, padding, application and unknown chunks") {
                    return s;
                }
            }
            let end = w.at.saturating_add(8).saturating_add(size);
            if end > w.n[0] {
                if w.n[3] > 1 {
                    return Step::Fail(format!("the chunk at byte {} runs past the {}'s declared end", w.at, w.kind));
                }
                // (a header whose size a writer got wrong, smaller than its chunks: scipy's test WAVs have one;
                // the chunks then run to the file's end, as a placeholder's do)
                w.n[0] = u64::MAX;
            }
            w.n[5] += 1;
            w.n[6] = size & 1;
            w.phase = 2;
            Step::Skip(8 + size)
        }
        2 => {
            // the pad byte after a chunk of odd size (a writer may leave it out at the form's end, or the file's)
            w.phase = 1;
            if w.n[6] == 1 && w.at != w.n[0] && !(b.is_empty() && eof) {
                if b.is_empty() {
                    w.phase = 2;
                    return Step::More(1);
                }
                return Step::Used(1);
            }
            Step::Used(0)
        }
        4 => {
            if eof { Step::Done } else { Step::Used(b.len()) }
        }
        _ => {
            // after the form: the end, the next part of a large AVI, or padding
            if b.is_empty() && eof {
                return Step::Done;
            }
            if b.len() < 12 && !eof {
                return Step::More(12);
            }
            if !aiff && b.starts_with(if be { b"RIFX" } else { b"RIFF" }) {
                w.phase = 0;
                return Step::Used(0);
            }
            pad(w, format!("bytes follow the {}'s declared end at byte {}", w.kind, w.at))
        }
    }
}

// ---- Matroska and WebM -------------------------------------------------------------------------------------------
//
// EBML elements: an ID and a size, both variable-length; a size of all ones is unknown (a live recording's segment
// and clusters). The file: its EBML header (DocType matroska or webm), then segments, each holding the top-level
// elements Matroska defines; a cluster of unknown size holds its own elements up to the next top-level one.
// Phases: 0 the file's level, 1 a segment's, 2 an unknown-size cluster's. n[0]: the segment's end (u64::MAX:
// unknown), n[1]: segments.

const LEVEL1: [u32; 10] = [0x114D9B74, 0x1549A966, 0x1654AE6B, 0x1F43B675, 0x1C53BB6B, 0x1941A469, 0x1043A770,
                           0x1254C367, 0xEC, 0xBF];
const CLUSTER: [u32; 9] = [0xE7, 0x5854, 0xA7, 0xAB, 0xA3, 0xA0, 0xAF, 0xEC, 0xBF];
const EBML: u32 = 0x1A45DFA3;
const SEGMENT: u32 = 0x18538067;
/// A Void element (space a muxer reserves) and the attachments (files of any kind) are free-form.
const VOID: u32 = 0xEC;
const ATTACHMENTS: u32 = 0x1941A469;

/// An element's ID and size at the start of `b`: (id, size or None when unknown, header length), or None.
fn element(b: &[u8]) -> Option<(u32, Option<u64>, usize)> {
    let first = *b.first()?;
    let idlen = first.leading_zeros() as usize + 1;
    if idlen > 4 || b.len() < idlen {
        return None;
    }
    let id = b[..idlen].iter().fold(0u32, |a, &c| (a << 8) | c as u32);
    let s0 = *b.get(idlen)?;
    let slen = s0.leading_zeros() as usize + 1;
    if slen > 8 || b.len() < idlen + slen {
        return None;
    }
    let mut v = (s0 & (0xffu16 >> slen) as u8) as u64;
    let mut ones = v == (0xffu64 >> slen);
    for &c in &b[idlen + 1..idlen + slen] {
        v = (v << 8) | c as u64;
        ones &= c == 0xff;
    }
    Some((id, if ones { None } else { Some(v) }, idlen + slen))
}

/// The DocType an EBML header's bytes name.
fn doctype(body: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    while i < body.len() {
        let (id, size, h) = element(&body[i..])?;
        let size = size? as usize;
        let end = i.checked_add(h)?.checked_add(size)?;
        if end > body.len() {
            return None;
        }
        if id == 0x4282 {
            return Some(&body[i + h..end]);
        }
        i = end;
    }
    None
}

pub fn ebml(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    match w.phase {
        0 => {
            if b.is_empty() && eof {
                return if w.n[1] > 0 { Step::Done } else { Step::Fail("it holds no segment".into()) };
            }
            if b.len() < 12 && !eof {
                return Step::More(12);
            }
            let Some((id, size, h)) = element(b) else {
                return if w.n[1] == 0 {
                    Step::Fail(format!("the bytes at {} are not an element", w.at))
                } else {
                    pad(w, format!("bytes follow the segment at byte {}", w.at))
                };
            };
            if id == EBML {
                let Some(size) = size.filter(|&s| s <= 4096) else {
                    return Step::Fail("its EBML header is not one".into());
                };
                if let Some(s) = need(b, h + size as usize, eof, w.at, "its EBML header") {
                    return s;
                }
                match doctype(&b[h..h + size as usize]) {
                    Some(b"webm") => w.kind = "WebM".into(),
                    Some(b"matroska") => w.kind = "Matroska".into(),
                    _ => return Step::Fail("its EBML header names no Matroska or WebM document".into()),
                }
                w.n[2] = 1;
                return Step::Used(h + size as usize);
            }
            if id == SEGMENT && w.n[2] == 1 {
                w.n[0] = size.map_or(u64::MAX, |s| w.at.saturating_add(h as u64).saturating_add(s));
                w.n[1] += 1;
                w.phase = 1;
                return Step::Used(h);
            }
            if w.n[1] == 0 {
                return Step::Fail(format!("the element at byte {} is not where Matroska puts one", w.at));
            }
            pad(w, format!("bytes follow the segment at byte {}", w.at))
        }
        1 => {
            if w.at == w.n[0] {
                w.phase = 0;
                return Step::Used(0);
            }
            if w.at > w.n[0] {
                return Step::Fail(format!("an element runs past its segment's end at byte {}", w.n[0]));
            }
            if b.is_empty() && eof {
                return if w.n[0] == u64::MAX {
                    Step::Done
                } else {
                    Step::Fail(format!("it is cut short: its segment ends at byte {}", w.n[0]))
                };
            }
            if b.len() < 12 && !eof {
                return Step::More(12);
            }
            let Some((id, size, h)) = element(b).filter(|e| LEVEL1.contains(&e.0)) else {
                if w.n[0] == u64::MAX && matches!(element(b), Some((EBML, _, _))) {
                    w.phase = 0;
                    return Step::Used(0);
                }
                return if w.n[0] == u64::MAX {
                    pad(w, format!("the bytes at {} are not an element of a segment", w.at))
                } else {
                    Step::Fail(format!("the bytes at {} are not an element of a segment", w.at))
                };
            };
            match size {
                Some(s) => {
                    let end = w.at.saturating_add(h as u64).saturating_add(s);
                    if end > w.n[0] {
                        return Step::Fail(format!("the element at byte {} runs past its segment's end", w.at));
                    }
                    if id == VOID || id == ATTACHMENTS {
                        if let Some(s) = free(w, s, "Matroska Void elements and attachments") {
                            return s;
                        }
                    }
                    Step::Skip(h as u64 + s)
                }
                None if id == 0x1F43B675 => {
                    w.phase = 2;
                    Step::Used(h)
                }
                None => Step::Fail(format!("the element at byte {} has no size", w.at)),
            }
        }
        _ => {
            // an unknown-size cluster's elements, to the next top-level element or the end
            if b.is_empty() && eof {
                return if w.n[0] == u64::MAX { Step::Done } else { Step::Fail("it is cut short inside a cluster".into()) };
            }
            if b.len() < 12 && !eof {
                return Step::More(12);
            }
            let Some((id, size, h)) = element(b) else {
                return pad(w, format!("the bytes at {} are not an element of a cluster", w.at));
            };
            if LEVEL1.contains(&id) && id != 0xEC && id != 0xBF || id == EBML || id == SEGMENT {
                w.phase = if id == EBML || id == SEGMENT { 0 } else { 1 };
                if id == SEGMENT {
                    w.n[2] = 1;
                }
                return Step::Used(0);
            }
            match (CLUSTER.contains(&id), size) {
                (true, Some(s)) => {
                    let end = w.at.saturating_add(h as u64).saturating_add(s);
                    if end > w.n[0] {
                        return Step::Fail(format!("the element at byte {} runs past its segment's end", w.at));
                    }
                    if id == VOID {
                        if let Some(s) = free(w, s, "Matroska Void elements and attachments") {
                            return s;
                        }
                    }
                    Step::Skip(h as u64 + s)
                }
                _ => pad(w, format!("the bytes at {} are not an element of a cluster", w.at)),
            }
        }
    }
}

// ---- PNG ---------------------------------------------------------------------------------------------------------
//
// The signature, then chunks (a length, a name of four letters, the data, a CRC-32 of the name and the data) from
// IHDR to IEND, image data (IDAT) among them. Text chunks and the chunks no one registered are free-form. Phases: 0
// the signature, 1 a chunk's header, 2 its data, 3 its CRC, 4 after IEND. n[0]: the data's bytes left, n[1]: the
// chunk's name, n[2]: chunks, n[3]: IDAT chunks.

/// The chunks the PNG specification (third edition) and its registry define, but text: their content is theirs.
const PNG_CHUNKS: &[&[u8; 4]] = &[
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB", b"cICP", b"mDCV",
    b"mDCv", b"cLLI", b"cLLi", b"eXIf", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"tIME", b"acTL", b"fcTL", b"fdAT",
    b"oFFs", b"pCAL", b"sCAL", b"gIFg", b"gIFx", b"sTER", b"dSIG",
];

pub fn png(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    use lazaret_verify::inflate::crc32;
    match w.phase {
        0 => {
            if let Some(s) = need(b, 8, eof, w.at, "its signature") {
                return s;
            }
            w.phase = 1;
            Step::Used(8)
        }
        1 => {
            if let Some(s) = need(b, 8, eof, w.at, "a chunk's header") {
                return s;
            }
            let len = be32(b, 0);
            let name = &b[4..8];
            if len > 0x7fff_ffff || !name.iter().all(|c| c.is_ascii_alphabetic()) {
                return Step::Fail(format!("the bytes at {} are not a chunk", w.at));
            }
            if w.n[2] == 0 && (name != b"IHDR" || len != 13) {
                return Step::Fail("its first chunk is not IHDR".into());
            }
            if name == b"IDAT" {
                w.n[3] += 1;
            } else if name == b"IEND" && w.n[3] == 0 {
                return Step::Fail("it has no image data (IDAT)".into());
            } else if !PNG_CHUNKS.iter().any(|c| &c[..] == name) {
                if let Some(s) = free(w, len, "PNG text, private and unregistered chunks") {
                    return s;
                }
            }
            w.n[0] = len;
            w.n[1] = be32(b, 4);
            w.n[2] += 1;
            w.crc = crc32(0, name);
            w.phase = 2;
            Step::Used(8)
        }
        2 => {
            let take = w.n[0].min(b.len() as u64) as usize;
            if w.n[0] > 0 && take == 0 && eof {
                return Step::Fail(format!("it is cut short inside a chunk at byte {}", w.at));
            }
            w.crc = crc32(w.crc, &b[..take]);
            w.n[0] -= take as u64;
            if w.n[0] == 0 {
                w.phase = 3;
            }
            Step::Used(take)
        }
        3 => {
            if let Some(s) = need(b, 4, eof, w.at, "a chunk's checksum") {
                return s;
            }
            if be32(b, 0) != w.crc as u64 {
                return Step::Fail(format!("the checksum of the chunk that ends at byte {} does not match", w.at + 4));
            }
            w.phase = if w.n[1] == u32::from_be_bytes(*b"IEND") as u64 { 4 } else { 1 };
            Step::Used(4)
        }
        _ => {
            if b.is_empty() && eof {
                return Step::Done;
            }
            pad(w, format!("bytes follow the image's end (IEND) at byte {}", w.at))
        }
    }
}

// ---- GIF ---------------------------------------------------------------------------------------------------------
//
// The header and the logical screen's descriptor (with its colour table), then blocks: extensions and images (each
// with its colour table and its data in sub-blocks of up to 255 bytes) to the trailer (0x3b), an image among them.
// Comments, plain text and the application extensions but the looping (NETSCAPE2.0) and XMP ones are free-form (the
// review of Oct 27). Phases: 0 the header, 1 a block, 2 sub-blocks, 3 an image's LZW code size, 4 after the
// trailer. n[0]: images. x[0]: 1 while the sub-blocks are a free-form extension's.

const GIF_APPS: &[&[u8; 11]] = &[b"NETSCAPE2.0", b"XMP DataXMP"];

pub fn gif(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    let table = |flags: u8| if flags & 0x80 != 0 { 3u64 << ((flags & 7) + 1) } else { 0 };
    match w.phase {
        0 => {
            if let Some(s) = need(b, 13, eof, w.at, "its header") {
                return s;
            }
            w.phase = 1;
            Step::Skip(13 + table(b[10]))
        }
        1 => {
            if let Some(s) = need(b, 1, eof, w.at, "a block") {
                return s;
            }
            match b[0] {
                0x21 => {
                    if let Some(s) = need(b, 2, eof, w.at, "an extension") {
                        return s;
                    }
                    w.x[0] = match b[1] {
                        0xf9 => 0,
                        0xff => {
                            if let Some(s) = need(b, 14, eof, w.at, "an application extension") {
                                return s;
                            }
                            (b[2] != 11 || !GIF_APPS.iter().any(|a| &a[..] == &b[3..14])) as u64
                        }
                        _ => 1,
                    };
                    w.phase = 2;
                    Step::Used(2)
                }
                0x2c => {
                    if let Some(s) = need(b, 10, eof, w.at, "an image's descriptor") {
                        return s;
                    }
                    w.n[0] += 1;
                    w.phase = 3;
                    Step::Skip(10 + table(b[9]))
                }
                0x3b => {
                    if w.n[0] == 0 {
                        return Step::Fail("it has no image".into());
                    }
                    w.phase = 4;
                    Step::Used(1)
                }
                _ => Step::Fail(format!("the bytes at {} are not a GIF block", w.at)),
            }
        }
        2 => {
            if let Some(s) = need(b, 1, eof, w.at, "a sub-block") {
                return s;
            }
            if b[0] == 0 {
                w.x[0] = 0;
                w.phase = 1;
                return Step::Used(1);
            }
            if w.x[0] == 1 {
                if let Some(s) = free(w, b[0] as u64, "GIF comments, plain text and application extensions") {
                    return s;
                }
            }
            Step::Skip(1 + b[0] as u64)
        }
        3 => {
            if let Some(s) = need(b, 1, eof, w.at, "an image") {
                return s;
            }
            if !(1..=12).contains(&b[0]) {
                return Step::Fail(format!("the image's code size at byte {} is not one", w.at));
            }
            w.phase = 2;
            Step::Used(1)
        }
        _ => {
            if b.is_empty() && eof {
                return Step::Done;
            }
            pad(w, format!("bytes follow the image's trailer at byte {}", w.at))
        }
    }
}

// ---- JPEG --------------------------------------------------------------------------------------------------------
//
// SOI, then marker segments (each its length) and, after each SOS, entropy-coded data, in which 0xff is followed by
// 0x00 (a stuffed byte) or a restart marker; any other marker ends the scan. EOI ends the image. After it: further
// images (a multi-picture file: a camera's or a phone's), the MP4 a motion photo appends, or padding of 0x00 or 0xff.
// Each image has a frame header (SOF) and a scan (SOS). Comments and the application segments no one registered are
// free-form. Phases: 0 SOI, 1 a marker, 2 a scan's data, 3 after EOI, 4 padding. n[0]: images. x[0]: this image's
// frame header (1) and scan (2) read.

/// The application segments' identifiers registered or in wide use (JFIF, JFXX, Motion JPEG's AVI1; Exif, XMP and
/// extended XMP; ICC profiles, MPF, FlashPix; JPEG XT and JUMBF; Ducky, PictureInfo; Photoshop's IRB; Adobe's),
/// by marker.
const JPEG_APPS: &[(u8, &[u8])] = &[
    (0xe0, b"JFIF "), (0xe0, b"JFXX "), (0xe0, b"AVI1"), (0xe1, b"Exif "), (0xe1, b"http://ns.adobe.com/xap/1.0/ "),
    (0xe1, b"http://ns.adobe.com/xmp/extension/ "), (0xe2, b"ICC_PROFILE "), (0xe2, b"MPF "), (0xe2, b"FPXR "),
    (0xeb, b"JP"), (0xec, b"Ducky"), (0xec, b"PictureInfo"), (0xed, b"Photoshop 3.0 "), (0xee, b"Adobe"),
];

pub fn jpeg(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    match w.phase {
        0 => {
            if let Some(s) = need(b, 2, eof, w.at, "its start") {
                return s;
            }
            w.n[0] += 1;
            w.x[0] = 0;
            w.phase = 1;
            Step::Used(2)
        }
        1 => {
            if let Some(s) = need(b, 2, eof, w.at, "a marker") {
                return s;
            }
            if b[0] != 0xff {
                return Step::Fail(format!("the bytes at {} are not a JPEG marker", w.at));
            }
            if b[1] == 0xff {
                return Step::Used(1);             // (a fill byte)
            }
            match b[1] {
                0xd9 => {
                    if w.x[0] != 3 {
                        return Step::Fail(format!("the image that ends at byte {} has no frame header (SOF) or no scan \
                                                   (SOS)", w.at + 2));
                    }
                    w.phase = 3;
                    Step::Used(2)
                }
                0x01 => Step::Used(2),
                0x00 | 0xd0..=0xd8 => Step::Fail(format!("the marker at byte {} is out of place", w.at)),
                m => {
                    if let Some(s) = need(b, 4, eof, w.at, "a segment") {
                        return s;
                    }
                    let len = be16(b, 2);
                    if len < 2 {
                        return Step::Fail(format!("the segment at byte {} is not one", w.at));
                    }
                    match m {
                        0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf => w.x[0] |= 1,
                        0xda => {
                            w.x[0] |= 2;
                            w.phase = 2;
                        }
                        0xe0..=0xef | 0xfe => {
                            // an application segment: its identifier, at most 35 bytes
                            let id = 4 + (len as usize - 2).min(35);
                            if let Some(s) = need(b, id, eof, w.at, "a segment") {
                                return s;
                            }
                            let known = m != 0xfe && JPEG_APPS.iter().any(|&(k, sig)| k == m && b[4..id].starts_with(sig));
                            if !known {
                                if let Some(s) = free(w, len - 2, "JPEG comments and unregistered application segments") {
                                    return s;
                                }
                            }
                        }
                        _ => {}
                    }
                    Step::Skip(2 + len)
                }
            }
        }
        2 => {
            // entropy-coded data: to the next marker that is not a restart
            let mut i = 0;
            while let Some(k) = b[i..].iter().position(|&c| c == 0xff) {
                let j = i + k;
                if j + 1 >= b.len() {
                    if eof {
                        break;
                    }
                    return if j == 0 { Step::More(2) } else { Step::Used(j) };
                }
                match b[j + 1] {
                    0x00 | 0xd0..=0xd7 => i = j + 2,
                    _ => {
                        w.phase = 1;
                        return Step::Used(j);
                    }
                }
            }
            if eof {
                return Step::Fail("it is cut short inside a scan".into());
            }
            Step::Used(b.len())
        }
        3 => {
            if b.is_empty() && eof {
                return Step::Done;
            }
            if b.len() < 8 && !eof {
                return Step::More(8);
            }
            if b.starts_with(b"\xff\xd8\xff") {
                w.phase = 0;
                return Step::Used(0);
            }
            if b.len() >= 8 && &b[4..8] == b"ftyp" {
                let kind = format!("{} with ISO media after it", w.kind);
                let s = switch(w, Fmt::Bmff, &kind);
                w.n[7] = 1;
                return s;
            }
            w.phase = 4;
            Step::Used(0)
        }
        _ => {
            // padding, and after it a further image (a multi-picture file pads between its images: Fujifilm's MPO)
            let mut k = 0;
            while k < b.len() && (b[k] == 0 || b[k] == 0xff) {
                if b[k] == 0xff && k + 3 > b.len() && !eof {
                    return if k == 0 { Step::More(3) } else { Step::Used(k) };
                }
                if b[k..].starts_with(b"\xff\xd8\xff") {
                    if k > 0 {
                        return Step::Used(k);
                    }
                    w.phase = 0;
                    return Step::Used(0);
                }
                k += 1;
            }
            if k < b.len() {
                return Step::Fail(format!("bytes follow the image's end at byte {}", w.at + k as u64));
            }
            if eof { Step::Done } else { Step::Used(k) }
        }
    }
}

// ---- Apple icon image (icns) -------------------------------------------------------------------------------------
//
// "icns" and the file's length, then elements, each a four-character type and its length. Phases: 0 the header,
// 1 an element, 2 after the declared end. n[0]: the declared end.

pub fn icns(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    match w.phase {
        0 => {
            if let Some(s) = need(b, 8, eof, w.at, "its header") {
                return s;
            }
            let len = be32(b, 4);
            if len < 8 {
                return Step::Fail("its header is not one".into());
            }
            w.n[0] = w.at + len;
            w.phase = 1;
            Step::Used(8)
        }
        1 => {
            if w.at == w.n[0] {
                w.phase = 2;
                return Step::Used(0);
            }
            if let Some(s) = need(b, 8, eof, w.at, "an element") {
                return s;
            }
            let len = be32(b, 4);
            if !fourcc(b) || len < 8 || w.at + len > w.n[0] {
                return Step::Fail(format!("the bytes at {} are not an icon element", w.at));
            }
            Step::Skip(len)
        }
        _ => {
            if b.is_empty() && eof {
                return Step::Done;
            }
            pad(w, format!("bytes follow the icon's declared end at byte {}", w.at))
        }
    }
}
