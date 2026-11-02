//! The formats that are a chain of frames or pages: MPEG audio (MP3, MP2) and ADTS (AAC) frames after their ID3v2
//! tags, Ogg's pages with their checksums, FLAC's metadata blocks and frames with theirs, a transport stream's
//! packets.

use super::{be24, be32, free, le32, need, pad, switch, Fmt, Step, Walker};

// ---- MPEG audio and ADTS -----------------------------------------------------------------------------------------
//
// n[0]: the first frame's shape (version, layer, sample rate; ADTS: its profile, rate and channels), n[1]: frames,
// n[2]: tags read, n[7]: 1 for ADTS. Phases: 0 ID3v2 tags, 1 the zero padding after them, 2 frames, 3 an ID3v1 tag,
// 4 after an APE tag, 5 trailing tags read whole at the end (an APE tag without its header, Lyrics3), 6 after ID3v1,
// 7 an ID3v2 tag's frames, 8 its padding. x[0]: where the tag's frames end, x[1]: its version, x[2]: its footer's
// length.

/// ID3v2.3 and v2.4 frames (and the ones iTunes and others write), whose content the frame's kind says; PRIV
/// (private), GEOB (an object of any kind) and an unknown frame are free-form.
const ID3_FRAMES: &[&[u8; 4]] = &[
    b"AENC", b"APIC", b"ASPI", b"CHAP", b"COMM", b"COMR", b"CTOC", b"ENCR", b"EQU2", b"EQUA", b"ETCO", b"GRID",
    b"GRP1", b"IPLS", b"LINK", b"MCDI", b"MLLT", b"MVIN", b"MVNM", b"OWNE", b"PCNT", b"PCST", b"POPM", b"POSS",
    b"RBUF", b"RGAD", b"RVA2", b"RVAD", b"RVRB", b"SEEK", b"SIGN", b"SYLT", b"SYTC", b"TALB", b"TBPM", b"TCAT",
    b"TCMP", b"TCOM", b"TCON", b"TCOP", b"TDAT", b"TDEN", b"TDES", b"TDLY", b"TDOR", b"TDRC", b"TDRL", b"TDTG",
    b"TENC", b"TEXT", b"TFLT", b"TGID", b"TIME", b"TIPL", b"TIT1", b"TIT2", b"TIT3", b"TKEY", b"TKWD", b"TLAN",
    b"TLEN", b"TMCL", b"TMED", b"TMOO", b"TOAL", b"TOFN", b"TOLY", b"TOPE", b"TORY", b"TOWN", b"TPE1", b"TPE2",
    b"TPE3", b"TPE4", b"TPOS", b"TPRO", b"TPUB", b"TRCK", b"TRDA", b"TRSN", b"TRSO", b"TSIZ", b"TSO2", b"TSOA",
    b"TSOC", b"TSOP", b"TSOT", b"TSRC", b"TSSE", b"TSST", b"TXXX", b"TYER", b"UFID", b"USER", b"USLT", b"WCOM",
    b"WCOP", b"WFED", b"WOAF", b"WOAR", b"WOAS", b"WORS", b"WPAY", b"WPUB", b"WXXX", b"XRVA",
];

/// ID3v2.2's three-letter frames; GEO (an object of any kind) and an unknown frame are free-form.
const ID3_FRAMES_22: &[&[u8; 3]] = &[
    b"BUF", b"CNT", b"COM", b"CRA", b"CRM", b"ETC", b"EQU", b"IPL", b"LNK", b"MCI", b"MLL", b"PIC", b"POP", b"REV",
    b"RVA", b"SLT", b"STC", b"TAL", b"TBP", b"TCM", b"TCO", b"TCP", b"TCR", b"TDA", b"TDY", b"TEN", b"TFT", b"TIM",
    b"TKE", b"TLA", b"TLE", b"TMT", b"TOA", b"TOF", b"TOL", b"TOR", b"TOT", b"TP1", b"TP2", b"TP3", b"TP4", b"TPA",
    b"TPB", b"TRC", b"TRD", b"TRK", b"TS2", b"TSA", b"TSC", b"TSI", b"TSP", b"TSS", b"TST", b"TT1", b"TT2", b"TT3",
    b"TXT", b"TXX", b"TYE", b"UFI", b"ULT", b"WAF", b"WAR", b"WAS", b"WCM", b"WCP", b"WPB", b"WXX",
];

/// An ID3v2 tag's header at `b` (its 10 bytes there): its frames, read (phase 7) unless the tag is written
/// unsynchronised or compressed (v2.2, v2.3: their bytes are not their frames'), when all of it is free-form.
fn id3_tag(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    if !(2..=4).contains(&b[3]) || b[4] == 0xff || b[6..10].iter().any(|&c| c >= 0x80) {
        return Step::Fail(format!("the ID3 tag at byte {} is not one", w.at));
    }
    let (version, flags) = (b[3] as u64, b[5]);
    let size = b[6..10].iter().fold(0u64, |a, &c| (a << 7) | c as u64);
    let footer = if version == 4 && flags & 0x10 != 0 { 10 } else { 0 };
    w.n[2] += 1;
    if (version < 4 && flags & 0x80 != 0) || (version == 2 && flags & 0x40 != 0) {
        if let Some(s) = free(w, size, "ID3 tags written unsynchronised or compressed") {
            return s;
        }
        return Step::Skip(10 + size + footer);
    }
    let mut ext = 0u64;
    if version > 2 && flags & 0x40 != 0 {
        // an extended header (v2.4: its size, synchsafe, counts itself; v2.3: the size does not)
        if let Some(s) = need(b, 14, eof, w.at, "an ID3 tag's extended header") {
            return s;
        }
        ext = if version == 4 { b[10..14].iter().fold(0u64, |a, &c| (a << 7) | (c & 0x7f) as u64) } else { be32(b, 10) + 4 };
        if ext > size {
            return Step::Fail(format!("the ID3 tag at byte {} is not one", w.at));
        }
    }
    w.x = [w.at + 10 + size, version, footer, 0];
    w.phase = 7;
    Step::Skip(10 + ext)
}

/// An ID3v2 tag's frames (phase 7), to its padding (zero bytes: phase 8) or its end.
fn id3_frames(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    let end = w.x[0];
    let v22 = w.x[1] == 2;
    let header = if v22 { 6 } else { 10 };
    if w.at > end {
        return Step::Fail(format!("a frame runs past its ID3 tag's end at byte {end}"));
    }
    let left = end - w.at;
    if left == 0 {
        w.phase = 0;
        return Step::Skip(std::mem::take(&mut w.x[2]));
    }
    if let Some(s) = need(b, header.min(left as usize), eof, w.at, "an ID3 frame") {
        return s;
    }
    if left < header as u64 || b[0] == 0 {
        w.phase = 8;
        return Step::Used(0);
    }
    let id = &b[..if v22 { 3 } else { 4 }];
    if !id.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return Step::Fail(format!("the bytes at {} are not an ID3 frame", w.at));
    }
    let size = match w.x[1] {
        2 => be24(b, 3),
        // (v2.4's sizes are synchsafe; some writers put v2.3's there)
        4 if b[4..8].iter().all(|&c| c < 0x80) => b[4..8].iter().fold(0u64, |a, &c| (a << 7) | c as u64),
        _ => be32(b, 4),
    };
    if header as u64 + size > left {
        return Step::Fail(format!("the ID3 frame at byte {} runs past its tag", w.at));
    }
    let known = if v22 {
        id != b"GEO" && ID3_FRAMES_22.iter().any(|f| &f[..] == id)
    } else {
        ID3_FRAMES.iter().any(|f| &f[..] == id)
    };
    if !known {
        if let Some(s) = free(w, size, "ID3 private, object and unknown frames") {
            return s;
        }
    }
    Step::Skip(header as u64 + size)
}

/// An ID3v2 tag's padding (phase 8): zero bytes to its end.
fn id3_padding(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    let left = w.x[0].saturating_sub(w.at);
    if left == 0 {
        w.phase = 0;
        return Step::Skip(std::mem::take(&mut w.x[2]));
    }
    let take = (left.min(b.len() as u64)) as usize;
    if take == 0 {
        return if eof { Step::Fail(format!("it is cut short inside an ID3 tag at byte {}", w.at)) } else { Step::More(1) };
    }
    if let Some(k) = b[..take].iter().position(|&c| c != 0) {
        return Step::Fail(format!("the ID3 tag's padding at byte {} is not zero bytes", w.at + k as u64));
    }
    Step::Used(take)
}

/// kbit/s: [MPEG-1, MPEG-2 and 2.5][layer I, II, III][index]
const BITRATES: [[[u16; 16]; 3]; 2] = [
    [
        [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0],
        [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0],
        [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0],
    ],
    [
        [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0],
        [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0],
        [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0],
    ],
];

/// [MPEG-1, MPEG-2, MPEG-2.5][index]
const RATES: [[u32; 3]; 3] = [[44100, 48000, 32000], [22050, 24000, 16000], [11025, 12000, 8000]];

/// An MPEG audio frame's header: (its shape, its length, its layer), or None. Free-format bit rates (index 0) are
/// not read: such a frame's length is not in its header.
fn mpeg_frame(h: &[u8]) -> Option<(u64, u64, u8)> {
    if h[0] != 0xff || h[1] & 0xe0 != 0xe0 {
        return None;
    }
    let version = (h[1] >> 3) & 3;                // 0: 2.5, 1: reserved, 2: MPEG-2, 3: MPEG-1
    let layer = (h[1] >> 1) & 3;                  // 1: III, 2: II, 3: I
    let bitrate = (h[2] >> 4) as usize;
    let rate = ((h[2] >> 2) & 3) as usize;
    let padding = ((h[2] >> 1) & 1) as u64;
    if version == 1 || layer == 0 || bitrate == 0 || bitrate == 15 || rate == 3 || h[3] & 3 == 2 {
        return None;
    }
    let v = match version { 3 => 0, 2 => 1, _ => 2 };
    let l = (3 - layer) as usize;                 // 0: I, 1: II, 2: III
    let kbps = BITRATES[(v > 0) as usize][l][bitrate] as u64 * 1000;
    let hz = RATES[v][rate] as u64;
    let len = match l {
        0 => (12 * kbps / hz + padding) * 4,
        2 if v > 0 => 72 * kbps / hz + padding,
        _ => 144 * kbps / hz + padding,
    };
    let shape = ((h[1] as u64 & 0x1e) << 8) | ((h[2] as u64 >> 2) & 3);
    Some((shape, len, l as u8))
}

/// An ADTS frame's header: (its shape, its length), or None.
fn adts_frame(h: &[u8]) -> Option<(u64, u64)> {
    if h[0] != 0xff || h[1] & 0xf6 != 0xf0 {
        return None;
    }
    let rate = (h[2] >> 2) & 0xf;
    let len = (((h[3] & 3) as u64) << 11) | ((h[4] as u64) << 3) | (h[5] as u64 >> 5);
    let header = if h[1] & 1 == 0 { 9 } else { 7 };
    if rate > 12 || len < header {
        return None;
    }
    let shape = ((h[1] as u64 & 0x08) << 16) | ((h[2] as u64 & 0xfc) << 8) | ((h[2] as u64 & 1) << 2) | (h[3] as u64 >> 6);
    Some((shape, len))
}

pub fn mpeg(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    let adts = w.n[7] == 1;
    match w.phase {
        0 => {
            if b.len() < 10 && !eof {
                return Step::More(10);
            }
            if b.starts_with(b"ID3") {
                if b.len() < 10 {
                    return Step::Fail(format!("it is cut short inside an ID3 tag at byte {}", w.at + b.len() as u64));
                }
                return id3_tag(w, b, eof);
            }
            if w.n[2] > 0 && b.starts_with(b"fLaC") {
                return switch(w, Fmt::Flac, "FLAC audio");
            }
            if b.len() >= 2 && b[0] == 0xff && b[1] & 0xf6 == 0xf0 {
                w.n[7] = 1;
                w.kind = "AAC audio (ADTS)".into();
            }
            w.phase = 1;
            Step::Used(0)
        }
        1 => {
            // the zero bytes some taggers leave after a tag
            let k = b.iter().take_while(|&&c| c == 0).count();
            if k < b.len() || eof {
                w.phase = 2;
            }
            Step::Used(k)
        }
        2 => {
            if b.is_empty() && eof {
                return if w.n[1] >= 2 { Step::Done } else { Step::Fail("it holds fewer than two audio frames".into()) };
            }
            if b.len() < 11 && !eof {
                return Step::More(11);
            }
            let head = if b.len() >= 7 {
                if adts { adts_frame(b).map(|(s, l)| (s, l, 0)) } else if b.len() >= 4 { mpeg_frame(b) } else { None }
            } else if b.len() >= 4 && !adts {
                mpeg_frame(b)
            } else {
                None
            };
            if let Some((shape, len, _layer)) = head {
                if w.n[1] == 0 || shape == w.n[0] {
                    if w.n[1] == 0 {
                        w.n[0] = shape;
                        if !adts && _layer == 2 {
                            w.kind = "MP3 audio".into();
                        }
                    }
                    w.n[1] += 1;
                    if eof && (b.len() as u64) < len && w.n[1] >= 3 {
                        // its last frame cut short (an MP3 cut anywhere), after two whole ones: what is there is that
                        // frame's
                        return Step::Done;
                    }
                    return Step::Skip(len);
                }
            }
            if w.n[1] == 0 {
                return Step::Fail(format!("the bytes at {} are not an audio frame", w.at));
            }
            // past the frames: enough bytes to tell a tag (an APE item's key runs to 255 bytes)
            if b.len() < 300 && !eof {
                return Step::More(300);
            }
            trailer(w, b, eof)
        }
        3 => {
            // an ID3v1 tag: 128 bytes, "TAG" first
            if let Some(s) = need(b, 128, eof, w.at, "an ID3v1 tag") {
                return s;
            }
            w.phase = 6;
            Step::Used(128)
        }
        4 => {
            // after an APE tag: an ID3v1 tag, or the end
            if b.is_empty() && eof {
                return Step::Done;
            }
            if b.len() < 3 && !eof {
                return Step::More(3);
            }
            if b.starts_with(b"TAG") {
                w.phase = 3;
                return Step::Used(0);
            }
            pad(w, format!("bytes follow the audio's tags at byte {}", w.at))
        }
        5 => {
            // tags read at the end, whole
            if !eof {
                return Step::More(b.len() + 1);
            }
            if tail_tags(b) {
                Step::Done
            } else {
                Step::Fail(format!("the bytes at {} are neither an audio frame nor a tag", w.at))
            }
        }
        7 => id3_frames(w, b, eof),
        8 => id3_padding(w, b, eof),
        _ => {
            if b.is_empty() && eof {
                return Step::Done;
            }
            pad(w, format!("bytes follow the audio's ID3v1 tag at byte {}", w.at))
        }
    }
}

/// Past the last frame: an ID3v1 tag, an APE tag (with its header: skipped by its size; without: read at the end),
/// Lyrics3 (read at the end), zero padding.
fn trailer(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    if b.starts_with(b"TAG") {
        w.phase = 3;
        return Step::Used(0);
    }
    if b.starts_with(b"APETAGEX") {
        if let Some(s) = need(b, 32, eof, w.at, "an APE tag") {
            return s;
        }
        let size = le32(b, 12);
        let flags = le32(b, 20);
        w.phase = 4;
        if flags & (1 << 29) != 0 {
            return Step::Skip(32 + size);       // (its header: the items and the footer follow)
        }
        return Step::Used(32);                  // (a footer alone: a tag of no items)
    }
    if b.starts_with(b"LYRICSBEGIN") || ape_item(b) {
        w.phase = 5;
        return Step::Used(0);
    }
    pad(w, format!("the bytes at {} are not an audio frame", w.at))
}

/// The first item of an APE tag written without its header: its value's length, flags, a key of printable ASCII.
fn ape_item(b: &[u8]) -> bool {
    b.len() >= 11 && le32(b, 4) & !0x7 == 0 && {
        let key = &b[8..b.len().min(8 + 256)];
        match key.iter().position(|&c| c == 0) {
            Some(k) => (2..=255).contains(&k) && key[..k].iter().all(|&c| (0x20..=0x7e).contains(&c)),
            None => false,
        }
    }
}

/// Tags that end an audio file, read whole: an APE tag (its footer's size is the tag's: items and footer), or
/// Lyrics3 v2 (its size, then "LYRICS200"), and an ID3v1 tag after either.
fn tail_tags(b: &[u8]) -> bool {
    let b = if b.len() >= 128 && &b[b.len() - 128..b.len() - 125] == b"TAG" { &b[..b.len() - 128] } else { b };
    if b.len() >= 32 && &b[b.len() - 32..b.len() - 24] == b"APETAGEX" {
        return le32(b, b.len() - 20) == b.len() as u64;
    }
    if b.starts_with(b"LYRICSBEGIN") && b.ends_with(b"LYRICS200") && b.len() >= 26 {
        let digits = &b[b.len() - 15..b.len() - 9];
        if digits.iter().all(|c| c.is_ascii_digit()) {
            let size: u64 = std::str::from_utf8(digits).ok().and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);
            return size == (b.len() - 15) as u64;
        }
    }
    false
}

// ---- Ogg ---------------------------------------------------------------------------------------------------------
//
// Phases: 0 a page's header, 1 its body. n[0]: the body's bytes left, n[1]: the page's stored checksum, n[2]: pages.
// claims: the streams begun ([serial number, 1 when the first packet names a codec known here]): a stream of no known
// codec's pages are free-form.

/// The first packet of a stream's first page, by codec (Vorbis, Opus, Theora, Speex, FLAC, Skeleton, Kate, PCM,
/// CELT, Dirac, OGM's streams, CMML, VP8, Daala).
const OGG_CODECS: &[&[u8]] = &[
    b"\x01vorbis", b"OpusHead", b"\x80theora", b"Speex   ", b"\x7fFLAC", b"fishead\0", b"\x80kate\0\0\0", b"PCM     ",
    b"CELT    ", b"BBCD\0", b"\x01video\0", b"\x01audio\0", b"\x01text\0", b"CMML\0\0\0\0", b"OVP80", b"\x80daala",
];

/// The most streams an Ogg file's walk keeps track of.
const OGG_STREAMS: usize = 256;

/// Ogg's CRC-32: polynomial 0x04c11db7, not reflected, from 0, nothing xored.
pub(super) fn ogg_crc(mut crc: u32, data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, v) in t.iter_mut().enumerate() {
            let mut r = (i as u32) << 24;
            for _ in 0..8 {
                r = if r & 0x8000_0000 != 0 { (r << 1) ^ 0x04c1_1db7 } else { r << 1 };
            }
            *v = r;
        }
        t
    });
    for &c in data {
        crc = (crc << 8) ^ t[((crc >> 24) as u8 ^ c) as usize];
    }
    crc
}

pub fn ogg(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    if w.phase == 1 {
        let take = (w.n[0].min(b.len() as u64)) as usize;
        if take == 0 && eof {
            return Step::Fail(format!("it is cut short inside a page at byte {}", w.at));
        }
        w.crc = ogg_crc(w.crc, &b[..take]);
        w.n[0] -= take as u64;
        if w.n[0] == 0 {
            if w.crc as u64 != w.n[1] {
                return Step::Fail(format!("the checksum of the page that ends at byte {} does not match",
                                          w.at + take as u64));
            }
            w.phase = 0;
        }
        return Step::Used(take);
    }
    if b.is_empty() && eof {
        return Step::Done;
    }
    if b.len() < 27 && !eof {
        return Step::More(27);
    }
    if !(b.len() >= 27 && b.starts_with(b"OggS") && b[4] == 0 && b[5] & !7 == 0) {
        if w.n[2] == 0 {
            return Step::Fail("its first page is not one".into());
        }
        return pad(w, format!("the bytes at {} are not an Ogg page", w.at));
    }
    if w.n[2] == 0 && b[5] & 2 == 0 {
        return Step::Fail("its first page does not begin a stream".into());
    }
    let segs = b[26] as usize;
    if let Some(s) = need(b, 27 + segs, eof, w.at, "a page's header") {
        return s;
    }
    let body: u64 = b[27..27 + segs].iter().map(|&c| c as u64).sum();
    let serial = le32(b, 14);
    let known = match w.claims.iter().find(|s| s.0 == serial) {
        Some(&(_, known)) if b[5] & 2 == 0 => known == 1,
        _ => {
            // a stream's first page: its first packet names its codec
            let peek = 27 + segs + (body.min(8) as usize);
            if let Some(s) = need(b, peek, eof, w.at, "a page") {
                return s;
            }
            let packet = &b[27 + segs..peek];
            let known = b[5] & 2 != 0 && OGG_CODECS.iter().any(|c| packet.starts_with(c));
            w.claims.retain(|s| s.0 != serial);
            if w.claims.len() >= OGG_STREAMS {
                return Step::Fail(format!("it holds more than {OGG_STREAMS} streams"));
            }
            w.claims.push((serial, known as u64));
            known
        }
    };
    if !known {
        if let Some(s) = free(w, body, "Ogg streams of no known codec") {
            return s;
        }
    }
    w.n[0] = body;
    w.n[1] = le32(b, 22);
    w.n[2] += 1;
    let mut crc = ogg_crc(0, &b[..22]);
    crc = ogg_crc(crc, &[0; 4]);
    w.crc = ogg_crc(crc, &b[26..27 + segs]);
    w.phase = 1;
    Step::Used(27 + segs)
}

// ---- FLAC --------------------------------------------------------------------------------------------------------
//
// Phases: 0 "fLaC", 1 metadata blocks, 2 a frame's header, 3 a frame's body, read to where the next frame's header
// is and the bytes since this one's start check (their CRC-16, the frame's own last two bytes among them, is 0).
// n[0]: channels, n[1]: bits a sample, n[2]: the blocking strategy (2: not known yet), n[3]: blocks read, n[4]:
// frames, n[5]: the frame's start, n[6]: the first byte the next frame may start at, n[7]: where "TAG" (an ID3v1
// tag) last began right after a frame.

fn crc8(data: &[u8]) -> u8 {
    let mut c = 0u8;
    for &x in data {
        c ^= x;
        for _ in 0..8 {
            c = if c & 0x80 != 0 { (c << 1) ^ 0x07 } else { c << 1 };
        }
    }
    c
}

fn crc16_table() -> &'static [u16; 256] {
    static TABLE: std::sync::OnceLock<[u16; 256]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u16; 256];
        for (i, v) in t.iter_mut().enumerate() {
            let mut r = (i as u16) << 8;
            for _ in 0..8 {
                r = if r & 0x8000 != 0 { (r << 1) ^ 0x8005 } else { r << 1 };
            }
            *v = r;
        }
        t
    })
}

/// A FLAC frame's header at the start of `b` (`b` holds at least 16 bytes, or the file's rest): its length, or None.
/// It must agree with the stream: its channels with STREAMINFO's, its blocking strategy with the first frame's.
fn flac_frame(w: &Walker, b: &[u8]) -> Option<usize> {
    if b.len() < 6 || b[0] != 0xff || b[1] & 0xfe != 0xf8 {
        return None;
    }
    let strategy = (b[1] & 1) as u64;
    if w.n[2] != 2 && strategy != w.n[2] {
        return None;
    }
    let block = b[2] >> 4;
    let rate = b[2] & 0xf;
    let chan = b[3] >> 4;
    let size = (b[3] >> 1) & 7;
    if block == 0 || rate == 15 || chan > 10 || size == 3 || b[3] & 1 != 0 {
        return None;
    }
    let channels = if chan < 8 { chan as u64 + 1 } else { 2 };
    if channels != w.n[0] {
        return None;
    }
    // the frame or sample number, UTF-8's way
    let mut i = 4;
    let lead = b[i].leading_ones() as usize;
    let more = match lead {
        0 => 0,
        2..=7 => lead - 1,
        _ => return None,
    };
    i += 1;
    for _ in 0..more {
        if b.get(i).is_none_or(|&c| c & 0xc0 != 0x80) {
            return None;
        }
        i += 1;
    }
    i += match block { 6 => 1, 7 => 2, _ => 0 };
    i += match rate { 12 => 1, 13 | 14 => 2, _ => 0 };
    if b.len() <= i || crc8(&b[..i]) != b[i] {
        return None;
    }
    Some(i + 1)
}

pub fn flac(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    match w.phase {
        0 => {
            if let Some(s) = need(b, 4, eof, w.at, "its signature") {
                return s;
            }
            if !b.starts_with(b"fLaC") {
                return Step::Fail("it does not start with FLAC's signature".into());
            }
            w.phase = 1;
            w.n[2] = 2;
            Step::Used(4)
        }
        1 => {
            if let Some(s) = need(b, 4, eof, w.at, "a metadata block") {
                return s;
            }
            let last = b[0] & 0x80 != 0;
            let kind = b[0] & 0x7f;
            let len = be24(b, 1);
            if kind == 127 {
                return Step::Fail(format!("the metadata block at byte {} is not one", w.at));
            }
            if w.n[3] == 0 {
                // STREAMINFO first: its channels and bits a sample
                if kind != 0 || len != 34 {
                    return Step::Fail("its first metadata block is not STREAMINFO".into());
                }
                if let Some(s) = need(b, 38, eof, w.at, "STREAMINFO") {
                    return s;
                }
                w.n[0] = ((b[16] >> 1) & 7) as u64 + 1;
                w.n[1] = ((((b[16] & 1) as u64) << 4) | (b[17] >> 4) as u64) + 1;
            }
            w.n[3] += 1;
            if last {
                w.phase = 2;
            }
            match kind {
                // PADDING: zero bytes (phase 4)
                1 => {
                    w.x = [w.at + 4 + len, w.phase as u64, 0, 0];
                    w.phase = 4;
                    return Step::Used(4);
                }
                // an APPLICATION block, or one of a kind not defined: free-form
                2 | 7..=126 => {
                    if let Some(s) = free(w, len, "FLAC application and unknown metadata blocks") {
                        return s;
                    }
                }
                _ => {}
            }
            Step::Skip(4 + len)
        }
        4 => {
            // a PADDING block's bytes, zero to its end; then the phase after it
            let left = w.x[0].saturating_sub(w.at);
            if left == 0 {
                w.phase = w.x[1] as u8;
                return Step::Used(0);
            }
            let take = (left.min(b.len() as u64)) as usize;
            if take == 0 {
                return if eof { Step::Fail(format!("it is cut short inside a padding block at byte {}", w.at)) } else { Step::More(1) };
            }
            if let Some(k) = b[..take].iter().position(|&c| c != 0) {
                return Step::Fail(format!("the padding block's byte {} is not zero", w.at + k as u64));
            }
            Step::Used(take)
        }
        2 => {
            if b.is_empty() && eof {
                return if w.n[4] > 0 { Step::Done } else { Step::Fail("it holds no audio frame".into()) };
            }
            if b.len() < 16 && !eof {
                return Step::More(16);
            }
            match flac_frame(w, b) {
                Some(len) => {
                    if w.n[2] == 2 {
                        w.n[2] = (b[1] & 1) as u64;
                    }
                    w.n[5] = w.at;
                    w.n[6] = w.at + len as u64 + 2;
                    w.crc = 0;
                    w.phase = 3;
                    Step::Used(0)
                }
                None if w.n[4] == 0 => Step::Fail(format!("the bytes at {} are not a FLAC frame", w.at)),
                None => pad(w, format!("the bytes at {} are not a FLAC frame", w.at)),
            }
        }
        _ => {
            // a frame's bytes, each into its CRC-16, to the next frame's header (its sync code where the CRC-16 of
            // the bytes before it is 0) or the end
            let t = crc16_table();
            let mut crc = w.crc as u16;
            for (i, &c) in b.iter().enumerate() {
                let pos = w.at + i as u64;
                if crc == 0 && pos >= w.n[6] {
                    if c == 0xff {
                        if b.len() - i < 16 && !eof {
                            w.crc = crc as u32;
                            return if i == 0 { Step::More(16) } else { Step::Used(i) };
                        }
                        if flac_frame(w, &b[i..]).is_some() {
                            w.crc = crc as u32;
                            w.n[4] += 1;
                            w.phase = 2;
                            return Step::Used(i);
                        }
                    } else if c == b'T' {
                        w.n[7] = pos;                 // (an ID3v1 tag may begin here)
                    }
                }
                crc = (crc << 8) ^ t[((crc >> 8) as u8 ^ c) as usize];
            }
            w.crc = crc as u32;
            if eof {
                let end = w.at + b.len() as u64;
                if crc == 0 || (end >= 128 && w.n[7] == end - 128 && b.len() >= 128 && {
                    let k = b.len() - 128;
                    &b[k..k + 3] == b"TAG"
                }) {
                    w.n[4] += 1;
                    return Step::Done;
                }
                return Step::Fail(format!("the checksum of its last frame, from byte {}, does not match", w.n[5]));
            }
            Step::Used(b.len())
        }
    }
}

// ---- MPEG transport stream ---------------------------------------------------------------------------------------
//
// n[0]: the packet's size (188, or 192 with a four-byte time code first: M2TS), n[1]: packets. x[0]: 1 once a
// program association table was read (every stream a player plays has one: the packets of PID 0).

pub fn ts(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    let size = w.n[0];
    let sync = if size == 192 { 4 } else { 0 };
    let end = |w: &Walker| -> Option<Step> {
        if w.n[1] < 2 {
            Some(Step::Fail("it holds fewer than two packets".into()))
        } else if w.x[0] == 0 {
            Some(Step::Fail("it has no program association table (no packet of PID 0 holds one)".into()))
        } else {
            None
        }
    };
    if b.is_empty() && eof {
        return end(w).unwrap_or(Step::Done);
    }
    if b.len() < sync + 4 && !eof {
        return Step::More(sync + 4);
    }
    if b.len() < sync + 4 || b[sync] != 0x47 {
        if let Some(s) = end(w) {
            return s;
        }
        return pad(w, format!("the packet at byte {} has no sync byte", w.at));
    }
    let pid = ((b[sync + 1] as u64 & 0x1f) << 8) | b[sync + 2] as u64;
    if pid == 0 && b[sync + 1] & 0x40 != 0 && w.x[0] == 0 {
        // a payload's start in PID 0: after the adaptation field and the pointer, table 0 (the PAT)
        if let Some(s) = need(b, size as usize, eof, w.at, "a packet") {
            return s;
        }
        let p = &b[sync..sync + 188];
        let mut i = 4usize;
        if p[3] & 0x20 != 0 {
            i += 1 + p[4] as usize;
        }
        if p[3] & 0x10 != 0 && i < 188 {
            let table = i + 1 + p[i] as usize;
            if table < 188 && p[table] == 0 {
                w.x[0] = 1;
            }
        }
    }
    w.n[1] += 1;
    Step::Skip(size)
}
