//! Media, image and font files read by their structure (FP-OPAQUE-MEDIA, 0.1.9, John's decision of Oct 21).
//!
//! SC-OPAQUE-BLOB reports a binary file whose first bytes are near-random: encrypted or packed data can be a second
//! stage that code decodes and runs. A compressed sound, picture, video or font is near-random too, and a file is one
//! of those when its bytes are that format from its first byte to its last: the walk here follows each format's own
//! chain (MPEG audio's and ADTS's frames, Ogg's pages with their checksums, FLAC's frames with theirs, a transport
//! stream's packets, ISO media's boxes, RIFF's and AIFF's chunks, Matroska's elements, PNG's chunks with their
//! checksums, JPEG's segments and entropy-coded scans, GIF's blocks, an Apple icon's elements) or the directory that
//! names its parts (a TrueType or OpenType font or collection, WOFF and WOFF2, BMP, ICO and CUR, TIFF, an ICC
//! profile), or a header and its exact pixel count (an IM Tools image, a binary Netpbm image), to the file's end.
//! Never its name or extension.
//!
//! It fails closed: bytes the structure does not account for (an appended payload, a gap between a directory's
//! parts, a chain broken anywhere, a checksum that does not match, a file cut short, whole or as its stream passes)
//! leave the file what it was, an opaque blob, and so does a file no walker here can read. What a format allows past
//! its end is allowed: an MP3's ID3v1, APEv2 or Lyrics3 tags, a cut last frame, the padding of zero bytes any file
//! may end with (zero bytes hold nothing), a JPEG's further images (a multi-picture file) or the MP4 a motion photo
//! appends.
//!
//! A walk that reaches the end proves the file is that format's shape, not what its parts hold, so the shapes a real
//! file has are required and what a format leaves to anyone is bounded (the review of Oct 27):
//! - shapes no real file has are not one: an ISO media file with no file type box and no movie box, a box of size 0
//!   (to the end) that is not the media data, a PNG with no image data, a JPEG image with no frame header or no scan,
//!   a font without the tables every font has;
//! - the free-form parts (`free` and unknown boxes, a PNG's text and unregistered chunks, a JPEG's comments and
//!   application segments no one registered, ID3's private, object and unknown frames, RIFF's JUNK and unknown chunks,
//!   a TIFF's private tags, a font's unregistered tables, Matroska's Void, a GIF's comments and application
//!   extensions, an Ogg stream of no known codec, a TGA's developer area, an ICC profile's unregistered tags; and those
//!   of a part walked as a format of its own, an icon's PNG images) hold at most FREE_MAX bytes and a quarter of the file
//!   (`Walker::free`): past either, the file stays opaque, and the message names the part;
//! - the formats whose samples are stored raw (Netpbm, IM Tools, TGA, an uncompressed BMP, PCM in WAV, AIFF, RIFX and
//!   RF64) have samples that follow one another: their first RAW_SAMPLE bytes' differences must have less than
//!   RAW_MAX_BITS of entropy (`raw_samples`), as a real picture's or sound's do and random bytes' do not.
//!
//! What stays unbounded is what a codec decodes (an MP4's media data, an audio frame, a scan): a payload there is
//! the code that reads it out, which the scan reads.
//!
//! The walk is a state machine fed a file's bytes in order (`feed`), so that a file of any size is walked as its
//! stream passes (a registry's archive member, a file too large to read whole) without being kept: the host carries
//! the state (`Walker`, `api::media_state`) between chunks and may pass over the bytes the walk skips (`Walker::at`),
//! never past the file's end (the host clamps its jump to the file's size: a part that runs past it is a file cut
//! short). A format read by a directory that may lie anywhere (TIFF, ICO, ICC) is read whole, up to MAX_CARRY bytes.

mod chains;
mod frames;
pub mod keystore;
mod tables;

#[cfg(test)]
mod tests;

/// The most bytes a walk keeps between chunks (a header cut by a chunk's end, a font's directory, a file read whole
/// by its directory: TIFF, ICO, ICC; an MP3's trailing tags). A file that needs more is not walked: it stays opaque.
pub const MAX_CARRY: usize = 1 << 20;

/// The most parts a directory read as its stream passes may name (a font's or a collection's tables, a WOFF's, a
/// bitmap's), which the walk holds and passes one by one (the re-review of Oct 27, N1: a collection of a thousand
/// fonts of 4,096 tables each). A real collection names a few hundred; one naming more is not walked: it stays
/// opaque. (The formats read whole are bounded by their own directories: TIFF by TIFF_ENTRIES and TIFF_VALUES, an
/// icon by its 1,024 images, an ICC profile by its 1,024 tags, a TGA by its 65,535 developer fields.)
pub const MAX_CLAIMS: usize = 1 << 16;

/// No file is this large (2^53 bytes): a size past it is not one, and the state's numbers stay exact in the npm
/// package's JSON.
pub const MAX_OFFSET: u64 = 1 << 53;

/// The most bytes a file's free-form parts may hold (`Walker::free`), and the share of the file (one in FREE_SHARE).
pub const FREE_MAX: u64 = 64 * 1024;
pub const FREE_SHARE: u64 = 4;

/// The bytes of a raw format's samples read for their differences' entropy (`raw_samples`), and the bits a byte below
/// which they are a picture's or a sound's (real files' are at most 6.5, random bytes' 7.98).
pub const RAW_SAMPLE: usize = 8192;
pub const RAW_MAX_BITS: f64 = 7.0;

/// The formats walked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Fmt {
    /// not known yet: the first bytes are read
    Start = 0,
    Mpeg,
    Ogg,
    Flac,
    Ts,
    Bmff,
    Riff,
    Aiff,
    Ebml,
    Png,
    Gif,
    Jpeg,
    Icns,
    Sfnt,
    Ttc,
    Woff,
    Woff2,
    Bmp,
    Ico,
    Tiff,
    Icc,
    Imt,
    /// the rest of the file must be zero bytes (padding after a format's end)
    Zeros,
    Pnm,
    Tga,
}

impl Fmt {
    fn of(n: u8) -> Fmt {
        use Fmt::*;
        [Start, Mpeg, Ogg, Flac, Ts, Bmff, Riff, Aiff, Ebml, Png, Gif, Jpeg, Icns, Sfnt, Ttc, Woff, Woff2, Bmp, Ico, Tiff,
         Icc, Imt, Zeros, Pnm, Tga]
            .get(n as usize)
            .copied()
            .unwrap_or(Zeros)
    }
}

/// A walk's state between chunks. Every field is the host's to carry and give back unchanged (api::media_state).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Walker {
    /// the format walked (Fmt), and where in it the walk is
    pub fmt: u8,
    pub phase: u8,
    /// the offset of the next byte the walk reads: bytes before it that a chunk holds are passed over
    pub at: u64,
    /// the offset past the last byte given
    pub fed: u64,
    /// bytes from `at` given and not used yet (a header a chunk's end cut)
    pub carry: Vec<u8>,
    /// the format's numbers (a part's length left, counts, the first frame's shape, where a part ends)
    pub n: [u64; 8],
    /// more of them (what a format requires: an image's frame header and scan, a movie box; a sound's sample format;
    /// where a raw format's samples start)
    pub x: [u64; 4],
    /// a running checksum (an Ogg page's, a PNG chunk's, a FLAC frame's)
    pub crc: u32,
    /// the parts a directory names that the walk has not passed yet ([start, end), sorted, merged); an Ogg file's
    /// streams ([serial number, 1 when its codec is known])
    pub claims: Vec<(u64, u64)>,
    /// the bytes of the free-form parts walked (at most FREE_MAX, and a quarter of the file), and which parts they are
    pub free: u64,
    pub free_what: String,
    /// what the file is (a label), once its first bytes are read
    pub kind: String,
    /// why the walk failed, when what follows turns out not to be padding
    pub why: String,
    /// how the walk ended: Ok (the file is `kind` to its end), Err (why not); None while it runs
    pub end: Option<Result<(), String>>,
}

/// What a step does with the bytes from `at`.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// these bytes were read
    Used(usize),
    /// these bytes are passed over unread (a part's body), however many of them are here
    Skip(u64),
    /// at least this many bytes are needed at `at` to go on
    More(usize),
    /// the file is the format to its end
    Done,
    Fail(String),
}

/// What a walk found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Walked {
    /// the file is this format, from its first byte to its last
    Is(String),
    /// its first bytes are this format's, but the file is not one to its end (why)
    Not(String, String),
    /// no format walked here starts so
    Unknown,
}

impl Walker {
    pub fn new() -> Walker {
        Walker::default()
    }

    /// The walk's answer, once it ended (None while it runs).
    pub fn walked(&self) -> Option<Walked> {
        Some(match self.end.as_ref()? {
            Ok(()) => Walked::Is(self.kind.clone()),
            Err(_) if self.kind.is_empty() => Walked::Unknown,
            Err(why) => Walked::Not(self.kind.clone(), why.clone()),
        })
    }

    fn fail(&mut self, why: String) {
        if self.end.is_none() {
            self.end = Some(Err(why));
        }
    }
}

/// The format whose structure a file's first bytes start (its label), or None: whether walking the file can tell.
pub fn starts(head: &[u8]) -> Option<String> {
    let mut w = Walker::new();
    match start(&mut w, head, true) {
        Step::Used(0) if w.fmt != Fmt::Start as u8 => Some(w.kind),
        _ => None,
    }
}

/// A walk of a whole file in memory.
pub fn walk(data: &[u8]) -> Walked {
    let mut w = Walker::new();
    feed(&mut w, 0, data, true);
    w.walked().unwrap_or(Walked::Unknown)
}

/// A walk of a part of a file that is itself a format (an icon's PNG image): the bytes of its free-form parts and
/// which they are, when it is that format to its end (None when it is not). They count toward the file's (the
/// re-review of Oct 27, N4: each image held its own 64 KiB).
fn walk_part(data: &[u8]) -> Option<(u64, String)> {
    let mut w = Walker::new();
    feed(&mut w, 0, data, true);
    matches!(w.walked(), Some(Walked::Is(_))).then_some((w.free, w.free_what))
}

/// Feed the walk the bytes of `chunk`, which start at `offset` of the file: `offset` is where the last chunk ended
/// (`fed`), or `at` when the walk skips past it and the host passes over the bytes between. `eof`: the file ends with
/// this chunk (an empty one will do). Once `end` is set, the walk is over and further chunks change nothing.
pub fn feed(w: &mut Walker, offset: u64, chunk: &[u8], eof: bool) {
    if w.end.is_some() {
        return;
    }
    // (the host passes over bytes the walk skips: to `at`, or to the file's end when that comes first)
    if offset != w.fed && !(w.carry.is_empty() && offset > w.fed && offset <= w.at) {
        w.fail(format!("the file's bytes were not given in order (byte {offset}, where byte {} was due)", w.fed));
        return;
    }
    let mut data = chunk;
    if offset < w.at {
        let pass = usize::try_from(w.at - offset).unwrap_or(usize::MAX).min(data.len());
        data = &data[pass..];
    }
    w.fed = offset + chunk.len() as u64;
    if eof && w.at > w.fed {
        // a part an earlier chunk began runs past the file's end
        cut_short(w);
        return;
    }
    let joined;
    let buf: &[u8] = if w.carry.is_empty() {
        data
    } else {
        joined = [std::mem::take(&mut w.carry).as_slice(), data].concat();
        &joined
    };
    // (a step that reads nothing must change the walk's format or phase: two that change neither are a fault)
    let mut idle = 0u32;
    let mut used = 0usize;
    loop {
        if w.end.is_some() {
            return;
        }
        let rest = &buf[used..];
        let before = (w.fmt, w.phase);
        match step(w, rest, eof) {
            Step::Used(n) => {
                let n = n.min(rest.len());
                used += n;
                w.at += n as u64;
                if n == 0 && (w.fmt, w.phase) == before {
                    idle += 1;
                    if idle > 2 {
                        w.fail(format!("the walk of the {} stopped at byte {}", label_or(w), w.at));
                        return;
                    }
                } else {
                    idle = 0;
                }
            }
            Step::Skip(n) => {
                idle = 0;
                if n <= rest.len() as u64 {
                    used += n as usize;
                    w.at += n;
                } else {
                    w.at = w.at.saturating_add(n);
                    if w.at > MAX_OFFSET {
                        w.fail(format!("a part of the {} runs past any file's end", label_or(w)));
                    } else if eof {
                        cut_short(w);
                    }
                    return;
                }
            }
            Step::More(k) => {
                if eof {
                    let msg = format!("it is cut short at byte {}", w.at + rest.len() as u64);
                    w.fail(msg);
                    return;
                }
                if rest.len() >= k || k > MAX_CARRY || rest.len() > MAX_CARRY {
                    let msg = format!("a part of the {} past byte {} is larger than the {} bytes read of one",
                                      label_or(w), w.at, MAX_CARRY);
                    w.fail(msg);
                    return;
                }
                w.carry = rest.to_vec();
                return;
            }
            Step::Done => {
                done(w);
                return;
            }
            Step::Fail(why) => {
                w.fail(why);
                return;
            }
        }
        if w.at > MAX_OFFSET || w.n.iter().chain(&w.x).any(|&v| v > MAX_OFFSET && v != u64::MAX) {
            w.fail(format!("a part of the {} runs past any file's end", label_or(w)));
            return;
        }
        if used == buf.len() && !eof {
            return;
        }
    }
}

/// The walk's end, read to it: the free-form parts' share of the file checked, now that its size is known.
fn done(w: &mut Walker) {
    if w.free > 0 && w.free.saturating_mul(FREE_SHARE) > w.fed {
        let why = free_why(w);
        w.fail(why);
    } else if w.end.is_none() {
        w.end = Some(Ok(()));
    }
}

/// A part the walk passed over runs past the file's end (`fed`): the file is cut short, but for what a whole walk
/// allows there too, an MP3's or AAC's last frame after two whole ones (frames::mpeg), so that a file walked as its
/// stream passes is what it is walked whole.
fn cut_short(w: &mut Walker) {
    if w.fmt == Fmt::Mpeg as u8 && w.phase == 2 && w.n[1] >= 3 {
        done(w);
    } else {
        let msg = format!("it is cut short: a part runs to byte {}, past its end at byte {}", w.at, w.fed);
        w.fail(msg);
    }
}

fn label_or(w: &Walker) -> String {
    if w.kind.is_empty() { "file".to_string() } else { w.kind.clone() }
}

fn step(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    match Fmt::of(w.fmt) {
        Fmt::Start => start(w, b, eof),
        Fmt::Mpeg => frames::mpeg(w, b, eof),
        Fmt::Ogg => frames::ogg(w, b, eof),
        Fmt::Flac => frames::flac(w, b, eof),
        Fmt::Ts => frames::ts(w, b, eof),
        Fmt::Bmff => chains::bmff(w, b, eof),
        Fmt::Riff | Fmt::Aiff => chains::iff(w, b, eof),
        Fmt::Ebml => chains::ebml(w, b, eof),
        Fmt::Png => chains::png(w, b, eof),
        Fmt::Gif => chains::gif(w, b, eof),
        Fmt::Jpeg => chains::jpeg(w, b, eof),
        Fmt::Icns => chains::icns(w, b, eof),
        Fmt::Sfnt | Fmt::Ttc | Fmt::Woff | Fmt::Woff2 | Fmt::Bmp => tables::directory(w, b, eof),
        Fmt::Ico | Fmt::Tiff | Fmt::Icc | Fmt::Tga => tables::whole(w, b, eof),
        Fmt::Imt => tables::imt(w, b, eof),
        Fmt::Pnm => tables::pnm(w, b, eof),
        Fmt::Zeros => zeros(w, b, eof),
    }
}

/// Switch the walk to another format (the first bytes read, an ID3 tag before FLAC, a motion photo's MP4).
fn switch(w: &mut Walker, fmt: Fmt, kind: &str) -> Step {
    w.fmt = fmt as u8;
    w.phase = 0;
    w.n = [0; 8];
    w.x = [0; 4];
    w.crc = 0;
    w.claims.clear();
    if !kind.is_empty() {
        w.kind = kind.to_string();
    }
    Step::Used(0)
}

/// The rest of the file must be zero bytes: padding after the format's end, which holds nothing. `why`: what the
/// walk says when a byte that is not zero follows.
fn pad(w: &mut Walker, why: String) -> Step {
    w.why = why;
    w.fmt = Fmt::Zeros as u8;
    w.phase = 0;
    Step::Used(0)
}

fn zeros(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    match b.iter().position(|&c| c != 0) {
        Some(_) => Step::Fail(std::mem::take(&mut w.why)),
        None if eof => Step::Done,
        None => Step::Used(b.len()),
    }
}

/// `k` bytes at `at`, or what to say when there are fewer: More while bytes are to come, else the file is cut short
/// inside `what`.
fn need(b: &[u8], k: usize, eof: bool, at: u64, what: &str) -> Option<Step> {
    if b.len() >= k {
        None
    } else if eof {
        Some(Step::Fail(format!("it is cut short inside {what} at byte {}", at + b.len() as u64)))
    } else {
        Some(Step::More(k))
    }
}

/// `n` bytes of a free-form part (`what`: a box, chunk, segment, frame or table whose content the format leaves to
/// anyone) counted; a Fail once the file's free-form parts hold more than FREE_MAX bytes.
fn free(w: &mut Walker, n: u64, what: &str) -> Option<Step> {
    w.free = w.free.saturating_add(n);
    if w.free_what.is_empty() {
        w.free_what = what.to_string();
    } else if w.free_what != what && !w.free_what.ends_with(" and other free-form parts") {
        w.free_what.push_str(" and other free-form parts");
    }
    (w.free > FREE_MAX).then(|| Step::Fail(free_why(w)))
}

fn free_why(w: &Walker) -> String {
    format!("its {} hold {} bytes that no picture, sound, video or font decodes, more than a real file's (at most {} \
             bytes, and a quarter of the file)", w.free_what, w.free, FREE_MAX)
}

/// The smallest of the entropies (bits a byte) of a sample's differences at lags 1 to 4: a picture's or a sound's
/// samples follow one another (a pixel its neighbour, a sample the one before, in each channel), random bytes do not.
pub fn diff_entropy(s: &[u8]) -> f64 {
    let mut least = 8.0f64;
    for lag in 1..=4usize {
        if s.len() <= lag {
            break;
        }
        let mut freq = [0u32; 256];
        for i in lag..s.len() {
            freq[s[i].wrapping_sub(s[i - lag]) as usize] += 1;
        }
        let n = (s.len() - lag) as f64;
        let e: f64 = -freq.iter().filter(|&&c| c > 0).map(|&c| {
            let q = c as f64 / n;
            q * q.log2()
        }).sum::<f64>();
        least = least.min(e);
    }
    least
}

/// A raw format's samples, `len` bytes from `at` (from byte `skip` of `b`): their first RAW_SAMPLE bytes, or as many
/// as the file holds, must differ as a picture's or a sound's do (diff_entropy below RAW_MAX_BITS). None when they do;
/// More while bytes are to come; a Fail when they are near-random. (A file cut short inside them is left to the walk's
/// next step; a few hundred bytes measure under the bound whatever they are.)
fn raw_samples(w: &Walker, b: &[u8], skip: usize, len: u64, eof: bool) -> Option<Step> {
    let k = len.min(RAW_SAMPLE as u64) as usize;
    if b.len() < skip.saturating_add(k) && !eof {
        return Some(Step::More(skip + k));
    }
    let from = skip.min(b.len());
    let e = diff_entropy(&b[from..b.len().min(from + k)]);
    (e >= RAW_MAX_BITS).then(|| Step::Fail(format!(
        "its samples from byte {} are near-random ({e:.2} bits a byte from one to the next): no picture's or sound's \
         are", w.at + skip as u64)))
}

fn be16(b: &[u8], i: usize) -> u64 {
    u16::from_be_bytes([b[i], b[i + 1]]) as u64
}

fn be24(b: &[u8], i: usize) -> u64 {
    ((b[i] as u64) << 16) | ((b[i + 1] as u64) << 8) | b[i + 2] as u64
}

fn be32(b: &[u8], i: usize) -> u64 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as u64
}

fn be64(b: &[u8], i: usize) -> u64 {
    u64::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3], b[i + 4], b[i + 5], b[i + 6], b[i + 7]])
}

fn le16(b: &[u8], i: usize) -> u64 {
    u16::from_le_bytes([b[i], b[i + 1]]) as u64
}

fn le32(b: &[u8], i: usize) -> u64 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as u64
}

fn le64(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3], b[i + 4], b[i + 5], b[i + 6], b[i + 7]])
}

/// A four-character code of printable ASCII (a box's, chunk's or table's name).
fn fourcc(b: &[u8]) -> bool {
    b.len() >= 4 && b[..4].iter().all(|&c| (0x20..=0x7e).contains(&c))
}

fn name4(b: &[u8]) -> String {
    b[..4].iter().map(|&c| if (0x20..=0x7e).contains(&c) { c as char } else { '?' }).collect()
}

/// The first bytes: which format's structure starts here (None: no format walked here starts so).
fn start(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    // (a transport stream's third sync byte is at 376; most formats need 16)
    let want = 377;
    if b.len() < want && !eof {
        return Step::More(want);
    }
    let at = |i: usize, s: &[u8]| b.len() >= i + s.len() && &b[i..i + s.len()] == s;
    if at(0, b"ID3") || (b.len() >= 2 && b[0] == 0xff && b[1] & 0xe0 == 0xe0 && b[1] & 0x06 != 0) {
        return switch(w, Fmt::Mpeg, "MPEG audio");
    }
    if b.len() >= 2 && b[0] == 0xff && b[1] & 0xf6 == 0xf0 {
        let s = switch(w, Fmt::Mpeg, "AAC audio (ADTS)");
        w.n[7] = 1;                               // (ADTS: AAC's frames)
        return s;
    }
    if at(0, b"OggS") {
        return switch(w, Fmt::Ogg, "Ogg");
    }
    if at(0, b"fLaC") {
        return switch(w, Fmt::Flac, "FLAC audio");
    }
    if at(0, b"\x1a\x45\xdf\xa3") {
        return switch(w, Fmt::Ebml, "Matroska");
    }
    if at(0, b"RIFF") || at(0, b"RF64") || at(0, b"BW64") {
        return switch(w, Fmt::Riff, "RIFF");
    }
    if at(0, b"RIFX") {
        let s = switch(w, Fmt::Riff, "RIFF");
        w.n[7] = 1;                               // (RIFX: RIFF big-endian)
        return s;
    }
    if at(0, b"FORM") && (at(8, b"AIFF") || at(8, b"AIFC")) {
        return switch(w, Fmt::Aiff, "AIFF audio");
    }
    if at(0, b"\x89PNG\r\n\x1a\n") {
        return switch(w, Fmt::Png, "PNG image");
    }
    if at(0, b"\xff\xd8\xff") {
        return switch(w, Fmt::Jpeg, "JPEG image");
    }
    if at(0, b"GIF87a") || at(0, b"GIF89a") {
        return switch(w, Fmt::Gif, "GIF image");
    }
    if at(0, b"BM") && b.len() >= 18 {
        return switch(w, Fmt::Bmp, "BMP image");
    }
    if at(0, b"II*\x00") || at(0, b"MM\x00*") || at(0, b"II+\x00") || at(0, b"MM\x00+") {
        return switch(w, Fmt::Tiff, "TIFF image");
    }
    if (at(0, b"\x00\x00\x01\x00") || at(0, b"\x00\x00\x02\x00")) && b.len() >= 6 && le16(b, 4) > 0 {
        let kind = if b[2] == 1 { "Windows icon (ICO)" } else { "Windows cursor (CUR)" };
        return switch(w, Fmt::Ico, kind);
    }
    if at(0, b"wOFF") {
        return switch(w, Fmt::Woff, "WOFF font");
    }
    if at(0, b"wOF2") {
        return switch(w, Fmt::Woff2, "WOFF2 font");
    }
    if at(0, b"\x00\x01\x00\x00") || at(0, b"true") || at(0, b"typ1") {
        return switch(w, Fmt::Sfnt, "TrueType font");
    }
    if at(0, b"OTTO") {
        return switch(w, Fmt::Sfnt, "OpenType font");
    }
    if at(0, b"ttcf") {
        return switch(w, Fmt::Ttc, "font collection");
    }
    if at(4, b"ftyp") || at(4, b"styp") || at(0, b"\x00\x00\x00\x0cjP  \r\n\x87\n")
        || ([b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot"].iter().any(|t| at(4, &t[..])) && be32(b, 0) >= 8)
    {
        return switch(w, Fmt::Bmff, "ISO media");
    }
    if at(0, b"icns") {
        return switch(w, Fmt::Icns, "Apple icon image");
    }
    if at(36, b"acsp") {
        return switch(w, Fmt::Icc, "ICC colour profile");
    }
    if b.len() > 188 && b[0] == 0x47 && b[188] == 0x47 {
        let s = switch(w, Fmt::Ts, "MPEG transport stream");
        w.n[0] = 188;
        return s;
    }
    if b.len() > 196 && b[4] == 0x47 && b[196] == 0x47 {
        let s = switch(w, Fmt::Ts, "MPEG transport stream (M2TS)");
        w.n[0] = 192;
        return s;
    }
    if tables::tga_header(b).is_some() {
        return switch(w, Fmt::Tga, "TGA image");
    }
    if tables::imt_header(b).is_some() {
        return switch(w, Fmt::Imt, "IM Tools image");
    }
    if b.len() >= 3 && b[0] == b'P' && (b'4'..=b'7').contains(&b[1]) && b[2].is_ascii_whitespace() {
        return switch(w, Fmt::Pnm, "Netpbm image");
    }
    Step::Fail("no format Lazaret walks starts with these bytes".to_string())
}
