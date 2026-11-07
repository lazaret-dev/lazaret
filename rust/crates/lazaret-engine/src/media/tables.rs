//! The formats whose first bytes hold a directory of their parts (where each is, how long): TrueType and OpenType
//! fonts and font collections, WOFF and WOFF2, BMP; ICO and CUR, TIFF and ICC profiles, whose directories may point
//! anywhere and which are read whole; and IM Tools images, a text header and the pixels' bytes.
//!
//! A directory's parts are claimed ranges of the file: the file must hold every part, and every byte no part holds
//! must be zero (a format's padding to a 2- or 4-byte boundary). What a part holds is not read (a font's glyphs, a
//! bitmap's pixels), but where a part is itself a format (an icon's PNG image), it is walked too, its free-form parts
//! counted as the file's. A font has the tables every font has, each once, and its unregistered tables are free-form
//! (as a WOFF's metadata and private data, a TIFF's private tags, a TGA's developer area and an ICC profile's
//! unregistered tags); a raw image's samples must follow one another (raw_samples). A walk holds at most MAX_CLAIMS
//! parts of a directory read as its stream passes (the re-review of Oct 27, N1: a font collection's thousands of
//! tables cost a walk time), and passes each once.

use super::{be16, be32, be64, diff_entropy, fourcc, free, le16, le32, le64, pad, raw_samples, walk_part, Fmt, Step,
            Walker, MAX_CLAIMS, RAW_MAX_BITS, RAW_SAMPLE};

enum P {
    /// this many bytes from the file's start are needed to read the directory
    Need(usize),
    Bad(String),
}

type R<T> = Result<T, P>;

fn get(b: &[u8], end: u64) -> R<()> {
    if (b.len() as u64) < end {
        Err(P::Need(usize::try_from(end).unwrap_or(usize::MAX)))
    } else {
        Ok(())
    }
}

fn bad<T>(why: &str) -> R<T> {
    Err(P::Bad(why.to_string()))
}

/// What a directory names: the parts' ranges (the directory's own among them) and the size the file declares; the
/// bytes of its free-form parts (and what they are); a raw image's samples ([start, length)).
struct Dir {
    claims: Vec<(u64, u64)>,
    total: Option<u64>,
    free: u64,
    free_what: String,
    raw: Option<(u64, u64)>,
}

impl Dir {
    fn of(claims: Vec<(u64, u64)>, total: Option<u64>) -> Dir {
        Dir { claims, total, free: 0, free_what: String::new(), raw: None }
    }

    /// `n` bytes of free-form parts (`what`).
    fn free(&mut self, n: u64, what: &str) {
        if n == 0 {
            return;
        }
        self.free = self.free.saturating_add(n);
        if self.free_what.is_empty() {
            self.free_what = what.to_string();
        } else if self.free_what != what && !self.free_what.ends_with(" and other free-form parts") {
            self.free_what.push_str(" and other free-form parts");
        }
    }
}

/// Ranges sorted by their start, those that overlap or touch merged (a collection's fonts share tables).
fn merged(mut claims: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    claims.retain(|&(s, e)| e > s);
    claims.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(claims.len());
    for (s, e) in claims {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

fn claim(claims: &mut Vec<(u64, u64)>, start: u64, len: u64) -> R<()> {
    match start.checked_add(len) {
        Some(end) => {
            claims.push((start, end));
            Ok(())
        }
        None => bad("a part's place is past any file's end"),
    }
}

// ---- formats read as their stream passes: the directory first, then its parts ------------------------------------
//
// Phases: 0 the directory, read from the file's first bytes; 1 the parts, passed over, and the bytes between them,
// which must be zero. n[0]: the size the file declares (0: none). x[0], x[1]: a raw image's samples (their start and
// length), x[2]: 1 until they are read. claims: the parts not passed yet, merged and sorted from the last to the
// first, so that the next is the last and each is dropped once passed (the re-review of Oct 27, N1: dropping the
// first of a vector moved every other, a collection's walk quadratic in its tables).

pub fn directory(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    if w.phase == 0 {
        let got = match Fmt::of(w.fmt) {
            Fmt::Sfnt => sfnt(b),
            Fmt::Ttc => ttc(b),
            Fmt::Woff => woff(b),
            Fmt::Woff2 => woff2(b),
            _ => bmp(b),
        };
        return match got {
            Ok(dir) => {
                if dir.claims.len() > MAX_CLAIMS {
                    return Step::Fail(too_many(dir.claims.len()));
                }
                if dir.free > 0 {
                    if let Some(s) = free(w, dir.free, &dir.free_what) {
                        return s;
                    }
                }
                if let Some((start, len)) = dir.raw {
                    w.x = [start, len, 1, 0];
                }
                w.claims = merged(dir.claims);
                w.claims.reverse();
                w.n[0] = dir.total.unwrap_or(0);
                w.phase = 1;
                Step::Used(0)
            }
            Err(P::Need(_)) if eof => Step::Fail(format!("it is cut short inside its directory at byte {}", b.len())),
            Err(P::Need(k)) => Step::More(k.max(b.len() + 1)),
            Err(P::Bad(why)) => Step::Fail(why),
        };
    }
    parts(w, b, eof)
}

/// What a directory naming more parts than MAX_CLAIMS is not.
fn too_many(n: usize) -> String {
    format!("its directories name {n} parts or more, more than a real file's (at most {MAX_CLAIMS})")
}

/// The parts a directory claimed, passed over, and the bytes between them, which must be zero.
fn parts(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    while w.claims.last().is_some_and(|&(_, e)| e <= w.at) {
        w.claims.pop();
    }
    if let Some(&(s, e)) = w.claims.last() {
        if s <= w.at {
            // (a raw image's samples in this part: read before it is passed over)
            if w.x[2] == 1 && w.x[0] >= w.at && w.x[0] < e {
                if let Some(step) = raw_samples(w, b, (w.x[0] - w.at) as usize, w.x[1], eof) {
                    return step;
                }
                w.x[2] = 0;
            }
            return Step::Skip(e - w.at);
        }
        if b.is_empty() {
            return if eof {
                Step::Fail(format!("it is cut short: a part its directory names starts at byte {s}"))
            } else {
                Step::More(1)
            };
        }
        let gap = ((s - w.at) as usize).min(b.len());
        if let Some(k) = b[..gap].iter().position(|&c| c != 0) {
            return Step::Fail(format!("the bytes at {} are in no part its directory names", w.at + k as u64));
        }
        return Step::Used(gap);
    }
    // past every part: the end, at the size the file declares (zero bytes may follow, as padding), checked at the
    // file's end however its bytes came (the re-review of Oct 27, N5: an empty chunk before the end passed it over)
    let total = w.n[0];
    if b.is_empty() {
        return if !eof {
            Step::More(1)
        } else if total != 0 && w.at < total {
            Step::Fail(format!("it is cut short: it declares {total} bytes and has {}", w.at))
        } else {
            Step::Done
        };
    }
    if total != 0 && w.at < total {
        // (zero bytes to the size it declares: read here, so that the size is checked at the file's end)
        let k = usize::try_from(total - w.at).unwrap_or(usize::MAX).min(b.len());
        if b[..k].iter().any(|&c| c != 0) {
            return Step::Fail(format!("the bytes at {} are in no part its directory names", w.at));
        }
        return Step::Used(k);
    }
    pad(w, format!("the bytes at {} are in no part its directory names", w.at))
}

/// The tables an OpenType, TrueType (Apple's AAT among them) or Graphite font may hold, registered with their
/// specifications or in wide use (ttfautohint's, FontForge's, VTT's sources); another table is free-form.
const FONT_TABLES: &[&[u8; 4]] = &[
    b"avar", b"BASE", b"CBDT", b"CBLC", b"CFF ", b"CFF2", b"cmap", b"COLR", b"CPAL", b"cvar", b"cvt ", b"DSIG",
    b"EBDT", b"EBLC", b"EBSC", b"fpgm", b"fvar", b"gasp", b"GDEF", b"glyf", b"GPOS", b"GSUB", b"gvar", b"hdmx",
    b"head", b"hhea", b"hmtx", b"HVAR", b"JSTF", b"kern", b"loca", b"LTSH", b"MATH", b"maxp", b"MERG", b"meta",
    b"MVAR", b"name", b"OS/2", b"PCLT", b"post", b"prep", b"sbix", b"STAT", b"SVG ", b"VDMX", b"vhea", b"vmtx",
    b"VORG", b"VVAR", b"acnt", b"ankr", b"bdat", b"bhed", b"bloc", b"bsln", b"fdsc", b"feat", b"fmtx", b"fond",
    b"gcid", b"hsty", b"just", b"kerx", b"lcar", b"ltag", b"mort", b"morx", b"opbd", b"prop", b"trak", b"xref",
    b"Zapf", b"Silf", b"Glat", b"Gloc", b"Feat", b"Sill", b"TTFA", b"FFTM", b"PfEd",
];

/// The tables every font has (the OpenType and TrueType specifications' required tables but OS/2 and post, which
/// Apple's fonts may leave out; `bhed` stands for `head` in a font of bitmaps alone).
const FONT_REQUIRED: &[&[&[u8; 4]]] = &[&[b"head", b"bhed"], &[b"cmap"], &[b"hhea"], &[b"hmtx"], &[b"maxp"], &[b"name"]];

const FONT_FREE: &str = "unregistered font tables";

/// Whether a font's tables (`tags`) are those every font has, each once (`once`: a WOFF2 collection's directory
/// lists a table of each of its fonts).
fn font_tables(tags: &[&[u8]], once: bool) -> R<()> {
    if once {
        let mut sorted = tags.to_vec();
        sorted.sort_unstable();
        if let Some(w) = sorted.windows(2).find(|w| w[0] == w[1]) {
            return Err(P::Bad(format!("its table directory names table '{}' twice", String::from_utf8_lossy(w[0]))));
        }
    }
    match FONT_REQUIRED.iter().find(|any| !any.iter().any(|t| tags.contains(&&t[..]))) {
        Some(missing) => Err(P::Bad(format!("it has no '{}' table, which every font has",
                                            String::from_utf8_lossy(&missing[0][..])))),
        None => Ok(()),
    }
}

/// A TrueType or OpenType font: its table directory, then the tables.
fn sfnt(b: &[u8]) -> R<Dir> {
    let mut claims = Vec::new();
    let mut unregistered = Vec::new();
    let end = sfnt_dir(b, 0, &mut claims, &mut unregistered)?;
    claims.push((0, end));
    let mut dir = Dir::of(claims, None);
    dir.free(merged(unregistered).iter().map(|&(s, e)| e - s).sum(), FONT_FREE);
    Ok(dir)
}

/// The table directory at `at`: each table claimed (the unregistered ones in `unregistered` too); where the
/// directory ends. A collection's directories name at most MAX_CLAIMS parts in all.
fn sfnt_dir(b: &[u8], at: u64, claims: &mut Vec<(u64, u64)>, unregistered: &mut Vec<(u64, u64)>) -> R<u64> {
    get(b, at + 12)?;
    let a = at as usize;
    let n = be16(b, a + 4);
    if n == 0 || n > 4096 {
        return bad("its table directory is not one");
    }
    if claims.len() + n as usize + 1 > MAX_CLAIMS {
        return Err(P::Bad(too_many(claims.len() + n as usize + 1)));
    }
    let end = at + 12 + 16 * n;
    get(b, end)?;
    let mut tags = Vec::new();
    for i in 0..n as usize {
        let r = a + 12 + 16 * i;
        let (off, len) = (be32(b, r + 8), be32(b, r + 12));
        // (a collection's later directory may follow tables an earlier font shares with it: a table may lie anywhere
        // but over its own directory)
        if !fourcc(&b[r..]) || (len > 0 && off < end && off.saturating_add(len) > at) {
            return bad("its table directory is not one");
        }
        claim(claims, off, len)?;
        let tag = &b[r..r + 4];
        if !FONT_TABLES.iter().any(|t| &t[..] == tag) {
            claim(unregistered, off, len)?;
        }
        tags.push(tag);
    }
    font_tables(&tags, true)?;
    claims.push((at, end));
    Ok(end)
}

/// A font collection: its header, then each font's table directory, then the tables (shared among them).
fn ttc(b: &[u8]) -> R<Dir> {
    get(b, 12)?;
    let version = be32(b, 4);
    let fonts = be32(b, 8);
    if !(version == 0x0001_0000 || version == 0x0002_0000) || fonts == 0 || fonts > 1024 {
        return bad("its header is not a font collection's");
    }
    let head = 12 + 4 * fonts + if version == 0x0002_0000 { 12 } else { 0 };
    get(b, head)?;
    let mut claims = vec![(0, head)];
    let mut unregistered = Vec::new();
    if version == 0x0002_0000 && &b[12 + 4 * fonts as usize..16 + 4 * fonts as usize] == b"DSIG" {
        let d = 16 + 4 * fonts as usize;
        claim(&mut claims, be32(b, d + 4), be32(b, d))?;
    }
    for i in 0..fonts as usize {
        let off = be32(b, 12 + 4 * i);
        if off < head {
            return bad("its header is not a font collection's");
        }
        sfnt_dir(b, off, &mut claims, &mut unregistered)?;
    }
    let mut dir = Dir::of(claims, None);
    // (the fonts share tables: each counted once)
    dir.free(merged(unregistered).iter().map(|&(s, e)| e - s).sum(), FONT_FREE);
    Ok(dir)
}

/// WOFF: its header and table directory, then the (compressed) tables, its metadata and private data.
fn woff(b: &[u8]) -> R<Dir> {
    get(b, 44)?;
    let length = be32(b, 8);
    let n = be16(b, 12);
    if be16(b, 14) != 0 || n == 0 || n > 4096 {
        return bad("its header is not WOFF's");
    }
    let end = 44 + 20 * n;
    get(b, end)?;
    let mut claims = vec![(0, end)];
    let mut tags = Vec::new();
    let mut free = 0u64;
    for i in 0..n as usize {
        let r = 44 + 20 * i;
        let (off, comp, orig) = (be32(b, r + 4), be32(b, r + 8), be32(b, r + 12));
        if !fourcc(&b[r..]) || comp > orig || (comp > 0 && off < end) {
            return bad("its table directory is not one");
        }
        claim(&mut claims, off, comp)?;
        let tag = &b[r..r + 4];
        if !FONT_TABLES.iter().any(|t| &t[..] == tag) {
            free += comp;
        }
        tags.push(tag);
    }
    font_tables(&tags, true)?;
    // (its metadata and its private data: free-form)
    for (o, l) in [(24, 28), (36, 40)] {
        if be32(b, o) != 0 {
            claim(&mut claims, be32(b, o), be32(b, l))?;
            free += be32(b, l);
        }
    }
    let mut dir = Dir::of(claims, Some(length));
    dir.free(free, "unregistered font tables, a WOFF's metadata and private data");
    Ok(dir)
}

/// UIntBase128 (WOFF2): at most five bytes, no leading zero byte, no overflow.
fn base128(b: &[u8], i: &mut usize) -> R<u64> {
    let mut v: u64 = 0;
    for k in 0..5 {
        get(b, *i as u64 + 1)?;
        let c = b[*i];
        *i += 1;
        if k == 0 && c == 0x80 {
            return bad("its table directory is not one");
        }
        v = (v << 7) | (c & 0x7f) as u64;
        if v > u32::MAX as u64 {
            return bad("its table directory is not one");
        }
        if c & 0x80 == 0 {
            return Ok(v);
        }
    }
    bad("its table directory is not one")
}

/// 255UInt16 (WOFF2).
fn u255(b: &[u8], i: &mut usize) -> R<u64> {
    get(b, *i as u64 + 1)?;
    let c = b[*i];
    *i += 1;
    match c {
        253 => {
            get(b, *i as u64 + 2)?;
            *i += 2;
            Ok(be16(b, *i - 2))
        }
        254 | 255 => {
            get(b, *i as u64 + 1)?;
            *i += 1;
            Ok(b[*i - 1] as u64 + if c == 254 { 506 } else { 253 })
        }
        _ => Ok(c as u64),
    }
}

/// WOFF2: its header, table directory (and a collection's), then one compressed block, its metadata and private
/// data, each at a four-byte boundary.
fn woff2(b: &[u8]) -> R<Dir> {
    get(b, 48)?;
    let flavor = be32(b, 4);
    let length = be32(b, 8);
    let n = be16(b, 12);
    if be16(b, 14) != 0 || n == 0 || n > 4096 {
        return bad("its header is not WOFF2's");
    }
    let compressed = be32(b, 20);
    let mut i = 48usize;
    let mut tags: Vec<&[u8]> = Vec::new();
    let mut free = 0u64;
    for _ in 0..n {
        get(b, i as u64 + 1)?;
        let flags = b[i];
        i += 1;
        let tag = flags & 0x3f;
        let name: &[u8] = if tag == 63 {
            get(b, i as u64 + 4)?;
            i += 4;
            &b[i - 4..i]
        } else {
            &WOFF2_TAGS[tag as usize][..]
        };
        let orig = base128(b, &mut i)?;
        let version = flags >> 6;
        let transformed = if tag == 10 || tag == 11 { version != 3 } else { version != 0 };
        if transformed {
            base128(b, &mut i)?;
        }
        if !FONT_TABLES.iter().any(|t| &t[..] == name) {
            // (the tables are compressed together: an unregistered one counted by its length once decompressed)
            free += orig;
        }
        tags.push(name);
    }
    let collection = flavor == u32::from_be_bytes(*b"ttcf") as u64;
    font_tables(&tags, !collection)?;
    if collection {
        get(b, i as u64 + 4)?;
        i += 4;
        let fonts = u255(b, &mut i)?;
        for _ in 0..fonts {
            let tables = u255(b, &mut i)?;
            get(b, i as u64 + 4)?;
            i += 4;
            // (each font's directory: tables of the collection's, each once)
            let mut own = Vec::new();
            for _ in 0..tables {
                let k = u255(b, &mut i)? as usize;
                own.push(*tags.get(k).ok_or(P::Bad("its collection names a table it does not have".into()))?);
            }
            font_tables(&own, true)?;
        }
    }
    let mut claims = vec![(0, i as u64)];
    claim(&mut claims, i as u64, compressed)?;
    for (o, l) in [(28, 32), (40, 44)] {
        if be32(b, o) != 0 {
            claim(&mut claims, be32(b, o), be32(b, l))?;
            free += be32(b, l);
        }
    }
    let mut dir = Dir::of(claims, Some(length));
    dir.free(free, "unregistered font tables, a WOFF2's metadata and private data");
    Ok(dir)
}

/// WOFF2's known tables, by their index (its table directory's flags).
const WOFF2_TAGS: [&[u8; 4]; 63] = [
    b"cmap", b"head", b"hhea", b"hmtx", b"maxp", b"name", b"OS/2", b"post", b"cvt ", b"fpgm", b"glyf", b"loca",
    b"prep", b"CFF ", b"VORG", b"EBDT", b"EBLC", b"gasp", b"hdmx", b"kern", b"LTSH", b"PCLT", b"VDMX", b"vhea",
    b"vmtx", b"BASE", b"GDEF", b"GPOS", b"GSUB", b"EBSC", b"JSTF", b"MATH", b"CBDT", b"CBLC", b"COLR", b"CPAL",
    b"SVG ", b"sbix", b"acnt", b"avar", b"bdat", b"bloc", b"bsln", b"cvar", b"fdsc", b"feat", b"fmtx", b"fvar",
    b"gvar", b"hsty", b"just", b"lcar", b"mort", b"morx", b"opbd", b"prop", b"trak", b"Zapf", b"Silf", b"Glat",
    b"Gloc", b"Feat", b"Sill",
];

/// BMP: its file header, its DIB header (with its colour masks), its colour table, its pixels at the offset the file
/// header gives (their size from the image's shape, or the header's for a compressed one), and an embedded colour
/// profile (a V5 header's).
fn bmp(b: &[u8]) -> R<Dir> {
    get(b, 18)?;
    let file_size = le32(b, 2);
    let pixels = le32(b, 10);
    let dib = le32(b, 14);
    if ![12, 16, 40, 52, 56, 64, 108, 124].contains(&dib) {
        return bad("its header is not a bitmap's");
    }
    get(b, 14 + dib)?;
    let (width, height, planes, bpp, comp, size_image, colours) = if dib == 12 {
        (le16(b, 18) as i64, le16(b, 20) as i64, le16(b, 22), le16(b, 24), 0, 0, 0)
    } else {
        let comp = if dib >= 20 { le32(b, 30) } else { 0 };
        let size_image = if dib >= 24 { le32(b, 34) } else { 0 };
        let colours = if dib >= 36 { le32(b, 46) } else { 0 };
        (le32(b, 18) as i32 as i64, le32(b, 22) as i32 as i64, le16(b, 26), le16(b, 28), comp, size_image, colours)
    };
    // (no bit count with JPEG or PNG compression: its pixels are that image, BI_JPEG and BI_PNG)
    let bits_ok = [1, 2, 4, 8, 16, 24, 32, 64].contains(&bpp) || (bpp == 0 && (comp == 4 || comp == 5));
    if planes != 1 || !bits_ok || width <= 0 || height == 0 || comp > 6 || width > 1 << 20 || height.abs() > 1 << 20
    {
        return bad("its header is not a bitmap's");
    }
    let masks = match (dib, comp) {
        (40, 3) => 12,
        (40, 6) => 16,
        _ => 0,
    };
    let head = 14 + dib + masks;
    let entries = if colours > 0 { colours } else if (1..=8).contains(&bpp) { 1 << bpp } else { 0 };
    if entries > 1 << 16 {
        return bad("its colour table is not one");
    }
    let table_end = head + entries * if dib == 12 { 3 } else { 4 };
    if pixels < head {
        return bad("its pixels' offset is inside its header");
    }
    let mut claims = vec![(0, table_end.min(pixels))];
    let raw = matches!(comp, 0 | 3 | 6);
    let size = match comp {
        _ if raw => (width as u64 * bpp).div_ceil(32) * 4 * height.unsigned_abs(),
        _ if size_image > 0 => size_image,
        _ => return bad("a compressed bitmap's size is not in its header"),
    };
    claim(&mut claims, pixels, size)?;
    if dib == 124 {
        let cs = le32(b, 14 + 56);
        if cs == u32::from_be_bytes(*b"MBED") as u64 || cs == u32::from_be_bytes(*b"LINK") as u64 {
            claim(&mut claims, 14 + le32(b, 14 + 112), le32(b, 14 + 116))?;
        }
    }
    let mut dir = Dir::of(claims, (file_size != 0).then_some(file_size));
    // (an uncompressed bitmap's pixels: raw samples)
    dir.raw = raw.then_some((pixels, size));
    Ok(dir)
}

// ---- formats read whole: ICO and CUR, TIFF, ICC profiles, TGA ----------------------------------------------------

pub fn whole(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    if !eof {
        return Step::More(b.len() + 1);
    }
    let got = match Fmt::of(w.fmt) {
        Fmt::Ico => ico(b),
        Fmt::Tiff => tiff(b),
        Fmt::Tga => tga(b),
        _ => icc(b),
    };
    let dir = match got {
        Ok(dir) => dir,
        Err(P::Need(_)) => return Step::Fail("it is cut short inside its directory".into()),
        Err(P::Bad(why)) => return Step::Fail(why),
    };
    if let Err(why) = covered(b, &dir.claims) {
        return Step::Fail(why);
    }
    if dir.free > 0 {
        if let Some(s) = free(w, dir.free, &dir.free_what) {
            return s;
        }
    }
    Step::Done
}

/// Every part within the file, and every byte no part holds zero.
fn covered(b: &[u8], claims: &[(u64, u64)]) -> Result<(), String> {
    let len = b.len() as u64;
    let mut at = 0u64;
    for (s, e) in merged(claims.to_vec()) {
        if e > len {
            return Err(format!("it is cut short: a part its directory names runs to byte {e}, past its end"));
        }
        if s > at {
            if let Some(k) = b[at as usize..s as usize].iter().position(|&c| c != 0) {
                return Err(format!("the bytes at {} are in no part its directory names", at + k as u64));
            }
        }
        at = at.max(e);
    }
    match b[at as usize..].iter().position(|&c| c != 0) {
        Some(k) => Err(format!("the bytes at {} are in no part its directory names", at + k as u64)),
        None => Ok(()),
    }
}

/// A TGA header (Truevision's, version 1 and 2), which has no signature: its fields as the format allows them, a
/// colour map exactly when the image type has one, and an image of at least one pixel. (id length, colour map bytes,
/// image type, width, height, bytes a pixel.)
pub fn tga_header(b: &[u8]) -> Option<(u64, u64, u8, u64, u64, u64)> {
    if b.len() < 18 {
        return None;
    }
    let (cmap_type, kind) = (b[1], b[2]);
    let (cmap_len, cmap_bits) = (le16(b, 5), b[7]);
    let (width, height, depth, desc) = (le16(b, 12), le16(b, 14), b[16], b[17]);
    let mapped = matches!(kind, 1 | 9);
    let cmap_ok = match cmap_type {
        0 => !mapped && le16(b, 3) == 0 && cmap_len == 0,
        1 => cmap_len > 0 && matches!(cmap_bits, 15 | 16 | 24 | 32),
        _ => false,
    };
    let depth_ok = match kind {
        1 | 9 => matches!(depth, 8 | 16),
        2 | 10 => matches!(depth, 15 | 16 | 24 | 32),
        3 | 11 => matches!(depth, 8 | 16),
        _ => false,
    };
    if !cmap_ok || !depth_ok || width == 0 || height == 0 || desc & 0xc0 != 0 || (desc & 0x0f) as u64 > depth as u64 {
        return None;
    }
    Some((b[0] as u64, cmap_len * (cmap_bits as u64).div_ceil(8), kind, width, height, (depth as u64).div_ceil(8)))
}

/// TGA: its header, image id, colour map and pixels (raw, or run-length packets to the image's last pixel); then a
/// version 2 file's developer area (its directory's tags, free-form: what an application keeps there), extension
/// area (with its colour correction table, postage stamp and scan-line table) and footer, where the footer names
/// them.
fn tga(b: &[u8]) -> R<Dir> {
    let (id, cmap, kind, width, height, px) = tga_header(b).ok_or(P::Bad("its header is not a TGA image's".into()))?;
    let len = b.len() as u64;
    let mut claims = vec![(0, 18)];
    let mut developer = Vec::new();
    claim(&mut claims, 18, id + cmap)?;
    let start = 18 + id + cmap;
    let pixels = width * height;
    let end = if kind < 9 {
        start + pixels * px
    } else {
        let (mut at, mut n) = (start, 0u64);
        while n < pixels {
            let head = *b.get(at as usize).ok_or(P::Bad("it is cut short inside its pixels".into()))?;
            let count = (head & 0x7f) as u64 + 1;
            at += 1 + if head & 0x80 != 0 { px } else { count * px };
            n += count;
        }
        if n != pixels {
            return bad("its run-length packets run past its last pixel");
        }
        at
    };
    claim(&mut claims, start, end - start)?;
    // (its pixels, raw or in run-length packets: samples that follow one another)
    let from = (start as usize).min(b.len());
    let e = diff_entropy(&b[from..(end.min(len) as usize).clamp(from, from + RAW_SAMPLE)]);
    if e >= RAW_MAX_BITS {
        return Err(P::Bad(format!("its samples from byte {start} are near-random ({e:.2} bits a byte from one to the \
                                   next): no picture's are")));
    }
    // (the footer ends with the signature and a zero byte; zero bytes after it are padding, as after any format)
    let mut tail = len;
    while tail > 0 && b[tail as usize - 1] == 0 {
        tail -= 1;
    }
    if tail < len && tail >= end + 25 && b[..tail as usize].ends_with(b"TRUEVISION-XFILE.") {
        let foot = tail + 1 - 26;
        claim(&mut claims, foot, 26)?;
        let (ext, dev) = (le32(b, foot as usize), le32(b, foot as usize + 4));
        if ext != 0 {
            get(b, ext + 495)?;
            if ext < end || le16(b, ext as usize) != 495 {
                return bad("its extension area is not one");
            }
            claim(&mut claims, ext, 495)?;
            let (cc, stamp, lines) = (le32(b, ext as usize + 482), le32(b, ext as usize + 486), le32(b, ext as usize + 490));
            if cc != 0 {
                claim(&mut claims, cc, 2048)?;
            }
            if stamp != 0 {
                get(b, stamp + 2)?;
                claim(&mut claims, stamp, 2 + b[stamp as usize] as u64 * b[stamp as usize + 1] as u64 * px)?;
            }
            if lines != 0 {
                claim(&mut claims, lines, 4 * height)?;
            }
        }
        if dev != 0 {
            get(b, dev + 2)?;
            let tags = le16(b, dev as usize);
            claim(&mut claims, dev, 2 + 10 * tags)?;
            get(b, dev + 2 + 10 * tags)?;
            for k in 0..tags {
                let at = (dev + 2 + 10 * k) as usize;
                claim(&mut claims, le32(b, at + 2), le32(b, at + 6))?;
                claim(&mut developer, le32(b, at + 2), le32(b, at + 6))?;
            }
        }
        if claims.iter().any(|&(s, e)| s < end && e > end) {
            return bad("a part its footer names is inside its pixels");
        }
    }
    let mut dir = Dir::of(claims, None);
    dir.free(merged(developer).iter().map(|&(s, e)| e - s).sum(), "TGA developer area fields");
    Ok(dir)
}

/// ICO and CUR: the directory of images, each a PNG (walked: its free-form parts the icon's) or a DIB (its header,
/// colour table, colour and mask bitmaps).
fn ico(b: &[u8]) -> R<Dir> {
    get(b, 6)?;
    let count = le16(b, 4);
    if count == 0 || count > 1024 {
        return bad("its directory is not an icon's");
    }
    let end = 6 + 16 * count;
    get(b, end)?;
    let mut claims = vec![(0, end)];
    let mut dir = Dir::of(Vec::new(), None);
    for i in 0..count as usize {
        let e = 6 + 16 * i;
        let (size, off) = (le32(b, e + 8), le32(b, e + 12));
        let stop = off.checked_add(size).filter(|&s| s <= b.len() as u64 && off >= end);
        let Some(stop) = stop else { return bad("an icon's image is not inside the file") };
        if claims[1..].contains(&(off, stop)) {
            continue;                               // (entries naming the same image: it is read once)
        }
        if claims[1..].iter().any(|&(s, e)| off < e && s < stop) {
            return bad("two of its images overlap");
        }
        let image = &b[off as usize..stop as usize];
        if image.starts_with(b"\x89PNG\r\n\x1a\n") {
            // (the re-review of Oct 27, N4: its free-form parts count toward the icon's 64 KiB and quarter)
            let Some((free, what)) = walk_part(image) else { return bad("an icon's PNG image is not one") };
            dir.free(free, &what);
        } else if !dib_image(image) {
            return bad("an icon's bitmap is not one");
        }
        claims.push((off, stop));
    }
    dir.claims = claims;
    Ok(dir)
}

/// An icon's DIB: header, colour masks and table, the colour bitmap and (usually) the AND mask, and nothing else.
fn dib_image(d: &[u8]) -> bool {
    if d.len() < 40 {
        return false;
    }
    let head = le32(d, 0);
    let width = le32(d, 4) as i32 as i64;
    let height = le32(d, 8) as i32 as i64;
    let bpp = le16(d, 14);
    let comp = le32(d, 16);
    let colours = le32(d, 32);
    if ![40, 108, 124].contains(&head) || width <= 0 || height <= 0 || height % 2 != 0
        || ![1, 4, 8, 16, 24, 32].contains(&bpp) || !(comp == 0 || comp == 3) || width > 1 << 16 || height > 1 << 17
    {
        return false;
    }
    let rows = (height / 2) as u64;
    let masks = if head == 40 && comp == 3 { 12 } else { 0 };
    let entries = if colours > 0 { colours.min(256) } else if bpp <= 8 { 1 << bpp } else { 0 };
    let colour = (width as u64 * bpp).div_ceil(32) * 4 * rows;
    let and = (width as u64).div_ceil(32) * 4 * rows;
    let least = head + masks + entries * 4 + colour;
    // (an entry the directory makes larger than its bitmap and mask: zero bytes, which hold nothing, as some icon
    // writers leave them; Pillow's own pillow.ico has 48 to 192 of them in three of its five icons)
    let len = d.len() as u64;
    len >= least && d[(least + and).min(len) as usize..].iter().all(|&c| c == 0)
}

/// TIFF (and BigTIFF): its image file directories (and their SubIFDs, Exif, GPS and interoperability directories),
/// each entry's values, the strips, tiles, free ranges and JPEG thumbnail they point at, and an old-style JPEG's
/// tables. Each tag once in a directory; at most TIFF_ENTRIES entries and TIFF_VALUES strip, tile and directory
/// offsets in all (a walk's cost bounded: a file over either is not walked, and stays opaque). The values of private
/// tags (32768 and up) other than the well-known ones (TIFF_PRIVATE) are free-form.
fn tiff(b: &[u8]) -> R<Dir> {
    get(b, 8)?;
    let le = &b[..2] == b"II";
    let u16_at = |i: usize| if le { le16(b, i) } else { be16(b, i) };
    let u32_at = |i: usize| if le { le32(b, i) } else { be32(b, i) };
    let u64_at = |i: usize| if le { le64(b, i) } else { be64(b, i) };
    let big = u16_at(2) == 43;
    if big && (b.len() < 16 || u16_at(4) != 8 || u16_at(6) != 0) {
        return bad("its header is not a BigTIFF's");
    }
    let (head, first) = if big { (16u64, u64_at(8)) } else { (8u64, u32_at(4)) };
    let len = b.len() as u64;
    let mut claims = vec![(0, head)];
    let mut queue = vec![first];
    let mut seen = std::collections::HashSet::new();
    let entry = if big { 20u64 } else { 12 };
    let inline = if big { 8u64 } else { 4 };
    let (mut entries_left, mut values_left, mut private) = (TIFF_ENTRIES, TIFF_VALUES, 0u64);
    // the values of an entry: (where they are, how many, each one's size)
    let mut values = |at: u64, size: u64, count: u64| -> R<Vec<u64>> {
        let bytes = size.checked_mul(count).ok_or(P::Bad("an entry's values are past any file's end".into()))?;
        let base = if bytes <= inline { at + 8 + if big { 4 } else { 0 } } else if big { u64_at(at as usize + 12) } else { u32_at(at as usize + 8) };
        if base.checked_add(bytes).is_none_or(|e| e > len) {
            return bad("an entry's values are past the file's end");
        }
        if count > values_left {
            return bad("its directories name more places than a file of pictures does");
        }
        values_left -= count;
        Ok((0..count).map(|k| {
            let i = (base + k * size) as usize;
            match size { 2 => u16_at(i), 4 => u32_at(i), _ => u64_at(i) }
        }).collect())
    };
    while let Some(ifd) = queue.pop() {
        if ifd == 0 {
            continue;
        }
        if !seen.insert(ifd) || seen.len() > 4096 {
            return bad("its directories loop");
        }
        if ifd.checked_add(if big { 8 } else { 2 }).is_none_or(|e| e > len) {
            return bad("a directory is past the file's end");
        }
        let n = if big { u64_at(ifd as usize) } else { u16_at(ifd as usize) };
        if n > entries_left {
            return bad("its directories hold more entries than a file of pictures does");
        }
        entries_left -= n;
        let first_entry = ifd + if big { 8 } else { 2 };
        let end = n.checked_mul(entry).and_then(|x| x.checked_add(first_entry + inline)).filter(|&e| e <= len);
        let Some(end) = end else { return bad("a directory is past the file's end") };
        claims.push((ifd, end));
        let mut pairs: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
        let mut tags = std::collections::HashSet::new();
        for k in 0..n {
            let at = first_entry + k * entry;
            let tag = u16_at(at as usize);
            if !tags.insert(tag) {
                return Err(P::Bad(format!("a directory names tag {tag} twice")));
            }
            let kind = u16_at(at as usize + 2);
            let count = if big { u64_at(at as usize + 4) } else { u32_at(at as usize + 4) };
            let size: u64 = match kind {
                1 | 2 | 6 | 7 => 1,
                3 | 8 => 2,
                4 | 9 | 11 | 13 => 4,
                5 | 10 | 12 | 16 | 17 | 18 => 8,
                _ => return bad("a directory entry's type is not one"),
            };
            let bytes = size.checked_mul(count).ok_or(P::Bad("an entry's values are past any file's end".into()))?;
            if bytes > inline {
                let off = if big { u64_at(at as usize + 12) } else { u32_at(at as usize + 8) };
                claim(&mut claims, off, bytes)?;
                if tag >= 32768 && !TIFF_PRIVATE.iter().any(|r| r.contains(&tag)) {
                    private += bytes;
                }
            }
            if [273, 279, 324, 325, 288, 289, 513, 514, 519, 520, 521, 330, 34665, 34853, 40965].contains(&tag) {
                if ![3, 4, 13, 16, 18].contains(&kind) {
                    return bad("a directory entry's type is not one");
                }
                let unit = match kind { 3 => 2, 4 | 13 => 4, _ => 8 };
                pairs.insert(tag, values(at, unit, count)?);
            }
        }
        let next = if big { u64_at(end as usize - 8) } else { u32_at(end as usize - 4) };
        queue.push(next);
        for (offsets, counts) in [(273, 279), (324, 325), (288, 289), (513, 514)] {
            let (Some(o), Some(c)) = (pairs.get(&offsets), pairs.get(&counts)) else {
                // (an old-style JPEG's JPEGInterchangeFormat without its length points into its strips: libtiff and
                // Pillow read it so, as their old-style-jpeg-compression test images have it)
                if pairs.contains_key(&offsets) != pairs.contains_key(&counts) && offsets != 513 {
                    return bad("a directory names its data's places without their sizes");
                }
                continue;
            };
            if o.len() != c.len() {
                return bad("a directory names its data's places without their sizes");
            }
            for (&off, &cnt) in o.iter().zip(c) {
                claim(&mut claims, off, cnt)?;
            }
        }
        // an old-style JPEG's tables (TIFF 6.0, section 22): quantization tables of 64 bytes, Huffman tables of 16
        // counts and the values they count
        for &off in pairs.get(&519).into_iter().flatten() {
            claim(&mut claims, off, 64)?;
        }
        for &off in pairs.get(&520).into_iter().chain(pairs.get(&521)).flatten() {
            get(b, off.saturating_add(16))?;
            let counts: u64 = b[off as usize..off as usize + 16].iter().map(|&c| c as u64).sum();
            claim(&mut claims, off, 16 + counts)?;
        }
        for tag in [330, 34665, 34853, 40965] {
            queue.extend(pairs.get(&tag).into_iter().flatten().copied());
        }
    }
    let mut dir = Dir::of(claims, None);
    dir.free(private, "TIFF private tags");
    Ok(dir)
}

/// The most directory entries, and strip, tile and directory offsets, a TIFF walk reads.
const TIFF_ENTRIES: u64 = 1 << 20;
const TIFF_VALUES: u64 = 1 << 20;

/// The private tags (32768 and up) in wide use, whose values are what their owners define: Exif's and GPS's
/// directories and tags, IPTC, Photoshop's, ICC profiles, GeoTIFF's, GDAL's, DNG's, ImageJ's, Micro-Manager's,
/// the microscopes' (MetaMorph, Molecular Dynamics, Zeiss, FluoView, LSM, TVIPS), SGI's, Windows' XP tags, PrintIM.
const TIFF_PRIVATE: &[std::ops::RangeInclusive<u64>] = &[
    32781..=32781, 32995..=32998, 33421..=33452, 33550..=33550, 33628..=33631, 33723..=33723, 33922..=33922,
    34118..=34122, 34264..=34264, 34361..=34363, 34377..=34377, 34386..=34386, 34412..=34412, 34665..=34665,
    34675..=34675, 34732..=34737, 34850..=34869, 36864..=37530, 37706..=37724, 40091..=40095, 40960..=42240,
    50341..=50341, 50706..=52600,
];

/// The tags of ICC profiles (ICC.1 version 2 and 4, and those of the private tags in wide use: Apple's display and
/// description tags, Adobe's `arts`, Microsoft's WCS tag): a profile's other tags are free-form.
const ICC_TAGS: &[&[u8; 4]] = &[
    b"A2B0", b"A2B1", b"A2B2", b"A2B3", b"A2M0", b"B2A0", b"B2A1", b"B2A2", b"B2A3", b"B2D0", b"B2D1", b"B2D2", b"B2D3",
    b"D2B0", b"D2B1", b"D2B2", b"D2B3", b"bXYZ", b"bTRC", b"bfd ", b"bkpt", b"calt", b"chad", b"chrm", b"cicp", b"ciis",
    b"clro", b"clrt", b"clot", b"cprt", b"crdi", b"desc", b"devs", b"dmdd", b"dmnd", b"gamt", b"gTRC", b"gXYZ", b"kTRC",
    b"lumi", b"meas", b"meta", b"mcta", b"ncol", b"ncl2", b"pre0", b"pre1", b"pre2", b"ps2c", b"ps2i", b"ps2r", b"ps2s",
    b"psd0", b"psd1", b"psd2", b"psd3", b"pseq", b"psid", b"resp", b"rig0", b"rig2", b"rTRC", b"rXYZ", b"scrd", b"scrn",
    b"targ", b"tech", b"view", b"vued", b"wtpt", b"arts", b"aarg", b"aagg", b"aabg", b"dscm", b"mmod", b"ndin", b"vcgt",
    b"MS00",
];

/// An ICC profile: its header (its size first), its tag table, the tags' data; a tag of no signature of ICC_TAGS is
/// free-form (the re-review of Oct 27, N4: what an application keeps in a tag of its own).
fn icc(b: &[u8]) -> R<Dir> {
    get(b, 132)?;
    let size = be32(b, 0);
    let n = be32(b, 128);
    if size < 132 || size > b.len() as u64 || n > 1024 || !(2..=5).contains(&b[8]) {
        return bad("its header is not an ICC profile's");
    }
    let end = 132 + 12 * n;
    get(b, end)?;
    let mut claims = vec![(0, end)];
    let mut unregistered = Vec::new();
    for i in 0..n as usize {
        let t = 132 + 12 * i;
        let (off, len) = (be32(b, t + 4), be32(b, t + 8));
        if off.checked_add(len).is_none_or(|e| e > size) {
            return bad("a tag of the profile is past its end");
        }
        claims.push((off, off + len));
        if !ICC_TAGS.iter().any(|tag| &tag[..] == &b[t..t + 4]) {
            unregistered.push((off, off + len));
        }
    }
    let mut dir = Dir::of(claims, Some(size));
    // (tags may share their data: counted once)
    dir.free(merged(unregistered).iter().map(|&(s, e)| e - s).sum(), "ICC profile tags no one registered");
    Ok(dir)
}

// ---- IM Tools images ---------------------------------------------------------------------------------------------
//
// Pillow's "IMT" (ImtImagePlugin): lines of `key value` (a key of lowercase letters, a value of no blank) or `*`
// comments, each of 2 to 100 bytes, then a form feed, then the pixels: width x height bytes of 8-bit grey for `pixel
// n8` (the only mode Pillow reads), raw samples. Phases: 0 the header, 1 after the pixels, 2 the pixels.

/// An IM Tools header at the start of `b`: (its length with the form feed, width, height), or None.
pub fn imt_header(b: &[u8]) -> Option<(usize, u64, u64)> {
    let (mut i, mut width, mut height, mut grey) = (0usize, 0u64, 0u64, false);
    while i < b.len().min(4096) {
        if b[i] == 0x0c {
            return (width > 0 && height > 0 && grey).then_some((i + 1, width, height));
        }
        let line_end = i + b[i..].iter().position(|&c| c == b'\n')?;
        let line = &b[i..line_end];
        if !(2..=100).contains(&line.len()) {
            return None;
        }
        if line[0] != b'*' {
            let sp = line.iter().position(|&c| c == b' ')?;
            let (key, value) = (&line[..sp], &line[sp + 1..]);
            if !key.iter().all(|c| c.is_ascii_lowercase()) || value.iter().any(|&c| c == b' ' || c == b'\r') {
                return None;
            }
            let number = || -> Option<u64> {
                (!value.is_empty() && value.len() <= 7 && value.iter().all(|c| c.is_ascii_digit()))
                    .then(|| std::str::from_utf8(value).ok()?.parse().ok())?
            };
            match key {
                b"width" => width = number()?,
                b"height" => height = number()?,
                b"pixel" => grey = value == b"n8",
                _ => {}
            }
        }
        i = line_end + 1;
    }
    None
}

pub fn imt(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    if w.phase == 0 {
        return match imt_header(b) {
            Some((head, width, height)) => {
                w.x[0] = width * height;
                w.phase = 2;
                Step::Used(head)
            }
            None if !eof && b.len() < 4096 => Step::More(4096),
            None => Step::Fail("its header is not an IM Tools image's".into()),
        };
    }
    if w.phase == 2 {
        if let Some(s) = raw_samples(w, b, 0, w.x[0], eof) {
            return s;
        }
        w.phase = 1;
        return Step::Skip(w.x[0]);
    }
    if b.is_empty() && eof {
        return Step::Done;
    }
    pad(w, format!("bytes follow the image's pixels at byte {}", w.at))
}

// ---- Netpbm images ------------------------------------------------------------------------------------------------
//
// The binary forms: P4 (bits), P5 (grey), P6 (colour) — a magic number, then width, height and (but for P4) the
// largest value, in ASCII between blanks and comments, one blank, then the raster: exactly its rows' bytes (one or two
// a sample); P7 (PAM) — WIDTH, HEIGHT, DEPTH, MAXVAL and TUPLTYPE lines to ENDHDR, then its raster. Images may follow
// one another; their rasters are raw samples. Phases: 0 a header, 1 after a raster, 2 a raster. n[0]: images. x[0]:
// the raster's length.

/// A binary Netpbm header at the start of `b`: (its length, the raster's), or None (Some(Err) when more bytes are
/// needed to tell).
fn pnm_header(b: &[u8]) -> Result<Option<(usize, u64)>, ()> {
    if b.len() < 3 || b[0] != b'P' || !(b'4'..=b'7').contains(&b[1]) {
        return Ok(None);
    }
    let kind = b[1];
    let mut i = 2;
    let more = |i: usize| if i >= b.len() { Err(()) } else { Ok(()) };
    if kind == b'7' {
        let (mut width, mut height, mut depth, mut maxval) = (0u64, 0u64, 0u64, 0u64);
        loop {
            let start = i;
            let end = match b[i..].iter().position(|&c| c == b'\n') {
                Some(k) => i + k,
                None => return if b.len() - i > 256 { Ok(None) } else { Err(()) },
            };
            let line = std::str::from_utf8(&b[start..end]).map_err(|_| ())?.trim();
            i = end + 1;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "ENDHDR" {
                break;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let (key, value) = (parts.next().unwrap_or(""), parts.next().unwrap_or("").trim());
            let n = || value.parse::<u64>().ok().filter(|&v| v > 0 && v <= 1 << 24);
            match key {
                "WIDTH" => width = match n() { Some(v) => v, None => return Ok(None) },
                "HEIGHT" => height = match n() { Some(v) => v, None => return Ok(None) },
                "DEPTH" => depth = match n() { Some(v) => v, None => return Ok(None) },
                "MAXVAL" => maxval = match n() { Some(v) => v, None => return Ok(None) },
                "TUPLTYPE" => {}
                _ => return Ok(None),
            }
            if i > 4096 {
                return Ok(None);
            }
        }
        if width == 0 || height == 0 || depth == 0 || maxval == 0 || maxval > 65535 {
            return Ok(None);
        }
        let raster = width.checked_mul(height).and_then(|x| x.checked_mul(depth))
            .and_then(|x| x.checked_mul(if maxval < 256 { 1 } else { 2 }));
        return Ok(raster.map(|r| (i, r)));
    }
    // P4, P5, P6: numbers between blanks and comments
    let mut nums = Vec::new();
    let want = if kind == b'4' { 2 } else { 3 };
    while nums.len() < want {
        more(i)?;
        match b[i] {
            c if c.is_ascii_whitespace() => i += 1,
            b'#' => match b[i..].iter().position(|&c| c == b'\n' || c == b'\r') {
                Some(k) => i += k,
                None => return Err(()),
            },
            c if c.is_ascii_digit() => {
                let start = i;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                more(i)?;
                if i - start > 8 {
                    return Ok(None);
                }
                nums.push(std::str::from_utf8(&b[start..i]).ok().and_then(|t| t.parse::<u64>().ok()).ok_or(())?);
            }
            _ => return Ok(None),
        }
        if i > 4096 {
            return Ok(None);
        }
    }
    more(i)?;
    if !b[i].is_ascii_whitespace() {
        return Ok(None);
    }
    i += 1;
    let (width, height) = (nums[0], nums[1]);
    let maxval = if kind == b'4' { 1 } else { nums[2] };
    if width == 0 || height == 0 || maxval == 0 || maxval > 65535 || width > 1 << 24 || height > 1 << 24 {
        return Ok(None);
    }
    let sample = if maxval < 256 { 1 } else { 2 };
    let raster = match kind {
        b'4' => width.div_ceil(8) * height,
        b'5' => width * height * sample,
        _ => width * height * 3 * sample,
    };
    Ok(Some((i, raster)))
}

pub fn pnm(w: &mut Walker, b: &[u8], eof: bool) -> Step {
    if w.phase == 0 {
        return match pnm_header(b) {
            Ok(Some((head, raster))) => {
                w.n[0] += 1;
                w.x[0] = raster;
                w.phase = 2;
                Step::Used(head)
            }
            Err(()) if !eof && b.len() < 4096 => Step::More(b.len().max(64) * 2),
            _ => Step::Fail(format!("the bytes at {} are not a Netpbm image's header", w.at)),
        };
    }
    if w.phase == 2 {
        if let Some(s) = raw_samples(w, b, 0, w.x[0], eof) {
            return s;
        }
        w.phase = 1;
        return Step::Skip(w.x[0]);
    }
    if b.is_empty() && eof {
        return Step::Done;
    }
    if b.len() < 3 && !eof {
        return Step::More(3);
    }
    if b.starts_with(b"P") && b.len() >= 3 && (b'4'..=b'7').contains(&b[1]) && b[2].is_ascii_whitespace() {
        w.phase = 0;
        return Step::Used(0);
    }
    pad(w, format!("bytes follow the image's raster at byte {}", w.at))
}
