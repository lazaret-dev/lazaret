//! The walker held to files the real encoders wrote (tests/fixtures/media: scripts/make_media_fixtures.py) and to
//! structures built here, whole and in chunks, and to what must stay opaque: bytes appended, a gap, a file cut
//! short, a checksum broken, a format's first bytes glued onto random data. Keystores built here as keytool, OpenSSL
//! and Bouncy Castle lay them out, with random bytes where their keys and certificates are (nothing secret).

use super::keystore::{self, Keystore};
use super::*;

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        &[$(($name, include_bytes!(concat!("../../../../../tests/fixtures/media/", $name)) as &[u8])),*]
    };
}

const FIXTURES: &[(&str, &[u8])] = fixtures![
    "gradient.imt", "noise-anim.gif", "noise-anim.png", "noise-id3.mp3", "noise-id3v1.mp3", "noise-jpeg.tif",
    "noise-lossless.webp", "noise-lossy.webp", "noise-lzw.tif", "noise-nopad.flac", "noise-progressive.jpg",
    "noise-raw.mp3", "noise-raw.tif", "noise.3gp", "noise.aac", "noise.avi", "noise.avif", "noise.flac", "noise.gif",
    "noise.icns", "noise.ico", "noise.jp2", "noise.jpg", "noise.m4a", "noise.mkv", "noise.mov", "noise.mp4",
    "noise.opus", "noise.otf", "noise.png", "noise.ts", "noise.ttc", "noise.ttf", "noise.webm", "noise.woff",
    "noise.woff2", "signal-rle.tga", "signal.aiff", "signal.bmp", "signal.pbm", "signal.pgm", "signal.ppm",
    "signal.tga", "signal.wav",
];

/// A seeded generator's bytes (xorshift), none of them zero.
fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..n).map(|_| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x >> 24) as u8 | 1
    }).collect()
}

/// Random bytes, every bit of them (noise's are odd, so their differences have 7 bits at most).
fn random(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..n).map(|_| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x >> 24) as u8
    }).collect()
}

/// Samples that follow one another (a slow wave and a little noise), as a picture's or a sound's do.
fn signal(seed: u64, n: usize) -> Vec<u8> {
    let r = noise(seed, n);
    (0..n).map(|i| {
        let t = i as f64;
        let v = 128.0 + 80.0 * (t * 0.013).sin() + 30.0 * (t * 0.0021 + seed as f64).sin();
        (v as i64 + (r[i] % 7) as i64 - 3).clamp(0, 255) as u8
    }).collect()
}

/// 16-bit PCM, little- or big-endian: a tone and a little noise.
fn pcm16(seed: u64, frames: usize, le: bool) -> Vec<u8> {
    let r = noise(seed, frames);
    (0..frames).flat_map(|i| {
        let v = (8000.0 * (i as f64 * 0.031).sin()) as i16 + (r[i] % 64) as i16 - 32;
        if le { v.to_le_bytes() } else { v.to_be_bytes() }
    }).collect()
}

/// A WAV file's format chunk's body: PCM, mono, 22,050 Hz, 16 bits.
fn pcm_format(be: bool) -> Vec<u8> {
    let (h, w): (fn(u16) -> [u8; 2], fn(u32) -> [u8; 4]) =
        if be { (u16::to_be_bytes, u32::to_be_bytes) } else { (u16::to_le_bytes, u32::to_le_bytes) };
    [&h(1)[..], &h(1), &w(22050), &w(44100), &h(2), &h(16)].concat()
}

/// A walk fed in chunks of `size` (`seek`: the host passes over what the walk skips, as a file on disk can, never
/// past the file's end).
fn chunked(data: &[u8], size: usize, seek: bool) -> Walked {
    let mut w = Walker::new();
    let mut off = 0usize;
    loop {
        let end = (off + size).min(data.len());
        feed(&mut w, off as u64, &data[off..end], end == data.len());
        if w.end.is_some() {
            break;
        }
        off = if seek { end.max(w.at.min(data.len() as u64) as usize) } else { end };
        if off >= data.len() {
            feed(&mut w, off as u64, b"", true);
            break;
        }
    }
    w.walked().unwrap()
}

fn is(w: &Walked) -> bool {
    matches!(w, Walked::Is(_))
}

#[test]
fn the_encoders_files_are_their_formats_to_their_end() {
    for (name, data) in FIXTURES {
        let got = walk(data);
        assert!(is(&got), "{name}: {got:?}");
        assert!(starts(data).is_some(), "{name}");
        for size in [1, 3, 64, 1000, 4096, 1 << 20] {
            for seek in [false, true] {
                assert_eq!(chunked(data, size, seek), got, "{name} in chunks of {size} (seek {seek})");
            }
        }
    }
}

#[test]
fn bytes_the_structure_does_not_hold_keep_a_file_opaque() {
    for (name, data) in FIXTURES {
        // an appended payload
        let mut more = data.to_vec();
        more.extend(noise(1, 300));
        assert!(!is(&walk(&more)), "{name} + 300 random bytes");
        // a format's first bytes glued onto random data
        let mut glued = data[..data.len().min(64)].to_vec();
        glued.extend(noise(2, 3000));
        assert!(!is(&walk(&glued)), "{name}'s first 64 bytes + random");
        // zero padding is no payload
        let mut padded = data.to_vec();
        padded.extend([0u8; 37]);
        assert!(is(&walk(&padded)), "{name} + zero bytes: {:?}", walk(&padded));
        // cut short (an MP3's or AAC's last frame may be cut anywhere: what is there is that frame's), whole and as
        // its stream passes, the host passing over what the walk skips or not
        if !(name.ends_with(".mp3") || name.ends_with(".aac")) {
            for cut in [data.len() - 5, data.len() / 2 + 1, data.len() * 3 / 4 + 3] {
                let cut = &data[..cut];
                assert!(!is(&walk(cut)), "{name} cut to {} bytes: {:?}", cut.len(), walk(cut));
                for size in [1, 64, 1000, 4096, 1 << 20] {
                    for seek in [false, true] {
                        let got = chunked(cut, size, seek);
                        assert!(!is(&got), "{name} cut to {} bytes, in chunks of {size} (seek {seek}): {got:?}", cut.len());
                    }
                }
            }
        } else {
            // (as its stream passes as whole: its last frame cut, after two whole ones, is that frame's)
            for cut in [data.len() - 5, data.len() / 2 + 1, data.len() * 3 / 4 + 3, 700] {
                let cut = &data[..cut];
                let whole = walk(cut);
                for size in [1, 64, 1000, 4096, 1 << 20] {
                    for seek in [false, true] {
                        let got = chunked(cut, size, seek);
                        assert_eq!(is(&got), is(&whole), "{name} cut to {} bytes, in chunks of {size} (seek {seek}): \
                                                          {got:?}, whole {whole:?}", cut.len());
                    }
                }
            }
        }
    }
}

#[test]
fn a_part_that_runs_past_the_end_is_a_file_cut_short_as_its_stream_passes() {
    // a box, a chunk, a frame or a raster that claims more than the file holds: the host passes over what the walk
    // skips, clamped to the file's end, and the walk fails there (the review's probes: 1 GB claimed, 20 KB present)
    let mut mp4 = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2".to_vec();
    mp4.extend(b"\x40\x00\x00\x00mdat");
    mp4.extend(noise(120, 20_000));
    let mut wav = b"RIFF\x00\x00\x00\x40WAVE".to_vec();
    wav.extend(b"fmt \x10\x00\x00\x00");
    wav.extend(pcm_format(false));
    wav.extend(b"data\x00\x00\x00\x40");
    wav.extend(pcm16(121, 10_000, true));
    let pgm = [b"P5\n4096 4096\n255\n".as_slice(), &signal(122, 20_000)].concat();
    for (name, f) in [("mp4", &mp4), ("wav", &wav), ("pgm", &pgm)] {
        assert!(!is(&walk(f)), "{name}");
        for size in [1000, 4096, 1 << 20] {
            for seek in [false, true] {
                let got = chunked(f, size, seek);
                assert!(matches!(&got, Walked::Not(_, why) if why.contains("cut short")), "{name} {size} {seek}: {got:?}");
            }
        }
    }
    // a host that passes over the skipped bytes to the file's end and says it ends there
    let mut w = Walker::new();
    feed(&mut w, 0, &mp4[..4096], false);
    assert!(w.end.is_none() && w.at > mp4.len() as u64);
    feed(&mut w, mp4.len() as u64, b"", true);
    assert!(matches!(w.walked(), Some(Walked::Not(_, why)) if why.contains("cut short")), "{:?}", w.walked());
}

#[test]
fn a_changed_byte_breaks_a_checksummed_format() {
    for name in ["noise.png", "noise-anim.png", "noise.opus", "noise-nopad.flac", "noise.flac"] {
        let data = FIXTURES.iter().find(|(n, _)| *n == name).unwrap().1;
        for at in [data.len() / 2, data.len() - 9] {
            let mut d = data.to_vec();
            d[at] ^= 0x10;
            assert!(!is(&walk(&d)), "{name} with byte {at} changed");
        }
    }
}

#[test]
fn what_is_not_a_known_format_is_unknown() {
    assert_eq!(walk(&noise(3, 5000)), Walked::Unknown);
    assert_eq!(walk(b""), Walked::Unknown);
    assert_eq!(starts(&noise(3, 512)), None);
    assert_eq!(starts(b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR").as_deref(), Some("PNG image"));
}

// ---- structures built here -----------------------------------------------------------------------------------------

/// MPEG-1 Layer III frames, 128 kbit/s at 44.1 kHz (417 or 418 bytes), their bodies random.
fn mp3_frames(n: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for k in 0..n {
        let pad = (k % 3 == 0) as u8;
        let len = 417 + pad as usize;
        out.extend([0xff, 0xfb, 0x90 | (pad << 1), 0x64]);
        out.extend(noise(seed + k as u64, len - 4));
    }
    out
}

/// An ID3v2.3 tag of `body` bytes (at least 10): a comment frame of text, then `pad` of them zero padding.
fn id3v2_with(body: usize, pad: usize, frame: &[u8; 4], content: &[u8]) -> Vec<u8> {
    let mut t = b"ID3\x03\x00\x00".to_vec();
    t.extend([(body >> 21) as u8 & 0x7f, (body >> 14) as u8 & 0x7f, (body >> 7) as u8 & 0x7f, body as u8 & 0x7f]);
    t.extend(frame);
    t.extend((content.len() as u32).to_be_bytes());
    t.extend([0, 0]);
    t.extend(content);
    assert_eq!(10 + content.len() + pad, body);
    t.extend(vec![0u8; pad]);
    t
}

fn id3v2(body: usize) -> Vec<u8> {
    let text: Vec<u8> = (0..body - 10 - 4).map(|i| b"Lazaret "[i % 8]).collect();
    id3v2_with(body, 4, b"COMM", &text)
}

#[test]
fn mp3_tags_and_trailers() {
    let frames = mp3_frames(12, 10);
    assert!(is(&walk(&frames)));
    // ID3v2, then the zero padding some taggers leave, then frames; an ID3v1 tag at the end
    let mut f = id3v2(300);
    f.extend([0; 40]);
    f.extend(&frames);
    let mut tag = b"TAG".to_vec();
    tag.extend(noise(4, 125));
    f.extend(&tag);
    assert_eq!(walk(&f), Walked::Is("MP3 audio".into()));
    // an APE tag with its header, then ID3v1
    let mut ape = frames.clone();
    let items = noise(5, 50);
    let mut header = b"APETAGEX".to_vec();
    header.extend(2000u32.to_le_bytes());
    header.extend(((items.len() + 32) as u32).to_le_bytes());
    header.extend(1u32.to_le_bytes());
    header.extend((0xa000_0000u32).to_le_bytes());
    header.extend([0; 8]);
    let mut footer = header.clone();
    footer[20..24].copy_from_slice(&(0x8000_0000u32).to_le_bytes());
    ape.extend(&header);
    ape.extend(&items);
    ape.extend(&footer);
    ape.extend(&tag);
    assert!(is(&walk(&ape)), "{:?}", walk(&ape));
    // an APE tag without its header: its first item, read at the end
    let mut bare = frames.clone();
    let mut item = 5u32.to_le_bytes().to_vec();
    item.extend(0u32.to_le_bytes());
    item.extend(b"Title\x00hello");
    bare.extend(&item);
    bare.extend(&footer[..12]);
    bare.extend(((item.len() + 32) as u32).to_le_bytes());
    bare.extend(&footer[16..]);
    assert!(is(&walk(&bare)), "{:?}", walk(&bare));
    for (size, seek) in [(7, false), (100, true)] {
        assert_eq!(chunked(&bare, size, seek), walk(&bare));
    }
    // Lyrics3 v2 before ID3v1
    let mut lyr = frames.clone();
    let body = b"LYRICSBEGININD00002110".to_vec();
    lyr.extend(&body);
    lyr.extend(format!("{:06}", body.len()).as_bytes());
    lyr.extend(b"LYRICS200");
    lyr.extend(&tag);
    assert!(is(&walk(&lyr)), "{:?}", walk(&lyr));
    // a frame of another shape, garbage between frames, garbage after the last
    let mut other = frames.clone();
    other.extend([0xff, 0xfb, 0x98, 0x64]);            // (48 kHz)
    other.extend(noise(6, 400));
    assert!(!is(&walk(&other)));
    let mut gap = frames[..418].to_vec();
    gap.extend([7]);
    gap.extend(&frames[418..]);
    assert!(!is(&walk(&gap)));
    // an ID3 tag and nothing else, or one frame and a payload
    assert!(!is(&walk(&id3v2(2000))));
    let mut one = mp3_frames(1, 11);
    one.extend(noise(12, 2000));
    assert!(!is(&walk(&one)));
    // a tag's frames: a frame that is not one, a frame past the tag, padding that is not zero
    let bad = [id3v2_with(30, 0, b"COM\x01", b"hello there, comment"), frames.clone()].concat();
    assert!(!is(&walk(&bad)));
    let mut long = id3v2(300);
    long[17] = 0x7f;
    assert!(!is(&walk(&[long, frames.clone()].concat())));
    let mut junk = id3v2(300);
    junk[308] = 1;
    assert!(!is(&walk(&[junk, frames.clone()].concat())));
}

#[test]
fn free_form_parts_hold_at_most_64_kib_and_a_quarter_of_the_file() {
    let frames = mp3_frames(400, 13);                  // (167 KB of audio)
    // a private frame (PRIV) of 30 KB: within both bounds; of 70 KB, past FREE_MAX
    let priv30 = id3v2_with(30_010, 0, b"PRIV", &noise(14, 30_000));
    assert!(is(&walk(&[priv30.as_slice(), &frames].concat())));
    let priv70 = id3v2_with(70_010, 0, b"PRIV", &noise(15, 70_000));
    let got = walk(&[priv70.as_slice(), &frames].concat());
    assert!(matches!(&got, Walked::Not(_, why) if why.contains("ID3 private, object and unknown frames hold")), "{got:?}");
    // 30 KB of a GEOB frame before 40 KB of audio: more than a quarter of the file
    let geob = id3v2_with(30_010, 0, b"GEOB", &noise(16, 30_000));
    assert!(!is(&walk(&[geob.as_slice(), &frames[..40_000]].concat())));
    // a known frame's content is the frame's (a cover picture's bytes)
    let apic = id3v2_with(70_010, 0, b"APIC", &noise(17, 70_000));
    assert!(is(&walk(&[apic.as_slice(), &frames].concat())));
    // ISO media: a `free` box, a `uuid` box, an unknown box
    let bx = |kind: &[u8], body: &[u8]| [&((body.len() + 8) as u32).to_be_bytes()[..], kind, body].concat();
    let ftyp = bx(b"ftyp", b"isom\x00\x00\x02\x00isom");
    let mdat = bx(b"mdat", &noise(18, 200_000));
    for kind in [b"free", b"uuid", b"zzzz"] {
        assert!(is(&walk(&[ftyp.as_slice(), &bx(kind, &noise(19, 1000)), &mdat].concat())), "{kind:?}");
        assert!(!is(&walk(&[ftyp.as_slice(), &bx(kind, &noise(19, 70_000)), &mdat].concat())), "{kind:?}");
    }
    // a PNG's text and private chunks, a JPEG's comments and unregistered segments: as their own tests' files
    let png = FIXTURES.iter().find(|(n, _)| *n == "noise.png").unwrap().1;
    let chunk = |name: &[u8], body: &[u8]| {
        let mut c = (body.len() as u32).to_be_bytes().to_vec();
        c.extend(name);
        c.extend(body);
        c.extend(lazaret_verify::inflate::crc32(lazaret_verify::inflate::crc32(0, name), body).to_be_bytes());
        c
    };
    for name in [b"zTXt", b"prVW"] {
        let f = [&png[..33], &chunk(name, &noise(20, 4000)), &png[33..]].concat();
        let got = walk(&f);
        assert!(matches!(&got, Walked::Not(_, why) if why.contains("PNG text, private and unregistered chunks")), "{got:?}");
        let small = [&png[..33], &chunk(name, &noise(20, 100)), &png[33..]].concat();
        assert!(is(&walk(&small)), "{:?}", walk(&small));
    }
    let jpg = FIXTURES.iter().find(|(n, _)| *n == "noise.jpg").unwrap().1;
    for marker in [0xfe, 0xe9] {
        let seg = [&[0xff, marker][..], &4002u16.to_be_bytes(), &noise(21, 4000)].concat();
        let f = [&jpg[..2], seg.as_slice(), &jpg[2..]].concat();
        assert!(!is(&walk(&f)), "marker {marker:x}");
        let small = [&[0xff, marker][..], &102u16.to_be_bytes(), &noise(21, 100)].concat();
        assert!(is(&walk(&[&jpg[..2], small.as_slice(), &jpg[2..]].concat())), "marker {marker:x}");
    }
    // Exif's segment is registered: its bytes are the camera's
    let exif = [&[0xff, 0xe1][..], &2008u16.to_be_bytes(), b"Exif\x00\x00", &noise(22, 2000)].concat();
    assert!(is(&walk(&[&jpg[..2], exif.as_slice(), &jpg[2..]].concat())));
}

#[test]
fn shapes_no_real_file_has() {
    let bx = |kind: &[u8], body: &[u8]| [&((body.len() + 8) as u32).to_be_bytes()[..], kind, body].concat();
    // ISO media: a size-0 box that is not the media data; a first box of free space and no movie box
    assert!(!is(&walk(&[b"\x00\x00\x00\x00ftyp".as_slice(), &noise(30, 5000)].concat())));
    let free_mdat = [bx(b"free", b"").as_slice(), b"\x00\x00\x00\x00mdat", &noise(31, 5000)].concat();
    assert!(!is(&walk(&free_mdat)));
    let qt = [bx(b"wide", b"").as_slice(), &bx(b"mdat", &noise(32, 5000)), &bx(b"moov", &noise(33, 100))].concat();
    assert_eq!(walk(&qt), Walked::Is("QuickTime movie".into()));
    // a PNG with no image data: IHDR, IEND
    let png = FIXTURES.iter().find(|(n, _)| *n == "noise.png").unwrap().1;
    let iend = &png[png.len() - 12..];
    assert!(!is(&walk(&[&png[..33], iend].concat())));
    // a JPEG with no frame header, or no scan: SOI, a segment, EOI
    let app = [&[0xff, 0xe0][..], &16u16.to_be_bytes(), b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"].concat();
    assert!(!is(&walk(&[b"\xff\xd8".as_slice(), &app, b"\xff\xd9"].concat())));
    // a GIF with no image, a transport stream with no program association table
    assert!(!is(&walk(b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x3b")));
    let ts: Vec<u8> = (0..20).flat_map(|k| [&[0x47u8, 0x01, 0x00, 0x10 | (k & 15) as u8][..], &noise(34 + k, 184)].concat()).collect();
    assert!(!is(&walk(&ts)));
    // an Ogg stream of no codec known here: its pages free-form
    let mut ogg = ogg_page(2, 0, &noise(35, 600));
    ogg.extend(ogg_page(4, 1, &noise(36, 3000)));
    assert!(!is(&walk(&ogg)));
}

#[test]
fn raw_samples_follow_one_another() {
    // a raster of random bytes is no picture; a signal's is
    for (head, n) in [(b"P5\n100 100\n255\n".as_slice(), 10_000), (b"P6\n50 50\n255\n", 7500),
                      (b"width 100\nheight 100\npixel n8\n\x0c", 10_000)] {
        assert!(is(&walk(&[head, &signal(40, n)].concat())), "{:?}", String::from_utf8_lossy(head));
        let got = walk(&[head, &random(41, n)].concat());
        assert!(matches!(&got, Walked::Not(_, why) if why.contains("near-random")), "{got:?}");
    }
    // fewer samples than RAW_SAMPLE: those there are measured (a few hundred bytes measure under the bound)
    let short = [b"P5\n60 50\n255\n".as_slice(), &random(44, 3000)].concat();
    assert!(matches!(walk(&short), Walked::Not(_, why) if why.contains("near-random")), "{:?}", walk(&short));
    assert!(is(&walk(&[b"P5\n60 50\n255\n".as_slice(), &signal(44, 3000)].concat())));
    assert!(is(&walk(&[b"P5\n10 10\n255\n".as_slice(), &random(45, 100)].concat())));
    // PCM: a tone is a sound, random bytes are not; coded audio is not raw
    let wav = |fmt: &[u8], data: &[u8]| {
        let mut body = b"WAVE".to_vec();
        for (id, c) in [(b"fmt ", fmt), (b"data", data)] {
            body.extend(id);
            body.extend((c.len() as u32).to_le_bytes());
            body.extend(c);
        }
        [b"RIFF".as_slice(), &(body.len() as u32).to_le_bytes(), &body].concat()
    };
    assert!(is(&walk(&wav(&pcm_format(false), &pcm16(42, 5000, true)))));
    // a format chunk no sound has: no channels, rate or block size (the review's probe: sixteen zero bytes)
    assert!(!is(&walk(&wav(&[0u8; 16], &pcm16(42, 5000, true)))));
    let mut mono0 = pcm_format(false);
    mono0[2] = 0;
    assert!(!is(&walk(&wav(&mono0, &pcm16(42, 5000, true)))));
    // a format of no name (0) is judged as raw samples
    let mut unnamed = pcm_format(false);
    unnamed[0] = 0;
    assert!(is(&walk(&wav(&unnamed, &pcm16(42, 5000, true)))));
    assert!(!is(&walk(&wav(&unnamed, &random(43, 10_000)))));
    assert!(!is(&walk(&wav(&pcm_format(false), &random(43, 10_000)))));
    let mut mp3_in_wav = pcm_format(false);
    mp3_in_wav[0] = 0x55;
    assert!(is(&walk(&wav(&mp3_in_wav, &noise(43, 10_000)))));
    // the PAM size that wraps: a header declaring 2^73 bytes of raster, and none
    let pam = b"P7\nWIDTH 16777216\nHEIGHT 16777216\nDEPTH 16777216\nMAXVAL 65535\nTUPLTYPE X\nENDHDR\n";
    assert!(!is(&walk(pam)));
}

/// An Ogg page with its checksum.
fn ogg_page(flags: u8, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut segs = vec![255u8; body.len() / 255];
    segs.push((body.len() % 255) as u8);
    let mut p = b"OggS\x00".to_vec();
    p.push(flags);
    p.extend([0; 8]);
    p.extend(7u32.to_le_bytes());
    p.extend(seq.to_le_bytes());
    p.extend([0; 4]);
    p.push(segs.len() as u8);
    p.extend(&segs);
    p.extend(body);
    let crc = super::frames::ogg_crc(0, &p);
    p[22..26].copy_from_slice(&crc.to_le_bytes());
    p
}

#[test]
fn ogg_pages_and_their_checksums() {
    let head = [b"OpusHead".as_slice(), &noise(20, 592)].concat();
    let mut f = ogg_page(2, 0, &head);
    f.extend(ogg_page(0, 1, &noise(21, 3000)));
    f.extend(ogg_page(4, 2, &noise(22, 100)));
    assert_eq!(walk(&f), Walked::Is("Ogg".into()));
    let mut no_bos = ogg_page(0, 0, &head);
    no_bos.extend(ogg_page(4, 1, &noise(21, 600)));
    assert!(!is(&walk(&no_bos)));
}

#[test]
fn riff_aiff_and_their_sizes() {
    let chunk = |id: &[u8], body: &[u8], le: bool| {
        let mut c = id.to_vec();
        c.extend(if le { (body.len() as u32).to_le_bytes() } else { (body.len() as u32).to_be_bytes() });
        c.extend(body);
        if body.len() % 2 == 1 {
            c.push(0);
        }
        c
    };
    let mut body = b"WAVE".to_vec();
    body.extend(chunk(b"fmt ", &pcm_format(false), true));
    body.extend(chunk(b"data", &[pcm16(31, 1000, true).as_slice(), &[7]].concat(), true));
    let mut wav = b"RIFF".to_vec();
    wav.extend((body.len() as u32).to_le_bytes());
    wav.extend(&body);
    assert_eq!(walk(&wav), Walked::Is("RIFF WAVE file".into()));
    // the last pad byte left out (and the RIFF's size without it)
    let mut short = wav[..wav.len() - 1].to_vec();
    short[4..8].copy_from_slice(&((body.len() - 1) as u32).to_le_bytes());
    assert!(is(&walk(&short)), "{:?}", walk(&short));
    // a streaming writer's placeholder sizes: the data to the end
    let mut live = b"RIFF\xff\xff\xff\xffWAVE".to_vec();
    live.extend(chunk(b"fmt ", &pcm_format(false), true));
    live.extend(b"data\xff\xff\xff\xff");
    live.extend(pcm16(32, 1500, true));
    assert!(is(&walk(&live)), "{:?}", walk(&live));
    let mut noisy = live[..live.len() - 3000].to_vec();
    noisy.extend(random(32, 3000));
    assert!(!is(&walk(&noisy)));
    // a RIFF that declares fewer bytes than the file holds: what follows is outside it
    let mut over = wav.clone();
    over.extend(noise(33, 100));
    assert!(!is(&walk(&over)));
    // a header whose size is smaller than its chunks (scipy's test-44100Hz-le-1ch-4bytes.wav): its chunks to the
    // file's end, every byte in one; not when the last runs past the end
    let mut wrong = wav.clone();
    wrong[4..8].copy_from_slice(&((body.len() - 12) as u32).to_le_bytes());
    assert!(is(&walk(&wrong)), "{:?}", walk(&wrong));
    assert!(!is(&walk(&wrong[..wrong.len() - 3])));
    assert!(!is(&walk(&[wrong.as_slice(), &noise(33, 100)].concat())));
    // RF64: the sizes in ds64
    let mut rf = b"RF64\xff\xff\xff\xffWAVE".to_vec();
    let data = pcm16(34, 750, true);
    let riff_size = 4 + (8 + 28) + (8 + 16) + (8 + data.len());
    let mut ds64 = (riff_size as u64).to_le_bytes().to_vec();
    ds64.extend((data.len() as u64).to_le_bytes());
    ds64.extend([0; 12]);
    rf.extend(chunk(b"ds64", &ds64, true));
    rf.extend(chunk(b"fmt ", &pcm_format(false), true));
    rf.extend(b"data\xff\xff\xff\xff");
    rf.extend(&data);
    assert!(is(&walk(&rf)), "{:?}", walk(&rf));
    // AIFF, big-endian
    let mut body = b"AIFF".to_vec();
    body.extend(chunk(b"COMM", &noise(35, 18), false));
    body.extend(chunk(b"SSND", &[[0u8; 8].as_slice(), &pcm16(36, 600, false), &[1]].concat(), false));
    let mut aiff = b"FORM".to_vec();
    aiff.extend((body.len() as u32).to_be_bytes());
    aiff.extend(&body);
    assert_eq!(walk(&aiff), Walked::Is("AIFF audio".into()));
}

#[test]
fn rifx_and_netpbm() {
    // RIFX: RIFF big-endian (scipy's test WAVs have it)
    let mut body = b"WAVE".to_vec();
    for (id, data) in [(b"fmt ", pcm_format(true)), (b"data", pcm16(38, 750, false))] {
        body.extend(id);
        body.extend((data.len() as u32).to_be_bytes());
        body.extend(&data);
    }
    let mut rifx = b"RIFX".to_vec();
    rifx.extend((body.len() as u32).to_be_bytes());
    rifx.extend(&body);
    assert_eq!(walk(&rifx), Walked::Is("RIFX WAVE file".into()));
    let mut le = rifx.clone();
    le[4..8].copy_from_slice(&(body.len() as u32).to_le_bytes());
    assert!(!is(&walk(&le)));
    // Netpbm: comments in the header, 16-bit samples, PAM, two images one after the other
    let ppm = [b"P6\n# made here\n4 3\n65535\n".as_slice(), &signal(39, 4 * 3 * 3 * 2)].concat();
    assert_eq!(walk(&ppm), Walked::Is("Netpbm image".into()));
    let pam = [b"P7\nWIDTH 5\nHEIGHT 2\nDEPTH 4\nMAXVAL 255\nTUPLTYPE RGB_ALPHA\nENDHDR\n".as_slice(), &signal(40, 40)].concat();
    assert!(is(&walk(&pam)));
    let two = [ppm.as_slice(), &ppm].concat();
    assert!(is(&walk(&two)));
    assert!(!is(&walk(&ppm[..ppm.len() - 1])));
    assert!(!is(&walk(&[ppm.as_slice(), b"x"].concat())));
    for size in [1, 7] {
        assert_eq!(chunked(&two, size, false), walk(&two));
    }
}

#[test]
fn iso_media_boxes() {
    let bx = |kind: &[u8], body: &[u8]| {
        let mut b = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        b.extend(kind);
        b.extend(body);
        b
    };
    let mut mp4 = bx(b"ftyp", b"isom\x00\x00\x02\x00isomiso2mp41");
    mp4.extend(bx(b"mdat", &noise(40, 3000)));
    mp4.extend(bx(b"moov", &noise(41, 300)));
    assert!(is(&walk(&mp4)));
    // a last box of size 0 runs to the end; a 64-bit size
    let mut open = bx(b"ftyp", b"isom\x00\x00\x02\x00isom");
    open.extend(b"\x00\x00\x00\x00mdat");
    open.extend(noise(42, 3000));
    assert!(is(&walk(&open)));
    let mut large = bx(b"ftyp", b"isom\x00\x00\x02\x00isom");
    large.extend(b"\x00\x00\x00\x01mdat");
    large.extend(((16 + 2000) as u64).to_be_bytes());
    large.extend(noise(43, 2000));
    assert!(is(&walk(&large)));
    // a box whose name is not one, a size past the end
    let mut bad = bx(b"ftyp", b"isom\x00\x00\x02\x00isom");
    bad.extend(b"\x00\x00\x00\x10\x01\x02\x03\x04");
    bad.extend(noise(44, 8));
    assert!(!is(&walk(&bad)));
    let mut long = bx(b"ftyp", b"isom\x00\x00\x02\x00isom");
    long.extend(bx(b"mdat", &noise(45, 100))[..50].to_vec());
    assert!(!is(&walk(&long)));
}

#[test]
fn matroska_of_unknown_sizes() {
    // a live recording's: the segment and its clusters of unknown size
    let mut f = vec![0x1a, 0x45, 0xdf, 0xa3, 0x8b, 0x42, 0x82, 0x84];
    f.extend(b"webm");
    f.extend([0x42, 0x87, 0x81, 0x02]);
    f.extend([0x18, 0x53, 0x80, 0x67, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    f.extend([0x15, 0x49, 0xa9, 0x66, 0x84]);
    f.extend(noise(50, 4));
    for k in 0..3 {
        f.extend([0x1f, 0x43, 0xb6, 0x75, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        f.extend([0xe7, 0x81, k]);
        f.extend([0xa3, 0x42, 0x00]);                  // (a SimpleBlock of 512 bytes)
        f.extend(noise(51 + k as u64, 512));
    }
    assert_eq!(walk(&f), Walked::Is("WebM".into()));
    for size in [5, 100] {
        assert_eq!(chunked(&f, size, false), walk(&f));
    }
    // an element a cluster does not hold
    let mut bad = f.clone();
    bad.extend([0x86, 0x81, 0x00]);
    assert!(!is(&walk(&bad)));
}

#[test]
fn jpeg_images_one_after_another_and_a_motion_photo() {
    let jpg = FIXTURES.iter().find(|(n, _)| *n == "noise.jpg").unwrap().1;
    let mp4 = FIXTURES.iter().find(|(n, _)| *n == "noise.mp4").unwrap().1;
    let mut two = jpg.to_vec();
    two.extend(jpg);
    assert!(is(&walk(&two)));
    let mut motion = jpg.to_vec();
    motion.extend(mp4);
    assert_eq!(walk(&motion), Walked::Is("JPEG image with ISO media after it".into()));
    // a scan's data with a byte 0xff not stuffed
    let mut bad = jpg.to_vec();
    let sos = jpg.windows(2).position(|w| w == [0xff, 0xda]).unwrap();
    bad[sos + 20] = 0xff;
    bad[sos + 21] = 0x55;
    assert!(!is(&walk(&bad)));
    // a multi-picture file's images with padding between them (Fujifilm's MPO), and only then
    let mpo = [jpg, b"\x00\x00", jpg, b"\xff\x00"].concat();
    assert!(is(&walk(&mpo)));
    for size in [1, 2, 3, 5] {
        assert_eq!(chunked(&mpo, size, false), walk(&mpo));
    }
    assert!(!is(&walk(&[jpg, b"\x00\xff\xd8\x00", jpg].concat())));
    assert!(!is(&walk(&[jpg, b"\x00", &noise(43, 300)].concat())));
}

#[test]
fn tga_images() {
    // Pillow's raw and run-length files are among the fixtures; here: a version 1 file (no footer), a colour-mapped
    // one, a version 2 footer naming an extension area and a developer area, and what is not one
    let mut v1 = vec![0u8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 4, 0, 24, 0];
    v1.extend(signal(44, 8 * 4 * 3));
    assert_eq!(walk(&v1), Walked::Is("TGA image".into()));
    let mut mapped = vec![3u8, 1, 1, 0, 0, 16, 0, 24, 0, 0, 0, 0, 8, 0, 4, 0, 8, 0];
    mapped.extend(b"abc");
    mapped.extend(noise(45, 16 * 3 + 32));
    assert!(is(&walk(&mapped)));
    let mut v2 = v1.clone();
    let ext = v2.len() as u32;
    let mut area = vec![0u8; 495];
    area[..2].copy_from_slice(&495u16.to_le_bytes());
    area[2..10].copy_from_slice(b"Lazaret ");
    v2.extend(&area);
    let dev = v2.len() as u32;
    v2.extend(1u16.to_le_bytes());
    v2.extend(1000u16.to_le_bytes());
    v2.extend((dev + 12).to_le_bytes());
    v2.extend(5u32.to_le_bytes());
    v2.extend(b"hello");
    v2.extend(ext.to_le_bytes());
    v2.extend(dev.to_le_bytes());
    v2.extend(b"TRUEVISION-XFILE.\x00");
    assert!(is(&walk(&v2)));
    assert!(!is(&walk(&[v1.as_slice(), &noise(46, 100)].concat())));
    assert!(!is(&walk(&v1[..v1.len() - 1])));
    // random pixels are no picture's
    let mut big = vec![0u8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 64, 0, 24, 0];
    big.extend(random(48, 64 * 64 * 3));
    assert!(matches!(walk(&big), Walked::Not(_, why) if why.contains("near-random")));
    // a run-length packet past the last pixel
    let mut rle = vec![0u8, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 24, 0];
    rle.extend([0x84, 1, 2, 3]);
    assert!(!is(&walk(&rle)));
    rle[18] = 0x83;
    assert!(is(&walk(&rle)));
    // a header that is not one: a colour map's fields on a true-colour image, an alpha deeper than its pixels
    let mut odd = v1.clone();
    odd[1] = 2;
    assert_eq!(walk(&odd), Walked::Unknown);
    let mut odd = v1.clone();
    odd[2] = 3;
    odd[16] = 8;
    odd[17] = 0x0f;
    assert_eq!(walk(&odd), Walked::Unknown);
}

#[test]
fn icons_with_zero_slack_and_bitmaps_of_png() {
    // an icon's bitmap whose entry the directory makes larger: zero bytes (Pillow's pillow.ico), not others
    let (w, h) = (16u32, 16u32);
    let mut dib = Vec::new();
    for v in [40u32, w, 2 * h] {
        dib.extend(v.to_le_bytes());
    }
    dib.extend(1u16.to_le_bytes());
    dib.extend(32u16.to_le_bytes());
    dib.extend([0u8; 24]);
    dib.extend(noise(47, (w * h * 4) as usize));
    dib.extend([0u8; 64]);                         // the mask: 4 bytes a row
    let ico = |image: &[u8]| {
        let mut b = vec![0u8, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0];
        b.extend((image.len() as u32).to_le_bytes());
        b.extend(22u32.to_le_bytes());
        b.extend(image);
        b
    };
    assert!(is(&walk(&ico(&dib))));
    assert!(is(&walk(&ico(&[dib.as_slice(), &[0u8; 64]].concat()))));
    assert!(!is(&walk(&ico(&[dib.as_slice(), &[0u8; 63], b"x"].concat()))));
    // a BMP whose pixels are a PNG (BI_PNG) or a JPEG (BI_JPEG): no bit count, the image's size in the header
    let png = FIXTURES.iter().find(|(n, _)| *n == "noise.png").unwrap().1;
    let bmp = |comp: u32, image: &[u8]| {
        let mut b = b"BM".to_vec();
        b.extend((54 + image.len() as u32).to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.extend(54u32.to_le_bytes());
        for v in [40u32, 48, 48] {
            b.extend(v.to_le_bytes());
        }
        b.extend(1u16.to_le_bytes());
        b.extend(0u16.to_le_bytes());
        b.extend(comp.to_le_bytes());
        b.extend((image.len() as u32).to_le_bytes());
        b.extend([0u8; 16]);
        b.extend(image);
        b
    };
    assert!(is(&walk(&bmp(5, png))));
    assert!(!is(&walk(&bmp(0, png))));
    assert!(!is(&walk(&[bmp(5, png).as_slice(), b"x"].concat())));
}

#[test]
fn a_directorys_parts_and_the_gaps_between_them() {
    // a TrueType font: a table directory, two tables, a gap of padding, and a gap that is not
    // (the tables every font has, the first of them 101 bytes and then 3 bytes of padding, the rest one after another)
    let tags: [&[u8; 4]; 7] = [b"glyf", b"cmap", b"head", b"hhea", b"hmtx", b"maxp", b"name"];
    let mut f = b"\x00\x01\x00\x00\x00\x07\x00\x40\x00\x02\x00\x30".to_vec();
    let start = 12 + 16 * tags.len();
    let t1 = noise(60, 101);
    let t2 = noise(61, 500);
    let mut off = start;
    for (k, tag) in tags.iter().enumerate() {
        let len = if k == 0 { t1.len() } else { t2.len() / 6 };
        f.extend(*tag);
        f.extend([0; 4]);
        f.extend((off as u32).to_be_bytes());
        f.extend((len as u32).to_be_bytes());
        off += if k == 0 { 104 } else { len };
    }
    f.extend(&t1);
    f.extend([0, 0, 0]);
    f.extend(&t2[..t2.len() / 6 * 6]);
    assert_eq!(walk(&f), Walked::Is("TrueType font".into()));
    for (size, seek) in [(1, false), (13, true), (100, false)] {
        assert_eq!(chunked(&f, size, seek), walk(&f));
    }
    let mut gap = f.clone();
    gap[start + 102] = 9;
    assert!(!is(&walk(&gap)));
    let mut cut = f.clone();
    cut.truncate(f.len() - 1);
    assert!(!is(&walk(&cut)));
    // a font without the tables every font has: a glyph table alone
    let mut one = b"\x00\x01\x00\x00\x00\x01\x00\x10\x00\x00\x00\x00glyf\x00\x00\x00\x00".to_vec();
    one.extend(28u32.to_be_bytes());
    one.extend(1000u32.to_be_bytes());
    one.extend(noise(62, 1000));
    assert!(matches!(walk(&one), Walked::Not(_, why) if why.contains("which every font has")));
    // an unregistered table: free-form
    let mut private = f.clone();
    private[12..16].copy_from_slice(b"zzzz");
    assert!(is(&walk(&private)), "{:?}", walk(&private));
    let mut big = f.clone();
    big[12..16].copy_from_slice(b"zzzz");
    let grow = 80_000u32;
    big[24..28].copy_from_slice(&(101 + grow).to_be_bytes());
    for k in 1..tags.len() {
        let at = 12 + 16 * k + 8;
        let o = u32::from_be_bytes(big[at..at + 4].try_into().unwrap()) + grow;
        big[at..at + 4].copy_from_slice(&o.to_be_bytes());
    }
    big.splice(start + 101..start + 101, noise(63, grow as usize));
    assert!(matches!(walk(&big), Walked::Not(_, why) if why.contains("unregistered font tables")), "{:?}", walk(&big));
}

#[test]
fn a_tiffs_tags_once_and_its_walk_bounded() {
    // a directory naming a tag twice; one repeating StripOffsets over one region (the review's DoS: each entry's
    // values were read again): no longer walked, and fast
    let entry = |tag: u16, kind: u16, count: u32, value: u32| {
        [&tag.to_le_bytes()[..], &kind.to_le_bytes(), &count.to_le_bytes(), &value.to_le_bytes()].concat()
    };
    let mut twice = b"II*\x00\x08\x00\x00\x00\x02\x00".to_vec();
    twice.extend(entry(256, 3, 1, 8));
    twice.extend(entry(256, 3, 1, 8));
    twice.extend(0u32.to_le_bytes());
    assert!(matches!(walk(&twice), Walked::Not(_, why) if why.contains("twice")));
    let n = 4000u32;
    let mut dos = b"II*\x00\x08\x00\x00\x00".to_vec();
    dos.extend((n as u16).to_le_bytes());
    let values = 8 + 2 + 12 * n + 4;
    for _ in 0..n {
        dos.extend(entry(273, 4, 1 << 20, values));
    }
    dos.extend(0u32.to_le_bytes());
    dos.extend(vec![0u8; 4 << 20]);
    let t = std::time::Instant::now();
    assert!(!is(&walk(&dos)));
    assert!(t.elapsed().as_secs_f64() < 5.0, "{:?}", t.elapsed());
}

#[test]
fn tiff_its_directories_wherever_they_are() {
    let tif = FIXTURES.iter().find(|(n, _)| *n == "noise-raw.tif").unwrap().1;
    assert!(is(&walk(tif)));
    // a byte in no strip, no directory and no value
    let mut more = tif.to_vec();
    more.extend([0, 0, 0, 5, 0, 0]);
    assert!(!is(&walk(&more)));
    // a directory that points at itself
    let mut lp = b"II*\x00\x08\x00\x00\x00\x01\x00".to_vec();
    lp.extend([0x00, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00]);
    lp.extend(8u32.to_le_bytes());
    assert!(!is(&walk(&lp)));
}

#[test]
fn an_im_tools_image_is_its_header_and_its_pixels() {
    let img = FIXTURES.iter().find(|(n, _)| *n == "gradient.imt").unwrap().1;
    assert_eq!(walk(img), Walked::Is("IM Tools image".into()));
    let mut more = img.to_vec();
    more.push(1);
    assert!(!is(&walk(&more)));
    assert!(!is(&walk(&img[..img.len() - 1])));
    // no `pixel n8`: Pillow reads no image from it
    let other = [b"width 4\nheight 4\npixel n1\n\x0c".as_slice(), &[7u8; 16]].concat();
    assert!(!is(&walk(&other)));
}

// ---- keystores -------------------------------------------------------------------------------------------------------

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = body.len();
    if n < 0x80 {
        v.push(n as u8);
    } else if n < 0x100 {
        v.extend([0x81, n as u8]);
    } else if n < 0x1_0000 {
        v.extend([0x82, (n >> 8) as u8, n as u8]);
    } else {
        v.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    v.extend(body);
    v
}

fn oid(bytes: &[u8]) -> Vec<u8> {
    der(0x06, bytes)
}

const DATA: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01";
const SIGNED: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02";
const ENCRYPTED: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x06";
const PBE: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x01\x03";
const RSA: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
const X509: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x16\x01";

fn bag(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut id = b"\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01".to_vec();
    id.push(kind);
    der(0x30, &[oid(&id), der(0xa0, body)].concat())
}

/// A DER Certificate's shape, its signature random bytes.
fn cert(seed: u64) -> Vec<u8> {
    let alg = der(0x30, &[oid(RSA), der(0x05, b"")].concat());
    let name = der(0x30, &der(0x31, &der(0x30, &[oid(b"\x55\x04\x03"), der(0x0c, b"Lazaret")].concat())));
    let spki = der(0x30, &[alg.clone(), der(0x03, &[&[0u8][..], &noise(seed, 140)].concat())].concat());
    let tbs = der(0x30, &[der(0xa0, &der(0x02, &[2])), der(0x02, &noise(seed + 1, 8)), alg.clone(), name.clone(),
                          der(0x30, &[der(0x17, b"261021000000Z"), der(0x17, b"361021000000Z")].concat()), name,
                          spki].concat());
    der(0x30, &[tbs, alg, der(0x03, &[&[0u8][..], &noise(seed + 2, 128)].concat())].concat())
}

/// An EncryptedPrivateKeyInfo of `n` random bytes.
fn epki(seed: u64, n: usize) -> Vec<u8> {
    let alg = der(0x30, &[oid(PBE), der(0x30, &[der(0x04, &noise(seed, 20)), der(0x02, &[8, 0])].concat())].concat());
    der(0x30, &[alg, der(0x04, &noise(seed + 1, n))].concat())
}

/// A PKCS#7 EncryptedData of `n` random bytes.
fn encrypted_data(seed: u64, n: usize) -> Vec<u8> {
    let alg = der(0x30, &[oid(PBE), der(0x30, &[der(0x04, &noise(seed, 8)), der(0x02, &[8, 0])].concat())].concat());
    der(0x30, &[der(0x02, &[0]), der(0x30, &[oid(DATA), alg, der(0x80, &noise(seed + 1, n))].concat())].concat())
}

/// A PFX as keytool and OpenSSL lay one out: the key in a shrouded key bag of an unencrypted part, the certificates
/// in an encrypted one, a MAC.
fn pfx(key: bool, encrypted: bool, certs_clear: bool) -> Vec<u8> {
    pfx_sized(key, encrypted, certs_clear, 400)
}

fn pfx_sized(key: bool, encrypted: bool, certs_clear: bool, sealed: usize) -> Vec<u8> {
    let mut infos = Vec::new();
    if key {
        let safe = der(0x30, &bag(2, &epki(70, 300)));
        infos.extend(der(0x30, &[oid(DATA), der(0xa0, &der(0x04, &safe))].concat()));
    }
    if certs_clear {
        let safe = der(0x30, &bag(3, &der(0x30, &[oid(X509), der(0xa0, &der(0x04, &cert(71)))].concat())));
        infos.extend(der(0x30, &[oid(DATA), der(0xa0, &der(0x04, &safe))].concat()));
    }
    if encrypted {
        infos.extend(der(0x30, &[oid(ENCRYPTED), der(0xa0, &encrypted_data(72, sealed))].concat()));
    }
    let auth = der(0x30, &infos);
    let ci = der(0x30, &[oid(DATA), der(0xa0, &der(0x04, &auth))].concat());
    let mac = der(0x30, &noise(73, 60));
    der(0x30, &[der(0x02, &[3]), ci, mac].concat())
}

fn jks(magic: &[u8], entries: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut f = magic.to_vec();
    f.extend(2u32.to_be_bytes());
    f.extend((entries.len() as u32).to_be_bytes());
    for (tag, body) in entries {
        f.extend(tag.to_be_bytes());
        f.extend(b"\x00\x05alias");
        f.extend([0; 8]);
        f.extend(body);
    }
    f.extend(noise(80, 20));
    f
}

fn cert_v2() -> Vec<u8> {
    let c = cert(81);
    [b"\x00\x05X.509".as_slice(), &(c.len() as u32).to_be_bytes(), &c].concat()
}

/// A JKS key entry: the protected key (an EncryptedPrivateKeyInfo of `n` bytes) and a chain of one certificate.
fn jks_key(n: usize) -> Vec<u8> {
    let key = epki(93, n);
    [&(key.len() as u32).to_be_bytes()[..], &key, &1u32.to_be_bytes(), &cert_v2()].concat()
}

/// A SealedObject as JCEKS writes a secret key: SealedObjectForKeyProtector, a subclass of javax.crypto.SealedObject
/// with its byte arrays and strings.
fn sealed_object() -> Vec<u8> {
    let utf = |s: &str| [&(s.len() as u16).to_be_bytes()[..], s.as_bytes()].concat();
    let mut o = b"\xac\xed\x00\x05\x73\x72".to_vec();
    o.extend(utf("com.sun.crypto.provider.SealedObjectForKeyProtector"));
    o.extend(noise(82, 8));
    o.extend([0x02, 0x00, 0x00, 0x78]);                 // (serializable, no fields, no annotation)
    o.push(0x72);
    o.extend(utf("javax.crypto.SealedObject"));
    o.extend(noise(83, 8));
    o.extend([0x02, 0x00, 0x04]);
    o.extend([b'[']);
    o.extend(utf("encodedParams"));
    o.push(0x74);
    o.extend(utf("[B"));
    o.extend([b'[']);
    o.extend(utf("encryptedContent"));
    o.extend([0x71, 0x00, 0x7e, 0x00, 0x02]);          // (a reference to the string "[B")
    o.extend([b'L']);
    o.extend(utf("paramsAlg"));
    o.push(0x74);
    o.extend(utf("Ljava/lang/String;"));
    o.extend([b'L']);
    o.extend(utf("sealAlg"));
    o.extend([0x71, 0x00, 0x7e, 0x00, 0x03]);
    o.extend([0x78, 0x70]);                            // (no annotation; no superclass)
    for n in [20usize, 32] {
        o.extend([0x75, 0x72]);
        o.extend(utf("[B"));
        o.extend(noise(84, 8));
        o.extend([0x02, 0x00, 0x00, 0x78, 0x70]);
        o.extend((n as u32).to_be_bytes());
        o.extend(noise(85 + n as u64, n));
    }
    o.push(0x74);
    o.extend(utf("PBEWithMD5AndTripleDES"));
    o.extend([0x71, 0x00, 0x7e, 0x00, 0x08]);
    o
}

fn bks(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut f = 2u32.to_be_bytes().to_vec();
    f.extend(20u32.to_be_bytes());
    f.extend(noise(90, 20));
    f.extend(1024u32.to_be_bytes());
    for (kind, body) in entries {
        f.push(*kind);
        f.extend(b"\x00\x03key");
        f.extend([0; 8]);
        f.extend(0u32.to_be_bytes());
        f.extend(body);
    }
    f.push(0);
    f.extend(noise(91, 20));
    f
}

#[test]
fn keystores_read_to_their_end() {
    let read = |b: &[u8]| keystore::read(b);
    assert!(keystore::sniff(&pfx(true, true, false)));
    let k = read(&pfx(true, true, false)).unwrap();
    assert_eq!((k.kind, k.keys, k.sealed), ("PKCS#12 keystore", 1, 1));
    let t = read(&pfx(false, true, false)).unwrap();
    assert_eq!((t.keys, t.sealed), (0, 1));
    let c = read(&pfx(false, false, true)).unwrap();
    assert_eq!((c.keys, c.certs, c.sealed), (0, 1, 0));
    let j = read(&jks(b"\xfe\xed\xfe\xed", &[(1, jks_key(300)), (2, cert_v2())])).unwrap();
    assert_eq!((j.kind, j.keys, j.certs), ("JKS keystore", 1, 1));
    let s = read(&jks(b"\xce\xce\xce\xce", &[(3, sealed_object()), (2, cert_v2())])).unwrap();
    assert_eq!((s.kind, s.secrets, s.certs), ("JCEKS keystore", 1, 1));
    let x509 = cert(94);
    let bks_cert = [b"\x00\x05X.509".as_slice(), &(x509.len() as u32).to_be_bytes(), &x509].concat();
    let pkcs8 = der(0x30, &[der(0x02, &[0]), der(0x30, &[oid(RSA), der(0x05, b"")].concat()),
                            der(0x04, &noise(95, 600))].concat());
    let mut keyentry = vec![0u8];
    keyentry.extend(b"\x00\x06PKCS#8\x00\x03RSA");
    keyentry.extend((pkcs8.len() as u32).to_be_bytes());
    keyentry.extend(&pkcs8);
    let b = read(&bks(&[(1, bks_cert.clone()), (2, keyentry)])).unwrap();
    assert_eq!((b.kind, b.keys, b.certs), ("BKS keystore", 1, 1));
    // anything after them, or less, is no keystore
    for f in [pfx(true, true, false), jks(b"\xfe\xed\xfe\xed", &[(2, cert_v2())]),
              jks(b"\xce\xce\xce\xce", &[(3, sealed_object())]), bks(&[(1, bks_cert)])] {
        assert!(read(&f).is_ok());
        assert!(read(&[f.as_slice(), b"x"].concat()).is_err());
        assert!(read(&f[..f.len() - 1]).is_err());
        let mut glued = f[..40].to_vec();
        glued.extend(noise(96, 2000));
        assert!(read(&glued).is_err());
    }
    assert_eq!(read(&noise(97, 100)), Err("it is no keystore".into()));
    assert_eq!(Keystore::default().keys, 0);
}

#[test]
fn a_keystores_parts_have_their_shapes_and_sizes() {
    let read = |b: &[u8]| keystore::read(b);
    // a certificate entry, a key's certificate or a certificate bag that is random bytes is no keystore's
    let blob = noise(100, 16_000);
    let random_cert = [b"\x00\x05X.509".as_slice(), &(blob.len() as u32).to_be_bytes(), &blob].concat();
    assert!(read(&jks(b"\xfe\xed\xfe\xed", &[(2, random_cert.clone())])).is_err());
    let key = epki(101, 300);
    let entry = [&(key.len() as u32).to_be_bytes()[..], &key, &1u32.to_be_bytes(), &random_cert].concat();
    assert!(read(&jks(b"\xfe\xed\xfe\xed", &[(1, entry)])).is_err());
    // a protected key that is random bytes, not an EncryptedPrivateKeyInfo
    let entry = [&16_000u32.to_be_bytes()[..], &blob, &0u32.to_be_bytes()].concat();
    assert!(read(&jks(b"\xfe\xed\xfe\xed", &[(1, entry)])).is_err());
    let safe = der(0x30, &bag(3, &der(0x30, &[oid(X509), der(0xa0, &der(0x04, &blob))].concat())));
    let ci = der(0x30, &[oid(DATA), der(0xa0, &der(0x04, &der(0x30, &der(0x30, &[oid(DATA),
                 der(0xa0, &der(0x04, &safe))].concat()))))].concat());
    assert!(read(&der(0x30, &[der(0x02, &[3]), ci].concat())).is_err());
    // the bytes no structure reads, counted: a real keystore's are a few kilobytes; a 20 KB encrypted key or part
    let k = read(&jks(b"\xfe\xed\xfe\xed", &[(1, jks_key(20_000))])).unwrap();
    assert!(k.largest > 16_384, "{k:?}");
    let k = read(&jks(b"\xfe\xed\xfe\xed", &[(1, jks_key(1200))])).unwrap();
    assert!(k.largest <= 16_384 && k.opaque < 2000, "{k:?}");
    let p = read(&pfx_sized(true, true, false, 20_000)).unwrap();
    assert!(p.largest > 16_384, "{p:?}");
    // a signed PKCS#12 (public-key integrity mode): its content read as an unsigned one's, its signature counted
    let safe = der(0x30, &bag(2, &epki(102, 300)));
    let auth = der(0x30, &der(0x30, &[oid(DATA), der(0xa0, &der(0x04, &safe))].concat()));
    let signer = der(0x30, &[der(0x02, &[1]), der(0x30, &noise(103, 20)), der(0x30, &oid(RSA)),
                             der(0x30, &oid(RSA)), der(0x04, &noise(104, 256))].concat());
    let signed = der(0x30, &[der(0x02, &[1]), der(0x31, &der(0x30, &oid(RSA))),
                             der(0x30, &[oid(DATA), der(0xa0, &der(0x04, &auth))].concat()),
                             der(0xa0, &cert(105)), der(0x31, &signer)].concat());
    let pfx = der(0x30, &[der(0x02, &[3]), der(0x30, &[oid(SIGNED), der(0xa0, &signed)].concat())].concat());
    let k = read(&pfx).unwrap();
    assert_eq!((k.keys, k.certs, k.largest), (1, 1, 300), "{k:?}");
    // a signed shell around random bytes is not one
    let shell = der(0x30, &[der(0x02, &[3]), der(0x30, &[oid(SIGNED), der(0xa0, &der(0x30, &noise(106, 16_000)))].concat())].concat());
    assert!(read(&shell).is_err());
}

// ---- the re-review of Oct 27 (N1, N2, N4, N5) ------------------------------------------------------------------------

/// A font collection of `fonts` fonts, each a directory of `tables` tables (the tables every font has, then tags of
/// its own: distinct, or one tag over and over), each table 1 byte with a zero byte after it.
fn collection(fonts: usize, tables: usize, distinct: bool) -> Vec<u8> {
    const REQUIRED: [&[u8; 4]; 6] = [b"head", b"cmap", b"hhea", b"hmtx", b"maxp", b"name"];
    let head = 12 + 4 * fonts;
    let dir = 12 + 16 * tables;
    let mut at = head + fonts * dir;
    let mut f = b"ttcf\x00\x01\x00\x00".to_vec();
    f.extend((fonts as u32).to_be_bytes());
    for k in 0..fonts {
        f.extend(((head + k * dir) as u32).to_be_bytes());
    }
    let mut body = Vec::new();
    for k in 0..fonts {
        f.extend(b"\x00\x01\x00\x00");
        f.extend((tables as u16).to_be_bytes());
        f.extend([0u8; 6]);
        for t in 0..tables {
            let tag: [u8; 4] = match REQUIRED.get(t) {
                Some(r) => **r,
                None if distinct => {
                    let n = k * tables + t;
                    [b'Z', b'a' + (n / 676 % 26) as u8, b'a' + (n / 26 % 26) as u8, b'a' + (n % 26) as u8]
                }
                None => *b"glyf",
            };
            f.extend(tag);
            f.extend([0u8; 4]);
            f.extend((at as u32).to_be_bytes());
            f.extend(1u32.to_be_bytes());
            body.extend([0x41, 0]);
            at += 2;
        }
    }
    f.extend(body);
    f
}

#[test]
fn a_collections_walk_passes_each_table_once_and_holds_a_bounded_number() {
    // (N1) 15 fonts of 4,096 tables, 61,456 parts: walked whole and in chunks in linear time (the walk dropped the
    // first of its parts, moving every other: 1.6 s for 65,536 parts, minutes for a 16 MB file)
    let f = collection(15, 4096, true);
    // (whole, and in the hosts' chunks: each walk was about 1.4 s when quadratic, is a few hundredths now)
    let t = std::time::Instant::now();
    let whole = walk(&f);
    let streamed = chunked(&f, 1 << 20, true);
    assert!(t.elapsed().as_secs_f64() < 1.5, "{:?}", t.elapsed());
    assert!(is(&whole), "{whole:?}");
    assert_eq!(streamed, whole);
    assert_eq!(chunked(&f, 4096, false), whole);
    // more parts than MAX_CLAIMS: not walked, and fast
    let more = collection(17, 4096, true);
    let t = std::time::Instant::now();
    let got = walk(&more);
    assert!(matches!(&got, Walked::Not(_, why) if why.contains("more than a real file's")), "{got:?}");
    assert!(matches!(chunked(&more, 1 << 20, true), Walked::Not(..)));
    assert!(t.elapsed().as_secs_f64() < 1.0, "{:?}", t.elapsed());
    // a directory naming a table twice (the re-review's file: one tag 4,090 times) is no font's
    let twice = collection(4, 4096, false);
    assert!(matches!(walk(&twice), Walked::Not(_, why) if why.contains("names table 'glyf' twice")), "{:?}", walk(&twice));
    let mut ttf = FIXTURES.iter().find(|(n, _)| *n == "noise.ttf").unwrap().1.to_vec();
    assert!(is(&walk(&ttf)));
    let first = ttf[12..16].to_vec();
    ttf[28..32].copy_from_slice(&first);
    assert!(matches!(walk(&ttf), Walked::Not(_, why) if why.contains("twice")), "{:?}", walk(&ttf));
}

/// A WOFF2 collection: a directory of the tables every font has (by WOFF2's own indices), each font's directory
/// naming them by their place in it (`fonts`), and 64 random bytes as its one compressed block.
fn woff2_collection(fonts: &[&[u8]]) -> Vec<u8> {
    let mut dir = Vec::new();
    for idx in 0u8..6 {
        dir.extend([idx, 0x10]);                        // (flags: a known tag, not transformed; 16 bytes)
    }
    dir.extend(0x0001_0000u32.to_be_bytes());
    dir.push(fonts.len() as u8);
    for font in fonts {
        dir.push(font.len() as u8);
        dir.extend(b"\x00\x01\x00\x00");
        dir.extend(*font);
    }
    let block = noise(160, 64);
    let length = 48 + dir.len() + block.len();
    let mut f = b"wOF2ttcf".to_vec();
    f.extend((length as u32).to_be_bytes());
    f.extend(6u16.to_be_bytes());
    f.extend([0u8; 6]);
    f.extend((block.len() as u32).to_be_bytes());
    f.extend([0u8; 24]);
    f.extend(dir);
    f.extend(block);
    f
}

#[test]
fn a_woff2_collections_fonts_name_their_tables_once() {
    // (N1) each font's own directory, as a font's or a collection's: tables the collection has, each once
    assert!(is(&walk(&woff2_collection(&[&[0, 1, 2, 3, 4, 5], &[5, 4, 3, 2, 1, 0]]))));
    let got = walk(&woff2_collection(&[&[0, 1, 2, 3, 4, 5], &[0, 1, 2, 3, 4, 5, 5]]));
    assert!(matches!(&got, Walked::Not(_, why) if why.contains("names table 'name' twice")), "{got:?}");
    let got = walk(&woff2_collection(&[&[0, 1, 2, 3, 4, 9]]));
    assert!(matches!(&got, Walked::Not(_, why) if why.contains("a table it does not have")), "{got:?}");
}

#[test]
fn a_declared_size_is_checked_at_the_end_however_the_bytes_come() {
    // (N5) noise.woff2 cut by one byte: whole, in chunks ending with the file, and in chunks followed by an empty one
    // that ends it (the registry's member stream), the host passing over what the walk skips or not
    let woff2 = FIXTURES.iter().find(|(n, _)| *n == "noise.woff2").unwrap().1;
    let fed_then_end = |data: &[u8], size: usize| {
        let mut w = Walker::new();
        for (k, piece) in data.chunks(size).enumerate() {
            feed(&mut w, (k * size) as u64, piece, false);
        }
        feed(&mut w, data.len() as u64, b"", true);
        w.walked().unwrap()
    };
    for cut in 1..=8 {
        let d = &woff2[..woff2.len() - cut];
        let whole = walk(d);
        assert!(!is(&whole), "cut by {cut}: {whole:?}");
        for size in [5, 64, 100, 836, 838, 1000, 4096] {
            for seek in [false, true] {
                assert_eq!(is(&chunked(d, size, seek)), false, "cut by {cut}, chunks of {size}, seek {seek}");
            }
            assert_eq!(is(&fed_then_end(d, size)), false, "cut by {cut}, chunks of {size}, then the end");
        }
    }
    // zero bytes short of the size a WOFF2 declares: cut short; to it and past it: padding
    let declared = u32::from_be_bytes(woff2[8..12].try_into().unwrap()) as usize;
    let mut longer = woff2.to_vec();
    longer[8..12].copy_from_slice(&((declared + 8) as u32).to_be_bytes());
    for (zeros, want) in [(4, false), (8, true), (20, true)] {
        let f = [longer.as_slice(), &vec![0u8; zeros]].concat();
        assert_eq!(is(&walk(&f)), want, "{zeros} zero bytes: {:?}", walk(&f));
        for size in [3, 64, 1000] {
            assert_eq!(is(&fed_then_end(&f, size)), want, "{zeros} zero bytes, chunks of {size}");
            assert_eq!(is(&chunked(&f, size, true)), want, "{zeros} zero bytes, chunks of {size}");
        }
    }
}

/// A PNG of `idat` bytes of image data and a private chunk of `private` bytes.
fn png_with(seed: u64, idat: usize, private: usize) -> Vec<u8> {
    let chunk = |name: &[u8], body: &[u8]| {
        let mut c = (body.len() as u32).to_be_bytes().to_vec();
        c.extend(name);
        c.extend(body);
        c.extend(lazaret_verify::inflate::crc32(lazaret_verify::inflate::crc32(0, name), body).to_be_bytes());
        c
    };
    let ihdr = [&64u32.to_be_bytes()[..], &64u32.to_be_bytes(), &[8, 2, 0, 0, 0]].concat();
    [b"\x89PNG\r\n\x1a\n".as_slice(), &chunk(b"IHDR", &ihdr), &chunk(b"IDAT", &noise(seed, idat)),
     &chunk(b"prVW", &noise(seed + 1, private)), &chunk(b"IEND", b"")].concat()
}

#[test]
fn free_form_parts_of_a_part_walked_and_of_a_tga_and_an_icc_profile_count() {
    // (N4) an icon's PNG images: each within its own bounds, three of them past the icon's 64 KiB
    let one = png_with(130, 120_000, 30_000);
    assert!(is(&walk(&one)));
    let icon = |images: &[Vec<u8>]| {
        let mut b = vec![0u8, 0, 1, 0];
        b.extend((images.len() as u16).to_le_bytes());
        let mut off = 6 + 16 * images.len();
        for im in images {
            b.extend([0u8, 0, 0, 0, 1, 0, 32, 0]);
            b.extend((im.len() as u32).to_le_bytes());
            b.extend((off as u32).to_le_bytes());
            off += im.len();
        }
        for im in images {
            b.extend(im);
        }
        b
    };
    assert!(is(&walk(&icon(&[one.clone()]))));
    let three = icon(&[one, png_with(131, 120_000, 30_000), png_with(132, 120_000, 30_000)]);
    let got = walk(&three);
    assert!(matches!(&got, Walked::Not(_, why) if why.contains("PNG text, private and unregistered chunks hold 90000")), "{got:?}");
    // a TGA's developer area: what an application keeps there
    let tga = |field: usize| {
        let mut v = vec![0u8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 64, 0, 24, 0];
        v.extend(signal(133, 64 * 64 * 3));
        let dev = v.len() as u32;
        v.extend(1u16.to_le_bytes());
        v.extend(1000u16.to_le_bytes());
        v.extend((dev + 12).to_le_bytes());
        v.extend((field as u32).to_le_bytes());
        v.extend(noise(134, field));
        v.extend(0u32.to_le_bytes());
        v.extend(dev.to_le_bytes());
        v.extend(b"TRUEVISION-XFILE.\x00");
        v
    };
    assert!(is(&walk(&tga(100))));
    assert!(matches!(walk(&tga(70_000)), Walked::Not(_, why) if why.contains("TGA developer area fields")), "{:?}", walk(&tga(70_000)));
    assert!(matches!(walk(&tga(5_000)), Walked::Not(_, why) if why.contains("a quarter of the file")));
    // an ICC profile's tags of no registered signature: what an application keeps there
    let icc = |tag: &[u8; 4], n: usize| {
        let mut icc = vec![0u8; 128];
        icc[8] = 4;
        icc[36..40].copy_from_slice(b"acsp");
        icc.extend(2u32.to_be_bytes());
        icc.extend(b"A2B0");
        icc.extend(156u32.to_be_bytes());
        icc.extend(20_000u32.to_be_bytes());
        icc.extend(tag);
        icc.extend((156 + 20_000u32).to_be_bytes());
        icc.extend((n as u32).to_be_bytes());
        icc.extend(noise(135, 20_000));
        icc.extend(noise(136, n));
        let size = icc.len() as u32;
        icc[..4].copy_from_slice(&size.to_be_bytes());
        icc
    };
    assert!(is(&walk(&icc(b"desc", 7000))));
    assert!(is(&walk(&icc(b"zzzz", 1000))));
    let got = walk(&icc(b"zzzz", 7000));
    assert!(matches!(&got, Walked::Not(_, why) if why.contains("ICC profile tags no one registered hold 7000")), "{got:?}");
}

/// A certificate's shape around `body` bytes in its fields (an extension's OCTET STRING) and a signature of `sig`.
fn cert_sized(seed: u64, body: usize, sig: usize) -> Vec<u8> {
    let alg = der(0x30, &[oid(RSA), der(0x05, b"")].concat());
    let name = der(0x30, &der(0x31, &der(0x30, &[oid(b"\x55\x04\x03"), der(0x0c, b"Lazaret")].concat())));
    let ext = der(0xa3, &der(0x30, &der(0x30, &[oid(b"\x55\x1d\x0e"), der(0x04, &noise(seed, body))].concat())));
    let tbs = der(0x30, &[der(0xa0, &der(0x02, &[2])), der(0x02, &noise(seed + 1, 8)), alg.clone(), name.clone(),
                          der(0x30, &[der(0x17, b"261021000000Z"), der(0x17, b"361021000000Z")].concat()), name,
                          der(0x30, &[alg.clone(), der(0x03, &[&[0u8][..], &noise(seed + 2, 140)].concat())].concat()),
                          ext].concat());
    der(0x30, &[tbs, alg, der(0x03, &[&[0u8][..], &noise(seed + 3, sig)].concat())].concat())
}

#[test]
fn a_keystores_certificates_and_names_are_counted() {
    // (N2) a certificate counts toward the total whole, its signature and its bytes past CERTIFICATE_MAX as one part;
    // an alias's bytes past NAME_MAX count
    let read = |b: &[u8]| keystore::read(b).unwrap();
    let typed = |c: &[u8]| [b"\x00\x05X.509".as_slice(), &(c.len() as u32).to_be_bytes(), c].concat();
    let jks_named = |alias: &[u8], entries: &[(u32, Vec<u8>)]| {
        let mut f = b"\xfe\xed\xfe\xed".to_vec();
        f.extend(2u32.to_be_bytes());
        f.extend((entries.len() as u32).to_be_bytes());
        for (tag, body) in entries {
            f.extend(tag.to_be_bytes());
            f.extend((alias.len() as u16).to_be_bytes());
            f.extend(alias);
            f.extend([0; 8]);
            f.extend(body);
        }
        f.extend(noise(140, 20));
        f
    };
    // a certificate as real ones are: its signature one part (129 bytes with the BIT STRING's first), all of it
    // toward the total
    let c = cert_sized(141, 200, 128);
    let k = read(&jks(b"\xfe\xed\xfe\xed", &[(2, typed(&c))]));
    assert_eq!((k.certs, k.largest, k.opaque), (1, 129, c.len() as u64), "{k:?}");
    // 40 KB in its fields, or a signature of 20 KB: past KEYSTORE_ELEMENT_MAX_BYTES (16 KiB)
    for c in [cert_sized(142, 40_000, 256), cert_sized(143, 200, 20_000)] {
        let k = read(&jks(b"\xfe\xed\xfe\xed", &[(2, typed(&c))]));
        assert!(k.largest > 16_384, "{k:?}");
    }
    // 100 certificates of 15 KB, each signature 11 KB: within the element bound, past the total's (1 MiB)
    let many: Vec<(u32, Vec<u8>)> = (0..100).map(|n| (2, typed(&cert_sized(200 + n, 4_000, 11_000)))).collect();
    let k = read(&jks(b"\xfe\xed\xfe\xed", &many));
    assert!(k.largest <= 16_384 && k.opaque > 1 << 20, "{k:?}");
    // in a key's chain, a PKCS#12 certificate bag, a signed PKCS#12's certificates
    let key = epki(144, 300);
    let chain = [&(key.len() as u32).to_be_bytes()[..], &key, &1u32.to_be_bytes(), &typed(&cert_sized(145, 40_000, 256))].concat();
    assert!(read(&jks(b"\xfe\xed\xfe\xed", &[(1, chain)])).largest > 16_384);
    let safe = der(0x30, &bag(3, &der(0x30, &[oid(X509), der(0xa0, &der(0x04, &cert_sized(146, 40_000, 256)))].concat())));
    let ci = der(0x30, &[oid(DATA), der(0xa0, &der(0x04, &der(0x30, &der(0x30, &[oid(DATA),
                 der(0xa0, &der(0x04, &safe))].concat()))))].concat());
    let k = read(&der(0x30, &[der(0x02, &[3]), ci].concat()));
    assert!(k.certs == 1 && k.largest > 16_384, "{k:?}");
    // an alias: a real one's name counts nothing, one of 300 bytes its 44 past NAME_MAX, one of 40 KB more than a part
    let c = cert_sized(147, 200, 128);
    let entry = typed(&c);
    assert_eq!(read(&jks_named(&[b'a'; 200], &[(2, entry.clone())])).opaque, c.len() as u64);
    assert_eq!(read(&jks_named(&[b'a'; 300], &[(2, entry.clone())])).opaque, c.len() as u64 + 44);
    assert!(read(&jks_named(&noise(148, 40_000), &[(2, entry.clone())])).largest > 16_384);
    // a BKS alias and key algorithm's name
    let mut bks_alias = 2u32.to_be_bytes().to_vec();
    bks_alias.extend(20u32.to_be_bytes());
    bks_alias.extend(noise(149, 20));
    bks_alias.extend(1024u32.to_be_bytes());
    bks_alias.push(1);
    bks_alias.extend(40_000u16.to_be_bytes());
    bks_alias.extend(noise(150, 40_000));
    bks_alias.extend([0; 8]);
    bks_alias.extend(0u32.to_be_bytes());
    bks_alias.extend(&entry);
    bks_alias.push(0);
    bks_alias.extend(noise(151, 20));
    let k = read(&bks_alias);
    assert!(k.certs == 1 && k.largest > 16_384, "{k:?}");
    // a PKCS#12's MAC salt and a bag's attributes: values nothing reads
    let attrs = der(0x31, &der(0x30, &[oid(b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x14"), der(0x31, &der(0x1e, &noise(152, 40_000)))].concat()));
    let bag_with = der(0x30, &[oid(b"\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01\x02"), der(0xa0, &epki(153, 300)), attrs].concat());
    let auth = der(0x30, &der(0x30, &[oid(DATA), der(0xa0, &der(0x04, &der(0x30, &bag_with)))].concat()));
    let ci = der(0x30, &[oid(DATA), der(0xa0, &der(0x04, &auth))].concat());
    let k = read(&der(0x30, &[der(0x02, &[3]), ci.clone()].concat()));
    assert!(k.keys == 1 && k.largest > 16_384, "{k:?}");
    let mac = |salt: usize| der(0x30, &[der(0x30, &[der(0x30, &oid(b"\x2b\x0e\x03\x02\x1a")), der(0x04, &noise(154, 20))].concat()),
                                        der(0x04, &noise(155, salt)), der(0x02, &[8, 0])].concat());
    let small = der(0x30, &[der(0x02, &[3]), ci.clone(), mac(20)].concat());
    let k0 = read(&small);
    let big = der(0x30, &[der(0x02, &[3]), ci, mac(40_000)].concat());
    let k1 = read(&big);
    assert!(k1.largest > 16_384 && k1.opaque > k0.opaque, "{k0:?} {k1:?}");
    // a JCEKS secret whose serialized object holds an int array, not a byte array: counted as a byte array is
    let sealed = sealed_object();
    let at = sealed.windows(6).position(|w| w == b"\x75\x72\x00\x02[B").unwrap();
    let ints = [&sealed[at..at + 5], b"I", &sealed[at + 6..at + 19], &10_000u32.to_be_bytes(), &noise(156, 40_000)].concat();
    let with_ints = [&sealed[..at], ints.as_slice(), &sealed[at + 19 + 4 + 20..]].concat();
    let k = read(&jks(b"\xce\xce\xce\xce", &[(3, sealed)]));
    assert!(k.secrets == 1 && k.largest == 32, "{k:?}");
    let k = read(&jks(b"\xce\xce\xce\xce", &[(3, with_ints)]));
    assert!(k.secrets == 1 && k.largest == 40_000, "{k:?}");
}

#[test]
fn a_trust_stores_certificates_count_toward_the_total_whole() {
    // (the coordinator's ruling of Oct 27 on N2) certificates each just under CERTIFICATE_MAX, none a part past
    // KEYSTORE_ELEMENT_MAX_BYTES: as many as fit in KEYSTORE_OPAQUE_MAX_BYTES are a keystore (S-SECRET alone), one
    // more is an opaque blob too
    let p = crate::pack::current();
    let (one, all) = (p.int("KEYSTORE_ELEMENT_MAX_BYTES") as u64, p.int("KEYSTORE_OPAQUE_MAX_BYTES") as u64);
    let typed = |c: &[u8]| [b"\x00\x05X.509".as_slice(), &(c.len() as u32).to_be_bytes(), c].concat();
    let certs: Vec<Vec<u8>> = (0..70).map(|n| cert_sized(300 + n, 15_700, 256)).collect();
    let size = certs[0].len() as u64;
    assert!(certs.iter().all(|c| c.len() as u64 == size) && size < CERTIFICATE_MAX_U64 && size > 16_000, "{size}");
    let fit = (all / size) as usize;
    let classify = |n: usize| {
        let f = jks(b"\xfe\xed\xfe\xed", &certs[..n].iter().map(|c| (2, typed(c))).collect::<Vec<_>>());
        let k = keystore::read(&f).unwrap();
        let path = crate::pystr::u("res/raw/trust.jks");
        let got = crate::binary::classify_more(&p, &path, &f[..8192], f.len() as u64, "npm", false, false,
                                               crate::binary::More::Whole(&f));
        let rules: Vec<String> = match got {
            crate::binary::Classified::Issue(v) => vec![v],
            crate::binary::Classified::Issues(v) => v,
            _ => vec![],
        }.iter().map(|v| crate::pystr::to_string(v.as_arr().and_then(|a| a[0].as_str()).unwrap())).collect();
        (k, rules)
    };
    let (k, rules) = classify(fit);
    assert!(k.certs == fit as u64 && k.largest <= one && k.opaque == fit as u64 * size && k.opaque <= all, "{k:?}");
    assert_eq!(rules, ["S-SECRET"]);
    let (k, rules) = classify(fit + 1);
    assert!(k.largest <= one && k.opaque > all, "{k:?}");
    assert_eq!(rules, ["S-SECRET", "SC-OPAQUE-BLOB"]);
}

const CERTIFICATE_MAX_U64: u64 = keystore::CERTIFICATE_MAX as u64;
