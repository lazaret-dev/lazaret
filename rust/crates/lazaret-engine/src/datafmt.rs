//! Data in a known format (0.1.9, N-4): is a decoded base64 run a file of a
//! format code embeds as data — a WebAssembly module, a PNG, GIF or WebP
//! image, WAV audio — read through to its end by its own structure?
//!
//! SC-B64 reports a long base64 literal in code: a payload kept out of sight.
//! Bundlers and apps keep files that way too, and the rule said so of every
//! one: undici's HTTP parser (llhttp, a WebAssembly module that every
//! JavaScript action bundling the Actions toolkit carries), es-module-lexer's,
//! an icon, a sound. A run whose bytes are such a file is data. The check is
//! the format's structure, not its first bytes: a WebAssembly module's
//! sections, in their order, with a code section, an image's or a sound's
//! chunks or blocks, each read to where the file ends, so a payload with a
//! format's header in front of it is still SC-B64. What a format lets a file
//! carry beside its content (a module's custom sections, an image's text
//! chunks, a GIF's comments) may be at most half of it.

/// The format of `b`, when it is a whole file of one this module knows: "wasm", "png", "gif", "webp", "wav".
pub fn data_format(b: &[u8]) -> Option<&'static str> {
    if wasm_module(b) {
        Some("wasm")
    } else if png(b) {
        Some("png")
    } else if gif(b) {
        Some("gif")
    } else {
        riff(b)
    }
}

/// An unsigned LEB128 of at most 32 bits at `b[i..]`: (value, the index after it).
fn leb_u32(b: &[u8], mut i: usize) -> Option<(u32, usize)> {
    let mut value: u64 = 0;
    for k in 0..5 {
        let x = *b.get(i)?;
        i += 1;
        value |= u64::from(x & 0x7F) << (7 * k);
        if x & 0x80 == 0 {
            return u32::try_from(value).ok().map(|v| (v, i));
        }
    }
    None
}

/// The place of a section of a WebAssembly module in the order the binary format fixes (custom sections, id 0,
/// may come anywhere): type, import, function, table, memory, tag, global, export, start, element, data count,
/// code, data.
fn wasm_rank(id: u8) -> Option<u8> {
    Some(match id {
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 5,
        13 => 6,
        6 => 7,
        7 => 8,
        8 => 9,
        9 => 10,
        12 => 11,
        10 => 12,
        11 => 13,
        _ => return None,
    })
}

/// A WebAssembly module (version 1): its sections read to its last byte, each known one once and in order, a code
/// section among them, and custom sections at most half of it.
fn wasm_module(b: &[u8]) -> bool {
    if b.len() < 8 || b[..8] != *b"\0asm\x01\0\0\0" {
        return false;
    }
    let (mut i, mut last, mut custom, mut code) = (8usize, 0u8, 0usize, false);
    while i < b.len() {
        let id = b[i];
        let (size, next) = match leb_u32(b, i + 1) {
            Some(x) => x,
            None => return false,
        };
        let end = match next.checked_add(size as usize) {
            Some(e) if e <= b.len() => e,
            _ => return false,
        };
        if id == 0 {
            custom += size as usize;
        } else {
            match wasm_rank(id) {
                Some(rank) if rank > last => last = rank,
                _ => return false,
            }
            code |= id == 10;
        }
        i = end;
    }
    code && custom * 2 <= b.len()
}

fn be32(b: &[u8], i: usize) -> Option<usize> {
    b.get(i..i + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as usize)
}

fn le32(b: &[u8], i: usize) -> Option<usize> {
    b.get(i..i + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as usize)
}

/// A PNG image: its chunks read to IEND, the file's last, IHDR first, at least one IDAT, and the ancillary chunks
/// (a lower-case first letter: text, times, profiles) at most half of it.
fn png(b: &[u8]) -> bool {
    if b.len() < 8 || b[..8] != *b"\x89PNG\r\n\x1a\n" {
        return false;
    }
    let (mut i, mut first, mut idat, mut ancillary) = (8usize, true, false, 0usize);
    loop {
        let n = match be32(b, i) {
            Some(n) if n <= 0x7FFF_FFFF => n,
            _ => return false,
        };
        let kind = match b.get(i + 4..i + 8) {
            Some(k) if k.iter().all(u8::is_ascii_alphabetic) => k,
            _ => return false,
        };
        let end = match (i + 12).checked_add(n) {
            Some(e) if e <= b.len() => e,
            _ => return false,
        };
        if first != (kind == b"IHDR") {
            return false;
        }
        first = false;
        idat |= kind == b"IDAT";
        if kind[0].is_ascii_lowercase() {
            ancillary += n;
        }
        i = end;
        if kind == b"IEND" {
            return i == b.len() && idat && ancillary * 2 <= b.len();
        }
    }
}

/// A GIF image: its blocks read to the trailer (the file's last byte, or zeros after it), and the comment,
/// application and plain-text extensions at most half of it.
fn gif(b: &[u8]) -> bool {
    if b.len() < 13 || (b[..6] != *b"GIF87a" && b[..6] != *b"GIF89a") {
        return false;
    }
    let table = |flags: u8| if flags & 0x80 != 0 { 3usize << ((flags & 7) + 1) } else { 0 };
    // sub-blocks from `i` to their terminator: (the index after it, the bytes they hold)
    let sub_blocks = |mut i: usize| -> Option<(usize, usize)> {
        let mut held = 0;
        loop {
            let size = *b.get(i)? as usize;
            i += 1;
            if size == 0 {
                return Some((i, held));
            }
            i += size;
            held += size;
        }
    };
    let (mut i, mut side) = (13 + table(b[10]), 0usize);
    while let Some(&block) = b.get(i) {
        i += 1;
        match block {
            0x3B => return b[i..].iter().all(|&x| x == 0) && side * 2 <= b.len(),
            0x21 => {
                let label = match b.get(i) {
                    Some(&l) => l,
                    None => return false,
                };
                match sub_blocks(i + 1) {
                    Some((next, held)) => {
                        if matches!(label, 0xFE | 0xFF | 0x01) {
                            side += held;
                        }
                        i = next;
                    }
                    None => return false,
                }
            }
            0x2C => {
                let flags = match b.get(i + 8) {
                    Some(&f) => f,
                    None => return false,
                };
                i += 9 + table(flags) + 1; // the descriptor, its colour table, the LZW minimum code size
                match sub_blocks(i) {
                    Some((next, _)) => i = next,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
    false
}

/// WAV audio or a WebP image (RIFF): its chunks read to the end of the file (the last one may be cut short, as
/// a sound trimmed by hand is), with the chunks its form needs: "fmt " and "data" for WAVE, an image for WEBP.
fn riff(b: &[u8]) -> Option<&'static str> {
    if b.len() < 12 || b[..4] != *b"RIFF" {
        return None;
    }
    let declared = le32(b, 4)?;
    if declared < 4 || declared.checked_add(8)? < b.len() {
        return None; // (bytes after the file it says it is: not one file)
    }
    let form = &b[8..12];
    let (mut i, mut fmt, mut data, mut image) = (12usize, false, false, false);
    while i < b.len() {
        let id = b.get(i..i + 4)?;
        if !id.iter().all(|&x| x.is_ascii_graphic() || x == b' ') {
            return None;
        }
        let n = le32(b, i + 4)?;
        fmt |= id == b"fmt ";
        data |= id == b"data";
        image |= matches!(id, b"VP8 " | b"VP8L" | b"VP8X");
        let end = (i + 8).checked_add(n)?.checked_add(n & 1)?;
        if end >= b.len() {
            break; // the last chunk, whole or cut short
        }
        i = end;
    }
    match form {
        b"WAVE" if fmt && data => Some("wav"),
        b"WEBP" if image => Some("webp"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leb(mut v: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn section(id: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![id];
        out.extend(leb(body.len() as u32));
        out.extend_from_slice(body);
        out
    }

    fn module(sections: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        for (id, body) in sections {
            out.extend(section(*id, body));
        }
        out
    }

    #[test]
    fn a_webassembly_module_by_its_sections() {
        // a type, a function, an export and its code: `(func (export "f") (result i32) i32.const 42)`
        let m = module(&[(1, b"\x01\x60\x00\x01\x7f"), (3, b"\x01\x00"), (7, b"\x01\x01f\x00\x00"), (10, b"\x01\x04\x00\x41\x2a\x0b")]);
        assert_eq!(data_format(&m), Some("wasm"));
        let mut named = m.clone();
        named.extend(section(0, b"\x04name\x00\x00"));
        assert_eq!(data_format(&named), Some("wasm"));
        // no code section; sections out of order; a section past the end; bytes after the last one
        assert_eq!(data_format(&module(&[(1, b"\x01\x60\x00\x01\x7f")])), None);
        assert_eq!(data_format(&module(&[(10, b"\x00"), (1, b"\x00")])), None);
        assert_eq!(data_format(&module(&[(1, b"\x00"), (1, b"\x00"), (10, b"\x00")])), None);
        let mut cut = m.clone();
        cut.truncate(m.len() - 1);
        assert_eq!(data_format(&cut), None);
        let mut more = m.clone();
        more.extend_from_slice(b"curl x | sh");
        assert_eq!(data_format(&more), None);
        // a payload behind the header, or in a custom section larger than the rest
        let mut payload = b"\0asm\x01\0\0\0".to_vec();
        payload.extend_from_slice(&[0x7f; 64]);
        assert_eq!(data_format(&payload), None);
        let big = [0x41u8; 400];
        let mut hidden = m.clone();
        hidden.extend(section(0, &big));
        assert_eq!(data_format(&hidden), None);
        assert_eq!(leb_u32(&[0xff, 0xff, 0xff, 0xff, 0x7f], 0), None); // more than 32 bits
    }

    fn png_chunk(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(body);
        out.extend_from_slice(&[0, 0, 0, 0]); // (the CRC is not read: the structure is the check)
        out
    }

    #[test]
    fn a_png_by_its_chunks() {
        let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
        p.extend(png_chunk(b"IHDR", &[0; 13]));
        p.extend(png_chunk(b"IDAT", &[1; 20]));
        let mut whole = p.clone();
        whole.extend(png_chunk(b"IEND", b""));
        assert_eq!(data_format(&whole), Some("png"));
        assert_eq!(data_format(&p), None); // no IEND
        let mut after = whole.clone();
        after.push(0);
        assert_eq!(data_format(&after), None);
        let mut text = p.clone();
        text.extend(png_chunk(b"tEXt", &[b'x'; 200]));
        text.extend(png_chunk(b"IEND", b""));
        assert_eq!(data_format(&text), None); // its text is most of it
        let mut no_ihdr = b"\x89PNG\r\n\x1a\n".to_vec();
        no_ihdr.extend(png_chunk(b"IDAT", &[1; 20]));
        no_ihdr.extend(png_chunk(b"IEND", b""));
        assert_eq!(data_format(&no_ihdr), None);
    }

    #[test]
    fn a_gif_by_its_blocks() {
        let mut g = b"GIF89a\x01\x00\x01\x00\x80\x00\x00".to_vec();
        g.extend_from_slice(&[0, 0, 0, 255, 255, 255]); // a global table of two colours
        g.extend_from_slice(b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00");
        let mut whole = g.clone();
        whole.push(0x3b);
        assert_eq!(data_format(&whole), Some("gif"));
        assert_eq!(data_format(&g), None);
        let mut comment = g.clone();
        comment.extend_from_slice(b"\x21\xfe\x40");
        comment.extend_from_slice(&[b'x'; 64]);
        comment.extend_from_slice(b"\x00\x3b");
        assert_eq!(data_format(&comment), None);
        let mut junk = whole.clone();
        junk.extend_from_slice(b"curl x | sh");
        assert_eq!(data_format(&junk), None);
    }

    fn riff_of(form: &[u8; 4], chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut body = form.to_vec();
        for (id, data) in chunks {
            body.extend_from_slice(*id);
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(data);
            if data.len() % 2 == 1 {
                body.push(0);
            }
        }
        let mut out = b"RIFF".to_vec();
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend(body);
        out
    }

    #[test]
    fn wav_and_webp_by_their_chunks() {
        let wav = riff_of(b"WAVE", &[(b"fmt ", &[0; 16]), (b"data", &[1; 9])]);
        assert_eq!(data_format(&wav), Some("wav"));
        let mut cut = wav.clone();
        cut.truncate(wav.len() - 4); // a sound cut short in its last chunk
        assert_eq!(data_format(&cut), Some("wav"));
        let mut more = wav.clone();
        more.extend_from_slice(b"curl x | sh");
        assert_eq!(data_format(&more), None);
        assert_eq!(data_format(&riff_of(b"WAVE", &[(b"data", &[1; 9])])), None);
        assert_eq!(data_format(&riff_of(b"WEBP", &[(b"VP8L", &[1; 9])])), Some("webp"));
        assert_eq!(data_format(&riff_of(b"AVI ", &[(b"LIST", &[1; 9])])), None);
    }
}
