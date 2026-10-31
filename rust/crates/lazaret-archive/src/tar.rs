//! TAR reading over one complete byte slice. No sparse files, links or devices.
//!
//! TAR readers disagree at the edges of the format, and an archive built on those edges shows a scanner one
//! set of members and an extractor another. This reader returns members only in the shape that every
//! reference extractor reads alike (Python's tarfile, which pip uses; node-tar, which npm uses; GNU tar;
//! bsdtar), and refuses the rest, with [`Error::Ambiguous`] where they read it differently:
//!
//! * the header checksum is the unsigned sum (node-tar knows no other), written in octal with a terminator
//!   inside its eight bytes (node-tar reads twelve);
//! * a number that starts with NUL is refused (GNU tar skips one NUL, the others read zero), and so is
//!   base-256 with a lead byte other than 0x80;
//! * a name field may hold bytes after its NUL, but no line break (node-tar keeps what follows one);
//! * the ustar prefix is read only in a POSIX ustar header (magic `ustar\0`, version `00`), and must be
//!   empty in any other (Python applies it whatever the magic, node-tar only there);
//! * a member has at most one pax header or one GNU long name, never both; their padding is all zeros and a
//!   long name ends at its NUL;
//! * a file's name does not end in `/` (most readers make it a directory and read its data as headers);
//! * no header except a link's has a link name (node-tar reads on from such a header's data);
//! * pax records: no leading zero in a length, no line break inside one, no all-digit path, no non-ASCII
//!   path byte past the first 512 bytes of the header's data (node-tar parses lines, numbers and the
//!   pieces a stream arrives in), and metadata of at most 1 MiB (node-tar skips larger);
//! * global (`g`) headers may hold only `comment` and `mtime`, as `git archive` writes;
//! * the archive ends at its last member or at a zero block followed by nothing but zeros.

use crate::{Builder, EntryKind, Error, Format, Limits, Result};

const BLOCK: usize = 512;
/// node-tar skips, rather than applies, metadata (pax or GNU long name) over this size.
const NODE_TAR_META_MAX: u64 = 1024 * 1024;
/// node-tar decodes metadata in the pieces a stream delivers; every piece but the last is at least this long.
const NODE_TAR_FIRST_PIECE: usize = 512;

/// Whether `data` starts like TAR: a header whose checksum matches (signed or unsigned, read leniently),
/// or nothing but zero blocks.
pub(crate) fn looks_like(data: &[u8]) -> bool {
    (data.len() >= 2 * BLOCK && data.len() % BLOCK == 0 && data.iter().all(|&b| b == 0))
        || (data.len() >= BLOCK && is_header_block(&data[..BLOCK]))
}

/// Whether a block after the first is one that GNU tar, bsdtar or node-tar would take as a header after
/// skipping the blocks before it.
pub(crate) fn has_later_header(data: &[u8]) -> bool {
    data.chunks_exact(BLOCK).skip(1).any(is_header_block)
}

fn sums(block: &[u8]) -> (i64, i64) {
    let (mut unsigned, mut signed) = (0i64, 0i64);
    for (i, &b) in block.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += i64::from(b);
        signed += i64::from(b as i8);
    }
    (unsigned, signed)
}

/// A block any reader may take as a header: leading NULs and spaces, octal digits, a matching sum.
fn is_header_block(block: &[u8]) -> bool {
    if block.iter().all(|&b| b == 0) { return false; }
    let field = &block[148..156];
    let mut i = field.iter().position(|&b| b != 0 && b != b' ').unwrap_or(field.len());
    let (mut value, start) = (0i64, i);
    while i < field.len() && (b'0'..=b'7').contains(&field[i]) {
        value = value * 8 + i64::from(field[i] - b'0');
        i += 1;
    }
    let (unsigned, signed) = sums(block);
    i > start && (value == unsigned || value == signed)
}

fn checksum(block: &[u8]) -> Result<()> {
    let field = &block[148..156];
    if field[0] == 0 {
        // GNU tar skips one leading NUL and may accept the header; Python, bsdtar and node-tar fail it.
        return Err(if is_header_block(block) {
            Error::Ambiguous("a TAR checksum that starts with NUL (GNU tar skips the NUL, the others fail the header)")
        } else {
            Error::Checksum("TAR header")
        });
    }
    let mut i = field.iter().position(|&b| b != b' ').unwrap_or(field.len());
    let (mut expected, start) = (0i64, i);
    while i < field.len() && (b'0'..=b'7').contains(&field[i]) {
        expected = expected * 8 + i64::from(field[i] - b'0');
        i += 1;
    }
    if i == start || field[i..].iter().any(|&b| b != 0 && b != b' ') { return Err(Error::Checksum("TAR header")); }
    let (unsigned, signed) = sums(block);
    if i == field.len() && (expected == unsigned || expected == signed) {
        return Err(Error::Ambiguous("a TAR checksum without a terminator (node-tar reads it into the next field)"));
    }
    if expected == unsigned { return Ok(()); }
    if expected == signed {
        return Err(Error::Ambiguous("a TAR header with a signed checksum (node-tar fails it and reads on from its data)"));
    }
    Err(Error::Checksum("TAR header"))
}

/// The size field: all NUL (zero); octal after leading spaces, up to a NUL or a space (what follows is
/// ignored, as GNU tar, bsdtar and node-tar ignore it; Python refuses it); or base-256 with lead byte 0x80.
fn size_field(raw: &[u8]) -> Result<u64> {
    if raw.iter().all(|&b| b == 0) { return Ok(0); }
    match raw[0] {
        0x80 => raw[1..].iter().try_fold(0u64, |n, &b| n.checked_mul(256).and_then(|n| n.checked_add(u64::from(b))))
            .ok_or(Error::Limit("TAR numeric field")),
        b if b & 0x80 != 0 => Err(Error::Ambiguous("a TAR base-256 number with a lead byte other than 0x80 (node-tar reads no size)")),
        0 => Err(Error::Ambiguous("a TAR number that starts with NUL (GNU tar skips one NUL, the others read zero)")),
        _ => {
            let mut n = 0u64;
            let mut i = raw.iter().position(|&b| b != b' ').unwrap_or(raw.len());
            while i < raw.len() && (b'0'..=b'7').contains(&raw[i]) {
                n = n * 8 + u64::from(raw[i] - b'0');
                i += 1;
            }
            if i < raw.len() && raw[i] != 0 && raw[i] != b' ' { return Err(Error::Corrupt("invalid octal TAR number")); }
            Ok(n)
        }
    }
}

/// A text field as every reader takes it: the bytes before the first NUL. node-tar's `/\0.*/` stops at a
/// line break, so it keeps whatever follows one; a line break after the NUL is refused.
fn text(raw: &[u8]) -> Result<&[u8]> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let rest = &raw[end..];
    if rest.iter().any(|&b| b == b'\n' || b == b'\r')
        || rest.windows(3).any(|w| w == [0xe2, 0x80, 0xa8] || w == [0xe2, 0x80, 0xa9]) {
        return Err(Error::Ambiguous("a line break after the NUL that ends a TAR name (node-tar keeps the rest)"));
    }
    Ok(&raw[..end])
}

fn utf8(raw: &[u8]) -> Result<&str> {
    std::str::from_utf8(raw).map_err(|_| Error::Corrupt("TAR name is not UTF-8"))
}

/// A non-ASCII byte at or after `NODE_TAR_FIRST_PIECE` in metadata, where node-tar may decode a
/// multi-byte character in two pieces and mangle or drop the record.
fn split_risk(bytes: &[u8], at: usize) -> bool {
    bytes.iter().enumerate().any(|(i, &b)| b >= 0x80 && at + i >= NODE_TAR_FIRST_PIECE)
}

struct Header<'a> {
    kind: u8,
    size: u64,
    name: &'a [u8],
    prefix: &'a [u8],
}

fn header(block: &[u8]) -> Result<Header<'_>> {
    checksum(block)?;
    let kind = block[156];
    match kind {
        0 | b'0' | b'7' | b'5' | b'x' | b'g' | b'L' => {}
        b'1' | b'2' => return Err(Error::Unsupported("TAR links")),
        b'3' | b'4' | b'6' => return Err(Error::Unsupported("TAR device or FIFO entries")),
        b'K' => return Err(Error::Unsupported("GNU long link names")),
        b'S' => return Err(Error::Unsupported("GNU sparse files")),
        _ => return Err(Error::Unsupported("unknown TAR entry type")),
    }
    if block[157..257].iter().any(|&b| b != 0) {
        return Err(Error::Ambiguous("a link name on a TAR header that is not a link (node-tar reads on from its data)"));
    }
    let prefix = if &block[257..265] == b"ustar\x0000" {
        text(&block[345..500])?
    } else {
        // GNU and V7 headers keep other things there; Python takes them for a prefix all the same.
        if block[345..500].iter().any(|&b| b != 0) {
            return Err(Error::Ambiguous("a TAR prefix field outside a POSIX ustar header (Python applies it, the others do not)"));
        }
        &[]
    };
    let name = text(&block[..100])?;
    let size = size_field(&block[124..136])?;
    Ok(Header { kind, size, name, prefix })
}

#[derive(Default)]
struct Pax {
    path: Option<String>,
    size: Option<u64>,
}

fn pax(data: &[u8], global: bool) -> Result<Pax> {
    let mut out = Pax::default();
    let mut pos = 0usize;
    while pos < data.len() {
        let space = data[pos..].iter().position(|&b| b == b' ').map(|n| pos + n)
            .ok_or(Error::Corrupt("PAX record has no length separator"))?;
        let digits = &data[pos..space];
        if digits.is_empty() || digits.len() > 20 || !digits.iter().all(u8::is_ascii_digit) {
            return Err(Error::Corrupt("invalid PAX record length"));
        }
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(Error::Ambiguous("a PAX record length with a leading zero (node-tar misreads the key)"));
        }
        let len = std::str::from_utf8(digits).ok().and_then(|d| d.parse::<usize>().ok())
            .ok_or(Error::Limit("PAX record length"))?;
        if len < digits.len() + 4 { return Err(Error::Corrupt("PAX record length overlaps its header")); }
        let end = pos.checked_add(len).ok_or(Error::Limit("PAX record length"))?;
        if end > data.len() || data[end - 1] != b'\n' { return Err(Error::Corrupt("truncated PAX record")); }
        let body = &data[space + 1..end - 1];
        if body.contains(&b'\n') {
            return Err(Error::Ambiguous("a line break inside a PAX record (node-tar splits the record there)"));
        }
        let equals = body.iter().position(|&b| b == b'=').ok_or(Error::Corrupt("PAX record has no key"))?;
        let (key, value) = (&body[..equals], &body[equals + 1..]);
        if key.is_empty() { return Err(Error::Corrupt("PAX record has no key")); }
        let value_at = space + 1 + equals + 1;
        match key {
            b"comment" | b"mtime" => {}
            _ if global => return Err(Error::Unsupported("PAX global header records other than comment and mtime")),
            b"path" => {
                if out.path.is_some() { return Err(Error::Ambiguous("two PAX path records for one TAR member")); }
                let path = std::str::from_utf8(value).map_err(|_| Error::Corrupt("PAX path is not UTF-8"))?;
                if !path.is_empty() && path.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::Ambiguous("an all-digit PAX path (node-tar reads it as a number)"));
                }
                if split_risk(value, value_at) {
                    return Err(Error::Ambiguous("a non-ASCII PAX path past the first 512 bytes of its header (node-tar may drop it)"));
                }
                out.path = Some(path.into());
            }
            b"size" => {
                if out.size.is_some() { return Err(Error::Ambiguous("two PAX size records for one TAR member")); }
                if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                    return Err(Error::Corrupt("invalid PAX size"));
                }
                out.size = Some(std::str::from_utf8(value).ok().and_then(|v| v.parse().ok()).ok_or(Error::Limit("PAX size"))?);
            }
            b"atime" | b"ctime" | b"uid" | b"gid" | b"uname" | b"gname" | b"LIBARCHIVE.creationtime" => {}
            b"hdrcharset" => {
                if value != b"BINARY" && value != b"ISO-IR 10646 2000 UTF-8" {
                    return Err(Error::Unsupported("PAX header character set"));
                }
            }
            // Extended attributes, as macOS bsdtar writes them: no part of a member's name or bytes.
            _ if key.starts_with(b"SCHILY.xattr.") || key.starts_with(b"LIBARCHIVE.xattr.") => {}
            b"linkpath" => {
                return Err(Error::Ambiguous("a PAX link path on a TAR member that is not a link (node-tar reads on from its data)"));
            }
            _ => return Err(Error::Unsupported("PAX metadata other than path, size, times, ownership, comments or extended attributes")),
        }
        pos = end;
    }
    Ok(out)
}

fn long_name(data: &[u8]) -> Result<String> {
    if data.first().is_none_or(|&b| b == 0) {
        return Err(Error::Ambiguous("an empty GNU long name (node-tar ignores it, the others name the member '')"));
    }
    let end = data.iter().position(|&b| b == 0).ok_or(Error::Corrupt("GNU long name without a NUL"))?;
    let name = text(data)?;
    if split_risk(&data[..end], 0) {
        return Err(Error::Ambiguous("a non-ASCII GNU long name past its first 512 bytes (node-tar may mangle it)"));
    }
    Ok(utf8(name)?.into())
}

/// Metadata a member's header waits on: at most one pax header or one GNU long name.
#[derive(Default)]
struct Pending {
    pax: Option<Pax>,
    long_name: Option<String>,
}

impl Pending {
    fn any(&self) -> bool { self.pax.is_some() || self.long_name.is_some() }
}

fn padded(end: usize) -> Result<usize> {
    end.checked_add((BLOCK - end % BLOCK) % BLOCK).ok_or(Error::Limit("TAR member padding"))
}

pub(crate) fn extract(data: &[u8], limits: Limits, format: Format) -> Result<crate::Archive> {
    let mut out = Builder::new(limits);
    let mut pos = 0usize;
    let mut pending = Pending::default();

    loop {
        if pos == data.len() {
            // No end blocks: Python, GNU tar, bsdtar and node-tar all end at the last member.
            if pending.any() { return Err(Error::Corrupt("TAR metadata has no following member")); }
            break;
        }
        if data.len() - pos < BLOCK { return Err(Error::Truncated); }
        let block = &data[pos..pos + BLOCK];
        if block.iter().all(|&b| b == 0) {
            if pending.any() { return Err(Error::Corrupt("TAR metadata has no following member")); }
            // One zero block ends the archive for Python, GNU tar and bsdtar; node-tar reads on until two,
            // so only zeros may follow.
            let rest = &data[pos..];
            if rest.iter().any(|&b| b != 0) {
                if rest.len() >= 2 * BLOCK && rest[..2 * BLOCK].iter().all(|&b| b == 0) {
                    return Err(Error::Corrupt("data after TAR end marker"));
                }
                return Err(Error::Ambiguous("data after a single TAR zero block (node-tar reads on, the others stop)"));
            }
            break;
        }
        let h = header(block)?;
        let data_start = pos + BLOCK;

        if matches!(h.kind, b'x' | b'g' | b'L') {
            if h.size > NODE_TAR_META_MAX {
                return Err(Error::Ambiguous("TAR metadata over 1 MiB (node-tar skips it, the others apply it)"));
            }
            out.reserve_metadata(h.size)?;
            let size = out.check_member_size(h.size)?;
            if h.name.is_empty() && h.prefix.is_empty() {
                return Err(Error::Ambiguous("a TAR metadata header without a name (node-tar skips it)"));
            }
            let end = data_start.checked_add(size).ok_or(Error::Limit("TAR metadata size"))?;
            let next = padded(end)?;
            let payload = data.get(data_start..end).ok_or(Error::Truncated)?;
            let padding = data.get(end..next).ok_or(Error::Truncated)?;
            if padding.iter().any(|&b| b != 0) {
                return Err(Error::Ambiguous("bytes in the padding after TAR metadata (Python and GNU tar read them too)"));
            }
            match h.kind {
                b'x' => {
                    if pending.pax.is_some() { return Err(Error::Ambiguous("two PAX headers for one TAR member")); }
                    if pending.long_name.is_some() { return Err(Error::Ambiguous("a GNU long name and a PAX header for one TAR member")); }
                    pending.pax = Some(pax(payload, false)?);
                }
                b'L' => {
                    if pending.long_name.is_some() { return Err(Error::Ambiguous("two GNU long names for one TAR member")); }
                    if pending.pax.is_some() { return Err(Error::Ambiguous("a PAX header and a GNU long name for one TAR member")); }
                    pending.long_name = Some(long_name(payload)?);
                }
                _ => {
                    if pending.any() { return Err(Error::Ambiguous("a PAX global header between a TAR member's own metadata and the member")); }
                    pax(payload, true)?;
                }
            }
            pos = next;
            continue;
        }

        let pax = pending.pax.take().unwrap_or_default();
        let long = pending.long_name.take();
        // A pax path or long name replaces the header's name and prefix for every reader (node-tar joins the
        // prefix to it in its header, then its entry takes the long name again).
        let name = match (pax.path, long) {
            (Some(name), _) | (None, Some(name)) => name,
            (None, None) if h.prefix.is_empty() => utf8(h.name)?.to_owned(),
            (None, None) => format!("{}/{}", utf8(h.prefix)?, utf8(h.name)?),
        };
        let size_u64 = match pax.size {
            Some(size) if h.size != 0 && h.size != size => {
                return Err(Error::Ambiguous("a PAX size that differs from the TAR header's size"));
            }
            Some(size) => size,
            None => h.size,
        };
        let size = out.check_member_size(size_u64)?;
        let end = data_start.checked_add(size).ok_or(Error::Limit("TAR member size"))?;
        let next = padded(end)?;
        let payload = data.get(data_start..end).ok_or(Error::Truncated)?;
        if next > data.len() { return Err(Error::Truncated); }

        if h.kind == b'5' {
            // Readers disagree on whether a directory's data is skipped.
            if size != 0 { return Err(Error::Corrupt("TAR directory has a payload")); }
            if !matches!(name.as_str(), "" | "." | "./") { out.add(&name, EntryKind::Directory, &[])?; }
        } else {
            out.add(&name, EntryKind::File, payload)?;
        }
        pos = next;
    }
    Ok(out.finish(format))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Zero-padded and NUL-terminated, as GNU tar, Python and node-tar write numbers.
    fn octal(field: &mut [u8], n: u64) {
        let text = format!("{:0width$o}\0", n, width = field.len() - 1);
        field.copy_from_slice(text.as_bytes());
    }

    fn header(name: &str, size: u64, kind: u8) -> [u8; BLOCK] {
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        octal(&mut h[100..108], 0o644);
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], size);
        octal(&mut h[136..148], 0);
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        octal(&mut h[148..156], sum);
        h
    }

    fn archive(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = header(name, payload.len() as u64, b'0').to_vec();
        out.extend_from_slice(payload);
        out.resize(out.len() + (BLOCK - payload.len() % BLOCK) % BLOCK, 0);
        out.resize(out.len() + 2 * BLOCK, 0);
        out
    }

    #[test]
    fn regular_file() {
        let got = extract(&archive("a.txt", b"hello"), Limits::default(), Format::Tar).unwrap();
        assert_eq!(got.entries[0].name, "a.txt");
        assert_eq!(got.entries[0].data, b"hello");
    }

    #[test]
    fn traversal_fails_and_duplicate_names_are_grouped() {
        assert!(matches!(extract(&archive("../x", b"x"), Limits::default(), Format::Tar), Err(Error::InvalidPath(_))));
        let mut two = archive("x", b"one");
        two.truncate(two.len() - 2 * BLOCK);
        two.extend_from_slice(&archive("x", b"two"));
        let got = extract(&two, Limits::default(), Format::Tar).unwrap();
        assert_eq!(got.entries.len(), 2);
        assert_eq!(got.entries[1].data, b"two");
        assert!(got.collisions[0].duplicate);
    }

    #[test]
    fn truncation_and_header_damage_fail() {
        let good = archive("x", b"content");
        assert_eq!(extract(&good[..512 + 3], Limits::default(), Format::Tar), Err(Error::Truncated));
        assert_eq!(extract(&good[..512 + 512 + 100], Limits::default(), Format::Tar), Err(Error::Truncated));
        let mut bad = good;
        bad[0] ^= 1;
        assert_eq!(extract(&bad, Limits::default(), Format::Tar), Err(Error::Checksum("TAR header")));
    }

    #[test]
    fn member_limit_is_checked_before_copying() {
        let limits = Limits::new(3, 100);
        assert_eq!(extract(&archive("x", b"four"), limits, Format::Tar), Err(Error::Limit("member size")));
    }

    #[test]
    fn gnu_long_name() {
        let name = "folder/a-very-long-name.txt";
        let mut raw = header("L", name.len() as u64 + 1, b'L').to_vec();
        raw.extend_from_slice(name.as_bytes());
        raw.push(0);
        raw.resize(raw.len() + (BLOCK - (name.len() + 1) % BLOCK) % BLOCK, 0);
        let file = archive("short", b"ok");
        raw.extend_from_slice(&file);
        let got = extract(&raw, Limits::default(), Format::Tar).unwrap();
        assert_eq!(got.entries[0].name, name);
        assert_eq!(got.entries[0].data, b"ok");
    }

    #[test]
    fn pax_path() {
        let record = b"16 path=a/b.txt\n";
        let mut raw = header("PaxHeader", record.len() as u64, b'x').to_vec();
        raw.extend_from_slice(record);
        raw.resize(raw.len() + (BLOCK - record.len() % BLOCK) % BLOCK, 0);
        raw.extend_from_slice(&archive("short", b"ok"));
        let got = extract(&raw, Limits::default(), Format::Tar).unwrap();
        assert_eq!(got.entries[0].name, "a/b.txt");
    }

    #[test]
    fn numbers_read_alike_everywhere_or_are_refused() {
        assert_eq!(size_field(b"00000000014\0"), Ok(12));
        assert_eq!(size_field(b"   14 \0\0\0\0\0\0"), Ok(12));
        assert_eq!(size_field(b"000000000014"), Ok(12));
        assert_eq!(size_field(&[0; 12]), Ok(0));
        assert_eq!(size_field(b"            "), Ok(0));
        assert_eq!(size_field(b"\x80\0\0\0\0\0\0\0\0\0\0\x0c"), Ok(12));
        assert!(matches!(size_field(b"\x0000000000014"), Err(Error::Ambiguous(_))));
        assert!(matches!(size_field(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), Err(Error::Ambiguous(_))));
        assert!(matches!(size_field(b"\x81\0\0\0\0\0\0\0\0\0\0\x0c"), Err(Error::Ambiguous(_))));
        assert_eq!(size_field(b"0000000014x\0"), Err(Error::Corrupt("invalid octal TAR number")));
    }

    #[test]
    fn text_fields_stop_at_nul_unless_a_line_break_follows() {
        assert_eq!(text(b"a.txt\0junk"), Ok(&b"a.txt"[..]));
        assert!(matches!(text(b"a.txt\0\nx"), Err(Error::Ambiguous(_))));
        assert!(matches!(text(b"a.txt\0\xe2\x80\xa8x"), Err(Error::Ambiguous(_))));
    }
}
