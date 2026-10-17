//! A source file's bytes decoded as its interpreter reads them (0.1.9, BR-7 step 4 (b)): core's decode_source,
//! detect_encoding, _python_cookie, _normal_codec and _decode_escapes, and the npm package's encoding.js, which held
//! each other equal by tests, decoding with Python's codecs on one side and with tables and the runtime's
//! TextDecoder on the other. The engine decodes for both, every text codec Python has (but the three that are not
//! a character encoding of a file: idna, punycode and undefined, which stay undecoded, as before).
//!
//! In order: a byte order mark, or a NUL in the first four bytes (BOM-less UTF-16, kept only when its first 4096
//! bytes read as plausible text); then, for Python source without either, the PEP 263 coding cookie on line 1 or 2
//! (line 2 only after a blank or comment line), resolved as the interpreter resolves it (utf-8 and latin-1
//! spellings fold to their codec; Python's aliases; ALIASES). UTF-7 and the escape codecs are noted (SC-UTF7,
//! SC-ESCAPE-CODEC), an unknown codec or one the engine does not decode read as UTF-8 (Q-ENCODING names it; the
//! latter SC-TRUNCATED). A codec's errors are replaced as Python's errors="replace" replaces them; a lone
//! surrogate a codec leaves becomes U+FFFD; line endings are normalized to "\n".

pub mod cjk;
pub mod escape;
pub mod iso2022;
pub mod utf;

use crate::generated::codecs as g;
use utf::Order;

/// What a decoding says of the file (core's info dict).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub encoding: String,
    pub reported: bool,
    pub utf7: bool,
    pub cookie_line: Option<usize>,
    pub escapes: bool,
    pub undecoded: bool,
}

/// detect_encoding: (codec, reported, the bytes of a byte order mark to drop).
pub fn detect_encoding(head: &[u8]) -> (&'static str, bool, usize) {
    if head.starts_with(&[0xFF, 0xFE]) {
        return ("utf-16-le", true, 2);
    }
    if head.starts_with(&[0xFE, 0xFF]) {
        return ("utf-16-be", true, 2);
    }
    if head.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return ("utf-8-sig", true, 0);
    }
    let first = &head[..head.len().min(4)];
    if first.contains(&0) {
        let le = first.get(1) == Some(&0) || first.get(3) == Some(&0);
        return (if le { "utf-16-le" } else { "utf-16-be" }, true, 0);
    }
    ("utf-8", false, 0)
}

/// _text_is_plausible: at least 70% of the first 2048 characters are printable ASCII, tab, CR or LF.
pub fn text_is_plausible(text: &[u32]) -> bool {
    if text.is_empty() {
        return false;
    }
    let sample = &text[..text.len().min(2048)];
    let plain = sample.iter().filter(|&&c| (0x20..=0x7E).contains(&c) || c == 9 || c == 10 || c == 13).count();
    plain as f64 / sample.len() as f64 >= 0.70
}

/// The first two lines of `data`, split at "\r\n", "\r" or "\n".
fn first_lines(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < data.len() && out.len() < 2 {
        match data[i] {
            b'\r' => {
                out.push(&data[start..i]);
                i += if data.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                start = i;
            }
            b'\n' => {
                out.push(&data[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if out.len() < 2 {
        out.push(&data[start..]);
    }
    out.truncate(2);
    out
}

/// `^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)` (bytes: \w is ASCII) on one line: the name.
fn cookie_on(line: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    while i < line.len() && matches!(line[i], b' ' | b'\t' | 0x0C) {
        i += 1;
    }
    if line.get(i) != Some(&b'#') {
        return None;
    }
    // the first "coding" followed by ':' or '=' (".*?" is lazy: the leftmost that completes the match)
    let mut k = i + 1;
    while k + 6 <= line.len() {
        if &line[k..k + 6] == b"coding" && matches!(line.get(k + 6), Some(b':' | b'=')) {
            let mut j = k + 7;
            while j < line.len() && matches!(line[j], b' ' | b'\t') {
                j += 1;
            }
            let start = j;
            while j < line.len() && (line[j].is_ascii_alphanumeric() || matches!(line[j], b'_' | b'-' | b'.')) {
                j += 1;
            }
            if j > start {
                return Some(&line[start..j]);
            }
        }
        k += 1;
    }
    None
}

/// `^[ \t\f]*(?:#.*)?$`: a blank or comment line.
fn blank_or_comment(line: &[u8]) -> bool {
    let rest = line.iter().position(|&c| !matches!(c, b' ' | b'\t' | 0x0C)).map_or(&line[line.len()..], |k| &line[k..]);
    rest.is_empty() || rest[0] == b'#'
}

/// _python_cookie: the PEP 263 declaration's name and line (1 or 2).
pub fn python_cookie(data: &[u8]) -> Option<(String, usize)> {
    for (idx, line) in first_lines(data).into_iter().enumerate() {
        if let Some(name) = cookie_on(line) {
            return Some((String::from_utf8_lossy(name).into_owned(), idx + 1));
        }
        if !blank_or_comment(line) {
            break;
        }
    }
    None
}

/// encodings.normalize_encoding on the lower-cased name: runs of characters other than letters, digits and "."
/// become "_", and none at either end.
fn normalize(name: &str) -> String {
    let mut out = String::new();
    let mut pending = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' {
            if pending && !out.is_empty() {
                out.push('_');
            }
            pending = false;
            out.push(ch);
        } else {
            pending = true;
        }
    }
    out
}

/// codecs.lookup(name).name for a text encoding Python has, by the generated alias table (the same on every
/// supported Python: core's CODEC_ALIAS_EXTRAS included, the host's code pages left out).
pub fn codec_of(name: &str) -> Option<&'static str> {
    let key = normalize(name);
    let find = |k: &str| g::ALIASES.binary_search_by(|(a, _)| (*a).cmp(k)).ok().map(|i| g::ALIASES[i].1);
    find(&key).or_else(|| find(&key.replace('.', "_")))
}

/// _normal_codec: utf-8 and latin-1 spellings fold to their codec, else codec_of.
pub fn normal_codec(name: &str) -> Option<&'static str> {
    let short: String = name.chars().take(12).collect::<String>().to_lowercase().replace('_', "-");
    if short == "utf-8" || short.starts_with("utf-8-") {
        return Some("utf-8");
    }
    if matches!(short.as_str(), "latin-1" | "iso-8859-1" | "iso-latin-1")
        || ["latin-1-", "iso-8859-1-", "iso-latin-1-"].iter().any(|p| short.starts_with(p))
    {
        return Some("iso8859-1");
    }
    codec_of(name)
}

const UTF7_NAMES: [&str; 4] = ["utf-7", "utf7", "u7", "unicode-1-1-utf-7"];
const ESCAPE_CODECS: [&str; 2] = ["unicode-escape", "raw-unicode-escape"];
/// Text codecs Python has that are not a file's character encoding: read as UTF-8, undecoded (SC-TRUNCATED).
const NOT_DECODED: [&str; 3] = ["idna", "punycode", "undefined"];

/// `body` in `codec` with errors="replace" (an escape codec: strict, None where Python raises or \N{name} is used;
/// None where Python's decoder raises otherwise, as iso2022_jp_2's does on single shift 2 with JIS X 0201 Roman in
/// G2, and for a codec the engine does not decode: decode_source reads such a file as UTF-8, as core did).
pub fn decode(codec: &'static str, body: &[u8]) -> Option<Vec<u32>> {
    Some(match codec {
        "utf-8" => utf::utf8(body),
        "utf-8-sig" => utf::utf8_sig(body),
        "utf-16" => utf::utf16(body, Order::Bom),
        "utf-16-le" => utf::utf16(body, Order::Le),
        "utf-16-be" => utf::utf16(body, Order::Be),
        "utf-32" => utf::utf32(body, Order::Bom),
        "utf-32-le" => utf::utf32(body, Order::Le),
        "utf-32-be" => utf::utf32(body, Order::Be),
        "utf-7" => utf::utf7(body),
        "ascii" => utf::ascii(body),
        "iso8859-1" | "charmap" => utf::latin1(body),
        "unicode-escape" => return escape::unicode_escape(body),
        "raw-unicode-escape" => return escape::raw_unicode_escape(body),
        "hz" => iso2022::hz(body),
        _ if iso2022::is_iso2022(codec) => return iso2022::iso2022(codec, body),
        _ => {
            if let Some(&(_, first)) = g::CJK_FIRST.iter().find(|(c, _)| *c == codec) {
                cjk::stateless(first, body)
            } else if let Some(&(_, table)) = g::SINGLE_BYTE.iter().find(|(c, _)| *c == codec) {
                single_byte(table, body)
            } else {
                return None;
            }
        }
    })
}

/// A single-byte codec: bytes 0x80..=0xFF (or all 256 when the table has them) from its table, U+FFFD for an
/// undefined byte (as errors="replace" gives).
fn single_byte(table: &str, body: &[u8]) -> Vec<u32> {
    let chars: Vec<u32> = table.chars().map(|c| c as u32).collect();
    let full = chars.len() == 256;
    body.iter().map(|&b| if full { chars[b as usize] } else if b < 0x80 { b as u32 } else { chars[(b - 0x80) as usize] }).collect()
}

/// normalize_newlines: "\r\n" and a lone "\r" become "\n".
pub fn normalize_newlines(text: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] == '\r' as u32 {
            out.push('\n' as u32);
            if text.get(i + 1) == Some(&('\n' as u32)) {
                i += 1;
            }
        } else {
            out.push(text[i]);
        }
        i += 1;
    }
    out
}

/// decode_source: the text (pinned to nothing: as the codec gives it, lone surrogates as U+FFFD, line endings
/// normalized) and what the decoding says of the file.
pub fn decode_source(data: &[u8], lang: Option<&str>) -> (Vec<u32>, Info) {
    let (mut codec, mut reported, mut bom) = detect_encoding(&data[..data.len().min(4)]);
    if reported && bom == 0 && codec.starts_with("utf-16") {
        let order = if codec == "utf-16-le" { Order::Le } else { Order::Be };
        if !text_is_plausible(&utf::utf16(&data[..data.len().min(4096)], order)) {
            // a NUL near the top of a UTF-8 file is not UTF-16
            (codec, reported, bom) = ("utf-8", false, 0);
        }
    }
    let body = &data[bom..];
    let mut info = Info { encoding: codec.to_string(), reported, utf7: false, cookie_line: None, escapes: false, undecoded: false };
    if lang == Some("py") && !reported {
        if let Some((name, line)) = python_cookie(data) {
            match normal_codec(&name) {
                None => {
                    info.encoding = name;
                    info.reported = true;
                    info.cookie_line = Some(line);
                }
                Some("utf-8") => {}
                Some(real) => {
                    info.encoding = real.to_string();
                    info.reported = true;
                    info.cookie_line = Some(line);
                    info.utf7 = real == "utf-7" || UTF7_NAMES.contains(&name.to_lowercase().replace('_', "-").as_str());
                    info.escapes = ESCAPE_CODECS.contains(&real);
                    if NOT_DECODED.contains(&real) {
                        info.undecoded = true;
                    } else {
                        codec = real;
                    }
                }
            }
        }
    }
    let text = match decode(codec, body) {
        Some(t) => t,
        None => {
            // an escape codec Python would not read, or one the engine does not decode: read as UTF-8
            if ESCAPE_CODECS.contains(&codec) || NOT_DECODED.contains(&codec) {
                info.undecoded = true;
            }
            utf::utf8(body)
        }
    };
    let text: Vec<u32> = text.into_iter().map(|c| if (0xD800..0xE000).contains(&c) { cjk::REPLACEMENT } else { c }).collect();
    (normalize_newlines(&text), info)
}

/// A rule of the pack (`name`: a map of id, name, type, sev, msg, why, fix, ref) as make_issues takes it, its
/// message's {encoding} filled.
fn rule_value(p: &crate::pack::Pack, name: &str, encoding: &str) -> crate::json::Value {
    use crate::json::Value;
    let keys = ["id", "name", "type", "sev", "msg", "why", "fix", "ref"];
    Value::Obj(keys.iter().map(|k| {
        let mut v = p.map_text(name, k);
        if *k == "msg" {
            let s = crate::pystr::to_string(&v).replace("{encoding}", encoding);
            v = crate::pystr::u(&s);
        }
        (crate::pystr::u(k), Value::Str(v))
    }).collect())
}

/// encoding_issues: for a file whose decoding is reported, Q-ENCODING (line 1), SC-UTF7 and SC-ESCAPE-CODEC (the
/// cookie's line), their snippets redacted with the file's own entropy literals and PEM blocks when `redact`; and
/// SC-TRUNCATED for a codec the engine does not decode. The engine's issue arrays (rule, name, type, sev, msg, why,
/// fix, ref, line, snippet, snipStart).
pub fn encoding_issues(p: &crate::pack::Pack, text: &[u32], info: &Info, redact: bool) -> Vec<crate::json::Value> {
    use crate::json::Value;
    if !info.reported {
        return Vec::new();
    }
    let line = info.cookie_line.unwrap_or(1) as i64;
    let mut items = vec![Value::Arr(vec![rule_value(p, "_ENC_RULE", &info.encoding), Value::Int(1), Value::Null])];
    if info.utf7 {
        items.push(Value::Arr(vec![rule_value(p, "_ENC_UTF7_RULE", &info.encoding), Value::Int(line), Value::Null]));
    }
    if info.escapes {
        items.push(Value::Arr(vec![rule_value(p, "_ENC_ESCAPE_CODEC_RULE", &info.encoding), Value::Int(line), Value::Null]));
    }
    let mut out = crate::redact::make_issues(p, text, &items, redact, true, false);
    if info.undecoded {
        out.push(crate::manifest::gyp::truncated_issue(
            p,
            &format!("its source encoding ({}) is not decoded by Lazaret; the file was read as UTF-8", info.encoding),
        ));
    }
    out
}

/// decode_member's measure of a file that does not read as text: the share of U+FFFD and of characters text does
/// not hold (C0 controls but whitespace and ESC, DEL, and the bytes surrogateescape keeps) among its first 65,536.
pub fn undecodable_share(text: &[u32]) -> f64 {
    let sample = &text[..text.len().min(65536)];
    if sample.is_empty() {
        return 0.0;
    }
    let bad = sample.iter().filter(|&&c| {
        c == 0xFFFD || c <= 0x08 || (0x0E..=0x1A).contains(&c) || (0x1C..=0x1F).contains(&c) || c == 0x7F
            || (0xDC80..=0xDCFF).contains(&c)
    }).count();
    bad as f64 / sample.len() as f64
}

/// More than this share of a file not text (undecodable_share): it was not read, SC-TRUNCATED.
pub const NON_TEXT_SHARE: f64 = 0.30;

/// Python's f"{x:.0%}": x * 100 rounded half to even on its exact binary value.
pub fn percent(x: f64) -> String {
    format!("{:.0}%", x * 100.0)
}

/// decode_member's finding for a file that does not decode to anything text-like (more than NON_TEXT_SHARE
/// not text, and not a video under TypeScript's extensions): SC-TRUNCATED, its scan proves nothing.
pub fn not_text_issue(p: &crate::pack::Pack, text: &[u32], name: &[u32], windows: bool, data: &[u8]) -> Option<crate::json::Value> {
    let share = undecodable_share(text);
    if share <= NON_TEXT_SHARE || crate::binary::mpeg_ts_named(p, name, windows, data) {
        return None;
    }
    Some(crate::manifest::gyp::truncated_issue(
        p,
        &format!("content is not decodable as text ({} invalid bytes or control characters), so no rule could read it", percent(share)),
    ))
}

/// An info object as info_value gives it, read back (the encoding_issues call's).
pub fn info_arg(v: Option<&crate::json::Value>) -> Result<Info, String> {
    use crate::json::Value;
    let Some(Value::Obj(_)) = v else {
        return Err("info is decode_source's info object".into());
    };
    let v = v.unwrap();
    let flag = |k: &str| matches!(v.get(k), Some(Value::Bool(true)));
    let encoding = match v.get("encoding") {
        Some(Value::Str(s)) => crate::pystr::to_string(s),
        _ => return Err("info.encoding is a string".into()),
    };
    let cookie_line = match v.get("cookieLine") {
        None | Some(Value::Null) => None,
        Some(Value::Int(n)) if *n >= 1 => Some(*n as usize),
        _ => return Err("info.cookieLine is a line number or null".into()),
    };
    Ok(Info { encoding, reported: flag("reported"), utf7: flag("utf7"), cookie_line, escapes: flag("escapes"), undecoded: flag("undecoded") })
}

/// What decode_source says of a file, as its answer gives it (core's info dict's keys).
pub fn info_value(info: &Info) -> crate::json::Value {
    use crate::json::Value;
    let mut items = vec![
        ("encoding", Value::str(&info.encoding)),
        ("reported", Value::Bool(info.reported)),
        ("utf7", Value::Bool(info.utf7)),
        ("cookieLine", info.cookie_line.map_or(Value::Null, |l| Value::Int(l as i64))),
    ];
    if info.escapes {
        items.push(("escapes", Value::Bool(true)));
    }
    if info.undecoded {
        items.push(("undecoded", Value::Bool(true)));
    }
    Value::obj(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sniff_reads_a_byte_order_mark_or_a_nul_in_the_first_four_bytes() {
        // (codec, reported, the byte order mark's bytes): FIX-SPEC 4's table
        for (head, want) in [
            (&b"\xff\xfeA\x00"[..], ("utf-16-le", true, 2)),
            (b"\xfe\xff\x00A", ("utf-16-be", true, 2)),
            (b"\xef\xbb\xbfx", ("utf-8-sig", true, 0)),
            (b"i\x00m\x00", ("utf-16-le", true, 0)), // NUL at index 1
            (b"im\x00\x00", ("utf-16-le", true, 0)), // NUL at index 3 (and 2)
            (b"\x00i\x00m", ("utf-16-be", true, 0)), // NUL at index 0 / 2
            (b"\x00\x05\x16\x07", ("utf-16-be", true, 0)), // AppleDouble magic
            (b"imp\x00", ("utf-16-le", true, 0)),
            (b"import os", ("utf-8", false, 0)),
            (b"ab", ("utf-8", false, 0)),
            (b"", ("utf-8", false, 0)),
        ] {
            assert_eq!(detect_encoding(&head[..head.len().min(4)]), want, "{head:?}");
        }
    }

    #[test]
    fn a_utf16_guess_is_kept_when_seven_in_ten_of_its_first_2048_characters_are_plain() {
        let u = |s: &str| s.chars().map(|c| c as u32).collect::<Vec<u32>>();
        assert!(!text_is_plausible(&[]));
        assert!(text_is_plausible(&u(&("a".repeat(7) + &"\u{4e00}".repeat(3))))); // exactly 70%
        assert!(!text_is_plausible(&u(&("a".repeat(69) + &"\u{4e00}".repeat(31)))));
        assert!(text_is_plausible(&u("\t\r\n ~")));
        assert!(!text_is_plausible(&u("\u{7f}\u{1f}\u{80}")));
        // characters, not UTF-16 units: 600 astral and 1448 ASCII of the first 2048
        assert!(text_is_plausible(&u(&("\u{1F600}".repeat(600) + &"a".repeat(5000)))));
        assert!(text_is_plausible(&u(&("a".repeat(2048) + &"\u{4e00}".repeat(10000)))));
    }

    #[test]
    fn percent_rounds_as_python_formats_a_percentage() {
        // f"{x:.0%}" on Python 3.13: half to even on x * 100 as a double
        for (x, want) in [(0.305, "30%"), (0.315, "32%"), (0.325, "32%"), (0.5, "50%"), (0.995, "100%"),
                          (0.3050000001, "31%"), (1.0 / 3.0, "33%"), (2.0 / 3.0, "67%"), (0.505, "50%"), (0.425, "42%"),
                          (0.435, "44%"), (0.445, "44%"), (0.455, "46%"), (0.495, "50%")] {
            assert_eq!(percent(x), want, "{x}");
        }
    }

    #[test]
    fn the_undecodable_share_counts_replacements_and_controls_in_the_first_65536() {
        let u = |s: &str| s.chars().map(|c| c as u32).collect::<Vec<u32>>();
        assert_eq!(undecodable_share(&[]), 0.0);
        assert_eq!(undecodable_share(&u("ab\u{fffd}\u{0}")), 0.5);
        assert_eq!(undecodable_share(&u("\t\n\r\u{b}\u{c}\u{1b} ")), 0.0);
        let mut controls = u("\u{1}\u{8}\u{e}\u{1a}\u{1c}\u{1f}\u{7f}");
        controls.push(0xDC80);
        assert_eq!(undecodable_share(&controls), 1.0);
        let mut long = vec!['a' as u32; 65536];
        long.extend(vec![0u32; 100_000]);
        assert_eq!(undecodable_share(&long), 0.0);
    }

    #[test]
    fn info_reads_back_as_info_value_writes_it() {
        let info = Info { encoding: "cp037".into(), reported: true, utf7: false, cookie_line: Some(2), escapes: true, undecoded: true };
        let back = info_arg(Some(&info_value(&info))).unwrap();
        assert_eq!((back.encoding.as_str(), back.reported, back.utf7, back.cookie_line, back.escapes, back.undecoded),
                   ("cp037", true, false, Some(2), true, true));
        assert!(info_arg(None).is_err());
        assert!(info_arg(Some(&crate::json::Value::Int(1))).is_err());
    }
}
