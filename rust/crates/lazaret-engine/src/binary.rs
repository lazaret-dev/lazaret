//! Binary and compiled artifacts, bytecode and .pth files (BR-7 step 3 d, 0.1.9; core's looks_binary,
//! classify_binary, disguised_binary, pyc_issues and pth_issues, and the npm package's binary.js and pth.js, until
//! then). A file's bytes come as text, a character per byte (latin-1): `bytes_of`.

use crate::findings::{format, Arg, Finding, RuleText, Snippets};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};

/// The bytes a text of latin-1 characters stands for (None: a character past U+00FF).
pub fn bytes_of(text: &[u32]) -> Option<Vec<u8>> {
    text.iter().map(|&c| u8::try_from(c).ok()).collect()
}

/// The length of the UTF-8 sequence that starts at `i` when it is a valid one (CPython's decoder: no overlong
/// forms, no surrogates, nothing past U+10FFFF), else None.
fn utf8_len(b: &[u8], i: usize) -> Option<usize> {
    let c = b[i];
    let cont = |k: usize, lo: u8, hi: u8| b.get(i + k).is_some_and(|&x| (lo..=hi).contains(&x));
    match c {
        0x00..=0x7F => Some(1),
        0xC2..=0xDF if cont(1, 0x80, 0xBF) => Some(2),
        0xE0 if cont(1, 0xA0, 0xBF) && cont(2, 0x80, 0xBF) => Some(3),
        0xE1..=0xEC | 0xEE..=0xEF if cont(1, 0x80, 0xBF) && cont(2, 0x80, 0xBF) => Some(3),
        0xED if cont(1, 0x80, 0x9F) && cont(2, 0x80, 0xBF) => Some(3),
        0xF0 if cont(1, 0x90, 0xBF) && cont(2, 0x80, 0xBF) && cont(3, 0x80, 0xBF) => Some(4),
        0xF1..=0xF3 if cont(1, 0x80, 0xBF) && cont(2, 0x80, 0xBF) && cont(3, 0x80, 0xBF) => Some(4),
        0xF4 if cont(1, 0x80, 0x8F) && cont(2, 0x80, 0xBF) && cont(3, 0x80, 0xBF) => Some(4),
        _ => None,
    }
}

/// core._NON_TEXT_CHARS_RE's controls: C0 but whitespace and ESC, and DEL.
fn non_text(c: u8) -> bool {
    matches!(c, 0x00..=0x08 | 0x0E..=0x1A | 0x1C..=0x1F | 0x7F)
}

/// core.looks_binary: more than _NON_TEXT_SHARE of `sample`'s bytes cannot be text (the bytes of invalid UTF-8,
/// each one a surrogate escape when Python decodes it, and the controls of `non_text`).
pub fn looks_binary(p: &Pack, sample: &[u8]) -> bool {
    if sample.is_empty() {
        return false;
    }
    let (mut bad, mut i) = (0usize, 0usize);
    while i < sample.len() {
        match utf8_len(sample, i) {
            Some(n) => {
                if n == 1 && non_text(sample[i]) {
                    bad += 1;
                }
                i += n;
            }
            None => {
                bad += 1;
                i += 1;
            }
        }
    }
    bad as f64 / sample.len() as f64 > p.float("_NON_TEXT_SHARE")
}

/// core._mpeg_ts: an MPEG transport stream's sync byte every 188 bytes.
pub fn mpeg_ts(header: &[u8]) -> bool {
    header.len() >= 377 && header[0] == 0x47 && header[188] == 0x47 && header[376] == 0x47
}

/// A list of [signature, words] pairs (EXEC_MAGIC, NESTED_ARCHIVE_MAGIC): signatures as latin-1 text.
fn pairs<'a>(p: &'a Pack, name: &str) -> &'a [(Vec<u8>, PyStr)] {
    p.derived(name, |v| {
        v.get("list")
            .and_then(|l| l.as_arr())
            .unwrap_or(&[])
            .iter()
            .filter_map(|it| {
                let a = it.get("list")?.as_arr()?;
                let sig = bytes_of(a.first()?.get("value")?.as_str()?)?;
                Some((sig, a.get(1)?.get("value")?.as_str()?.to_vec()))
            })
            .collect::<Vec<_>>()
    })
}

fn sigs<'a>(p: &'a Pack, name: &str) -> &'a [Vec<u8>] {
    p.derived(name, |v| {
        v.get("list")
            .and_then(|l| l.as_arr())
            .unwrap_or(&[])
            .iter()
            .filter_map(|it| bytes_of(it.get("value")?.as_str()?))
            .collect::<Vec<_>>()
    })
}

fn has(p: &Pack, name: &str, s: &[u32]) -> bool {
    p.strs(name).iter().any(|x| x.as_slice() == s)
}

/// What a program's first bytes say it is (EXEC_MAGIC), or None.
fn program(p: &Pack, header: &[u8]) -> Option<PyStr> {
    pairs(p, "EXEC_MAGIC").iter().find(|(sig, _)| header.starts_with(sig)).map(|(_, d)| d.clone())
}

/// os.path.splitext(path)[1] and os.path.basename(path), with "\\" a separator too where `windows`.
pub fn ext_and_base(path: &[u32], windows: bool) -> (PyStr, PyStr) {
    let sep = path.iter().rposition(|&c| c == '/' as u32 || (windows && c == '\\' as u32));
    let start = sep.map_or(0, |s| s + 1);
    let base = path[start..].to_vec();
    let ext = match path.iter().rposition(|&c| c == '.' as u32) {
        Some(dot) if dot >= start && path[start..dot].iter().any(|&c| c != '.' as u32) => path[dot..].to_vec(),
        _ => Vec::new(),
    };
    (ext, base)
}

/// decode_member's exception to "not text": an MPEG transport stream under one of its extensions (MPEG_TS_EXTS:
/// TypeScript's too) is a video, not source that failed to decode.
pub(crate) fn mpeg_ts_named(p: &Pack, path: &[u32], windows: bool, data: &[u8]) -> bool {
    let ext = pystr::lower(&ext_and_base(path, windows).0);
    has(p, "MPEG_TS_EXTS", &ext) && mpeg_ts(&data[..data.len().min(512)])
}

/// core.is_benign_media: an image, font, media or document format by its signature, a colour profile, a video
/// under TypeScript's extensions, a font by its extension and first bytes.
fn benign_media(p: &Pack, header: &[u8], ext: &[u32]) -> bool {
    if sigs(p, "BENIGN_MAGIC").iter().any(|sig| header.starts_with(sig))
        || header[..header.len().min(16)].windows(4).any(|w| w == b"ftyp")
    {
        return true;
    }
    if header.get(36..40) == Some(b"acsp") {
        return true;
    }
    if has(p, "MPEG_TS_EXTS", ext) && mpeg_ts(header) {
        return true;
    }
    has(p, "FONT_EXTS", ext) && sigs(p, "_FONT_MAGIC").iter().any(|m| header.get(..4) == Some(m.as_slice()))
}

/// core.byte_entropy: -sum(p * log2(p)) over the byte values in order, summed as this Python's sum() adds floats.
pub fn byte_entropy(data: &[u8], neumaier: bool) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let (mut total, mut comp, mut first) = (0.0f64, 0.0f64, true);
    for &c in freq.iter().filter(|&&c| c > 0) {
        let q = c as f64 / n;
        let x = q * q.log2();
        if first {
            total = x;
            first = false;
        } else if neumaier {
            let sum = total + x;
            comp += if total.abs() >= x.abs() { (total - sum) + x } else { (x - sum) + total };
            total = sum;
        } else {
            total += x;
        }
    }
    if neumaier && comp != 0.0 && comp.is_finite() {
        total += comp;
    }
    -total
}

/// A file-level finding (line 1, no snippet), as core's issue() helpers make them.
fn file_issue(rule: RuleText, msg: PyStr) -> Value {
    let mut r = rule;
    r.msg = msg;
    Value::Arr(vec![
        Value::Str(r.id),
        Value::Str(r.name),
        Value::Str(r.typ),
        Value::Str(r.sev),
        Value::Str(r.msg),
        Value::Str(r.why),
        Value::Str(r.fix),
        Value::Str(r.ref_),
        Value::Int(1),
        Value::Arr(Vec::new()),
        Value::Int(1),
    ])
}

fn s(x: &[u32]) -> Arg {
    Arg::S(x.to_vec())
}

/// core.classify_binary: the SC-BINARY, SC-NESTED-ARCHIVE or SC-OPAQUE-BLOB finding of a file that is not source,
/// from its leading bytes (`data`: at least _OPAQUE_SAMPLE of them when it has as many) and its `size`; `context` is
/// "sdist", "npm", "wheel" or "repo". None for an asset, a document container, or a file that says nothing.
pub fn classify(p: &Pack, path: &[u32], data: &[u8], size: u64, context: &str, windows: bool, neumaier: bool) -> Option<Value> {
    let header = &data[..data.len().min(512)];
    let ext = pystr::lower(&ext_and_base(path, windows).0);
    let is_bin = looks_binary(p, &data[..data.len().min(p.usize("_LOOKS_SAMPLE"))]);
    let mut desc = program(p, header);
    if desc.is_none() && is_bin && header.starts_with(b"MZ") {
        desc = Some(p.text("_PE_DESC"));
    }
    if desc.is_none() && has(p, "COMPILED_EXTS", &ext) {
        desc = Some(pystr::u(&format!("compiled artifact ({})", pystr::to_string(&ext))));
    }
    if let Some(desc) = desc {
        if context == "wheel" {
            let r = RuleText::of(p, "_BIN_WHEEL_RULE");
            let msg = format(&r.msg, &[("desc", s(&desc))]);
            return Some(file_issue(r, msg));
        }
        let wheres = p.map_strs("_BINARY_WHERE");
        let where_ = wheres
            .iter()
            .find(|(k, _)| pystr::eq(k, context))
            .and_then(|(_, v)| v.first().cloned())
            .unwrap_or_else(|| p.text("_BINARY_WHERE_ELSE"));
        let r = RuleText::of(p, "_BIN_RULE");
        let msg = format(&r.msg, &[("where", s(&where_)), ("desc", s(&desc))]);
        return Some(file_issue(r, msg));
    }
    if has(p, "CONTAINER_DOCUMENT_EXTS", &ext) {
        return None;
    }
    if header.get(257..262) == Some(b"ustar") {
        let r = RuleText::of(p, "_BIN_TAR_RULE");
        let msg = r.msg.clone();
        return Some(file_issue(r, msg));
    }
    for (sig, kind) in pairs(p, "NESTED_ARCHIVE_MAGIC") {
        if header.starts_with(sig) {
            if context == "wheel" && pystr::eq(kind, "zip") {
                break;
            }
            let r = RuleText::of(p, "_BIN_NESTED_RULE");
            let msg = format(&r.msg, &[("kind", s(kind))]);
            return Some(file_issue(r, msg));
        }
    }
    if benign_media(p, header, &ext) {
        return None;
    }
    if is_bin && size >= p.int("_OPAQUE_MIN_SIZE") as u64 {
        let ent = byte_entropy(&data[..data.len().min(p.usize("_OPAQUE_SAMPLE"))], neumaier);
        if ent > p.float("_OPAQUE_ENTROPY") {
            let r = RuleText::of(p, "_BIN_OPAQUE_RULE");
            let msg = format(
                &r.msg,
                &[("size", Arg::I(size as i64)), ("entropy", Arg::S(pystr::u(&format!("{:.1}", ent))))],
            );
            return Some(file_issue(r, msg));
        }
    }
    None
}

/// core.disguised_binary: SC-BINARY, CRITICAL, for a program's bytes (EXEC_MAGIC, a Windows PE) in a file named as
/// source code; else None.
pub fn disguised(p: &Pack, path: &[u32], data: &[u8], windows: bool) -> Option<Value> {
    let header = &data[..data.len().min(512)];
    let desc = program(p, header).or_else(|| header.starts_with(b"MZ").then(|| p.text("_PE_DESC")))?;
    if !looks_binary(p, &data[..data.len().min(p.usize("DISGUISE_SAMPLE_BYTES"))]) {
        return None;
    }
    let base = ext_and_base(path, windows).1;
    let r = RuleText::of(p, "_BIN_DISGUISED_RULE");
    let msg = format(&r.msg, &[("base", s(&base)), ("desc", s(&desc))]);
    Some(file_issue(r, msg))
}

/// The registry's _native_program: a program the system loads (EXEC_MAGIC, a PE), binary bytes only.
pub fn native_program(p: &Pack, raw: &[u8]) -> bool {
    looks_binary(p, &raw[..raw.len().min(p.usize("_LOOKS_SAMPLE"))])
        && (program(p, raw).is_some() || raw.starts_with(b"MZ"))
}

/// core.pyc_issues: SC-PYC-UNCHECKED for an unchecked-hash .pyc (PEP 552: flags 0b01 after the magic's "\r\n"),
/// SC-PYC-ORPHAN when no source sits next to its __pycache__.
pub fn pyc_issues(p: &Pack, path: &[u32], header: &[u8], has_source: bool) -> Vec<Value> {
    let mut out = Vec::new();
    if header.len() >= 8 && &header[2..4] == b"\r\n" && u32::from_le_bytes([header[4], header[5], header[6], header[7]]) == 1 {
        let r = RuleText::of(p, "_PYC_UNCHECKED_RULE");
        let msg = format(&r.msg, &[("path", s(path))]);
        out.push(file_issue(r, msg));
    }
    if !has_source {
        let r = RuleText::of(p, "_PYC_ORPHAN_RULE");
        let msg = format(&r.msg, &[("path", s(path))]);
        out.push(file_issue(r, msg));
    }
    out
}

/// core.normalize_newlines: CRLF and CR to LF.
fn normalize_newlines(text: &[u32]) -> PyStr {
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

/// str.splitlines()' line ends, but for \n and \r (a normalized line has neither).
fn splitlines_break(c: u32) -> bool {
    matches!(c, 0x0B | 0x0C | 0x1C | 0x1D | 0x1E | 0x85 | 0x2028 | 0x2029)
}

/// core.pth_issues: SC-PTH-EXEC for each line of a .pth file site.py runs (a line, or a part of it as
/// str.splitlines() splits it, that starts with "import " or "import\t"): CRITICAL when the line does what
/// signs::pth_line_risk looks for, MAJOR otherwise; reported at the physical line, its snippet mk_issue's with no
/// scan context.
pub fn pth_issues(p: &Pack, text: &[u32], redact: bool, neumaier: bool) -> Vec<Value> {
    let norm = normalize_newlines(text);
    let lines = pystr::split_char(&norm, '\n' as u32);
    let prefixes = p.strs("_PTH_IMPORT");
    let runs = |l: &[u32]| prefixes.iter().any(|pre| l.starts_with(pre));
    let payload = p.strs("_PTH_REASONS")[0].clone();
    let mut found = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let hit = runs(line) || line.split(|&c| splitlines_break(c)).any(runs);
        if !hit {
            continue;
        }
        let reasons = crate::signs::pth_line_risk(p, line);
        let tail = if reasons.is_empty() {
            pystr::u(".")
        } else if reasons.contains(&payload) {
            p.text("_PTH_PAYLOAD_TAIL")
        } else {
            let parts: Vec<&[u32]> = reasons.iter().map(|r| r.as_slice()).collect();
            let mut t = pystr::u(", and it ");
            t.extend(pystr::join(&pystr::u("; and "), &parts));
            t.push('.' as u32);
            t
        };
        let mut r = RuleText::of(p, "_PTH_RULE");
        r.msg = format(&r.msg, &[("tail", Arg::S(tail))]);
        if !reasons.is_empty() {
            r.sev = pystr::u("CRITICAL");
        }
        found.push(Finding::new(r, i + 1, None));
    }
    let snippets = Snippets::new(p, lines, redact, neumaier).plain();
    found.iter().map(|f| snippets.issue(f)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_and_names() {
        let p = crate::pack::current();
        assert!(!looks_binary(&p, b""));
        assert!(!looks_binary(&p, "caf\u{e9} \u{1F600} text\n\t".as_bytes()));
        assert!(looks_binary(&p, b"\x00\x01\x02abc"));
        assert!(looks_binary(&p, b"\xff\xfe\xfdab"));
        assert!(!looks_binary(&p, b"\xe2\x82abcdefghij"));            // 2 of 12
        assert!(looks_binary(&p, b"\xed\xa0\x80abcd"));                 // a surrogate's three bytes
        let u = pystr::u;
        assert_eq!(ext_and_base(&u("a/b.tar.GZ"), false), (u(".GZ"), u("b.tar.GZ")));
        assert_eq!(ext_and_base(&u("a/..js"), false), (u(""), u("..js")));
        assert_eq!(ext_and_base(&u("a\\b.so"), false), (u(".so"), u("a\\b.so")));
        assert_eq!(ext_and_base(&u("a\\b.so"), true), (u(".so"), u("b.so")));
        assert_eq!(byte_entropy(&[7u8; 10], false), 0.0);
        assert!((byte_entropy(&(0..=255).collect::<Vec<u8>>(), false) - 8.0).abs() < 1e-12);
        let elf = classify(&p, &u("x/a.bin"), b"\x7fELF\x02\x01\x01\x00", 900, "npm", false, false).unwrap();
        assert_eq!(elf.as_arr().unwrap()[0], Value::Str(u("SC-BINARY")));
        assert!(classify(&p, &u("x/a.bin"), b"\x7fELF", 9, "wheel", false, false).is_some());
        assert!(classify(&p, &u("a.png"), b"\x89PNG\r\n\x1a\n", 9, "repo", false, false).is_none());
        assert!(disguised(&p, &u("a.py"), b"MZ\x90\x00\x03\x00\x00\x00\x04\x00", false).is_some());
        assert!(disguised(&p, &u("a.py"), b"MZ=1; print(1)", false).is_none());
        let pyc = pyc_issues(&p, &u("__pycache__/a.cpython-311.pyc"), b"\xa7\r\r\n\x01\x00\x00\x00", false);
        assert_eq!(pyc.len(), 2);
        let pth = pth_issues(&p, &u("x\r\n# n\x0cimport os\nimport sys; exec('1')\n"), true, false);
        assert_eq!(pth.len(), 2);
        assert_eq!(pth[0].as_arr().unwrap()[8], Value::Int(2));
    }
}
