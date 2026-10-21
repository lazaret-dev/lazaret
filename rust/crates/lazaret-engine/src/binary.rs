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

/// An image or document format by its first bytes alone (UNWALKED_MAGIC: PDF, PostScript, Photoshop, JPEG 2000's
/// codestream, DDS, GIMP's, SGI's, Sun's, FITS, QOI and Radiance images), as core.is_benign_media judged every
/// format until FP-OPAQUE-MEDIA. The formats media.rs walks (sound, video, images, fonts, colour profiles) are no
/// longer taken by their first bytes: a file is one of them when it is one to its end.
fn unwalked_format(p: &Pack, header: &[u8]) -> bool {
    sigs(p, "UNWALKED_MAGIC").iter().any(|sig| header.starts_with(sig))
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

/// A file-level finding with its rule's message as it is.
pub(crate) fn file_issue_of(rule: RuleText) -> Value {
    let msg = rule.msg.clone();
    file_issue(rule, msg)
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

/// What the caller can give of a file past its first bytes (FP-OPAQUE-MEDIA).
#[derive(Clone, Copy, Debug)]
pub enum More<'a> {
    /// nothing: a file whose first bytes start a format that is walked, or a keystore, is judged without the walk
    /// (an opaque blob stays one)
    No,
    /// the caller reads the whole file, or walks it as its stream passes (media::feed), when asked (Classified::Need)
    Ask,
    /// the whole file
    Whole(&'a [u8]),
    /// a walk of the whole file, as its stream passed
    Walked(&'a crate::media::Walked),
    /// a Gradle wrapper jar (FP-GRADLE-WRAPPER): its bytes (None when it was not read whole) and its
    /// gradle-wrapper.properties, as its host found it
    Wrapper { jar: Option<&'a [u8]>, props: crate::gradle::Sibling<'a> },
}

/// classify_more's answer.
#[derive(Clone, Debug, PartialEq)]
pub enum Classified {
    Issue(Value),
    /// a keystore whose unread bytes are more than a keystore's (S-SECRET and SC-OPAQUE-BLOB, in that order)
    Issues(Vec<Value>),
    Quiet,
    /// the whole file is needed (More::Ask): its bytes (More::Whole), or its walk (More::Walked) when it is too
    /// large to read whole
    Need,
    /// a Gradle wrapper jar: its bytes and the gradle-wrapper.properties beside it are needed (More::Wrapper)
    Wrapper,
}

/// core.classify_binary: the SC-BINARY, SC-NESTED-ARCHIVE or SC-OPAQUE-BLOB finding of a file that is not source,
/// from its leading bytes (`data`: at least _OPAQUE_SAMPLE of them when it has as many) and its `size`; `context` is
/// "sdist", "npm", "wheel" or "repo". None for an asset, a document container, or a file that says nothing. A
/// keystore is S-SECRET, and a near-random file that is a sound, video, image or font to its end is quiet, only
/// when the whole file is given (classify_more; here it is not).
pub fn classify(p: &Pack, path: &[u32], data: &[u8], size: u64, context: &str, windows: bool, neumaier: bool) -> Option<Value> {
    match classify_more(p, path, data, size, context, windows, neumaier, More::No) {
        Classified::Issue(v) => Some(v),
        _ => None,
    }
}

/// classify, with what the caller can give past the first bytes (`more`): a keystore read to its end is S-SECRET
/// (media::keystore), and a file that would be an opaque blob is quiet when it is a format media.rs walks, read to
/// its end (FP-OPAQUE-MEDIA). With More::Ask, Need when that takes the whole file. A Gradle wrapper jar
/// (`gradle/wrapper/gradle-wrapper.jar`) is judged by its checksum with More::Wrapper (gradle.rs: FP-GRADLE-WRAPPER),
/// which More::Ask and More::Whole ask for (Classified::Wrapper); given its first bytes alone, it is any jar.
#[allow(clippy::too_many_arguments)]
pub fn classify_more(p: &Pack, path: &[u32], data: &[u8], size: u64, context: &str, windows: bool, neumaier: bool,
                     more: More) -> Classified {
    if crate::gradle::wrapper_path(path, windows) {
        match more {
            More::Wrapper { jar, props } => {
                return match crate::gradle::judge(p, jar, props, size) {
                    Some(v) => Classified::Issue(v),
                    None => Classified::Quiet,
                };
            }
            More::Ask | More::Whole(_) => return Classified::Wrapper,
            More::No | More::Walked(_) => {}
        }
    }
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
            return Classified::Issue(file_issue(r, msg));
        }
        let wheres = p.map_strs("_BINARY_WHERE");
        let where_ = wheres
            .iter()
            .find(|(k, _)| pystr::eq(k, context))
            .and_then(|(_, v)| v.first().cloned())
            .unwrap_or_else(|| p.text("_BINARY_WHERE_ELSE"));
        let r = RuleText::of(p, "_BIN_RULE");
        let msg = format(&r.msg, &[("where", s(&where_)), ("desc", s(&desc))]);
        return Classified::Issue(file_issue(r, msg));
    }
    if has(p, "CONTAINER_DOCUMENT_EXTS", &ext) {
        return Classified::Quiet;
    }
    if header.get(257..262) == Some(b"ustar") {
        let r = RuleText::of(p, "_BIN_TAR_RULE");
        let msg = r.msg.clone();
        return Classified::Issue(file_issue(r, msg));
    }
    for (sig, kind) in pairs(p, "NESTED_ARCHIVE_MAGIC") {
        if header.starts_with(sig) {
            if context == "wheel" && pystr::eq(kind, "zip") {
                break;
            }
            let r = RuleText::of(p, "_BIN_NESTED_RULE");
            let msg = format(&r.msg, &[("kind", s(kind))]);
            return Classified::Issue(file_issue(r, msg));
        }
    }
    // a keystore read to its end is a credential file, whatever its entropy (S-SECRET: listed, setting no verdict)
    if crate::media::keystore::sniff(header) {
        match more {
            More::Whole(whole) => {
                if let Ok(k) = crate::media::keystore::read(whole) {
                    let issue = keystore_issue(p, &k);
                    // (bytes no structure reads, more than a real keystore holds: an opaque blob too)
                    let (one, all) = (p.int("KEYSTORE_ELEMENT_MAX_BYTES") as u64, p.int("KEYSTORE_OPAQUE_MAX_BYTES") as u64);
                    if k.largest > one || k.opaque > all {
                        let r = RuleText::of(p, "_BIN_OPAQUE_RULE");
                        let msg = format(&p.text("_KEYSTORE_OPAQUE_MSG"), &[
                            ("size", Arg::I(size as i64)), ("kind", Arg::S(pystr::u(k.kind))),
                            ("largest", Arg::I(k.largest as i64)), ("opaque", Arg::I(k.opaque as i64)),
                            ("one", Arg::I(one as i64)), ("all", Arg::I(all as i64)),
                        ]);
                        return Classified::Issues(vec![issue, file_issue(r, msg)]);
                    }
                    return Classified::Issue(issue);
                }
            }
            More::Ask if size <= p.int("KEYSTORE_MAX_BYTES").max(0) as u64 => return Classified::Need,
            _ => {}
        }
    }
    if unwalked_format(p, header) {
        return Classified::Quiet;
    }
    if !(is_bin && size >= p.int("_OPAQUE_MIN_SIZE") as u64) {
        return Classified::Quiet;
    }
    let ent = byte_entropy(&data[..data.len().min(p.usize("_OPAQUE_SAMPLE"))], neumaier);
    if ent <= p.float("_OPAQUE_ENTROPY") {
        return Classified::Quiet;
    }
    // near-random: a sound, video, image or font when its bytes are that format to the end (media.rs), else opaque
    let starts = crate::media::starts(header);
    let walked = match (more, &starts) {
        (_, None) => None,
        (More::Whole(whole), _) => Some(crate::media::walk(whole)),
        (More::Walked(w), _) => Some(w.clone()),
        (More::Ask, _) => return Classified::Need,
        (More::No | More::Wrapper { .. }, Some(kind)) => {
            Some(crate::media::Walked::Not(kind.clone(), p.string("_OPAQUE_UNREAD")))
        }
    };
    let r = RuleText::of(p, "_BIN_OPAQUE_RULE");
    let (size_a, ent_a) = (Arg::I(size as i64), Arg::S(pystr::u(&format!("{:.1}", ent))));
    let msg = match walked {
        Some(crate::media::Walked::Is(_)) => return Classified::Quiet,
        Some(crate::media::Walked::Not(kind, why)) => format(
            &p.text("_OPAQUE_WALK_MSG"),
            &[("size", size_a), ("entropy", ent_a), ("kind", Arg::S(pystr::u(&kind))), ("why", Arg::S(pystr::u(&why)))],
        ),
        _ => format(&r.msg, &[("size", size_a), ("entropy", ent_a)]),
    };
    Classified::Issue(file_issue(r, msg))
}

/// S-SECRET for a keystore read to its end (FP-OPAQUE-MEDIA): BLOCKER when it holds a private or secret key in the
/// clear part of its structure, MAJOR when its entries are encrypted whole (it may hold one), INFO for certificates
/// alone.
fn keystore_issue(p: &Pack, k: &crate::media::keystore::Keystore) -> Value {
    let rule = if k.keys + k.secrets > 0 {
        "_KEYSTORE_RULE"
    } else if k.sealed > 0 {
        "_KEYSTORE_SEALED_RULE"
    } else {
        "_KEYSTORE_CERTS_RULE"
    };
    let mut parts = Vec::new();
    for (n, one, many) in [(k.keys, "private key", "private keys"), (k.secrets, "secret key", "secret keys"),
                           (k.certs, "certificate", "certificates"), (k.sealed, "encrypted part", "encrypted parts")] {
        if n > 0 {
            parts.push(format!("{n} {}", if n == 1 { one } else { many }));
        }
    }
    let entries = match parts.len() {
        0 => "no entry".to_string(),
        1 => parts[0].clone(),
        n => format!("{} and {}", parts[..n - 1].join(", "), parts[n - 1]),
    };
    let r = RuleText::of(p, rule);
    let msg = format(&r.msg, &[("kind", Arg::S(pystr::u(k.kind))), ("entries", Arg::S(pystr::u(&entries)))]);
    file_issue(r, msg)
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
        // RA-12: CRITICAL for a strong reason, MAJOR for a weaker one (cert-off) alone, MAJOR for none
        if let Some(sev) = crate::signs::install_script_severity(p, &reasons) {
            r.sev = pystr::u(sev);
        }
        found.push(Finding::new(r, i + 1, None));
    }
    let snippets = Snippets::new(p, lines, redact, neumaier).plain();
    found.iter().map(|f| snippets.issue(f)).collect()
}

/// A .pth file too large to read whole, read in chunks for the lines site.py runs (FP-MODEL-FILES, John's decision of
/// Oct 21: a 200 MB `model.pth` checkpoint is judged by its import lines, streamed, and its pickle, read by range). The
/// state between chunks, which the host keeps (`pth_stream`): the line the next byte is on, whether a `\r` ended the
/// last chunk (a `\n` after it is the same line end), and the current line's bytes so far: its last 16 when it holds
/// no import start yet (enough for a start a chunk's end cuts in two), or what is kept of it from its import start,
/// or nothing when that passed PTH_MAX_LINE (cut).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PthStream {
    pub line: u64,
    pub cr: bool,
    pub carry: Vec<u8>,
    /// the carry starts at its line's start
    pub whole: bool,
    /// the carry is what is kept of its line, from an import start
    pub keeping: bool,
    /// the line passed the bound: its bytes are passed over to its end
    pub skipping: bool,
    /// the bytes of the lines kept so far, and whether they reached PTH_MAX_KEPT (no more is kept: a cut)
    pub kept: u64,
    pub full: bool,
}

/// What a chunk of a .pth file gave: each line Python would run whose end it reached ((line, its bytes from its first
/// import start)), and why a line could not be kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PthLines {
    pub lines: Vec<(u64, Vec<u8>)>,
    pub cuts: Vec<String>,
}

/// Where a line's bytes start a line site.py runs, byte-wise and on the safe side whatever the decoding: "import " or
/// "import\t" at the line's start (after a UTF-8 byte order mark on the file's first line), or after a break
/// str.splitlines() splits at (\x0b, \x0c, \x1c to \x1e, \x85, UTF-8's U+0085, U+2028 and U+2029), as pth_issues reads
/// the parts of a line. `whole`: the bytes start at the line's start.
fn pth_import_start(prefixes: &[Vec<u8>], b: &[u8], whole: bool, first_line: bool) -> Option<usize> {
    let first = prefixes.first().and_then(|pre| pre.first()).copied()?;
    debug_assert!(prefixes.iter().all(|pre| pre.first() == Some(&first)));
    let at = |i: usize| (i == 0 && whole)
        || (i == 3 && whole && first_line && b.starts_with(b"\xef\xbb\xbf"))
        || (i >= 1 && matches!(b[i - 1], 0x0B | 0x0C | 0x1C | 0x1D | 0x1E | 0x85))
        || (i >= 3 && (b[i - 3..i] == *b"\xe2\x80\xa8" || b[i - 3..i] == *b"\xe2\x80\xa9"));
    // (each place the prefixes' first byte is, found by a plain scan: a checkpoint's megabytes hold few)
    let mut from = 0;
    while let Some(k) = b[from..].iter().position(|&c| c == first) {
        let i = from + k;
        if prefixes.iter().any(|pre| b[i..].starts_with(pre)) && at(i) {
            return Some(i);
        }
        from = i + 1;
    }
    None
}

/// The next chunk of a .pth file (`end`: its last), read for the lines site.py runs: the lines whose end it reached,
/// and the state for the next chunk. Lines end at \n, \r and \r\n, as pth_issues numbers them; a kept line runs from
/// its first import start to its end, at most PTH_MAX_LINE bytes (more is a cut: SC-TRUNCATED). The chunk is read
/// for the prefixes' first byte and its line ends counted between them, not line by line: a checkpoint's random bytes
/// end a "line" every hundred bytes or so.
pub fn pth_stream(p: &Pack, st: &PthStream, chunk: &[u8], end: bool) -> (PthStream, PthLines) {
    let max = p.usize("PTH_MAX_LINE") as u64;
    let max_kept = p.int("PTH_MAX_KEPT").max(0) as u64;
    // (_PTH_IMPORT's prefixes, ASCII, as bytes)
    let prefixes: Vec<Vec<u8>> = p.strs("_PTH_IMPORT").iter().map(|pre| pre.iter().map(|&c| c as u8).collect()).collect();
    let first = prefixes.first().and_then(|pre| pre.first()).copied().unwrap_or(b'i');
    let mut out = PthLines::default();
    let mut s = st.clone();
    if s.line == 0 {
        s = PthStream { line: 1, whole: true, ..PthStream::default() };
    }
    let mut data = std::mem::take(&mut s.carry);
    data.extend_from_slice(chunk);
    let n = data.len();
    let mut pos = 0usize;
    if s.cr && data.first() == Some(&b'\n') {
        pos = 1;                                  // (\r\n across chunks: one line end)
    }
    s.cr = false;
    let is_break = |c: u8| c == b'\n' || c == b'\r';
    // a line end at k (\r\n counts at its \n; a \r at the chunk's end counts, the \n after it skipped next time)
    let ends_in = |a: usize, b: usize| -> u64 {
        data[a..b].iter().enumerate().filter(|&(k, &c)| c == b'\n' || (c == b'\r' && data.get(a + k + 1) != Some(&b'\n'))).count() as u64
    };
    // (where the content of the line at `from` ends, and where the next line starts), or None
    let line_end = |from: usize| -> Option<(usize, usize)> {
        let e = from + data[from..].iter().position(|&c| is_break(c))?;
        Some((e, if data[e] == b'\r' && data.get(e + 1) == Some(&b'\n') { e + 2 } else { e + 1 }))
    };
    let emit = |s: &mut PthStream, out: &mut PthLines, line: u64, b: &[u8]| {
        let len = b.len() as u64;
        if len > max {
            out.cuts.push(format!("line {line}, which Python would run, is longer than the {} bytes read of a line",
                                  commas(max)));
        } else if !s.full && s.kept + len > max_kept {
            out.cuts.push(format!("the lines Python would run, from line {line}, pass the {} bytes read of them",
                                  commas(max_kept)));
            s.full = true;
        } else if !s.full {
            s.kept += len;
            out.lines.push((line, b.to_vec()));
        }
    };
    // a line the last chunk left: kept from its import start, or passed over to its end
    if s.keeping || s.skipping {
        match line_end(pos) {
            Some((e, after)) => {
                if s.keeping {
                    let line = s.line;
                    emit(&mut s, &mut out, line, &data[pos..e]);
                }
                s.keeping = false;
                s.skipping = false;
                s.whole = true;
                s.line += 1;
                s.cr = data[e] == b'\r' && after == n && !end;
                pos = after;
            }
            None => {
                if s.keeping && end {
                    let line = s.line;
                    emit(&mut s, &mut out, line, &data[pos..]);
                } else if s.keeping {
                    if (n - pos) as u64 > max {
                        let line = s.line;
                        emit(&mut s, &mut out, line, &data[pos..]);      // (the cut)
                        s.keeping = false;
                        s.skipping = true;
                    } else {
                        s.carry = data[pos..].to_vec();
                    }
                }
                return (s, out);
            }
        }
    }
    // each import start, by the prefixes' first byte; the line ends before it counted
    let mut counted = pos;                        // line ends counted up to here
    let mut line_start = pos;                     // the current line's first byte here
    let mut whole = s.whole;                      // ... and whether it is the line's own first byte
    let mut from = pos;
    while let Some(k) = data[from..].iter().position(|&c| c == first) {
        let i = from + k;
        from = i + 1;
        if !prefixes.iter().any(|pre| data[i..].starts_with(pre)) {
            continue;
        }
        if let Some(r) = data[counted..i].iter().rposition(|&c| is_break(c)) {
            let ls = counted + r + 1;
            s.line += ends_in(counted, ls);
            counted = ls;
            line_start = ls;
            whole = true;
        }
        if pth_import_start(&prefixes, &data[line_start..i + prefixes[0].len().min(n - i)], whole, s.line == 1)
            != Some(i - line_start)
        {
            continue;
        }
        let line = s.line;
        match line_end(i) {
            Some((e, after)) => {
                emit(&mut s, &mut out, line, &data[i..e]);
                s.line += 1;
                s.cr = data[e] == b'\r' && after == n && !end;
                counted = after;
                line_start = after;
                whole = true;
                from = after;
            }
            None if end => {
                emit(&mut s, &mut out, line, &data[i..]);
                return (s, out);
            }
            None => {
                // the line goes on in the next chunk: kept from here
                if (n - i) as u64 > max {
                    emit(&mut s, &mut out, line, &data[i..]);            // (the cut)
                    s.skipping = true;
                } else {
                    s.carry = data[i..].to_vec();
                    s.keeping = true;
                }
                return (s, out);
            }
        }
    }
    // no more: the line ends left counted, the last line's last 16 bytes carried (a start a chunk's end cuts in two)
    let last = data[counted..].iter().rposition(|&c| is_break(c)).map(|r| counted + r);
    s.line += ends_in(counted, n);
    if let Some(e) = last {
        s.cr = data[e] == b'\r' && e + 1 == n && !end;
        line_start = e + 1;
        whole = true;
    }
    if !end {
        let tail = &data[line_start..];
        if tail.len() > 16 {
            s.carry = tail[tail.len() - 16..].to_vec();
            s.whole = false;
        } else {
            s.carry = tail.to_vec();
            s.whole = whole;
        }
    }
    (s, out)
}

/// A .pth file read whole, by the rule a .pth file read in chunks is read by (M1, the external review of Oct 21: the
/// whole file's text was split as UTF-8 alone, a chunk's bytes byte-wise, so a lone \x85 — U+0085 under the
/// locale's latin-1 that site.py falls back to — split a line in one route and not the other): its kept lines checked
/// at their lines (pth_kept_issues), and why a line could not be kept (SC-TRUNCATED).
pub fn pth_bytes_issues(p: &Pack, data: &[u8], redact: bool, neumaier: bool) -> (Vec<Value>, Vec<String>) {
    let (_, got) = pth_stream(p, &PthStream::default(), data, true);
    (pth_kept_issues(p, &got.lines, redact, neumaier), got.cuts)
}

/// core.pth_issues for the lines pth_stream kept of a .pth file read in chunks: each read as pth_issues reads a line,
/// at its line in the file.
pub fn pth_kept_issues(p: &Pack, lines: &[(u64, Vec<u8>)], redact: bool, neumaier: bool) -> Vec<Value> {
    let mut out = Vec::new();
    for (n, b) in lines {
        for mut issue in pth_issues(p, &crate::decode::utf::utf8(b), redact, neumaier) {
            if let Value::Arr(a) = &mut issue {
                if a.len() > 10 {
                    a[8] = Value::Int(*n as i64);
                    a[10] = Value::Int(*n as i64);
                }
            }
            out.push(issue);
        }
    }
    out
}

fn commas(n: u64) -> String {
    let d = n.to_string();
    let mut out = String::new();
    for (k, c) in d.chars().enumerate() {
        if k > 0 && (d.len() - k) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
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

    /// A .pth file read in chunks of `size` bytes (and an empty last one, as a host reads to its end) -> its kept
    /// lines and cuts.
    fn streamed(p: &Pack, data: &[u8], size: usize, empty_end: bool) -> PthLines {
        let mut st = PthStream::default();
        let mut all = PthLines::default();
        let chunks: Vec<&[u8]> = data.chunks(size.max(1)).collect();
        for (k, c) in chunks.iter().enumerate() {
            let (next, got) = pth_stream(p, &st, c, !empty_end && k + 1 == chunks.len());
            all.lines.extend(got.lines);
            all.cuts.extend(got.cuts);
            st = next;
        }
        if empty_end || chunks.is_empty() {
            let (_, got) = pth_stream(p, &st, b"", true);
            all.lines.extend(got.lines);
            all.cuts.extend(got.cuts);
        }
        all
    }

    fn rows(issues: &[Value]) -> Vec<(String, String, i64)> {
        issues.iter().map(|i| {
            let a = i.as_arr().unwrap();
            (pystr::to_string(a[0].as_str().unwrap()), pystr::to_string(a[3].as_str().unwrap()), a[8].as_i64().unwrap())
        }).collect()
    }

    #[test]
    fn a_pth_file_read_in_chunks_is_checked_as_it_is_whole() {
        let p = crate::pack::current();
        // a byte order mark, \r\n, \r, a comment, a path, a part after a form feed and after U+2028, a tab, lines
        // that do not start with import, an import line after a long run of bytes with no line end (a storage)
        let mut text = b"\xef\xbb\xbfimport os; os.system('id')\r\n# c\n./lib\rx\x0cimport sys\r\nimport\tz\n".to_vec();
        text.extend_from_slice(b"  import no\nimportx\ny\xe2\x80\xa8import base64; exec(base64.b64decode('aWQ='))\n");
        text.extend(std::iter::repeat_n(0u8, 3000));
        text.extend_from_slice(b"\nimport json\r");
        let whole = rows(&pth_issues(&p, &crate::decode::utf::utf8_sig(&text), true, false));
        assert_eq!(whole.len(), 5, "{whole:?}");
        for size in [1, 2, 3, 5, 7, 10, 16, 17, 64, 1000, text.len()] {
            for empty_end in [false, true] {
                let got = streamed(&p, &text, size, empty_end);
                assert!(got.cuts.is_empty(), "{size}: {:?}", got.cuts);
                assert_eq!(rows(&pth_kept_issues(&p, &got.lines, true, false)), whole, "chunks of {size}");
            }
        }
        // a line that does not end with a line end, and none at all
        let got = streamed(&p, b"a\nimport os", 3, true);
        assert_eq!(got.lines, vec![(2, b"import os".to_vec())]);
        assert!(streamed(&p, b"", 3, true).lines.is_empty());
        // \r\n cut in two by a chunk's end is one line end
        let got = streamed(&p, b"a\r\nimport os\n", 2, false);
        assert_eq!(got.lines, vec![(2, b"import os".to_vec())]);
    }

    #[test]
    fn a_pth_file_read_whole_is_read_as_it_is_in_chunks() {
        // M1, the external review of Oct 21: one rule for every route, a line counting when it starts "import " under
        // any decoding site.py may use (UTF-8, or the locale's latin-1, whose \x85 is U+0085)
        let p = crate::pack::current();
        let seps: [&[u8]; 13] = [b"\n", b"\r", b"\r\n", b"\x0b", b"\x0c", b"\x1c", b"\x1d", b"\x1e", b"\x85", b"\xc2\x85",
                                 b"\xe2\x80\xa8", b"\xe2\x80\xa9", b"\x00"];
        for sep in seps {
            for (lead, bom) in [(&b""[..], false), (&b"./lib\n"[..], false), (&b""[..], true)] {
                let mut text = if bom { b"\xef\xbb\xbf".to_vec() } else { Vec::new() };
                for _ in 0..50 {
                    text.extend_from_slice(lead);
                }
                text.extend_from_slice(b"./x");
                text.extend_from_slice(sep);
                text.extend_from_slice(b"import review_marker\n");
                let (whole, cuts) = pth_bytes_issues(&p, &text, true, false);
                assert!(cuts.is_empty());
                let want = if sep == b"\x00" { 0 } else { 1 };
                assert_eq!(whole.len(), want, "{sep:?}");
                for size in [1, 2, 3, 7, 64, text.len()] {
                    let got = streamed(&p, &text, size, true);
                    assert_eq!(rows(&pth_kept_issues(&p, &got.lines, true, false)), rows(&whole), "{sep:?} in chunks of {size}");
                }
            }
        }
        // an import line at a chunk's edge (a MiB's), read whole and in chunks alike
        for k in [-3i64, -1, 0, 1, 3] {
            let mut text = b"#".to_vec();
            text.extend(std::iter::repeat_n(b'x', ((1i64 << 20) + k - 2) as usize));
            text.extend_from_slice(b"\nimport review_marker\n");
            let (whole, _) = pth_bytes_issues(&p, &text, true, false);
            assert_eq!(rows(&whole), rows(&pth_kept_issues(&p, &streamed(&p, &text, 1 << 20, true).lines, true, false)));
            assert_eq!(whole.len(), 1);
        }
    }

    #[test]
    fn a_pth_file_read_in_chunks_is_bounded() {
        let p = crate::pack::current();
        let max = p.usize("PTH_MAX_LINE");
        // a line Python would run past the bound: a cut, and the next line still read
        let mut text = b"import os  # ".to_vec();
        text.extend(std::iter::repeat_n(b'a', max + 10));
        text.extend_from_slice(b"\nimport sys\n");
        let got = streamed(&p, &text, 1 << 16, true);
        assert_eq!(got.cuts.len(), 1, "{:?}", got.cuts);
        assert!(got.cuts[0].contains("line 1, which Python would run, is longer than"), "{:?}", got.cuts);
        assert_eq!(got.lines, vec![(2, b"import sys".to_vec())]);
        // a long line that is not one: nothing kept, nothing cut, its carry 16 bytes
        let mut text = vec![b'x'; 5 * max];
        text.extend_from_slice(b"\x0cimport os\n");
        let got = streamed(&p, &text, 1 << 16, true);
        assert!(got.cuts.is_empty());
        assert_eq!(got.lines, vec![(1, b"import os".to_vec())]);
        let (st, _) = pth_stream(&p, &PthStream::default(), &vec![b'x'; 100_000], false);
        assert_eq!(st.carry.len(), 16);
        // the lines kept in all: at most PTH_MAX_KEPT, then a cut
        let kept = p.int("PTH_MAX_KEPT") as usize;
        let line = format!("import os  # {}\n", "a".repeat(100_000 - 14));
        let text = line.repeat(kept / 100_000 + 2);
        let got = streamed(&p, text.as_bytes(), 1 << 20, true);
        assert_eq!(got.cuts.len(), 1, "{:?}", got.cuts.len());
        assert!(got.lines.iter().map(|(_, b)| b.len()).sum::<usize>() <= kept);
    }
}
