//! A Gradle wrapper jar checked against Gradle's published wrapper checksums (FP-GRADLE-WRAPPER, 0.1.9, John's
//! decision of Oct 21: "Yes, check checksums").
//!
//! `./gradlew` runs `gradle/wrapper/gradle-wrapper.jar` on every build, on developers' machines and in CI, which is
//! why Gradle publishes the SHA-256 of each release's wrapper jar and checks a project's against them in its
//! wrapper-validation action. Nearly every Gradle project commits one, and SC-BINARY reported each as a binary to
//! review. The engine checks the jar's content as Gradle's validation does: a jar named `gradle-wrapper.jar` in a
//! `gradle/wrapper/` folder whose SHA-256 is one of the checksums Lazaret ships (GRADLE_WRAPPER_CHECKSUMS: version ->
//! checksum, Gradle's own list as gradle/actions ships it: scripts/update_gradle_wrapper_checksums.py) is Gradle's
//! wrapper; one that matches none is SC-GRADLE-WRAPPER, CRITICAL, a changed wrapper. What the list cannot judge is
//! MAJOR, reported as one that can't be verified, and only what it cannot (the review of Oct 27): a Git LFS pointer
//! committed in the jar's place; a jar whose manifest names a Gradle version Gradle publishes no checksum for
//! (GRADLE_WRAPPER_NO_CHECKSUM: 3.3 to 4.0.2 and their candidates, whose wrapper jars were not reproducible); a
//! wrapper jar (its main class in it) for a release that may be the next one, newer than the list (`newer`: Gradle's
//! release form, within two patches, two minors or the next major's first two lines of the list's newest, a nightly
//! no older than the list), named by the last distributionUrl of `gradle/wrapper/gradle-wrapper.properties`, as Java
//! reads the file, or, when that names a listed release, by the jar's own manifest; a jar not read whole (over the
//! size limit, yet no larger than a wrapper jar can be). A genuine wrapper whose distribution comes over plain HTTP,
//! or from what is not a URL, is MAJOR, and from a host other than services.gradle.org with no
//! distributionSha256Sum, INFO (`./gradlew` downloads and runs it); one whose properties can't be read as Java reads
//! them (longer than GRADLE_PROPERTIES_MAX_BYTES, a `\uXXXX` escape Java refuses, read otherwise by Java 8 than by
//! later Java, not readable here) is MAJOR, its distribution not known (the re-review of Oct 27, N3). A jar
//! elsewhere or under another name is judged as any jar is (SC-BINARY), and so is a wrapper jar whose caller gives
//! only its first bytes.

use crate::findings::{format, Arg, RuleText};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};

/// The wrapper's properties, beside its jar. The pack's GRADLE_PROPERTIES_MAX_BYTES of them are read (they are a few
/// hundred bytes), and the hosts give one byte more when there is one (`read_limit`), so that a longer file is told:
/// Java reads it whole, and its last distributionUrl is the one the wrapper uses.
pub const PROPERTIES: &str = "gradle-wrapper.properties";

/// The bytes of a gradle-wrapper.properties a host reads: GRADLE_PROPERTIES_MAX_BYTES and one more.
pub fn read_limit(p: &Pack) -> u64 {
    p.int("GRADLE_PROPERTIES_MAX_BYTES").max(0) as u64 + 1
}

/// The gradle-wrapper.properties beside a wrapper jar, as its host found it.
#[derive(Clone, Copy, Debug)]
pub enum Sibling<'a> {
    /// there is none
    None,
    /// its bytes (its first `read_limit`, when it has as many)
    Bytes(&'a [u8]),
    /// it is there, and was not read: why (a symbolic link, which Java follows and the scan does not; an error)
    Error(&'a [u32]),
}

/// The jar's path ends `gradle/wrapper/gradle-wrapper.jar`, the names exactly ("\\" a separator too where `windows`).
pub fn wrapper_path(path: &[u32], windows: bool) -> bool {
    let parts: Vec<&[u32]> = path.split(|&c| c == '/' as u32 || (windows && c == '\\' as u32)).collect();
    parts.len() >= 3 && {
        let n = parts.len();
        pystr::eq(parts[n - 1], "gradle-wrapper.jar") && pystr::eq(parts[n - 2], "wrapper") && pystr::eq(parts[n - 3], "gradle")
    }
}

/// The versions of Gradle's list whose wrapper jar has this SHA-256 (lowercase hex).
fn versions_of<'a>(p: &'a Pack, checksum: &str) -> Vec<&'a str> {
    list(p).iter().filter(|(_, c)| c == checksum).map(|(v, _)| v.as_str()).collect()
}

/// GRADLE_WRAPPER_CHECKSUMS as (version, checksum) pairs.
fn list(p: &Pack) -> &[(String, String)] {
    p.derived("GRADLE_WRAPPER_CHECKSUMS", |v| {
        v.get("map")
            .and_then(|m| m.as_obj())
            .unwrap_or(&[])
            .iter()
            .filter_map(|(k, x)| Some((pystr::to_string(k), pystr::to_string(x.get("value")?.as_str()?))))
            .collect::<Vec<_>>()
    })
}

/// A Gradle version, ordered as Gradle orders its releases: major, minor, patch, then a milestone before a release
/// candidate before the release (a nightly's timestamp before them all), then the qualifier's number.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    numbers: [u64; 3],
    stage: u8,
    qualifier: u64,
}

impl Version {
    pub fn parse(v: &str) -> Option<Version> {
        let (base, rest) = match v.find('-') {
            Some(k) => (&v[..k], Some(&v[k + 1..])),
            None => (v, None),
        };
        let mut numbers = [0u64; 3];
        let parts: Vec<&str> = base.split('.').collect();
        if parts.is_empty() || parts.len() > 3 {
            return None;
        }
        for (k, part) in parts.iter().enumerate() {
            if part.is_empty() || part.len() > 9 || !part.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            numbers[k] = part.parse().ok()?;
        }
        let (stage, qualifier) = match rest {
            None => (4, 0),
            Some(q) => {
                let (name, n) = match q.rfind('-') {
                    Some(k) => (&q[..k], &q[k + 1..]),
                    None => (q, ""),
                };
                let n: u64 = if n.is_empty() { 0 } else { n.parse().ok()? };
                match name {
                    "milestone" | "M" => (1, n),
                    "preview" => (2, n),
                    "rc" | "RC" => (3, n),
                    // (a nightly, `9.9-20261020000000+0000`: its timestamp's digits)
                    _ if q.len() >= 14 && q.as_bytes()[..14].iter().all(|c| c.is_ascii_digit()) => (0, q[..14].parse().ok()?),
                    _ => return None,
                }
            }
        };
        Some(Version { numbers, stage, qualifier })
    }

    fn line(&self) -> (u64, u64) {
        (self.numbers[0], self.numbers[1])
    }
}

/// The wrapper's properties as java.util.Properties reads them (the last of a key's lines wins): the distribution's
/// URL and its SHA-256 (distributionSha256Sum).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Props {
    pub url: Option<String>,
    pub sha256: Option<String>,
}

/// Why a gradle-wrapper.properties can't be read as Java reads it, so that the distribution the wrapper downloads is
/// not known (the re-review of Oct 27, N3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unread {
    /// longer than the bytes read (Java reads the whole file, and its last distributionUrl wins)
    Long,
    /// a `\uXXXX` escape that is not one, which Properties.load refuses (Java 17 and later; earlier ones may read
    /// past the escape's line)
    Malformed,
    /// Java 8's reader and later Java's read it into different distributions (a lone backslash continued onto a
    /// comment line, a comment that ends in a backslash: Java 8 tells a comment only at a logical line's start, and
    /// counts a comment's backslashes on into the next line)
    Versions,
}

/// gradle-wrapper.properties read as java.util.Properties.load(InputStream) reads it, as Gradle's WrapperExecutor
/// does (ISO-8859-1; `\r\n`, `\r` or `\n` ends a line; blank lines and `#` or `!` comments skipped; a line ending in
/// an odd number of backslashes goes on with the next, its leading blanks dropped; the key ends at the first `=`,
/// `:` or blank not escaped, and blanks and one `=` or `:` after it are dropped; `\uXXXX`, `\t`, `\n`, `\r`, `\f` and
/// `\x` for any other `x` decoded in keys and values; a key given twice: its last value). At most `limit` bytes:
/// longer, it can't be read so. Read by Java 9's reader and later Java's escapes, and by Java 8's: when they name
/// different distributions, it can't be known which the wrapper uses.
pub fn read(b: &[u8], limit: usize) -> Result<Props, Unread> {
    if b.len() > limit {
        return Err(Unread::Long);
    }
    let now = props_of(&lines(b, false), false)?;
    // (Java 8 reads on past a line for a backslash or a `\u` at its end: what it reads is not known here)
    let java8 = props_of(&lines(b, true), true).map_err(|_| Unread::Versions)?;
    if java8 != now {
        return Err(Unread::Versions);
    }
    Ok(now)
}

/// The distribution's URL and checksum among a file's logical lines (the last of each key's). `java8`: Java 8's
/// lines, of which one of backslashes alone, an odd number (its count run on from a comment), names no key the
/// wrapper reads (Java 8's loadConvert takes a character past the line for the last one's escape, or fails).
fn props_of(lines: &[Vec<u8>], java8: bool) -> Result<Props, Unread> {
    let mut out = Props::default();
    for line in lines {
        let (key, value) = match entry(line) {
            Err(_) if java8 && line.iter().all(|&c| c == b'\\') => continue,
            got => got?,
        };
        if key == "distributionUrl" {
            out.url = Some(value);
        } else if key == "distributionSha256Sum" {
            out.sha256 = Some(value);
        }
    }
    Ok(out)
}

/// A properties file's logical lines, as java.util.Properties' LineReader reads them. `java8`: Java 8's reader (its
/// `isNewLine`, `isCommentLine` and `skipLF`), which tells a comment only at a logical line's first character and
/// runs its backslash count on through a comment's characters; else the reader of Java 9 and later, which tells one
/// wherever the logical line is still empty and reads a comment through without counting.
fn lines(b: &[u8], java8: bool) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(line) = if java8 { line_java8(b, &mut at) } else { line_java9(b, &mut at) } {
        out.push(line);
    }
    out
}

fn blank(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == 0x0c
}

/// LineReader.readLine of Java 9 and later: the next logical line from `at`, None at the end.
fn line_java9(b: &[u8], at: &mut usize) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let (mut skip_blanks, mut appended, mut backslash) = (true, false, false);
    loop {
        let Some(&c) = b.get(*at) else {
            if line.is_empty() {
                return None;
            }
            if backslash {
                line.pop();
            }
            return Some(line);
        };
        *at += 1;
        if skip_blanks {
            if blank(c) || (!appended && (c == b'\r' || c == b'\n')) {
                continue;
            }
            skip_blanks = false;
            appended = false;
        }
        if line.is_empty() && (c == b'#' || c == b'!') {
            // a comment: to the end of its line (at the file's end, no line)
            loop {
                let &d = b.get(*at)?;
                *at += 1;
                if d == b'\r' || d == b'\n' {
                    break;
                }
            }
            skip_blanks = true;
            continue;
        }
        if c != b'\n' && c != b'\r' {
            line.push(c);
            backslash = c == b'\\' && !backslash;
            continue;
        }
        if line.is_empty() {
            skip_blanks = true;
            continue;
        }
        if *at >= b.len() || !backslash {
            if backslash {
                line.pop();
            }
            return Some(line);
        }
        // a line that goes on: its backslash dropped, the next line's leading blanks too (and the `\n` of a `\r\n`)
        line.pop();
        skip_blanks = true;
        appended = true;
        backslash = false;
        if c == b'\r' && b.get(*at) == Some(&b'\n') {
            *at += 1;
        }
    }
}

/// LineReader.readLine of Java 8: the next logical line from `at`, None at the end.
fn line_java8(b: &[u8], at: &mut usize) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let (mut skip_blanks, mut comment, mut new_line, mut appended, mut backslash, mut skip_lf) =
        (true, false, true, false, false, false);
    loop {
        let Some(&c) = b.get(*at) else {
            if line.is_empty() || comment {
                return None;
            }
            if backslash {
                line.pop();
            }
            return Some(line);
        };
        *at += 1;
        if skip_lf {
            skip_lf = false;
            if c == b'\n' {
                continue;
            }
        }
        if skip_blanks {
            if blank(c) || (!appended && (c == b'\r' || c == b'\n')) {
                continue;
            }
            skip_blanks = false;
            appended = false;
        }
        if new_line {
            new_line = false;
            if c == b'#' || c == b'!' {
                comment = true;
                continue;
            }
        }
        if c != b'\n' && c != b'\r' {
            line.push(c);
            backslash = c == b'\\' && !backslash;
            continue;
        }
        if comment || line.is_empty() {
            // (a comment's characters were kept, and its backslash count goes on)
            comment = false;
            new_line = true;
            skip_blanks = true;
            line.clear();
            continue;
        }
        if *at >= b.len() || !backslash {
            if backslash {
                line.pop();
            }
            return Some(line);
        }
        line.pop();
        skip_blanks = true;
        appended = true;
        backslash = false;
        skip_lf = c == b'\r';
    }
}

/// A logical line's key and value, unescaped, as Properties.load splits it; Malformed for a `\uXXXX` escape Java
/// refuses, or a backslash that escapes nothing (none is left at a line's end by Java 9's reader).
fn entry(line: &[u8]) -> Result<(String, String), Unread> {
    let n = line.len();
    let (mut key_len, mut value_start, mut sep, mut backslash) = (0usize, n, false, false);
    while key_len < n {
        let c = line[key_len];
        if (c == b'=' || c == b':') && !backslash {
            value_start = key_len + 1;
            sep = true;
            break;
        }
        if blank(c) && !backslash {
            value_start = key_len + 1;
            break;
        }
        backslash = c == b'\\' && !backslash;
        key_len += 1;
    }
    while value_start < n {
        let c = line[value_start];
        if !blank(c) {
            if !sep && (c == b'=' || c == b':') {
                sep = true;
            } else {
                break;
            }
        }
        value_start += 1;
    }
    Ok((unescape(&line[..key_len])?, unescape(&line[value_start..])?))
}

/// Properties' loadConvert: escapes decoded into UTF-16 code units, then text (a lone surrogate as U+FFFD).
fn unescape(s: &[u8]) -> Result<String, Unread> {
    let mut out: Vec<u16> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c != b'\\' {
            out.push(c as u16);
            continue;
        }
        let Some(&e) = s.get(i) else { return Err(Unread::Malformed) };
        i += 1;
        if e == b'u' {
            let hex = s.get(i..i + 4).ok_or(Unread::Malformed)?;
            let mut v = 0u16;
            for &h in hex {
                v = (v << 4) | (h as char).to_digit(16).ok_or(Unread::Malformed)? as u16;
            }
            out.push(v);
            i += 4;
        } else {
            out.push(match e {
                b't' => '\t' as u16,
                b'n' => '\n' as u16,
                b'r' => '\r' as u16,
                b'f' => 0x0c,
                x => x as u16,
            });
        }
    }
    Ok(String::from_utf16_lossy(&out))
}

/// The version of Gradle a distribution URL names (`…/gradle-8.5-bin.zip`, `-all.zip`).
pub fn url_version(url: &str) -> Option<String> {
    let name = url.rsplit('/').next()?;
    let v = name.strip_prefix("gradle-")?;
    let v = v.strip_suffix("-bin.zip").or_else(|| v.strip_suffix("-all.zip"))?;
    (!v.is_empty()).then(|| v.to_string())
}

/// The version of Gradle a gradle-wrapper.properties' distributionUrl names (its last one, as Gradle reads it); None
/// when it names none, or can't be read as Java reads it.
pub fn distribution_version(props: &[u8]) -> Option<String> {
    url_version(&read(props, usize::MAX).ok()?.url?)
}

/// The SHA-256 of `data`, lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    use lazaret_verify::crypto::sha2::{Hash, Sha256};
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// A Git LFS pointer (the spec's first line, its oid and size): the jar is in LFS storage, not here.
fn lfs_pointer(data: &[u8]) -> bool {
    data.len() < 1024 && data.starts_with(b"version https://git-lfs.github.com/spec/v1\n")
        && data.windows(11).any(|w| w == b"oid sha256:")
}

/// The Gradle version a wrapper jar's manifest names (`Implementation-Title: Gradle`, `Implementation-Version: 4.0`:
/// the wrappers Gradle 4.x and older wrote say so; later ones name no version).
fn manifest_version(jar: &[u8]) -> Option<String> {
    use crate::pickle::zip;
    let src = zip::Bytes::whole(jar);
    // (a listing the zip's readers may not agree on proves nothing: FP-MODEL-FILES' zip::entries, at stacking)
    let entries = zip::entries(&src, 10_000, 1 << 20).ok().filter(|l| !l.is_ambiguous())?.entries;
    let e = entries.iter().find(|e| e.name == b"META-INF/MANIFEST.MF")?;
    let text = zip::read(&src, e, 64 * 1024).ok()?;
    let text: String = text.iter().map(|&c| c as char).collect();
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string()));
    let title = field("Implementation-Title:")?;
    if !(title == "Gradle" || title == "Gradle Wrapper") {
        return None;
    }
    field("Implementation-Version:").filter(|v| Version::parse(v).is_some())
}

/// A version in Gradle's release form (`8.5`, `8.5.1`, `9.0.0-rc-2`, `4.0-milestone-1`): `^\d+\.\d+(\.\d+)?
/// (-(rc|milestone)-\d+)?$`.
pub fn release_form(v: &str) -> bool {
    let (base, rest) = match v.find('-') {
        Some(k) => (&v[..k], Some(&v[k + 1..])),
        None => (v, None),
    };
    let numbers: Vec<&str> = base.split('.').collect();
    let digits = |s: &str| !s.is_empty() && s.len() <= 9 && s.bytes().all(|c| c.is_ascii_digit());
    (2..=3).contains(&numbers.len()) && numbers.iter().all(|n| digits(n)) && match rest {
        None => true,
        Some(q) => match q.rsplit_once('-') {
            Some((name, n)) => (name == "rc" || name == "milestone") && digits(n),
            None => false,
        },
    }
}

/// A nightly build's version (`9.9.0-20261021152326+0000`): its base release and the date of its timestamp
/// (YYYYMMDD).
fn nightly(v: &str) -> Option<(&str, u64)> {
    let (base, stamp) = v.split_once('-')?;
    let digits = stamp.strip_suffix("+0000")?;
    (digits.len() == 14 && digits.bytes().all(|c| c.is_ascii_digit()) && release_form(base))
        .then(|| (base, digits[..8].parse().unwrap_or(0)))
}

/// The date of Lazaret's list (GRADLE_WRAPPER_CHECKSUMS_DATE, YYYY-MM-DD) as YYYYMMDD.
fn list_date(p: &Pack) -> u64 {
    p.string("GRADLE_WRAPPER_CHECKSUMS_DATE").replace('-', "").parse().unwrap_or(u64::MAX)
}

/// Whether Gradle `v` may be a release newer than Lazaret's list, the next one Gradle publishes (the review of Oct
/// 27): in Gradle's release form, not in the list, and newer than the list's releases of its line by at most two
/// patches; or a new line of the list's newest major, at most two minors past its newest; or the next major's first
/// two lines. A nightly build is one when its base release is, and its timestamp is no older than the list. The
/// release it is newer than (its line's newest, or the list's); None when it is none of these.
pub fn newer(p: &Pack, v: &str) -> Option<String> {
    let base = match nightly(v) {
        Some((base, date)) => {
            if date < list_date(p) {
                return None;
            }
            base
        }
        None if release_form(v) => v,
        None => return None,
    };
    let ver = Version::parse(base)?;
    let versions: Vec<(Version, &str)> = list(p).iter().filter_map(|(x, _)| Some((Version::parse(x)?, x.as_str()))).collect();
    if versions.iter().any(|(x, _)| *x == ver && (base == v || x.stage == 4)) {
        return None;
    }
    let newest = versions.iter().max_by(|a, b| a.0.cmp(&b.0))?;
    match versions.iter().filter(|(x, _)| x.line() == ver.line()).max_by(|a, b| a.0.cmp(&b.0)) {
        // a line the list has: newer than its newest, by at most two patches
        Some((top, name)) => (ver > *top && ver.numbers[2] <= top.numbers[2] + 2).then(|| name.to_string()),
        None => {
            let (major, minor) = newest.0.line();
            let next = (ver.numbers[0] == major && ver.numbers[1] > minor && ver.numbers[1] <= minor + 2)
                || (ver.numbers[0] == major + 1 && ver.numbers[1] <= 1);
            next.then(|| newest.1.to_string())
        }
    }
}

/// Whether Gradle publishes no wrapper checksum for Gradle `v` (GRADLE_WRAPPER_NO_CHECKSUM: the versions of Gradle's
/// versions/all with no wrapperChecksumUrl, 3.3 to 4.0.2 and their release candidates and milestones among them,
/// whose wrapper jars were not reproducible).
fn no_checksum(p: &Pack, v: &str) -> bool {
    p.strs("GRADLE_WRAPPER_NO_CHECKSUM").iter().any(|x| pystr::eq(x, v))
}

/// The jar is a zip that holds the wrapper's main class (org/gradle/wrapper/GradleWrapperMain.class).
fn wrapper_main(jar: &[u8]) -> bool {
    use crate::pickle::zip;
    let src = zip::Bytes::whole(jar);
    // (a listing the zip's readers may not agree on proves nothing: FP-MODEL-FILES' zip::entries, at stacking)
    zip::entries(&src, 10_000, 1 << 20).is_ok_and(|l| {
        !l.is_ambiguous() && l.entries.iter().any(|e| e.name == b"org/gradle/wrapper/GradleWrapperMain.class")
    })
}

/// Where a wrapper's distribution comes from, when that is not as safe as Gradle's default (the review of Oct 27):
/// MAJOR for plain HTTP or what is not a URL (`./gradlew` downloads and runs the distribution); INFO for HTTPS from
/// a host other than services.gradle.org with no distributionSha256Sum (a company's mirror, often: listed, not
/// counted); None from services.gradle.org, or with the distribution's checksum, or with no URL.
fn distribution_issue(p: &Pack, props: &Props) -> Option<Value> {
    let url = props.url.as_deref()?.trim();
    let shown: String = url.chars().take(200).collect();
    let rest = url.get(..8).filter(|s| s.eq_ignore_ascii_case("https://")).map(|_| &url[8..]);
    let Some(rest) = rest else {
        let mut r = RuleText::of(p, "_GRADLE_DISTRIBUTION_RULE");
        r.msg = format(&r.msg, &[("url", Arg::S(pystr::u(&shown)))]);
        return Some(crate::binary::file_issue_of(r));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("").split(':').next().unwrap_or("").to_ascii_lowercase();
    if host.is_empty() {
        let mut r = RuleText::of(p, "_GRADLE_DISTRIBUTION_RULE");
        r.msg = format(&r.msg, &[("url", Arg::S(pystr::u(&shown)))]);
        return Some(crate::binary::file_issue_of(r));
    }
    if host == "services.gradle.org" || props.sha256.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        return None;
    }
    let mut r = RuleText::of(p, "_GRADLE_DISTRIBUTION_HOST_RULE");
    r.msg = format(&r.msg, &[("host", Arg::S(pystr::u(&host)))]);
    Some(crate::binary::file_issue_of(r))
}

fn listed(p: &Pack, v: &str) -> bool {
    list(p).iter().any(|(x, _)| x == v)
}

/// What a gradle-wrapper.jar is (`jar`: its bytes, None when it was not read whole; `props`: its
/// gradle-wrapper.properties as its host found it; `size`: its size). A jar whose SHA-256 is one of Gradle's is
/// Gradle's wrapper: None, or what its distribution's URL is (distribution_issue), or MAJOR when its properties can't
/// be read as Java reads them (`read`, or not readable here: the distribution it downloads is not known). Else
/// SC-GRADLE-WRAPPER, MAJOR when it can't be verified: a Git LFS pointer, not the jar; a wrapper jar (its main class
/// in it) whose manifest names a version Gradle publishes no checksum for (GRADLE_WRAPPER_NO_CHECKSUM), or for a
/// release that may be newer than Lazaret's list (the last distributionUrl's version, or, the properties naming a
/// listed one, the jar's manifest's: `newer`); not read whole, and no larger than GRADLE_WRAPPER_MAX_BYTES. CRITICAL
/// otherwise: a changed wrapper (the review of Oct 27: whatever else matches no checksum; properties that can't be
/// read name no release it may be).
pub fn judge(p: &Pack, jar: Option<&[u8]>, props: Sibling, size: u64) -> Option<Value> {
    let newest = list_newest(p);
    let limit = p.int("GRADLE_PROPERTIES_MAX_BYTES").max(0);
    let read = match props {
        Sibling::None => Ok(Props::default()),
        Sibling::Bytes(b) => read(b, limit as usize).map_err(|why| match why {
            Unread::Long => format(&p.text("_GRADLE_PROPERTIES_LONG"), &[("limit", Arg::I(limit))]),
            Unread::Malformed => p.text("_GRADLE_PROPERTIES_MALFORMED"),
            Unread::Versions => p.text("_GRADLE_PROPERTIES_VERSIONS"),
        }),
        Sibling::Error(e) => Err(format(&p.text("_GRADLE_PROPERTIES_ERROR"), &[("error", Arg::S(e.to_vec()))])),
    };
    let (props, unread) = match read {
        Ok(props) => (props, None),
        Err(why) => (Props::default(), Some(why)),
    };
    let version = props.url.as_deref().and_then(url_version);
    let unverified = |why: PyStr| {
        let mut r = RuleText::of(p, "_GRADLE_WRAPPER_UNVERIFIED_RULE");
        r.msg = format(&r.msg, &[("why", Arg::S(why))]);
        Some(crate::binary::file_issue_of(r))
    };
    let said = |text: &str, v: &str, than: &str| {
        format(&p.text(text), &[("version", Arg::S(pystr::u(v))), ("newest", Arg::S(pystr::u(than)))])
    };
    let what = match jar {
        Some(jar) => {
            if !versions_of(p, &sha256_hex(jar)).is_empty() {
                // (Gradle's wrapper, but what it downloads and runs is not known)
                if let Some(why) = &unread {
                    let why = format(&p.text("_GRADLE_WRAPPER_PROPERTIES_UNREAD"), &[("why", Arg::S(why.clone()))]);
                    return unverified(why);
                }
                return distribution_issue(p, &props);
            }
            if lfs_pointer(jar) {
                return unverified(p.text("_GRADLE_WRAPPER_LFS"));
            }
            let manifest = manifest_version(jar);
            // what can't be verified yet is a wrapper jar (its main class in it), else it is no wrapper of Gradle's
            if wrapper_main(jar) {
                if let Some(v) = manifest.as_deref().filter(|v| no_checksum(p, v)) {
                    return unverified(said("_GRADLE_WRAPPER_UNLISTED", v, &newest));
                }
                match &version {
                    Some(v) if !listed(p, v) => {
                        if let Some(than) = newer(p, v) {
                            let text = if nightly(v).is_some() { "_GRADLE_WRAPPER_NIGHTLY" } else { "_GRADLE_WRAPPER_NEWER" };
                            return unverified(said(text, v, &than));
                        }
                    }
                    // (properties naming a listed version: a jar written by a newer Gradle says so in its manifest)
                    Some(_) => {
                        if let Some(m) = manifest.as_deref().filter(|m| !listed(p, m)) {
                            if let Some(than) = newer(p, m) {
                                return unverified(said("_GRADLE_WRAPPER_MANIFEST_NEWER", m, &than));
                            }
                        }
                    }
                    // (no distribution named: nothing says which release it may be)
                    None => {}
                }
            }
            p.text("_GRADLE_WRAPPER_JAR")
        }
        // (a jar larger than any of Gradle's: the 290 wrapper jars gradle/gradle committed from 2012 to 2026 are
        // 43 to 64 KB)
        // (`size` may be what is known of it: the registry knows an oversized member is larger than its limit)
        None if size > p.int("GRADLE_WRAPPER_MAX_BYTES").max(0) as u64 => {
            format(&p.text("_GRADLE_WRAPPER_TOO_LARGE"), &[("limit", Arg::I(p.int("GRADLE_WRAPPER_MAX_BYTES")))])
        }
        None => return unverified(p.text("_GRADLE_WRAPPER_UNREAD")),
    };
    let named = match (&version, unread) {
        (_, Some(why)) => format(&p.text("_GRADLE_WRAPPER_PROPERTIES_NOT_READ"), &[("why", Arg::S(why))]),
        (Some(v), None) => format(&p.text("_GRADLE_WRAPPER_DISTRIBUTION"), &[("version", Arg::S(pystr::u(v)))]),
        (None, None) => p.text("_GRADLE_WRAPPER_NO_DISTRIBUTION"),
    };
    let mut r = RuleText::of(p, "_GRADLE_WRAPPER_RULE");
    r.msg = format(&r.msg, &[("what", Arg::S(what)), ("count", Arg::I(list(p).len() as i64)),
                             ("newest", Arg::S(pystr::u(&newest))), ("distribution", Arg::S(named))]);
    Some(crate::binary::file_issue_of(r))
}

fn list_newest(p: &Pack) -> String {
    list(p).iter().filter_map(|(x, _)| Some((Version::parse(x)?, x))).max_by(|a, b| a.0.cmp(&b.0))
        .map(|x| x.1.clone()).unwrap_or_default()
}

#[cfg(test)]
mod tests;
