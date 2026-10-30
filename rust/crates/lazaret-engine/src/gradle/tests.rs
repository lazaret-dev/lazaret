//! The wrapper check held to genuine wrapper jars (tests/fixtures/gradle-wrapper: taken from projects that commit
//! them), changed ones, and the properties and versions that decide what cannot be verified yet. The versions the
//! tests name are made from the list's own (its newest release and lines), so that a refresh of the list leaves them
//! true.

use super::*;

macro_rules! jar {
    ($v:literal) => {
        include_bytes!(concat!("../../../../../tests/fixtures/gradle-wrapper/", $v, "/gradle/wrapper/gradle-wrapper.jar"))
            as &[u8]
    };
}

const GENUINE: &[(&str, &[u8])] = &[("4.10.3", jar!("4.10.3")), ("8.14", jar!("8.14")), ("9.8", jar!("9.8"))];

fn props_at(version: &str, url: &str) -> Vec<u8> {
    format!("distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\ndistributionUrl={url}/gradle-{version}-bin.zip\nzipStoreBase=GRADLE_USER_HOME\n").into_bytes()
}

fn props(version: &str) -> Vec<u8> {
    props_at(version, "https\\://services.gradle.org/distributions")
}

fn rule(v: &Option<Value>) -> Option<(String, String)> {
    let a = v.as_ref()?.as_arr()?;
    Some((pystr::to_string(a[0].as_str()?), pystr::to_string(a[3].as_str()?)))
}

fn msg(v: &Option<Value>) -> String {
    pystr::to_string(v.as_ref().unwrap().as_arr().unwrap()[4].as_str().unwrap())
}

fn sev(s: &str) -> Option<(String, String)> {
    Some(("SC-GRADLE-WRAPPER".to_string(), s.to_string()))
}

/// Properties given as their bytes, or none.
fn given(pr: Option<&[u8]>) -> Sibling<'_> {
    pr.map_or(Sibling::None, Sibling::Bytes)
}

/// The list's newest release as (major, minor), a line it has and that line's newest patch.
fn newest(p: &Pack) -> ((u64, u64), (u64, u64), u64) {
    let all: Vec<Version> = list(p).iter().filter_map(|(x, _)| Version::parse(x)).collect();
    let top = all.iter().max().unwrap();
    let line = (8, 14);
    let patch = all.iter().filter(|v| v.line() == line).map(|v| v.numbers[2]).max().unwrap();
    (top.line(), line, patch)
}

#[test]
fn genuine_wrappers_are_quiet_from_gradles_distributions() {
    let p = crate::pack::current();
    for (name, jar) in GENUINE {
        for pr in [None, Some(props("9.8.1")), Some(props("99.0")), Some(b"junk".to_vec())] {
            assert_eq!(judge(&p, Some(jar), given(pr.as_deref()), jar.len() as u64), None, "{name}");
        }
    }
}

#[test]
fn a_genuine_wrappers_distribution_from_elsewhere() {
    // (the review of Oct 27: ./gradlew downloads and runs the distribution its properties name)
    let p = crate::pack::current();
    let jar = GENUINE[1].1;
    let got = |pr: &[u8]| judge(&p, Some(jar), Sibling::Bytes(pr), jar.len() as u64);
    // plain HTTP, or what is not a URL: MAJOR
    for pr in [props_at("8.14", "http\\://192.0.2.1/gradle"), props_at("8.14", "file\\:/tmp"),
               b"distributionUrl=gradle-8.14-bin.zip\n".to_vec()] {
        let g = got(&pr);
        assert_eq!(rule(&g), sev("MAJOR"), "{}", String::from_utf8_lossy(&pr));
    }
    // HTTPS from another host without the distribution's checksum: INFO, listed; with it, or Gradle's own: quiet
    let mirror = props_at("8.14", "https\\://mirror.example.invalid/gradle");
    let g = got(&mirror);
    assert_eq!(rule(&g), sev("INFO"));
    assert!(msg(&g).contains("mirror.example.invalid"), "{}", msg(&g));
    let summed = [mirror.as_slice(), b"distributionSha256Sum=0123456789abcdef\n"].concat();
    assert_eq!(got(&summed), None);
    assert_eq!(got(&props_at("8.14", "https\\://SERVICES.gradle.org/distributions")), None);
    // the last distributionUrl is the one Gradle reads
    let twice = [props("8.14").as_slice(), b"distributionUrl=http\\://192.0.2.1/gradle-8.14-bin.zip\n"].concat();
    assert_eq!(rule(&got(&twice)), sev("MAJOR"));
}

#[test]
fn a_changed_wrapper_is_critical_unless_it_may_be_newer_than_the_list() {
    let p = crate::pack::current();
    let mut one = GENUINE[2].1.to_vec();
    let k = one.len() / 2;
    one[k] ^= 1;
    let judge_ = |jar: &[u8], v: &str| judge(&p, Some(jar), Sibling::Bytes(&props(v)), jar.len() as u64);
    let ((major, minor), (lm, ln), patch) = newest(&p);
    // a listed release, an older one missing from the list, versions no release will have, any version form but
    // Gradle's: CRITICAL
    for v in ["9.8.1", "8.14", "7.99", "9.8.0-rc-9", "99.0", "999999999.0", &format!("{lm}.{ln}.{}", patch + 3),
              &format!("{major}.{}", minor + 3), &format!("{}.2", major + 1), &format!("{}.0", major + 2),
              &format!("{major}.{}-beta-1", minor + 1), "1.0-00000000000000+0000"] {
        assert_eq!(rule(&judge_(&one, v)), sev("CRITICAL"), "{v}");
    }
    assert_eq!(rule(&judge(&p, Some(&one), Sibling::None, one.len() as u64)), sev("CRITICAL"));
    // the next releases: its line's next two patches, the major's next two minors, the next major's first two lines,
    // their candidates and milestones, a nightly no older than the list
    for v in [format!("{lm}.{ln}.{}", patch + 1), format!("{lm}.{ln}.{}", patch + 2), format!("{major}.{}", minor + 1),
              format!("{major}.{}.0-rc-1", minor + 2), format!("{}.0", major + 1), format!("{}.1-milestone-1", major + 1),
              format!("{major}.{}.0-20991231000000+0000", minor + 1)] {
        let got = judge_(&one, &v);
        assert_eq!(rule(&got), sev("MAJOR"), "{v}");
        assert!(msg(&got).contains("newer than Lazaret's list") || msg(&got).contains("nightly"), "{v}: {}", msg(&got));
    }
    // ... but a nightly older than the list, and anything that is not a wrapper jar (its main class): CRITICAL
    assert_eq!(rule(&judge_(&one, &format!("{major}.{}.0-20200101000000+0000", minor + 1))), sev("CRITICAL"));
    let elf = b"\x7fELF\x02\x01\x01\x00 no wrapper here";
    assert_eq!(rule(&judge_(elf, &format!("{}.0", major + 1))), sev("CRITICAL"));
    // not read whole: larger than any wrapper jar of Gradle's, a changed one; else it can't be verified
    assert_eq!(rule(&judge(&p, None, Sibling::Bytes(&props("9.8.1")), 2 << 20)), sev("CRITICAL"));
    let got = judge(&p, None, Sibling::Bytes(&props("9.8.1")), 48_749);
    assert_eq!(rule(&got), sev("MAJOR"));
    assert!(msg(&got).contains("not read whole"));
    // a Git LFS pointer is not the jar
    let lfs = b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7e3c1b2a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d\nsize 43764\n";
    assert_eq!(rule(&judge(&p, Some(lfs), Sibling::Bytes(&props("8.14")), lfs.len() as u64)), sev("MAJOR"));
}

#[test]
fn versions_in_gradles_order() {
    let v = |s: &str| Version::parse(s).unwrap();
    assert!(v("9.9.0-milestone-2") < v("9.9.0-rc-1"));
    assert!(v("9.9.0-rc-1") < v("9.9.0"));
    assert!(v("9.8.2") < v("9.9.0-milestone-1"));
    assert_eq!(v("8.14"), v("8.14.0"));
    assert!(v("8.14.6") < v("9.0.0"));
    assert!(v("9.9-20261020000000+0000") < v("9.9.0-milestone-1"));
    assert!(Version::parse("9.x").is_none() && Version::parse("").is_none() && Version::parse("1.2.3.4").is_none());
    for f in ["8.5", "8.5.1", "9.0.0-rc-2", "4.0-milestone-1"] {
        assert!(release_form(f), "{f}");
    }
    for f in ["8", "8.5.1.2", "9.0-RC1", "9.0-M1", "9.0-preview-1", "9.0-rc", "8.5-custom", "v8.5", "8.x"] {
        assert!(!release_form(f), "{f}");
    }
}

#[test]
fn the_distribution_as_java_reads_the_properties() {
    let d = |s: &str| distribution_version(s.as_bytes());
    assert_eq!(d("distributionUrl=https\\://services.gradle.org/distributions/gradle-8.5-bin.zip\n").as_deref(), Some("8.5"));
    assert_eq!(d("# c\n! c\ndistributionUrl : https://mirror.invalid/gradle/gradle-9.8.1-all.zip").as_deref(), Some("9.8.1"));
    assert_eq!(d("distributionUrl=https\\://services.gradle.org/distri\\\n    butions/gradle-7.6.4-bin.zip").as_deref(), Some("7.6.4"));
    assert_eq!(d("distributionUrl https\\u003a//x.invalid/gradle-8.0-rc-1-bin.zip").as_deref(), Some("8.0-rc-1"));
    assert_eq!(d("#distributionUrl=https://x.invalid/gradle-1.0-bin.zip\n"), None);
    assert_eq!(d("distributionUrl=https://x.invalid/gradle-dist.zip"), None);
    assert_eq!(d(""), None);
    // a key given twice: its last value, as java.util.Properties reads it
    assert_eq!(d("distributionUrl=https://a.invalid/gradle-8.5-bin.zip\ndistributionUrl=https://a.invalid/gradle-99.0-bin.zip\n").as_deref(),
               Some("99.0"));
    let pr = read(b"distributionSha256Sum=ab\ndistributionUrl=x\ndistributionSha256Sum=cd\n", 1 << 16).unwrap();
    assert_eq!((pr.url.as_deref(), pr.sha256.as_deref()), (Some("x"), Some("cd")));
}

/// The distributionUrl a file names as Java reads it (JDK 8, 11, 17 and 21's Properties.load(InputStream), each of
/// these cases run through each of them, gave the answers written here), or why it can't be known.
#[test]
fn the_properties_as_java_8_to_21_read_them() {
    const S: &str = "https\\://services.gradle.org/distributions/gradle-8.5-bin.zip";
    const H: &str = "http\\://192.0.2.1/gradle-8.5-bin.zip";
    let s = "https://services.gradle.org/distributions/gradle-8.5-bin.zip";
    let h = "http://192.0.2.1/gradle-8.5-bin.zip";
    let url = |text: &str| read(&text.chars().map(|c| c as u8).collect::<Vec<u8>>(), 1 << 16).map(|p| p.url);
    let cases: Vec<(String, Result<Option<&str>, Unread>)> = vec![
        // the re-review's N3: a key's `\uXXXX` escapes are decoded (every Java: the second line's)
        (format!("distributionUrl={S}\n\\u0064istributionUrl={H}\n"), Ok(Some(h))),
        (format!("distributionUrl={S}\n\\u0064istribution\\u0055rl={H}\n"), Ok(Some(h))),
        // `\r\n` ends a continued line once: the next line goes on the value (every Java: the first line's URL)
        (format!("distributionUrl={H}\nzipStorePath=wrapper/dists\\\r\ndistributionUrl={S}\r\n"), Ok(Some(h))),
        (format!("distributionUrl={H}\r\nzipStorePath=wrapper/dists\\\r\n   distributionUrl={S}\r\n"), Ok(Some(h))),
        (format!("distributionUrl={H}\rzipStorePath=wrapper/dists\\\rdistributionUrl={S}\r"), Ok(Some(h))),
        // Java 8 against later Java: a lone backslash continued onto a comment (8: the first URL, 11 to 21: the
        // second); a comment ending in a backslash before a line of backslashes (8: the second, 11 to 21: the
        // first); a blank line between them (every Java: the second)
        (format!("distributionUrl={H}\n\\\n#x=\\\ndistributionUrl={S}\n"), Err(Unread::Versions)),
        (format!("distributionUrl={H}\n#c\\\n\\\\\\\ndistributionUrl={S}\n"), Err(Unread::Versions)),
        (format!("distributionUrl={H}\n\\\n\n#x=\\\ndistributionUrl={S}\n"), Ok(Some(s))),
        // a `\u` escape that is not one: IllegalArgumentException (every Java)
        (format!("distributionUrl={S}\\u12\n"), Err(Unread::Malformed)),
        (format!("distributionUrl={S}\\u12g4\n"), Err(Unread::Malformed)),
        (format!("\\u00=x\ndistributionUrl={S}\n"), Err(Unread::Malformed)),
        // the separators: `=`, `:` or blanks, the blanks around them, a second one kept in the value
        (format!("distributionUrl = {S}\n"), Ok(Some(s))),
        (format!("   distributionUrl:{S}\n"), Ok(Some(s))),
        (format!("distributionUrl                    :{S}\n"), Ok(Some(s))),
        (format!("distributionUrl {S}\n"), Ok(Some(s))),
        (format!("distributionUrl\t:\t{S}\n"), Ok(Some(s))),
        ("distributionUrl = = x\n".to_string(), Ok(Some("= x"))),
        ("distributionUrl:=x\n".to_string(), Ok(Some("=x"))),
        // `\x` is `x`; continuations, in a value, a key, before the separator, at the end of the file
        ("distributionUrl=https\\://ser\\vices.gradle.org/distri\\\n        butions/gradle-8.5-bin.zip\n".to_string(), Ok(Some(s))),
        (format!("distribution\\\n   Url={S}"), Ok(Some(s))),
        (format!("distributionUrl\\\n={S}\\"), Ok(Some(s))),
        (format!("# distributionUrl={H}\n! distributionUrl={H}\ndistributionUrl={S}\n"), Ok(Some(s))),
        (format!("distributionUrl={S}\\\\\n"), Ok(Some("https://services.gradle.org/distributions/gradle-8.5-bin.zip\\"))),
        // an escaped blank or separator is the key's
        ("distribution\\ Url=x\ndistributionUrl\\=x=y\n".to_string(), Ok(None)),
        ("distributionUrl=\\thttps\\://h/\\n\\r\\f\\\\\n".to_string(), Ok(Some("\thttps://h/\n\r\x0c\\"))),
        // UTF-16 code units: a pair is one character, a lone surrogate is none (U+FFFD here); ISO-8859-1 bytes
        ("distributionUrl=https\\://h/\\ud800\\uD83D\\uDE00\n".to_string(), Ok(Some("https://h/\u{fffd}\u{1f600}"))),
        ("distributionUrl=caf\u{e9}\u{ff}\n".to_string(), Ok(Some("caf\u{e9}\u{ff}"))),
        ("\\\n".to_string(), Ok(None)),
        ("\\".to_string(), Ok(None)),
    ];
    for (text, want) in &cases {
        assert_eq!(url(text).as_ref().map(|u| u.as_deref()), want.as_ref().map(|w| *w), "{text:?}");
    }
    // longer than the bytes read: Java reads it whole, and its last distributionUrl wins
    let long = format!("distributionUrl={S}\n{}distributionUrl={H}\n", "# padding\n".repeat(7000));
    assert_eq!(read(long.as_bytes(), 1 << 16), Err(Unread::Long));
    assert_eq!(read(long.as_bytes(), long.len()).map(|p| p.url), Ok(Some(h.to_string())));
}

#[test]
fn a_genuine_wrapper_whose_properties_are_not_read_as_java_reads_them() {
    // (the re-review of Oct 27, N3: each of these was quiet, the engine reading a distribution Java does not use)
    let p = crate::pack::current();
    let jar = GENUINE[1].1;
    let s = "https\\://services.gradle.org/distributions/gradle-8.14-bin.zip";
    let h = "http\\://192.0.2.1/gradle-8.14-bin.zip";
    let got = |pr: &[u8]| judge(&p, Some(jar), Sibling::Bytes(pr), jar.len() as u64);
    for pr in [format!("distributionUrl={s}\n\\u0064istributionUrl={h}\n"),
               format!("distributionUrl={h}\nzipStorePath=wrapper/dists\\\r\ndistributionUrl={s}\r\n")] {
        let g = got(pr.as_bytes());
        assert_eq!(rule(&g), sev("MAJOR"), "{pr:?}");
        assert!(msg(&g).contains("plain HTTP"), "{}", msg(&g));
    }
    // a file longer than the bytes read, an escape Java refuses, a file Java 8 reads otherwise: can't be verified
    let max = p.int("GRADLE_PROPERTIES_MAX_BYTES") as usize;
    assert_eq!(read_limit(&p), max as u64 + 1);
    let fill = "# a comment\n".repeat(max / 12 + 1);
    let long = format!("distributionUrl={s}\n{fill}distributionUrl={h}\n");
    let long = &long.as_bytes()[..max + 1];
    for (pr, why) in [(long.to_vec(), "longer than the 65536 bytes"),
                      (format!("distributionUrl={s}\\u00\n").into_bytes(), "escape that is not one"),
                      (format!("distributionUrl={h}\n\\\n#x=\\\ndistributionUrl={s}\n").into_bytes(), "Java 8")] {
        let g = got(&pr);
        assert_eq!(rule(&g), sev("MAJOR"), "{why}");
        assert!(msg(&g).contains("can't be verified") && msg(&g).contains(why) && msg(&g).contains("not known"), "{}", msg(&g));
    }
    // exactly as long as the bytes read: read
    let fits = [format!("distributionUrl={s}\n").as_bytes(), &vec![b'#'; max - s.len() - 17]].concat();
    assert_eq!(fits.len(), max);
    assert_eq!(got(&fits), None);
    // there, and not read (a symbolic link Java follows): can't be verified
    let g = judge(&p, Some(jar), Sibling::Error(&pystr::u("Too many levels of symbolic links")), jar.len() as u64);
    assert_eq!(rule(&g), sev("MAJOR"));
    assert!(msg(&g).contains("Too many levels of symbolic links"), "{}", msg(&g));
    // a changed jar with such properties names no release it may be: CRITICAL, saying why
    let mut one = jar.to_vec();
    one[jar.len() / 2] ^= 1;
    let g = judge(&p, Some(&one), Sibling::Bytes(long), one.len() as u64);
    assert_eq!(rule(&g), sev("CRITICAL"));
    assert!(msg(&g).contains("longer than the 65536 bytes"), "{}", msg(&g));
}

#[test]
fn only_the_wrappers_place() {
    let u = pystr::u;
    assert!(wrapper_path(&u("gradle/wrapper/gradle-wrapper.jar"), false));
    assert!(wrapper_path(&u("android/gradle/wrapper/gradle-wrapper.jar"), false));
    assert!(wrapper_path(&u("a\\gradle\\wrapper\\gradle-wrapper.jar"), true));
    assert!(!wrapper_path(&u("a\\gradle\\wrapper\\gradle-wrapper.jar"), false));
    for path in ["gradle-wrapper.jar", "wrapper/gradle-wrapper.jar", "gradle/wrapper/gradle-wrapper-1.jar",
                 "gradle/Wrapper/gradle-wrapper.jar", "gradle/wrapper/x/gradle-wrapper.jar", "lib/gradle-wrapper.jar"] {
        assert!(!wrapper_path(&u(path), false), "{path}");
    }
}

#[test]
fn the_versions_gradle_publishes_no_checksum_for() {
    let p = crate::pack::current();
    for v in ["3.3", "3.4-rc-2", "3.5.1", "4.0-milestone-1", "4.0.2"] {
        assert!(no_checksum(&p, v), "{v}");
        assert!(!listed(&p, v), "{v}");
    }
    for v in ["3.2.1", "4.0.3", "4.1", "8.14", "4.10.3"] {
        assert!(!no_checksum(&p, v), "{v}");
    }
}
