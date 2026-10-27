//! Archive member names as safe, platform-independent relative paths.

use crate::{Error, Result};

/// Canonicalize a member name without ever resolving it against the host filesystem: `/` separates
/// segments, `.` and empty segments are dropped. A `\` stays part of the name, as Linux and macOS
/// extractors (Python's tarfile, GNU tar, bsdtar, node-tar, 7-Zip, unrar for Unix-made archives) keep it;
/// the caller checks the Windows reading, where `\` separates, with this same function after replacing it.
/// Names that are unsafe or ambiguous on Windows are refused here on every platform, so a name cannot be
/// safe on Unix and dangerous when the same archive is later consumed on Windows.
pub(crate) fn canonical(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Err(Error::InvalidPath("empty member name".into()));
    }
    if raw.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(Error::InvalidPath("member name contains a control character".into()));
    }
    if raw.starts_with('/') {
        return Err(Error::InvalidPath(format!("absolute member path: {raw}")));
    }
    let mut parts = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => continue,
            ".." => return Err(Error::InvalidPath(format!("parent traversal in member path: {raw}"))),
            _ => {}
        }
        // Colons cover drive names, drive-relative paths, UNC oddities and NTFS ADS.
        if part.contains([':', '<', '>', '"', '|', '?', '*']) {
            return Err(Error::InvalidPath(format!("drive or alternate-stream syntax in member path: {raw}")));
        }
        if part.ends_with(['.', ' ']) {
            return Err(Error::InvalidPath(format!("Windows-ambiguous member path: {raw}")));
        }
        let stem = part.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
            || ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"].contains(&stem.as_str());
        if reserved {
            return Err(Error::InvalidPath(format!("reserved device name in member path: {raw}")));
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Err(Error::InvalidPath(format!("member path has no file name: {raw}")));
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::canonical;

    #[test]
    fn safe_names_are_canonical() {
        assert_eq!(canonical("a/./b//c.txt").unwrap(), "a/b/c.txt");
        // A backslash is part of the name, as on Linux; the Windows reading is checked separately.
        assert_eq!(canonical("a\\b\\c.txt").unwrap(), "a\\b\\c.txt");
        assert_eq!(canonical("..\\x").unwrap(), "..\\x");
        assert!(canonical(&"..\\x".replace('\\', "/")).is_err());
    }

    #[test]
    fn dangerous_names_are_refused() {
        for name in ["../x", "a/../../x", "/tmp/x", "C:/x", "C:x", "a:ads", "a/../x", "CON.txt", "CON .txt", "COM¹", "LPT².txt", "a?b", "x.", "x ", "a\0b", "a\nb"] {
            assert!(canonical(name).is_err(), "accepted {name:?}");
        }
    }
}
