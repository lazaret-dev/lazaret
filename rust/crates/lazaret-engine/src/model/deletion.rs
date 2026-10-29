//! RA-6: paths deleted, not merely mentioned. Unknown paths are not evidence of destruction.
use super::val::Val;
use crate::{pack::Pack, pystr::{self, u}, shell};
use std::collections::BTreeMap;

pub const REASON: &str = "deletes the user's files";
pub const REPOSITORIES: &str = "<all-git-repositories>";

// Like the other deletion-path data below, these are lexical path components,
// not host filesystem queries or an assertion of package ownership. Compare
// without case so a Linux scanner also protects case-insensitive target volumes.
const PERSONAL: &[&str] = &[
    "Documents", "Desktop", "Downloads", "Pictures", "Music", "Movies", "Videos",
    "Library/Mobile Documents", "Library/CloudStorage", "Library/Mail", "Library/Messages",
    "Library/Photos", "Library/Safari", "Library/Containers/com.apple.Safari",
    "Library/Application Support/Google/Chrome", "Library/Application Support/Google/Chrome Canary",
    "Library/Application Support/Chromium", "Library/Application Support/Firefox",
    "Library/Application Support/Safari", "Library/Application Support/Microsoft Edge",
    "Library/Application Support/BraveSoftware", ".mozilla",
    ".config/google-chrome", ".config/google-chrome-beta", ".config/google-chrome-unstable",
    ".config/chromium", ".config/firefox", ".config/microsoft-edge",
    ".config/microsoft-edge-beta", ".config/microsoft-edge-dev", ".config/BraveSoftware",
    "AppData/Local/Google/Chrome", "AppData/Local/Microsoft/Edge", "AppData/Local/BraveSoftware",
    "AppData/Roaming/Mozilla/Firefox", "AppData/Roaming/Apple Computer/Safari",
];
const CREDENTIALS: &[&str] = &[
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gcloud",
    "Library/Keychains", ".npmrc", ".pypirc", ".netrc", ".git-credentials",
];

fn uncertain(part: &str) -> bool {
    part.chars().any(|c| "*$?[]{}".contains(c) || c == '\u{fffd}' || c.is_control())
}

// Protect the named subtree and ancestors that would delete it too, e.g.
// Library/Application Support must not become an exemption above Chrome.
fn overlaps(parts: &[&str], protected: &str) -> bool {
    parts.iter().zip(protected.split('/')).all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Lexical normalization preserves home/absolute namespaces and resolves '..' before cache exclusions.
pub fn dangerous(path: &Val) -> bool {
    let Some(raw) = &path.s else { return false };
    let mut s = pystr::to_string(raw).replace('\\', "/");
    if s == REPOSITORIES { return true }
    for h in ["${HOME}", "$HOME", "${USERPROFILE}", "$USERPROFILE", "$env:USERPROFILE", "$env:HOME", "%USERPROFILE%", "%HOME%"] {
        if s == h || s.starts_with(&format!("{h}/")) { s = format!("~{}", &s[h.len()..]); break }
    }
    let lower = s.to_ascii_lowercase();
    let drive = lower.len() >= 3 && lower.as_bytes()[0].is_ascii_alphabetic() && &lower.as_bytes()[1..3] == b":/";
    let absolute = s.starts_with('/');
    let home = s == "~" || s.starts_with("~/");
    if !home && !absolute && !drive { return false }
    let body = if home { &s[1..] } else if drive { &s[3..] } else { &s[1..] };
    let unknown = body.split('/').any(uncertain);
    let mut escaped_home = false;
    let mut parts = Vec::new();
    for p in body.split('/') {
        match p { "" | "." => {}, ".." => { if home && parts.is_empty() { escaped_home = true; } parts.pop(); }, _ => parts.push(p) }
    }
    if parts.is_empty() || parts.iter().all(|x| *x == "*" || *x == "**") { return true }
    let user_parts = if home { &parts[..] }
        else if parts.len() >= 2 && (parts[0].eq_ignore_ascii_case("users") || parts[0] == "home") { &parts[2..] }
        else if parts[0] == "root" && absolute { &parts[1..] }
        else { return false };
    // A named cache's subtree, not the entire cache directory. Unknown or globbed owners aren't exempt.
    let cache_skip = if user_parts.first() == Some(&".cache") { 1 }
        else if user_parts.starts_with(&["Library", "Caches"]) { 2 } else { 0 };
    if cache_skip > 0 {
        if let Some(owner) = user_parts.get(cache_skip) {
            if !owner.is_empty() && !owner.chars().any(|c| "*$?[]{}".contains(c) || c == '\u{fffd}' || c as u32 == super::val::UNKNOWN) { return false }
        }
    }
    // Preserve the named-cache exception above, including its existing handling
    // of an unknown suffix below a known owner. The whole cache is not exempt.
    if cache_skip > 0 || unknown || escaped_home || user_parts.len() < 2 { return true }
    if PERSONAL.iter().chain(CREDENTIALS).any(|p| overlaps(user_parts, p)) { return true }
    let first = user_parts[0].to_ascii_lowercase();
    if ["onedrive", "dropbox"].iter().any(|p| first == *p || first.starts_with(&format!("{p} - "))
        || first.starts_with(&format!("{p} ("))) { return true }
    if user_parts.iter().any(|part| {
        let part = part.to_ascii_lowercase();
        part == ".git" || part.ends_with(".photoslibrary") || part.ends_with(".photolibrary")
    }) { return true }
    false
}

pub fn parent(v: &Val) -> Val {
    if v.s.as_ref().is_some_and(|s| pystr::eq(s, REPOSITORIES)) { return v.clone() }
    let Some(s) = &v.s else { return Val::unknown().with_kinds(v) };
    let s = pystr::to_string(s).replace('\\', "/");
    let s = s.trim_end_matches('/');
    let mut out = match s.rsplit_once('/') { Some((p, _)) => Val::text(u(if p.is_empty() { "/" } else { p })), None => Val::unknown() };
    out.add_kinds(v);
    out
}

/// A recursive glob explicitly selecting .git directories denotes all matching repositories.
pub fn glob_path(v: &Val) -> Val {
    if v.s.as_ref().is_some_and(|s| { let s=pystr::to_string(s); s.contains("**") && s.split('/').any(|p| p == ".git") }) {
        repositories(v)
    } else { Val::unknown() }
}

/// Fixture/build trees contain repositories too; deleting those is ordinary cleanup.
pub fn repositories(root: &Val) -> Val {
    if let Some(s) = &root.s {
        let text = pystr::to_string(s).replace('\\', "/");
        let text = text.trim_start_matches("./");
        if ["tests/", "test/", "fixtures/", "build/", "dist/", "node_modules/.cache/"]
            .iter().any(|p| text.starts_with(p) || text == p.trim_end_matches('/')) {
            return Val::unknown().with_kinds(root);
        }
    }
    Val::text(u(REPOSITORIES)).with_kinds(root)
}

fn word(raw: &[u32], vars: &BTreeMap<String, String>) -> String {
    // sh_parse marks quoted/escaped dollars with NUL; never expand those.
    let mut s = pystr::to_string(raw).replace('\0', "<literal-dollar>");
    for (k,v) in vars {
        let needle = format!("${{{k}}}");
        let extra = s.matches(&needle).count().saturating_mul(v.len());
        if s.len().saturating_add(extra) > 65536 { return "\u{2}".to_string() }
        s=s.replace(&needle,v);
        let needle=format!("${k}");
        let mut start=0;
        while let Some(i)=s[start..].find(&needle) {
            let i=start+i; let end=i+needle.len();
            if s[end..].chars().next().is_none_or(|c| !(c.is_ascii_alphanumeric() || c=='_')) {
                if s.len().saturating_add(v.len()) > 65536 { return "\u{2}".to_string() }
                s.replace_range(i..end,v); start=i+v.len();
            } else { start=end; }
        }
    }
    s
}

/// The shell parser supplies real command positions, so comments and echo's quoted examples don't count.
pub fn shell_deletes(p: &Pack, text: &[u32]) -> Vec<(usize, Val)> {
    let clean = shell::sh_comments_blanked(text).unwrap_or_else(|| text.to_vec());
    let mut vars = BTreeMap::new();
    let mut out = Vec::new();
    for cmd in shell::sh_parse(p, &clean) {
        let (at,name,_) = shell::sh_program(p,&cmd);
        for w in cmd.words.iter().take(at.unwrap_or(cmd.words.len())) {
            let raw = pystr::to_string(w);
            if let Some((k,v)) = raw.split_once('=') {
                if vars.len()<64 && k.chars().all(|c| c.is_ascii_alphanumeric() || c=='_') { vars.insert(k.to_string(),word(&u(v),&vars)); }
            }
        }
        let Some(at)=at else {continue};
        let name=pystr::to_string(&name);
        let args:Vec<String>=cmd.words.iter().skip(at+1).map(|s|word(s,&vars)).collect();
        let recursive=args.iter().any(|a| a.eq_ignore_ascii_case("-recurse") || a.eq_ignore_ascii_case("/s"));
        let deleting=matches!(name.as_str(),"rm"|"shred") || (matches!(name.as_str(),"del"|"erase"|"rd"|"rmdir"|"remove-item"|"ri") && recursive);
        if deleting {
            for a in &args { if a.starts_with('-') || matches!(a.to_ascii_lowercase().as_str(),"/s"|"/q"|"/f") {continue} out.push((0,Val::text(u(a)))); }
        }
        if name=="find" {
            let executes_delete = args.windows(2).enumerate().any(|(k,a)| {
                (a[0]=="-exec" || a[0]=="-execdir") && (a[1]=="rm" || a[1]=="shred")
                    && args[k+2..].iter().take_while(|a| a.as_str()!=";" && a.as_str()!="+").any(|a| a=="{}")
            });
            let deletes=args.iter().any(|a| a=="-delete") || executes_delete;
            if deletes {
                let repos=args.windows(2).any(|a| (a[0]=="-name" || a[0]=="-iname") && a[1]==".git");
                if repos {out.push((0,repositories(&Val::text(u(args.first().map(String::as_str).unwrap_or("."))))));}
                else {for a in args.iter().take_while(|a|!a.starts_with('-')) {out.push((0,Val::text(u(a))));}}
            }
        }
        if out.len()>256 {out.truncate(256);break}
    }
    out
}

#[cfg(test)]
mod own_folder_tests {
    use super::*;
    use crate::{json, signs};

    #[test]
    fn approved_paths_and_source_shapes() {
        let fixture = json::parse_str(include_str!("../../../../../tests/fixtures/ra6-own-folders.json")).unwrap();
        for case in fixture.get("paths").unwrap().as_arr().unwrap() {
            let path = case.get("path").unwrap().as_str().unwrap();
            let expected = case.get("found") == Some(&json::Value::Bool(true));
            assert_eq!(dangerous(&Val::text(path.to_vec())), expected, "{}", pystr::to_string(path));
        }
        let pack = crate::pack::current();
        for case in fixture.get("sources").unwrap().as_arr().unwrap() {
            let text = case.get("text").unwrap().as_str().unwrap();
            let lang = case.get("lang").unwrap().as_string().unwrap();
            let name = case.get("name").unwrap().as_string().unwrap();
            let expected = case.get("found") == Some(&json::Value::Bool(true));
            let install = signs::install_script_risk(&pack, text, Some(&lang));
            assert_eq!(install.contains(&u(REASON)), expected, "{name}: {install:?}");
            if expected { assert_eq!(signs::install_script_severity(&pack, &install), Some("CRITICAL")); }
            let (import, line) = signs::import_time_risk(&pack, text, Some(&lang));
            assert_eq!(import.contains(&u(REASON)), expected, "{name}: {import:?}");
            if let Some(want) = case.get("line").and_then(|v| v.as_i64()) {
                assert_eq!(line, Some(want as usize), "{name}");
            }
        }
    }

    #[test]
    fn deep_literal_paths_remain_bounded() {
        let path = format!("~/.tool/{}state", "part/".repeat(10000));
        assert!(!dangerous(&Val::text(u(&path))));
        // Values beyond the reader limit end in UNKNOWN and cannot earn an exemption.
        assert!(dangerous(&Val::text(u(&path.repeat(2)))));
        assert!(dangerous(&Val::text(u(&format!("{path}/$unknown")))));
        assert!(dangerous(&Val::text(u(&format!("~/Documents/{}", "part/".repeat(10000))))));
    }
}
