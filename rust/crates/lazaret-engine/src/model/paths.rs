//! Lexical path APIs, independent of the scanner's host. Native APIs keep a
//! POSIX and a Windows interpretation. No filesystem or process cwd is read.
use super::val::{Val, UNKNOWN, MAX_TEXT};
use crate::pystr::{self, u};

#[derive(Clone, Copy, Debug)]
pub enum Flavor { Posix, Windows, Native }
#[derive(Clone, Copy, Debug)]
pub enum Api { NodeJoin(Flavor), NodeResolve(Flavor), PythonJoin(Flavor), GoJoin(Flavor), RustJoin }

pub fn apply(api: Api, parts: &[Val]) -> Val {
    // Reserve room for roots, separators, normalization and the home sentinel.
    // Check lengths before cloning/converting any input. Every temporary used by
    // evaluate is bounded by this sum; an overflowing join never materializes.
    let units=parts.iter().fold(16usize,|n,v|n.saturating_add(4).saturating_add(
        v.s.as_ref().map_or(40,|s|s.len()).max(v.path_win.as_ref().map_or(0,|s|s.len()))));
    if !crate::budget::spend((units.min(MAX_TEXT).saturating_mul(4)/16+parts.len()+1) as u64) {
        return Val::text(vec!['/' as u32,UNKNOWN])
    }
    if units>MAX_TEXT {
        // Keep a bounded prefix for read/source matching, with an unknown tail.
        // The other interpretation is explicitly unsafe: truncation must never
        // earn an own-folder exemption, even after later normalization/reset.
        let mut text=Vec::with_capacity(MAX_TEXT);
        for part in parts {
            if !text.is_empty() {text.push('/' as u32)}
            let remaining=(MAX_TEXT-2).saturating_sub(text.len());
            if let Some(s)=&part.s {text.extend(s.iter().take(remaining).copied())}
            else {text.push(UNKNOWN)}
            if text.len()>=MAX_TEXT-2 {break}
        }
        text.push(UNKNOWN);
        let mut v=Val::text(text);v.set_windows(vec!['/' as u32,UNKNOWN]);
        for part in parts {v.add_kinds(part)}
        return v
    }
    // A home API's '~' is a model anchor, not a literal tilde argument. Make
    // it absolute during lexical operations; an unknown root cannot cancel
    // through '..'. Literal tildes never get this treatment.
    let mut symbolic=false;
    let mut text=|v:&Val,win:bool| {
        let s=pystr::to_string(&if win {v.windows_text()} else {v.text_or_unknown()});
        if v.kinds & crate::jsflow::supply::K_PATH!=0 && (s=="~" || s.starts_with("~/") || s.starts_with("~\\")) {
            symbolic=true;format!("/\u{1}{}",&s[1..])
        } else {s}
    };
    let p:Vec<_>=parts.iter().map(|v|text(v,false)).collect();
    let alternatives=parts.iter().any(|v|v.path_win.is_some());
    let w:Vec<_>=if alternatives {parts.iter().map(|v|text(v,true)).collect()} else {Vec::new()};
    let restore=|s:String| {
        // The home anchor is distinct from UNKNOWN/cwd: a discarded home
        // must not relabel another drive's unknown cwd as the user's home.
        let offset=if s.as_bytes().get(1)==Some(&b':') && s.as_bytes()[0].is_ascii_alphabetic() {2} else {0};
        let tail=&s[offset..];
        if symbolic && (tail.starts_with("/\u{1}") || tail.starts_with("\\\u{1}")) && (tail.len()==2 || tail[2..].starts_with(sep)) {format!("~{}",&tail[2..])} else {s}
    };
    let (primary,other)=evaluate_home(api,&p,false);
    let mut v=Val::text(u(&restore(primary)));
    let same_api=matches!(api,Api::NodeJoin(Flavor::Posix|Flavor::Windows)|Api::NodeResolve(Flavor::Posix|Flavor::Windows)|Api::PythonJoin(Flavor::Posix|Flavor::Windows)|Api::GoJoin(Flavor::Posix|Flavor::Windows));
    if !same_api || alternatives {v.set_windows(u(&restore(evaluate_home(api,if alternatives {&w} else {&p},true).0)));}
    else if let Some(other)=other {v.set_windows(u(&restore(other)));}
    for part in parts {v.add_kinds(part)}
    v
}

fn windows(f:Flavor, target:bool)->bool {match f {Flavor::Posix=>false,Flavor::Windows=>true,Flavor::Native=>target}}
fn sep(c:char)->bool {c=='/' || c=='\\'}

/// A symbolic home may be on the drive named by a drive-relative component.
/// Python retains home when that first drive matches; Node resolve selects the
/// rightmost drive. Evaluate that possible reading as well as the drive-less
/// reading. A later absolute reset still discards home normally. This retains
/// credential suffixes instead of replacing an entire path with UNKNOWN.
fn evaluate_home(api:Api,parts:&[String],target:bool)->(String,Option<String>) {
    let home=|s:&str|s.starts_with("/\u{1}") || s.starts_with("\\\u{1}");
    let drive=|s:&String| {
        let (d,_,_)=nt_root(s);
        (d.len()==2 && d.as_bytes()[0].is_ascii_alphabetic() && d.as_bytes()[1]==b':').then(||d.to_owned())
    };
    let chosen=parts.iter().rposition(|s|home(s)).and_then(|i|match api {
        Api::PythonJoin(f) if windows(f,target)=>parts[i+1..].iter().find_map(drive),
        Api::NodeResolve(f) if windows(f,target)=>parts.iter().rev().find_map(drive),
        _=>None,
    });
    let Some(drive)=chosen else {return (evaluate(api,parts,target),None)};
    let matched:Vec<_>=parts.iter().map(|s|if home(s) {format!("{drive}{s}")} else {s.clone()}).collect();
    let got=evaluate(api,&matched,target);let other=evaluate(api,parts,target);
    let different=(got!=other).then_some(other);
    (got,different)
}

/// Python's drive/root split preserves original separator spelling. UNC shares
/// are part of the drive, so a rooted component keeps the existing share.
fn nt_root(s:&str)->(&str,&str,&str) {
    let b=s.as_bytes();
    if b.len()>=2 && sep(b[0] as char) && sep(b[1] as char) {
        let start=if s.get(..8).is_some_and(|x|x.replace('/',"\\").eq_ignore_ascii_case("\\\\?\\UNC\\")) {8} else {2};
        if let Some(a)=s[start..].find(sep).map(|i|start+i) {
            if let Some(z)=s[a+1..].find(sep).map(|i|a+1+i) {return (&s[..z],&s[z..z+1],&s[z+1..])}
        }
        return (s,"","")
    }
    let d=if b.len()>=2 && b[1]==b':' {2} else {0};
    if b.get(d).is_some_and(|&c|sep(c as char)) {(&s[..d],&s[d..d+1],&s[d+1..])} else {(&s[..d],"",&s[d..])}
}

fn python_join(parts:&[String], win:bool)->String {
    let mut result=String::new();
    if !win {
        for (i,p) in parts.iter().enumerate() {
            if i==0 || p.starts_with('/') {result=p.clone()}
            else {if !result.is_empty() && !result.ends_with('/') {result.push('/')} result.push_str(p)}
        }
        return result
    }
    let (mut drive,mut root,mut tail)=(String::new(),String::new(),String::new());
    for (i,p) in parts.iter().enumerate() {
        let (d,r,t)=nt_root(p);
        if i==0 || (!d.is_empty() && !d.eq_ignore_ascii_case(&drive)) {
            drive=d.into();root=r.into();tail=t.into();
        } else if !r.is_empty() {
            if !d.is_empty() || drive.is_empty() {drive=d.into()}
            root=r.into();tail=t.into();
        } else {
            if !d.is_empty() {drive=d.into()}
            if !tail.is_empty() && !tail.ends_with(sep) {tail.push('\\')}
            tail.push_str(t);
        }
    }
    if !tail.is_empty() && root.is_empty() && !drive.is_empty() && !drive.ends_with(|c|sep(c)||c==':') {root.push('\\')}
    format!("{drive}{root}{tail}")
}

/// Node uses a complete host/share as a UNC root, accepting repeated separators
/// between them. An incomplete UNC is just a rooted path.
fn node_root(s:&str)->(String,bool,String) {
    let s=s.replace('/',"\\");let b=s.as_bytes();
    if s.starts_with("\\\\") && b.get(2).is_some_and(|&c|c!=b'\\') {
        if let Some(i)=s[2..].find('\\').map(|i|i+2) {
            let host=&s[2..i];let rest=s[i..].trim_start_matches('\\');
            if !rest.is_empty() {
                if host=="." || host=="?" {return (format!("\\\\{host}"),true,rest.into())}
                let end=rest.find('\\').unwrap_or(rest.len());
                return (format!("\\\\{host}\\{}",&rest[..end]),true,rest[end..].trim_start_matches('\\').into())
            }
        }
    }
    let d=if b.len()>=2 && b[0].is_ascii_alphabetic() && b[1]==b':' {2} else {0};
    (s[..d].into(),s[d..].starts_with('\\'),s[d..].trim_start_matches('\\').into())
}

fn components(s:&str,absolute:bool,win:bool)->String {
    let mut out:Vec<&str>=Vec::new();
    for x in s.split(|c|c=='/' || (win && c=='\\')) {
        match x {
            ""|"."=>{},
            ".."=>{
                if out.last().is_some_and(|p|*p!=".." && !p.contains(char::from_u32(UNKNOWN).unwrap()) && !p.contains('\u{1}')) {out.pop();}
                else if !absolute || out.last().is_some() {out.push(x)}
            }
            _=>out.push(x),
        }
    }
    out.join(if win {"\\"} else {"/"})
}

fn normalize(s:&str,win:bool,trailing:bool)->String {
    let (drive,absolute,tail)=if win {node_root(s)} else {(String::new(),s.starts_with('/'),s.to_owned())};
    let mut tail=components(&tail,absolute,win);let slash=if win {'\\'} else {'/'};
    if tail.is_empty() && !absolute {tail.push('.')}
    if trailing && !tail.is_empty() && s.ends_with(|c|c=='/' || (win && c=='\\')) {tail.push(slash)}
    let mut out=drive;
    if absolute {out.push(slash)}
    out.push_str(&tail);out
}

fn node_join(parts:&[String],win:bool)->String {
    let nonempty:Vec<_>=parts.iter().filter(|s|!s.is_empty()).map(String::as_str).collect();
    let mut s=nonempty.join(if win {"\\"} else {"/"});
    if win {
        // Joining a separator and a name must not manufacture a UNC root.
        let first=nonempty.first().copied().unwrap_or("");
        let b=first.as_bytes();
        let unc=b.len()>2 && sep(b[0] as char) && sep(b[1] as char) && !sep(b[2] as char);
        if !unc && s.starts_with(sep) {s=format!("\\{}",s.trim_start_matches(sep));}
    }
    let mut result=normalize(&s,win,true);
    if win {
        let (drive,absolute,_)=node_root(&s);
        let b=result.as_bytes();
        if drive.is_empty() && !absolute && ((b.len()>1 && b[0].is_ascii_alphabetic() && b[1]==b':') ||
            s.match_indices(':').any(|(i,_)|s.get(i+1..).is_some_and(|t|t.is_empty() || t.starts_with(sep)))) {
            result=format!(".\\{result}");
        }
    }
    result
}

fn node_resolve(parts:&[String],win:bool)->String {
    if !win {
        let mut selected=Vec::new();let mut absolute=false;
        for p in parts.iter().rev().filter(|p|!p.is_empty()) {
            selected.push(p.as_str());if p.starts_with('/') {absolute=true;break}
        }
        selected.reverse();let mut s=selected.join("/");
        // Relative resolution depends on the target's cwd, not this host's.
        if !absolute {s=format!("\u{2}/{s}")}
        let tail=components(&s,absolute,false);
        return if absolute {format!("/{tail}")} else {tail}
    }
    let (mut drive,mut absolute,mut selected)=(String::new(),false,Vec::new());
    for p in parts.iter().rev().filter(|p|!p.is_empty()) {
        let (d,a,t)=node_root(p);
        if !d.is_empty() {
            if !drive.is_empty() && !d.eq_ignore_ascii_case(&drive) {continue}
            if drive.is_empty() {drive=d}
        }
        if !absolute {selected.push(t);absolute=a}
        if absolute && !drive.is_empty() {break}
    }
    selected.reverse();let mut tail=selected.join("\\");
    if !absolute {tail=format!("\u{2}\\{tail}")}
    let tail=components(&tail,absolute,true);
    // An explicit drive resolves against that drive's unknown absolute cwd.
    // A wholly relative expression still supplies no evidence of user files.
    format!("{drive}{}{tail}",if absolute || !drive.is_empty() {"\\"} else {""})
}

fn go_join(parts:&[String],win:bool)->String {
    if !win {
        let p:Vec<_>=parts.iter().filter(|p|!p.is_empty()).map(String::as_str).collect();
        return if p.is_empty() {String::new()} else {normalize(&p.join("/"),false,false)}
    }
    let mut s=String::new();
    for p in parts {
        if s.is_empty() {s.push_str(p)}
        else if s.ends_with(sep) {
            let p=p.trim_start_matches(sep);
            if s.len()==1 && (p=="??" || p.starts_with("??\\") || p.starts_with("??/")) {s.push_str(".\\")}
            s.push_str(p);
        } else {
            if !s.ends_with(':') {s.push('\\')}
            s.push_str(p);
        }
    }
    if s.is_empty() {return s}
    let mut result=normalize(&s,true,false);
    // Go's Clean preserves a bare UNC share without Node's trailing separator.
    let (d,r,t)=nt_root(&s);
    if d.starts_with(sep) && r.is_empty() && t.is_empty() {result=d.replace('/',"\\")}
    if !s.starts_with(sep) && !s.as_bytes().get(1).is_some_and(|&c|c==b':') && result.split('\\').next().is_some_and(|p|p.contains(':')) {result=format!(".\\{result}")}
    result
}

fn evaluate(api:Api,parts:&[String],target:bool)->String {
    match api {
        Api::NodeJoin(f)=>node_join(parts,windows(f,target)),
        Api::NodeResolve(f)=>node_resolve(parts,windows(f,target)),
        Api::PythonJoin(f)=>python_join(parts,windows(f,target)),
        Api::GoJoin(f)=>go_join(parts,windows(f,target)),
        Api::RustJoin=>{
            if !target {return python_join(parts,false)}
            let mut path=String::new();
            for p in parts {
                let (drive,root,_)=nt_root(p);
                if !drive.is_empty() {path=p.clone()}
                else if !root.is_empty() {path=format!("{}{p}",nt_root(&path).0)}
                else {if !path.is_empty() && !path.ends_with(sep) && !path.ends_with(':') {path.push('\\')} path.push_str(p);}
            }
            path
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn symbolic_home_drive_and_cwd_are_not_erased() {
        use super::super::{deletion,events};
        use crate::jsflow::supply::K_CRED_FILE;
        for api in [Api::PythonJoin(Flavor::Windows),Api::PythonJoin(Flavor::Native),Api::NodeResolve(Flavor::Windows),Api::NodeResolve(Flavor::Native)] {
            let home=Val::home(u("~"));
            for suffix in ["C:","C:Documents","C:.ssh/id_ed25519"] {
                let got=apply(api,&[home.clone(),Val::text(u(suffix))]);
                assert!(deletion::dangerous(&got),"{api:?} {got:?}");
                assert!(!deletion::exempt_folder(&got));
                if suffix.contains(".ssh") {assert!(events::file_read(&crate::pack::current(),&got,0).kinds & K_CRED_FILE!=0,"{api:?} {got:?}");}
            }
            let reset=apply(api,&[home,Val::text(u("C:")),Val::text(u("D:/tmp/cache"))]);
            assert!(!deletion::dangerous(&reset),"{api:?} {reset:?}");
        }
        let rooted=apply(Api::NodeResolve(Flavor::Windows),&[Val::text(u("C:")),Val::text(u("..\\.."))]);
        assert!(deletion::dangerous(&rooted));
        for api in [Api::NodeResolve(Flavor::Native),Api::NodeResolve(Flavor::Posix),Api::NodeResolve(Flavor::Windows)] {
            assert!(!deletion::dangerous(&apply(api,&[Val::text(u("cache"))])));
        }
    }
    #[test]
    fn wide_joins_are_capped_before_evaluation() {
        use super::super::deletion;
        for api in [Api::NodeJoin(Flavor::Native),Api::NodeResolve(Flavor::Native),Api::PythonJoin(Flavor::Native),Api::GoJoin(Flavor::Native),Api::RustJoin] {
            for width in [4,8,16,32] {
                let mut parts=vec![Val::home(u("~/.tool/cache"))];
                parts.extend((0..width).map(|_|Val::text(vec!['a' as u32;60000])));
                let got=apply(api,&parts);
                assert!(got.s.as_ref().unwrap().len()<=MAX_TEXT);
                assert!(got.path_win.as_ref().unwrap().len()<=MAX_TEXT);
                assert!(!got.known());assert!(deletion::dangerous(&got));assert!(!deletion::exempt_folder(&got));
            }
        }
    }

    #[test]
    fn runtime_matrix() {
        let data=crate::json::parse_str(include_str!("../../../../../tests/fixtures/path-api-semantics.json")).unwrap();
        let mut failures=Vec::new();
        for row in data.as_arr().unwrap() {
            let api=match pystr::to_string(row.get("api").unwrap().as_str().unwrap()).as_str() {
                "node.posix.join"=>Api::NodeJoin(Flavor::Posix),"node.win32.join"=>Api::NodeJoin(Flavor::Windows),
                "node.posix.resolve"=>Api::NodeResolve(Flavor::Posix),"node.win32.resolve"=>Api::NodeResolve(Flavor::Windows),
                "python.posixpath.join"=>Api::PythonJoin(Flavor::Posix),"python.ntpath.join"=>Api::PythonJoin(Flavor::Windows),
                "go.path.Join"=>Api::GoJoin(Flavor::Posix),"go.filepath.windows.Join"=>Api::GoJoin(Flavor::Windows),
                x=>panic!("unknown API {x}"),
            };
            let parts:Vec<_>=row.get("parts").unwrap().as_arr().unwrap().iter().map(|p|Val::text(p.as_str().unwrap().to_vec())).collect();
            let got=pystr::to_string(&apply(api,&parts).text_or_unknown());
            let expected=pystr::to_string(row.get("result").unwrap().as_str().unwrap());
            if got!=expected {failures.push(format!("{api:?} {parts:?}: {got:?} != {expected:?}"));}
        }
        assert!(failures.is_empty(),"{}",failures.join("\n"));
    }

    #[test]
    fn platform_alternatives_reach_deletions_and_reads() {
        use super::super::{deletion,events};
        use crate::jsflow::supply::K_CRED_FILE;
        let v=apply(Api::PythonJoin(Flavor::Native),&[Val::text(u("C:/Users/example/.tool/state")),Val::text(u("D:/Users/example/Documents"))]);
        assert!(v.path_win.is_some());assert!(deletion::dangerous(&v));assert!(!deletion::exempt_folder(&v));
        assert!(deletion::dangerous(&Val::concat(&v,&Val::text(u("/child")))));
        let v=apply(Api::RustJoin,&[Val::text(u("C:/Users/example/.tool/state")),Val::text(u("D:/Users/example/.ssh/id_ed25519"))]);
        assert!(events::file_read(&crate::pack::current(),&v,0).kinds & K_CRED_FILE!=0);
        let v=apply(Api::NodeJoin(Flavor::Native),&[Val::text(u("/home/example")),Val::text(u("/.ssh/id_ed25519"))]);
        assert!(events::file_read(&crate::pack::current(),&v,0).kinds & K_CRED_FILE!=0);
        // API-derived home is absolute; a literal '~' is just a component.
        let home=Val::home(u("~"));
        let v=apply(Api::NodeResolve(Flavor::Native),&[home.clone(),Val::text(u(".tool/state"))]);
        assert!(deletion::exempt_folder(&v),"{v:?}");
        for api in [Api::NodeJoin(Flavor::Native),Api::NodeResolve(Flavor::Native),Api::GoJoin(Flavor::Native)] {
            assert!(deletion::dangerous(&apply(api,&[home.clone(),Val::text(u(".."))])));
        }
        assert_eq!(apply(Api::NodeJoin(Flavor::Posix),&[Val::text(u("~")),Val::text(u(".."))]).text_or_unknown(),u("."));
    }
}
