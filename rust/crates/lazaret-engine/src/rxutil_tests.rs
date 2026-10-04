//! P-16: the patterns linre could not run as they were written, rewritten
//! (a second group for a backreference to a name, unbounded repeats for
//! counts larger than a program holds) and checked where they are used
//! (rxutil::finditer_checked with the call site's check), answer as the
//! originals did on sre's own matcher: the same matches, spans and groups,
//! on texts built to sit on each side of every limit. The two rewrites that
//! read further than before (SC-EVAL-DECODER's decoder body, the arguments
//! of open() for a shell-profile write) answer as before within the old
//! limits, and find past them what the old ones cut off.

use super::*;
use crate::pack::{Pack, EMBEDDED};

/// The pack's patterns before P-16 (rule set 2.27.0).
const ORIGINALS: &[(&str, &str)] = &[
    ("_DV_CC_FOR_RE", r#"\bfor[ \t]*\([ \t]*(?:var|let)[ \t]+(?P<i>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*0[ \t]*;[ \t]*\1[ \t]*<[ \t]*(?P<d>[A-Za-z_$][\w$]*)[ \t]*\.[ \t]*length[ \t]*;"#),
    ("_DV_CC_LITERAL_RE", r#"\bString[ \t]*\.[ \t]*fromCharCode[ \t]*(?:\([ \t]*(?:\.\.\.[ \t]*\[[ \t]*(?P<a>(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})(?:[ \t]*,[ \t]*(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})){0,399}[ \t]*,?)[ \t]*\]|(?P<b>(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})(?:[ \t]*,[ \t]*(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})){0,399}[ \t]*,?))[ \t]*\)|\.[ \t]*apply[ \t]*\([ \t]*(?:null|undefined|this|String)[ \t]*,[ \t]*\[[ \t]*(?P<c>(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})(?:[ \t]*,[ \t]*(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})){0,399}[ \t]*,?)[ \t]*\][ \t]*\))|(?:''|"")[ \t]*\.[ \t]*join[ \t]*\([ \t]*(?:map[ \t]*\([ \t]*chr[ \t]*,[ \t]*[\[(][ \t]*(?P<d>(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})(?:[ \t]*,[ \t]*(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})){0,399}[ \t]*,?)[ \t]*[\])][ \t]*\)|\[?[ \t]*chr[ \t]*\([ \t]*(?P<v>[A-Za-z_]\w*)[ \t]*\)[ \t]+for[ \t]+\5[ \t]+in[ \t]+[\[(][ \t]*(?P<e>(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})(?:[ \t]*,[ \t]*(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})){0,399}[ \t]*,?)[ \t]*[\])][ \t]*\]?)[ \t]*\)|\bbyte(?:s|array)[ \t]*\([ \t]*[\[(][ \t]*(?P<f>(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})(?:[ \t]*,[ \t]*(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})){0,399}[ \t]*,?)[ \t]*[\])][ \t]*\)[ \t]*\.[ \t]*decode[ \t]*\([^()\n]{0,20}\)"#),
    ("_SA_CHECKSUM_RE", r#"try\s*\{\s*(?:var|const|let)\s+(?P<v>[A-Za-z_$][\w$]*)\s*=\s*(?P<e>[^;]{1,6000});\s*if\s*\(\s*(?P=v)\s*===\s*[A-Za-z_$][\w$]*\s*\)\s*break"#),
    ("_DV_ARRAY_RE", r#"(?<![\w$.])(?P<name>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*\[(?P<items>(?:\s*(?:'[^'\\\n]{0,400}'|"[^"\\\n]{0,400}")\s*,){0,63}\s*(?:'[^'\\\n]{0,400}'|"[^"\\\n]{0,400}")\s*,?\s*)\]"#),
    ("_SA_ACC_A_HEAD", r#"function\s+(?P<g>[A-Za-z_$][\w$]*)\s*\(\s*(?P<p>[A-Za-z_$][\w$]*)\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*\{\s*(?P=p)\s*=\s*(?P=p)\s*-\s*(?P<off>[^;{}]{1,300});\s*(?:var|const|let)\s+[A-Za-z_$][\w$]*\s*=\s*"#),
    ("_SA_ACC_B_TAIL", r#"\s*\(\s*\)\s*;\s*return\s+(?P=g)\s*=\s*function\s*\(\s*(?P<p>[A-Za-z_$][\w$]*)\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*\{\s*(?P=p)\s*=\s*(?P=p)\s*-\s*(?P<off>[^;{}]{1,300});"#),
    ("_DV_CC_CALL_TAIL", r#"[ \t]*\((?P<args>(?:[^()'"\n]|'[^'\\\n]{0,400}'|"[^"\\\n]{0,400}"){0,20000})\)"#),
    ("_DV_CC_ARRAY_TAIL", r#"[ \t]*=[ \t]*[\[(]\s*(?P<items>(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})(?:\s*,\s*(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})){0,4095}\s*,?)\s*[\])]"#),
    ("_PERSIST_WRITE_RE", r#"\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|outputFileSync|outputFile|outputJsonSync|outputJson|writeJsonSync|writeJson|copyFileSync|copyFile|cpSync|renameSync|symlinkSync|write_text|write_bytes|createOrUpdateFileContents)\s*\(|\bjson\.dump\s*\(|\bshutil\.(?:copy\w*|move)\s*\(|\bopen\s*\((?:[^()\n]|\([^()\n]{0,200}\)){0,300}?["'][wax]b?\+?["']"#),
    ("RULES[47]", r#"\b(?:eval|(?:new\s+)?Function|runIn(?:This|New)?Context)\s*\(\s*(?:\(?\s*function\s*\([^()]{0,80}\)\s*\{(?:[^{}]|\{[^{}]{0,2000}\}){0,2000}\}\s*\)?|[A-Za-z_$][\w$]*)\s*\(\s*(?:\[\s*\d+(?:\s*,\s*\d+){199}|'[^'\n]{1000}|\"[^\"\n]{1000}|`[^`]{1000})"#),
];

fn cps(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn original(name: &str) -> String {
    ORIGINALS.iter().find(|(n, _)| *n == name).map(|(_, t)| t.to_string()).unwrap_or_else(|| panic!("{}", name))
}

fn sre(src: &str) -> Regex {
    Regex::new_backtracking(&cps(src), 0).unwrap_or_else(|e| panic!("{:?}: {}", src, e.0))
}

fn lin(src: &[u32]) -> Regex {
    Regex::new(src, 0).unwrap_or_else(|e| panic!("{:?}: {}", crate::pystr::to_string(src), e.0))
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn text(&mut self, pieces: &[&str], most: usize) -> Vec<u32> {
        let n = self.below(most + 1);
        let mut t = Vec::new();
        for _ in 0..n {
            t.extend(cps(pieces[self.below(pieces.len())]));
        }
        t
    }
}

type View = (usize, usize, Vec<Option<Vec<u32>>>);

fn view(m: &Match, groups: &[&str]) -> View {
    (m.start(), m.end(), groups.iter().map(|g| m.name(g).map(|x| x.to_vec())).collect())
}

/// The original's finditer (sre's matcher) and the rewrite's checked one
/// find the same matches.
fn agree(name: &str, old: &Regex, new: &Regex, text: &[u32], groups: &[&str], ok: &dyn Fn(&Match) -> bool) {
    let want: Vec<View> = old.finditer(text).map(|m| view(&m, groups)).collect();
    let got: Vec<View> = finditer_checked(new, text, 0, text.len(), |m| ok(m)).iter().map(|m| view(m, groups)).collect();
    assert_eq!(got, want, "{}: on {:?}", name, crate::pystr::to_string(text));
}

fn numbers(rng: &mut Rng, n: usize) -> String {
    (0..n).map(|k| if rng.below(5) == 0 { format!("0x{:X}", k % 4096) } else { (k % 997).to_string() }).collect::<Vec<_>>().join(", ")
}

#[test]
fn a_name_matched_again_is_checked_as_its_backreference_was() {
    let p = Pack::from_json(EMBEDDED).unwrap();
    let mut rng = Rng(16);
    // the loop's index named again
    let (old, new) = (sre(&original("_DV_CC_FOR_RE")), p.re("_DV_CC_FOR_RE"));
    let pieces = ["for", "for(", "for (", "var ", "let ", "i", "ii", "j", " = ", "=", "0", ";", " ", "<", "d", "data",
                  ".length", "\t", "x", "(", "for(var i=0;i<d.length;", "for (let ab = 0; a < x.length;"];
    for _ in 0..3000 {
        let t = rng.text(&pieces, 14);
        agree("_DV_CC_FOR_RE", &old, new, &t, &["i", "d"], &|m| same_groups(m, &[("i", "i_again")]));
    }
    // the checksum loop's variable named again
    let (old, new) = (sre(&original("_SA_CHECKSUM_RE")), p.re("_SA_CHECKSUM_RE"));
    let pieces = ["try", "{", " ", "var ", "const ", "v", "w", "vv", "=", "a+b", "parseInt(x)", ";", "if", "(", "===",
                  "t", ")", "break", "}", "try{var v=a+b;if(v===t)break", "try { const w = 1; if (v === t) break"];
    for _ in 0..3000 {
        let t = rng.text(&pieces, 14);
        agree("_SA_CHECKSUM_RE", &old, new, &t, &["v", "e"], &|m| same_groups(m, &[("v", "v_again")]));
    }
    // the string arrays' accessors: the parameter, and form B's function
    let name = "_0xab";
    for (head, tail, form) in [("_SA_ACC_A_HEAD", "_SA_CALL_TAIL", 'A'), ("_SA_ACC_B_HEAD", "_SA_ACC_B_TAIL", 'B')] {
        let old_head = if form == 'A' { original(head) } else { crate::pystr::to_string(&p.text(head)) };
        let old_tail = if form == 'B' { original(tail) } else { crate::pystr::to_string(&p.text(tail)) };
        let old = sre(&format!("{}{}{}", old_head, name, old_tail));
        let mut src = p.text(head);
        src.extend(cps(name));
        src.extend(p.text(tail));
        let new = lin(&src);
        let same: &[(&str, &str)] = if form == 'A' { &[("p", "p2"), ("p", "p3")] } else { &[("g", "g2"), ("p", "p2"), ("p", "p3")] };
        let pieces = ["function ", "g", "h", "(", "p", "q", "pp", ",", " ", "x", ")", "{", "=", "-", "0x1", "7", ";",
                      "var ", "const ", "a", name, "(", ")", "return ", "function(", "}",
                      "function g(p, x) { p = p - 0x1; var a = _0xab();",
                      "function g(x, y) { var a = _0xab(); return g = function(p, x) { p = p - 7;"];
        for _ in 0..3000 {
            let t = rng.text(&pieces, 16);
            agree(head, &old, &new, &t, &["g", "p", "off"], &|m| same_groups(m, same));
        }
    }
}

#[test]
fn counts_past_what_a_program_holds_are_checked_as_they_were() {
    let p = Pack::from_json(EMBEDDED).unwrap();
    let mut rng = Rng(17);
    // the decoded view's constant arrays: at most 64 strings of 400 characters
    let (old, new) = (sre(&original("_DV_ARRAY_RE")), p.re("_DV_ARRAY_RE"));
    let (items, chars) = (p.usize("_DV_ARRAY_MAX_ITEMS"), p.usize("_DV_ARRAY_MAX_CHARS"));
    let check = |m: &Match| crate::signs::dv_array_fits(m.name("items").unwrap_or(&[]), items, chars);
    let pieces = ["x", "arr", " = ", "=", "[", "]", "'", "\"", "abc", ",", " ", "\n", "'a'", "\"b\"", "y = ['q', \"r\"]"];
    for k in 0..2500 {
        let mut t = rng.text(&pieces, 12);
        if k % 10 == 0 {
            // an array at the limits: 63 to 66 strings, one of 398 to 402 characters
            let n = 63 + rng.below(4);
            let long = 398 + rng.below(5);
            let mut a = String::from("v = [");
            for i in 0..n {
                let s = if i == n / 2 { "s".repeat(long) } else { format!("s{}", i) };
                a.push_str(&format!("'{}', ", s));
            }
            a.push(']');
            t.extend(cps(&a));
        }
        agree("_DV_ARRAY_RE", &old, new, &t, &["name", "items"], &check);
    }
    // a decoder's call: at most 20,000 items, strings of at most 400 characters
    let (most, longest) = (p.usize("_DV_CC_CALL_MAX_ITEMS"), p.usize("_DV_CC_CALL_MAX_CHARS"));
    let head = crate::pystr::to_string(&p.text("_DV_NAME_HEAD"));
    let old = sre(&format!("{}(?P<name>dec|f){}", head, original("_DV_CC_CALL_TAIL")));
    let mut src = p.text("_DV_NAME_HEAD");
    src.extend(cps("(?P<name>dec|f)"));
    src.extend(p.text("_DV_CC_CALL_TAIL"));
    let new = lin(&src);
    let check = |m: &Match| crate::signs::cc_call_fits(m.name("args").unwrap_or(&[]), most, longest);
    let pieces = ["dec", "f", "(", ")", "'abc'", "\"x\"", ",", " ", "1", "a", "\n", "'", "dec('a', 2)", "x.dec(1)"];
    for k in 0..2500 {
        let mut t = rng.text(&pieces, 12);
        if k % 25 == 0 {
            let s = "w".repeat(398 + rng.below(5));
            t.extend(cps(&format!("dec('{}', 1)", s)));
        }
        if k % 250 == 0 {
            let n = 19_995 + rng.below(10);
            t.extend(cps(&format!("f({})", "z".repeat(n))));
        }
        agree("_DV_CC_CALL_TAIL", &old, &new, &t, &["name", "args"], &check);
    }
    // a decoder's array of character codes: at most 4,096 numbers
    let most = p.usize("_DV_CC_ARRAY_MAX_INTS");
    let old = sre(&format!("{}codes{}", head, original("_DV_CC_ARRAY_TAIL")));
    let mut src = p.text("_DV_NAME_HEAD");
    src.extend(cps("codes"));
    src.extend(p.text("_DV_CC_ARRAY_TAIL"));
    let new = lin(&src);
    let check = |m: &Match| count_numbers(m.name("items").unwrap_or(&[])) <= most;
    for k in 0..400 {
        let n = if k % 4 == 0 { 4094 + rng.below(4) } else { 1 + rng.below(30) };
        let t = cps(&format!("var codes = [{}]; codes = ({}, )", numbers(&mut rng, n), numbers(&mut rng, 3)));
        agree("_DV_CC_ARRAY_TAIL", &old, &new, &t, &["items"], &check);
    }
    // String.fromCharCode and its kin: lists of at most 400 numbers, and the
    // comprehension's name again
    let (old, new) = (sre(&original("_DV_CC_LITERAL_RE")), p.re("_DV_CC_LITERAL_RE"));
    let most = p.usize("_DV_CC_LITERAL_MAX_INTS");
    let groups = ["a", "b", "c", "d", "e", "f", "v"];
    let check = |m: &Match| {
        same_groups(m, &[("v", "v_again")]) && groups[..6].iter().all(|g| m.name(g).map_or(true, |l| count_numbers(l) <= most))
    };
    let shapes = ["String.fromCharCode({})", "String.fromCharCode(...[{}])", "String.fromCharCode.apply(null, [{}])",
                  "''.join(map(chr, [{}]))", "''.join([chr(c) for c in [{}]])", "''.join(chr(c) for d in ({}))",
                  "bytes([{}]).decode('utf-8')", "bytearray(({})).decode()"];
    for k in 0..1600 {
        let n = if k % 5 == 0 { 398 + rng.below(5) } else { 1 + rng.below(6) };
        let shape = shapes[rng.below(shapes.len())];
        let mut t = cps(&shape.replace("{}", &numbers(&mut rng, n)));
        t.extend(rng.text(&["x", " ", ";", "chr(", ")", "1, 2", "]"], 4));
        agree("_DV_CC_LITERAL_RE", &old, new, &t, &groups, &check);
    }
}

#[test]
fn the_two_that_read_further_answer_as_before_within_their_old_limits() {
    let p = Pack::from_json(EMBEDDED).unwrap();
    let mut rng = Rng(18);
    // SC-EVAL-DECODER: a decoder body cut at 2,000 items before
    let new_src = {
        let raw = p.raw("RULES").unwrap();
        let list = raw.get("list").and_then(|l| l.as_arr()).unwrap();
        let e = list.iter().find(|r| r.get("map").and_then(|m| m.get("id")).and_then(|i| i.get("value")).and_then(|v| v.as_string()).as_deref() == Some("SC-EVAL-DECODER")).unwrap();
        e.get("map").unwrap().get("re").unwrap().get("re").unwrap().as_str().unwrap().to_vec()
    };
    let (old, new) = (sre(&original("RULES[47]")), lin(&new_src));
    let blob = format!("'{}'", "q".repeat(1000));
    for k in 0..300 {
        let body = "x+=1;".repeat(1 + rng.below(if k % 3 == 0 { 390 } else { 20 }));
        let t = cps(&format!("eval(function(p){{{}}}({}))", body, blob));
        let o: Vec<(usize, usize)> = old.finditer(&t).map(|m| m.span()).collect();
        let n: Vec<(usize, usize)> = new.finditer(&t).map(|m| m.span()).collect();
        assert_eq!(n, o, "a body of {} characters", body.len());
    }
    let long = cps(&format!("eval(function(p){{{}}}({}))", "x+=1;".repeat(500), blob));
    assert!(old.search(&long).is_none() && new.search(&long).is_some(), "a body of 2,500 characters");
    // a shell-profile write: open()'s arguments cut at 300 items before
    let (old, new) = (sre(&original("_PERSIST_WRITE_RE")), p.re("_PERSIST_WRITE_RE"));
    for k in 0..300 {
        let pad = "a".repeat(rng.below(if k % 3 == 0 { 280 } else { 30 }));
        let t = cps(&format!("open(os.path.join(h, '.bashrc'){}, 'a')", pad));
        assert_eq!(new.search(&t).map(|m| m.span()), old.search(&t).map(|m| m.span()), "{} characters", pad.len());
    }
    let far = cps(&format!("open('/root/.bashrc'{}, 'a')", " ".repeat(400)));
    assert!(old.search(&far).is_none() && new.search(&far).is_some(), "a mode 400 characters on");
}
