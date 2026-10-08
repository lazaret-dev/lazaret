//! A project's line metrics, one file's part (0.1.9, Q-1 step 4): what core's `compute_metrics` read from each
//! file, once its scan had read it, by lexing the file again in a second call and walking its lines in Python
//! (13 to 18% of a project scan after Q-1); the npm package did the same with its own lexer.
//!
//! For one file of the project (a dependency's are not counted): its non-blank lines that are comments (something
//! other than whitespace, all of it in comments, as `_comment_layout` reads them), its lines of code (the other
//! non-blank lines), and, in a language whose duplication is measured (Python, JavaScript, SQL, and a file of no
//! language: core's `DUP_LANGS`), the windows of six consecutive lines of code, each as a 64-bit FNV-1a hash of
//! the code points of its six lines stripped and joined with nothing between them, as core keyed a window. The
//! caller finds the windows that occur twice or more across the project's files, and counts their lines.
//!
//! The lines are core's: the text pinned to Unicode 13.0 and split at "\n" alone (a file's text arrives with its
//! line endings normalized; a JavaScript U+2028 does not end a line here, as it does for the rules), each stripped
//! as `str.strip()` strips.

use crate::filectx::{cut_spans, pin, FileCtx, Lang};
use crate::lexer;
use crate::pack::Pack;
use crate::pystr;

/// One file's part of the metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetrics {
    /// Non-blank lines that are not comment lines.
    pub ncloc: usize,
    /// Comment lines.
    pub comments: usize,
    /// Lines of code whose duplication is measured (`ncloc`, or 0 in a language not measured).
    pub measured: usize,
    /// Each window of six consecutive measured lines, in order (`measured - 5` of them, or none).
    pub windows: Vec<u64>,
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// The languages whose duplication is measured (core.DUP_LANGS), and a file of no language.
fn measured_lang(lang: Option<&str>) -> bool {
    matches!(lang, None | Some("py") | Some("js") | Some("sql"))
}

/// FNV-1a over code points: each one xored in whole, then the product.
fn window_hash(lines: &[&[u32]]) -> u64 {
    let mut h = FNV_OFFSET;
    for line in lines {
        for &c in line.iter() {
            h ^= c as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
    }
    h
}

/// The tally of a file's lines: (the line, whether it is a comment line), in order.
fn tally<'a>(lines: impl Iterator<Item = (&'a [u32], bool)>, measure: bool) -> FileMetrics {
    let (mut ncloc, mut comments) = (0, 0);
    let mut code: Vec<&[u32]> = Vec::new();
    for (line, comment) in lines {
        let t = pystr::strip(line);
        if t.is_empty() {
            continue;
        }
        if comment {
            comments += 1;
            continue;
        }
        ncloc += 1;
        if measure {
            code.push(t);
        }
    }
    let windows = if code.len() >= 6 { (0..code.len() - 5).map(|k| window_hash(&code[k..k + 6])).collect() } else { Vec::new() };
    FileMetrics { ncloc, comments, measured: code.len(), windows }
}

/// The metrics of a file the scan has read into `ctx`, from `text` as it arrived: the scan's own lines and comment
/// lines when they are core's (no CR in the text, and no U+2028 or U+2029, which end a JavaScript line for the
/// rules), else the file read again as `file_metrics` reads it. The same either way: the lines, and the lexer's
/// input, are then the same.
pub fn of_ctx(ctx: &FileCtx, text: &[u32]) -> FileMetrics {
    let split_elsewhere = text.iter().any(|&c| c == '\r' as u32 || (ctx.lang == Lang::Js && (c == 0x2028 || c == 0x2029)));
    if split_elsewhere {
        return file_metrics(ctx.p, text, ctx.lang.name(), ctx.jsx);
    }
    tally((0..ctx.len()).map(|i| (ctx.line(i), ctx.cmask[i])), measured_lang(ctx.lang.name()))
}

/// The metrics of one file of the project: `lang` as the scan read it (a language the lexer does not know is read
/// as text of none), `jsx` false for a TypeScript file.
pub fn file_metrics(p: &Pack, text: &[u32], lang: Option<&str>, jsx: bool) -> FileMetrics {
    let lang = lang.filter(|l| matches!(*l, "py" | "js" | "sql" | "go" | "rs"));
    let mut content = text.to_vec();
    if !pystr::is_ascii(&content) {
        pin(&mut content);
    }
    let spans = lexer::lex_comment_spans(p, &content, lang, None, jsx, None);
    // the lines, at "\n" alone, and each one's comment spans (core's _comment_layout)
    let mut starts = vec![0usize];
    for (i, &c) in content.iter().enumerate() {
        if c == '\n' as u32 {
            starts.push(i + 1);
        }
    }
    let n = starts.len();
    let end = |i: usize| if i + 1 < n { starts[i + 1] - 1 } else { content.len() };
    let mut cspans: Vec<Vec<(usize, usize)>> = vec![Vec::new(); n];
    for &(s, e) in &spans {
        let mut i = starts.partition_point(|&x| x <= s) - 1;
        while i < n {
            let (ls, le) = (starts[i], end(i));
            let a = s.max(ls) - ls;
            let b = e.min(le).saturating_sub(ls);
            if b > a {
                cspans[i].push((a, b));
            }
            if e <= le + 1 {
                break;
            }
            i += 1;
        }
    }
    let lines = cspans.iter().enumerate().map(|(i, sp)| {
        let line = &content[starts[i]..end(i)];
        // a comment line: something other than whitespace, all of it in comments (_comment_layout's mask)
        (line, !sp.is_empty() && pystr::strip(&cut_spans(line, sp)).is_empty() && !pystr::strip(line).is_empty())
    });
    tally(lines, measured_lang(lang))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack;

    fn cps(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    fn of(text: &str, lang: Option<&str>) -> FileMetrics {
        file_metrics(&pack::current(), &cps(text), lang, true)
    }

    #[test]
    fn comment_lines_code_lines_and_blank_lines() {
        let m = of("# a note\n\nx = 1  # and a comment\n   \n\"\"\"a docstring\"\"\"\ny = 2\n", Some("py"));
        assert_eq!((m.ncloc, m.comments, m.measured), (3, 1, 3));
        assert!(m.windows.is_empty(), "fewer than six lines of code: no window");
        let m = of("/* one\n   two */\nlet a = 1; // b\n", Some("js"));
        assert_eq!((m.ncloc, m.comments), (1, 2));
        let m = of("-- a\nSELECT 1;\n", Some("sql"));
        assert_eq!((m.ncloc, m.comments, m.measured), (1, 1, 1));
    }

    #[test]
    fn a_window_is_six_lines_of_code_and_a_repeat_has_the_same_key() {
        let six = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n";
        let m = of(&format!("{six}# between\n\n{six}"), Some("py"));
        assert_eq!((m.ncloc, m.comments, m.measured, m.windows.len()), (12, 1, 12, 7));
        assert_eq!(m.windows[0], m.windows[6], "the same six lines, the same key");
        assert_ne!(m.windows[0], m.windows[1]);
        // the lines are stripped, and joined with nothing between them, as core keyed a window
        let indented = of(&six.lines().map(|l| format!("    {l}\t")).collect::<Vec<_>>().join("\n"), None);
        assert_eq!(indented.windows, of(six, None).windows);
        assert_eq!(of("ab\nc\nd\ne\nf\ng\n", None).windows, of("a\nbc\nd\ne\nf\ng\n", None).windows);
    }

    #[test]
    fn go_and_rust_count_their_lines_but_not_their_windows() {
        let go = "// a\npackage x\n\nfunc a() {}\nfunc b() {}\nfunc c() {}\nfunc d() {}\nfunc e() {}\n";
        let m = of(go, Some("go"));
        assert_eq!((m.ncloc, m.comments, m.measured, m.windows.len()), (6, 1, 0, 0));
        let m = of("/// doc\nfn a() {}\n", Some("rs"));
        assert_eq!((m.ncloc, m.comments, m.measured), (1, 1, 0));
    }

    #[test]
    fn the_lines_are_cores_split_at_a_newline_alone() {
        // a JavaScript U+2028 does not end a line here (core.compute_metrics), nor does a CR the text kept
        let m = of("let a = 1;\u{2028}let b = 2;\nlet c = 3;\r\n", Some("js"));
        assert_eq!((m.ncloc, m.comments), (2, 0));
        // whitespace as str.isspace() reads it: U+3000, U+0085, the separators
        assert_eq!(of("\u{3000}\u{85}\n\u{2029}\nx\n", None).ncloc, 1);
        // a code point Unicode 13.0 leaves unassigned is U+FFFD (pinned), so its window's key does not depend on it
        assert_eq!(of("\u{10D4A}\nb\nc\nd\ne\nf\n", None).windows, of("\u{FFFD}\nb\nc\nd\ne\nf\n", None).windows);
    }

    #[test]
    fn a_scans_own_reading_gives_the_same_metrics() {
        // the scan's lines are core's but where a CR or (in JavaScript) a line separator is: then the file is read
        // again; the same metrics either way
        let p = pack::current();
        for (text, lang) in [("# a\nx = 1\n\ny = 2\n", "py"), ("// a\nlet b = 1;\u{2028}let c;\n/* d */\n", "js"),
                             ("x = 1\r\n# b\r\n", "py"), ("a();\u{2029}b();\n", "js"), ("-- a\nSELECT 1;\r", "sql"),
                             ("// a\nfn b() {}\n", "rs"), ("a = '\u{2028}'\n", "py")] {
            let t = cps(text);
            let ctx = FileCtx::new(&p, &t, Lang::from(Some(lang)), true);
            assert_eq!(of_ctx(&ctx, &t), file_metrics(&p, &t, Some(lang), true), "{text:?}");
        }
    }

    #[test]
    fn the_key_is_fnv_1a_over_code_points() {
        assert_eq!(window_hash(&[&cps("")[..]]), FNV_OFFSET);
        assert_eq!(window_hash(&[&cps("a")[..]]), (FNV_OFFSET ^ 0x61).wrapping_mul(FNV_PRIME));
        assert_eq!(window_hash(&[&cps("\u{10000}")[..]]), (FNV_OFFSET ^ 0x10000).wrapping_mul(FNV_PRIME));
    }
}
