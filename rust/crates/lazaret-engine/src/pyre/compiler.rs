// SPDX-License-Identifier: Apache-2.0 AND Python-2.0.1
//
// A Rust translation of CPython's Lib/re/_compiler.py,
// changed as rust/NOTICE summarizes, and distributed under CPython's
// license (rust/LICENSE-PYTHON) as well as Lazaret's. The original's
// notices:
//
//   Copyright (c) 1997-2001 by Secret Labs AB.  All rights reserved.
//   See the __init__.py file for information on usage and redistribution.
//
//   (Lib/re/__init__.py:)
//   This version of the SRE library can be redistributed under CNRI's
//   Python 1.6 license.  For any other use, please contact Secret Labs
//   AB (info@pythonware.com).
//
//   Copyright (c) 2001 Python Software Foundation; All Rights Reserved

//! Python's `re` compiler (re/_compiler.py, CPython 3.11-3.14), ported line
//! for line: parse tree to sre's code words, with the same case folding,
//! set optimizations and INFO block (min width, literal prefix, first
//! character set). One deliberate layout difference: a BIGCHARSET keeps its
//! 256 block numbers one per word (CPython packs four per word), which only
//! its matcher reads.

use super::constants::*;
use super::parser::{Node, RepeatKind, SetItem, State, SubPattern};
use crate::unicode;

/// One member of an optimized set (_optimize_charset's output).
#[derive(Clone, Debug)]
enum Cs {
    Negate,
    Literal(u32),
    Range(u32, u32),
    RangeUniIgnore(u32, u32),
    Category(u32),
    Charset(Vec<u32>),    // 8 words
    BigCharset(Vec<u32>), // count, 256 block numbers, count * 8 words
}

#[derive(Clone, Copy)]
struct Fold {
    unicode: bool,
}

impl Fold {
    fn iscased(&self, c: u32) -> bool {
        if self.unicode {
            unicode::sre_iscased(c)
        } else {
            c < 128 && (c as u8).is_ascii_alphabetic()
        }
    }
    fn tolower(&self, c: u32) -> u32 {
        if self.unicode {
            unicode::sre_lower(c)
        } else if c < 128 {
            (c as u8).to_ascii_lowercase() as u32
        } else {
            c
        }
    }
    fn fixes(&self, c: u32) -> Option<&'static [u32]> {
        if self.unicode {
            unicode::case_fixes(c)
        } else {
            None
        }
    }
}

fn combine_flags(flags: u32, add: u32, del: u32) -> u32 {
    let mut f = flags;
    if add & TYPE_FLAGS != 0 {
        f &= !TYPE_FLAGS;
    }
    (f | add) & !del
}

pub struct CompileError(pub String);

fn fold_for(flags: u32) -> Option<Fold> {
    if flags & FLAG_IGNORECASE != 0 && flags & FLAG_LOCALE == 0 {
        Some(Fold { unicode: flags & FLAG_UNICODE != 0 })
    } else {
        None
    }
}

fn compile(code: &mut Vec<u32>, pattern: &SubPattern, flags: u32, state: &State) -> Result<(), CompileError> {
    let fold = fold_for(flags);
    for node in &pattern.data {
        match node {
            Node::Literal(av) | Node::NotLiteral(av) => {
                let not = matches!(node, Node::NotLiteral(_));
                let op = if not { NOT_LITERAL } else { LITERAL };
                match fold {
                    None => {
                        code.push(op);
                        code.push(*av);
                    }
                    Some(f) if !f.iscased(*av) => {
                        code.push(op);
                        code.push(*av);
                    }
                    Some(f) => {
                        let lo = f.tolower(*av);
                        if !f.unicode {
                            code.push(if not { NOT_LITERAL_IGNORE } else { LITERAL_IGNORE });
                            code.push(lo);
                        } else if let Some(fx) = f.fixes(lo) {
                            code.push(IN_UNI_IGNORE);
                            let skip = code.len();
                            code.push(0);
                            if not {
                                code.push(NEGATE);
                            }
                            code.push(LITERAL);
                            code.push(lo);
                            for &k in fx {
                                code.push(LITERAL);
                                code.push(k);
                            }
                            code.push(FAILURE);
                            code[skip] = (code.len() - skip) as u32;
                        } else {
                            code.push(if not { NOT_LITERAL_UNI_IGNORE } else { LITERAL_UNI_IGNORE });
                            code.push(lo);
                        }
                    }
                }
            }
            Node::In(av) => {
                let (charset, hascased) = optimize_charset(av, fold);
                if !hascased {
                    code.push(IN);
                } else if fold.map(|f| !f.unicode).unwrap_or(false) {
                    code.push(IN_IGNORE);
                } else {
                    code.push(IN_UNI_IGNORE);
                }
                let skip = code.len();
                code.push(0);
                compile_charset(&charset, flags, code);
                code[skip] = (code.len() - skip) as u32;
            }
            Node::Any => code.push(if flags & FLAG_DOTALL != 0 { ANY_ALL } else { ANY }),
            Node::Repeat { kind, min, max, item } => {
                let (op, until, one) = match kind {
                    RepeatKind::Min => (REPEAT, MIN_UNTIL, MIN_REPEAT_ONE),
                    RepeatKind::Max => (REPEAT, MAX_UNTIL, REPEAT_ONE),
                    RepeatKind::Possessive => (POSSESSIVE_REPEAT, SUCCESS, POSSESSIVE_REPEAT_ONE),
                };
                if simple(item) {
                    code.push(one);
                    let skip = code.len();
                    code.push(0);
                    code.push(*min);
                    code.push(*max);
                    compile(code, item, flags, state)?;
                    code.push(SUCCESS);
                    code[skip] = (code.len() - skip) as u32;
                } else {
                    code.push(op);
                    let skip = code.len();
                    code.push(0);
                    code.push(*min);
                    code.push(*max);
                    compile(code, item, flags, state)?;
                    code[skip] = (code.len() - skip) as u32;
                    code.push(until);
                }
            }
            Node::Subpattern { group, add, del, p } => {
                if let Some(g) = group {
                    if *g > 0 {
                        code.push(MARK);
                        code.push(((g - 1) * 2) as u32);
                    }
                }
                compile(code, p, combine_flags(flags, *add, *del), state)?;
                if let Some(g) = group {
                    if *g > 0 {
                        code.push(MARK);
                        code.push(((g - 1) * 2 + 1) as u32);
                    }
                }
            }
            Node::Atomic(p) => {
                code.push(ATOMIC_GROUP);
                let skip = code.len();
                code.push(0);
                compile(code, p, flags, state)?;
                code.push(SUCCESS);
                code[skip] = (code.len() - skip) as u32;
            }
            Node::Failure => code.push(FAILURE),
            Node::Assert { dir, p } | Node::AssertNot { dir, p } => {
                code.push(if matches!(node, Node::Assert { .. }) { ASSERT } else { ASSERT_NOT });
                let skip = code.len();
                code.push(0);
                if *dir >= 0 {
                    code.push(0);
                } else {
                    let (lo, hi) = p.getwidth(state);
                    if lo > MAXCODE as u128 {
                        return Err(CompileError("looks too much behind".into()));
                    }
                    if lo != hi {
                        return Err(CompileError("look-behind requires fixed-width pattern".into()));
                    }
                    code.push(lo as u32);
                }
                compile(code, p, flags, state)?;
                code.push(SUCCESS);
                code[skip] = (code.len() - skip) as u32;
            }
            Node::At(av) => {
                code.push(AT);
                let mut av = *av;
                if flags & FLAG_MULTILINE != 0 {
                    av = at_multiline(av);
                }
                if flags & FLAG_LOCALE != 0 {
                    av = at_locale(av);
                } else if flags & FLAG_UNICODE != 0 {
                    av = at_unicode(av);
                }
                code.push(av);
            }
            Node::Branch(items) => {
                code.push(BRANCH);
                let mut tails = Vec::new();
                for av in items {
                    let skip = code.len();
                    code.push(0);
                    compile(code, av, flags, state)?;
                    code.push(JUMP);
                    tails.push(code.len());
                    code.push(0);
                    code[skip] = (code.len() - skip) as u32;
                }
                code.push(FAILURE);
                for t in tails {
                    code[t] = (code.len() - t) as u32;
                }
            }
            Node::Category(av) => {
                code.push(CATEGORY);
                code.push(if flags & FLAG_LOCALE != 0 {
                    ch_locale(*av)
                } else if flags & FLAG_UNICODE != 0 {
                    ch_unicode(*av)
                } else {
                    *av
                });
            }
            Node::GroupRef(g) => {
                code.push(match fold {
                    None if flags & FLAG_IGNORECASE == 0 => GROUPREF,
                    None => GROUPREF_LOC_IGNORE,
                    Some(f) if !f.unicode => GROUPREF_IGNORE,
                    Some(_) => GROUPREF_UNI_IGNORE,
                });
                code.push((*g - 1) as u32);
            }
            Node::GroupRefExists { group, yes, no } => {
                code.push(GROUPREF_EXISTS);
                code.push((*group - 1) as u32);
                let skipyes = code.len();
                code.push(0);
                compile(code, yes, flags, state)?;
                match no {
                    Some(no) if !no.is_empty() => {
                        code.push(JUMP);
                        let skipno = code.len();
                        code.push(0);
                        code[skipyes] = (code.len() - skipyes + 1) as u32;
                        compile(code, no, flags, state)?;
                        code[skipno] = (code.len() - skipno) as u32;
                    }
                    _ => {
                        code[skipyes] = (code.len() - skipyes + 1) as u32;
                    }
                }
            }
        }
    }
    Ok(())
}

fn compile_charset(charset: &[Cs], flags: u32, code: &mut Vec<u32>) {
    for item in charset {
        match item {
            Cs::Negate => code.push(NEGATE),
            Cs::Literal(c) => {
                code.push(LITERAL);
                code.push(*c);
            }
            Cs::Range(a, b) => {
                code.push(RANGE);
                code.push(*a);
                code.push(*b);
            }
            Cs::RangeUniIgnore(a, b) => {
                code.push(RANGE_UNI_IGNORE);
                code.push(*a);
                code.push(*b);
            }
            Cs::Charset(words) => {
                code.push(CHARSET);
                code.extend_from_slice(words);
            }
            Cs::BigCharset(words) => {
                code.push(BIGCHARSET);
                code.extend_from_slice(words);
            }
            Cs::Category(c) => {
                code.push(CATEGORY);
                code.push(if flags & FLAG_LOCALE != 0 {
                    ch_locale(*c)
                } else if flags & FLAG_UNICODE != 0 {
                    ch_unicode(*c)
                } else {
                    *c
                });
            }
        }
    }
    code.push(FAILURE);
}

fn cs_of(item: &SetItem) -> Cs {
    match item {
        SetItem::Literal(c) => Cs::Literal(*c),
        SetItem::Range(a, b) => Cs::Range(*a, *b),
        SetItem::Category(c) => Cs::Category(*c),
        SetItem::Negate => Cs::Negate,
    }
}

fn mk_bitmap(bits: &[u8]) -> Vec<u32> {
    bits.chunks(32)
        .map(|chunk| chunk.iter().enumerate().fold(0u32, |w, (j, &b)| if b != 0 { w | (1 << j) } else { w }))
        .collect()
}

/// _optimize_charset: (set, hascased).
fn optimize_charset(charset: &[SetItem], fold: Option<Fold>) -> (Vec<Cs>, bool) {
    let mut out: Vec<Cs> = Vec::new();
    let mut tail: Vec<Cs> = Vec::new();
    let mut charmap: Vec<u8> = vec![0; 256];
    let mut hascased = false;
    for item in charset {
        let mut item = item.clone();
        loop {
            // one attempt; Err(()) is Python's IndexError
            let attempt: Result<(), ()> = (|| {
                match &mut item {
                    SetItem::Literal(av) => {
                        if let Some(f) = fold {
                            *av = f.tolower(*av);
                            set_at(&mut charmap, *av)?;
                            if let Some(fx) = f.fixes(*av) {
                                for &k in fx {
                                    set_at(&mut charmap, k)?;
                                }
                            }
                            if !hascased && f.iscased(*av) {
                                hascased = true;
                            }
                        } else {
                            set_at(&mut charmap, *av)?;
                        }
                    }
                    SetItem::Range(a, b) => {
                        let (a, b) = (*a, *b);
                        if let Some(f) = fold {
                            for i in a..=b {
                                let i = f.tolower(i);
                                set_at(&mut charmap, i)?;
                                if let Some(fx) = f.fixes(i) {
                                    for &k in fx {
                                        set_at(&mut charmap, k)?;
                                    }
                                }
                            }
                            if !hascased {
                                hascased = (a..=b).any(|i| f.iscased(i));
                            }
                        } else {
                            for i in a..=b {
                                set_at(&mut charmap, i)?;
                            }
                        }
                    }
                    SetItem::Negate => out.push(Cs::Negate),
                    other => tail.push(cs_of(other)),
                }
                Ok(())
            })();
            if attempt.is_err() {
                if charmap.len() == 256 {
                    charmap.resize(0x10000, 0);
                    continue;
                }
                // a character outside the BMP
                let mut cs = cs_of(&item);
                if let Some(f) = fold {
                    match &item {
                        SetItem::Range(a, b) => {
                            if f.unicode {
                                cs = Cs::RangeUniIgnore(*a, *b);
                            }
                            hascased = true;
                        }
                        SetItem::Literal(av) => {
                            if !hascased && f.iscased(*av) {
                                hascased = true;
                            }
                        }
                        _ => {}
                    }
                }
                tail.push(cs);
            }
            break;
        }
    }
    // compress the character map
    let mut runs: Option<Vec<(usize, usize)>> = Some(Vec::new());
    let mut q = 0usize;
    loop {
        let p = match charmap[q.min(charmap.len())..].iter().position(|&b| b == 1) {
            None => break,
            Some(i) => q + i,
        };
        if runs.as_ref().map(|r| r.len() >= 2).unwrap_or(false) {
            runs = None;
            break;
        }
        match charmap[p..].iter().position(|&b| b == 0) {
            None => {
                if let Some(r) = runs.as_mut() {
                    r.push((p, charmap.len()));
                }
                break;
            }
            Some(i) => {
                q = p + i;
                if let Some(r) = runs.as_mut() {
                    r.push((p, q));
                }
            }
        }
    }
    if let Some(runs) = runs {
        for (p, q) in runs {
            if q - p == 1 {
                out.push(Cs::Literal(p as u32));
            } else {
                out.push(Cs::Range(p as u32, (q - 1) as u32));
            }
        }
        out.extend(tail);
        if hascased || out.len() < charset.len() {
            return (out, hascased);
        }
        return (charset.iter().map(cs_of).collect(), hascased);
    }
    if charmap.len() == 256 {
        out.push(Cs::Charset(mk_bitmap(&charmap)));
        out.extend(tail);
        return (out, hascased);
    }
    // a big charset: 256-character chunks, duplicates shared
    let mut comps: Vec<&[u8]> = Vec::new();
    let mut mapping: Vec<u32> = Vec::with_capacity(256);
    let mut data: Vec<u8> = Vec::new();
    for i in (0..65536).step_by(256) {
        let chunk = &charmap[i..i + 256];
        match comps.iter().position(|c| *c == chunk) {
            Some(b) => mapping.push(b as u32),
            None => {
                mapping.push(comps.len() as u32);
                comps.push(chunk);
                data.extend_from_slice(chunk);
            }
        }
    }
    let mut words = vec![comps.len() as u32];
    words.extend(mapping);
    words.extend(mk_bitmap(&data));
    out.push(Cs::BigCharset(words));
    out.extend(tail);
    (out, hascased)
}

fn set_at(charmap: &mut [u8], i: u32) -> Result<(), ()> {
    match charmap.get_mut(i as usize) {
        Some(slot) => {
            *slot = 1;
            Ok(())
        }
        None => Err(()),
    }
}

fn simple(p: &SubPattern) -> bool {
    if p.data.len() != 1 {
        return false;
    }
    match &p.data[0] {
        Node::Subpattern { group, p, .. } => group.is_none() && simple(p),
        Node::Literal(_) | Node::NotLiteral(_) | Node::Any | Node::In(_) => true,
        _ => false,
    }
}

fn generate_overlap_table(prefix: &[u32]) -> Vec<u32> {
    let mut table = vec![0u32; prefix.len()];
    for i in 1..prefix.len() {
        let mut idx = table[i - 1] as usize;
        loop {
            if prefix[i] != prefix[idx] {
                if idx == 0 {
                    table[i] = 0;
                    break;
                }
                idx = table[idx - 1] as usize;
            } else {
                table[i] = (idx + 1) as u32;
                break;
            }
        }
    }
    table
}

fn get_iscased(flags: u32) -> Option<Fold> {
    if flags & FLAG_IGNORECASE == 0 {
        None
    } else {
        Some(Fold { unicode: flags & FLAG_UNICODE != 0 })
    }
}

/// (prefix, prefix_skip, got_all)
fn get_literal_prefix(pattern: &SubPattern, flags: u32) -> (Vec<u32>, Option<usize>, bool) {
    let mut prefix = Vec::new();
    let mut prefix_skip: Option<usize> = None;
    let iscased = get_iscased(flags);
    for node in &pattern.data {
        match node {
            Node::Literal(av) => {
                if let Some(f) = iscased {
                    if f.iscased(*av) {
                        return (prefix, prefix_skip, false);
                    }
                }
                prefix.push(*av);
            }
            Node::Subpattern { group, add, del, p } => {
                let flags1 = combine_flags(flags, *add, *del);
                if flags1 & FLAG_IGNORECASE != 0 && flags1 & FLAG_LOCALE != 0 {
                    return (prefix, prefix_skip, false);
                }
                let (prefix1, prefix_skip1, got_all) = get_literal_prefix(p, flags1);
                if prefix_skip.is_none() {
                    if group.is_some() {
                        prefix_skip = Some(prefix.len());
                    } else if let Some(s1) = prefix_skip1 {
                        prefix_skip = Some(prefix.len() + s1);
                    }
                }
                prefix.extend(prefix1);
                if !got_all {
                    return (prefix, prefix_skip, false);
                }
            }
            _ => return (prefix, prefix_skip, false),
        }
    }
    (prefix, prefix_skip, true)
}

fn get_charset_prefix(pattern: &SubPattern, flags: u32) -> Option<Vec<SetItem>> {
    let mut pattern = pattern;
    let mut flags = flags;
    let first = loop {
        let node = pattern.data.first()?;
        match node {
            Node::Subpattern { add, del, p, .. } => {
                pattern = p;
                flags = combine_flags(flags, *add, *del);
                if flags & FLAG_IGNORECASE != 0 && flags & FLAG_LOCALE != 0 {
                    return None;
                }
            }
            other => break other,
        }
    };
    let iscased = get_iscased(flags);
    let cased = |c: u32| iscased.map(|f| f.iscased(c)).unwrap_or(false);
    match first {
        Node::Literal(av) => {
            if cased(*av) {
                None
            } else {
                Some(vec![SetItem::Literal(*av)])
            }
        }
        Node::Branch(items) => {
            let mut charset = Vec::new();
            for p in items {
                match p.data.first() {
                    Some(Node::Literal(av)) if !cased(*av) => charset.push(SetItem::Literal(*av)),
                    _ => return None,
                }
            }
            Some(charset)
        }
        Node::In(av) => {
            if iscased.is_some() {
                for item in av {
                    match item {
                        SetItem::Literal(c) if cased(*c) => return None,
                        SetItem::Range(a, b) => {
                            if *b > 0xFFFF {
                                return None;
                            }
                            if (*a..=*b).any(&cased) {
                                return None;
                            }
                        }
                        _ => {}
                    }
                }
            }
            Some(av.clone())
        }
        _ => None,
    }
}

fn compile_info(code: &mut Vec<u32>, pattern: &SubPattern, flags: u32, state: &State) {
    let (lo, hi) = pattern.getwidth(state);
    let hi = hi.min(MAXCODE as u128) as u32;
    if lo == 0 {
        code.extend_from_slice(&[INFO, 4, 0, 0, hi]);
        return;
    }
    let mut prefix: Vec<u32> = Vec::new();
    let mut prefix_skip: Option<usize> = Some(0);
    let mut got_all = false;
    let mut charset: Option<Vec<SetItem>> = None;
    if !(flags & FLAG_IGNORECASE != 0 && flags & FLAG_LOCALE != 0) {
        let (p, s, g) = get_literal_prefix(pattern, flags);
        prefix = p;
        prefix_skip = s;
        got_all = g;
        if prefix.is_empty() {
            charset = get_charset_prefix(pattern, flags);
        }
    }
    code.push(INFO);
    let skip = code.len();
    code.push(0);
    let mut mask = 0;
    let charset = charset.filter(|c| !c.is_empty());
    if !prefix.is_empty() {
        mask = INFO_PREFIX;
        if prefix_skip.is_none() && got_all {
            mask |= INFO_LITERAL;
        }
    } else if charset.is_some() {
        mask |= INFO_CHARSET;
    }
    code.push(mask);
    if lo < MAXCODE as u128 {
        code.push(lo as u32);
    } else {
        code.push(MAXCODE as u32);
        prefix.truncate(MAXCODE as usize);
    }
    code.push(hi);
    if !prefix.is_empty() {
        code.push(prefix.len() as u32);
        code.push(prefix_skip.unwrap_or(prefix.len()) as u32);
        code.extend_from_slice(&prefix);
        code.extend(generate_overlap_table(&prefix));
    } else if let Some(cs) = charset {
        let (cs, _hascased) = optimize_charset(&cs, None);
        compile_charset(&cs, flags, code);
    }
    code[skip] = (code.len() - skip) as u32;
}

/// _code: the complete program for a parsed pattern.
pub fn code(p: &SubPattern, state: &State, flags: u32) -> Result<Vec<u32>, CompileError> {
    let flags = state.flags | flags;
    let mut code = Vec::new();
    compile_info(&mut code, p, flags, state);
    compile(&mut code, p, flags, state)?;
    code.push(SUCCESS);
    Ok(code)
}
