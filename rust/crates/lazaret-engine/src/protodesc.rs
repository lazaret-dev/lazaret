//! A protobuf file's descriptor that generated code hands to its runtime (0.1.9, FP-B64-PROTOBUF).
//!
//! protoc-gen-es (protobuf-es 2.x) embeds each `.proto` file's serialized FileDescriptorProto in the code it
//! generates, as base64, and hands it to the runtime's loader: `export const file_x = fileDesc("Ci…", [deps])`,
//! `fileDesc` imported from `@bufbuild/protobuf/codegenv1` or `codegenv2` (or required from it, or called as
//! `(0, x.fileDesc)(…)` once TypeScript has compiled the file to CommonJS). SC-B64 reported every such file, a long
//! base64 literal in code. The file scan still does: whether its finding is dropped is decided over the whole scan
//! (a project, a `--deps` tree, a package: [`usage`], the engine's `b64_descriptors`), where every file that could
//! read the descriptor back is in hand. A run is passed over only when
//!
//! - its bytes are one FileDescriptorProto read to its end by descriptor.proto's structure ([`file_descriptor`]):
//!   field 1 a `.proto` path, field 2 a package, the messages, enums, services and extensions with their fields,
//!   values and methods, each a known field of its message with its wire type, every name a protobuf name, every
//!   string UTF-8, nothing left over; no source information (comments: field 9), no JSON name (a field's 10) but the
//!   one protoc derives from the field's name (protoc-gen-es writes it for an extension: it carries nothing), a
//!   default value of at most [`MAX_DEFAULT`] characters (the review of Oct 27: what free text a descriptor can
//!   carry, which generated code never holds); options (which carry custom options of any number) read as
//!   well-formed fields;
//! - it is the whole first argument of that loader, bound as generated code binds it, and the descriptor it makes is
//!   used only as generated code uses it, in that file and in every other file of the scan (see [`usage`]).
//!
//! Base64 that is not such a descriptor (code, a descriptor with bytes after it, another message such as the
//! custom option values ts-proto embeds), or a descriptor handed to anything else (eval, Function, a write, a
//! function of the file's own, a module of another name) or read back (`file_x.proto…`), is SC-B64 as before. No
//! path or file name is read.

pub mod usage;

/// Nesting of messages read at most (descriptor.proto's own nest a few deep).
const MAX_DEPTH: usize = 64;

/// A field's default value is this many characters at most: a number, an enum value's name, a short string (the
/// longest of 61 real descriptors measured in the review of Oct 27 was 12), not free text.
pub const MAX_DEFAULT: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Msg {
    File,
    Message,
    ExtensionRange,
    Range,
    Field,
    Oneof,
    Enum,
    EnumValue,
    Service,
    Method,
}

/// What a field of a descriptor message holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Is {
    /// a `.proto` path: the file's name, a dependency
    Path,
    /// a package: dotted names, or empty
    Package,
    /// a name: a message's, a field's, an enum's …
    Name,
    /// a type's full name: `.pkg.Msg` (or relative)
    TypeName,
    /// "proto2", "proto3" or "editions"
    Syntax,
    /// UTF-8 text (the edition string protobuf 23 wrote)
    Text,
    /// a field's default value: UTF-8, MAX_DEFAULT characters at most
    Default,
    /// a varint
    Int,
    /// varints, one by one or packed
    Ints,
    /// a message of descriptor.proto
    Sub(Msg),
    /// an options message: well-formed fields of any number (custom options are extensions)
    Options,
}

/// descriptor.proto's fields of `m` (as of protobuf 30, editions 2024 included), but a file's source information
/// (9: comments of any length): text generated code never carries (FP-B64-PROTOBUF's review, B-1). A field's JSON
/// name (10) is held to the one its name gives (`message`).
fn field(m: Msg, n: u64) -> Option<Is> {
    use Is::*;
    use Msg::*;
    Some(match (m, n) {
        (File, 1) | (File, 3) | (File, 15) => Path,
        (File, 2) => Package,
        (File, 10) | (File, 11) => Ints,
        (File, 4) => Sub(Message),
        (File, 5) => Sub(Enum),
        (File, 6) => Sub(Service),
        (File, 7) => Sub(Field),
        (File, 8) => Options,
        (File, 12) => Syntax,
        (File, 13) => Text, // (protobuf 23's `string edition`, since reserved)
        (File, 14) => Int,
        (Message, 1) | (Message, 10) => Name,
        (Message, 2) | (Message, 6) => Sub(Field),
        (Message, 3) => Sub(Message),
        (Message, 4) => Sub(Enum),
        (Message, 5) => Sub(ExtensionRange),
        (Message, 7) => Options,
        (Message, 8) => Sub(Oneof),
        (Message, 9) => Sub(Range),
        (Message, 11) => Int,
        (ExtensionRange, 1) | (ExtensionRange, 2) => Int,
        (ExtensionRange, 3) => Options,
        (Range, 1) | (Range, 2) => Int,
        (Field, 1) => Name,
        (Field, 2) | (Field, 6) => TypeName,
        (Field, 3) | (Field, 4) | (Field, 5) | (Field, 9) | (Field, 17) => Int,
        (Field, 7) => Default,
        (Field, 10) => Text, // (the JSON name protoc derives from the name, and no other: `message`)
        (Field, 8) => Options,
        (Oneof, 1) => Name,
        (Oneof, 2) => Options,
        (Enum, 1) | (Enum, 5) => Name,
        (Enum, 2) => Sub(EnumValue),
        (Enum, 3) => Options,
        (Enum, 4) => Sub(Range),
        (Enum, 6) => Int,
        (EnumValue, 1) => Name,
        (EnumValue, 2) => Int,
        (EnumValue, 3) => Options,
        (Service, 1) => Name,
        (Service, 2) => Sub(Method),
        (Service, 3) => Options,
        (Method, 1) => Name,
        (Method, 2) | (Method, 3) => TypeName,
        (Method, 4) => Options,
        (Method, 5) | (Method, 6) => Int,
        _ => return None,
    })
}

/// The field a message must hold exactly once: its name (a file's, a message's …).
fn named(m: Msg) -> bool {
    !matches!(m, Msg::ExtensionRange | Msg::Range)
}

/// A varint at `b[i..]`: (value, the index after it).
fn varint(b: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for k in 0..10 {
        let x = *b.get(i)?;
        i += 1;
        v |= u64::from(x & 0x7F) << (7 * k);
        if x & 0x80 == 0 {
            return Some((v, i));
        }
    }
    None
}

/// A field read: its number, wire type, and its varint or its bytes' span.
struct Wire {
    num: u64,
    wt: u8,
    start: usize,
    end: usize,
}

/// The fields of `b`, read to its end (groups whole), or None when it is not well-formed protobuf.
fn wire(b: &[u8]) -> Option<Vec<Wire>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let (key, j) = varint(b, i)?;
        let (num, wt) = (key >> 3, (key & 7) as u8);
        if num == 0 || num > 0x1FFF_FFFF {
            return None;
        }
        let (start, end) = match wt {
            0 => {
                let (_, e) = varint(b, j)?;
                (j, e)
            }
            1 => (j, j.checked_add(8)?),
            5 => (j, j.checked_add(4)?),
            2 => {
                let (n, k) = varint(b, j)?;
                (k, k.checked_add(usize::try_from(n).ok()?)?)
            }
            3 => (j, group_end(b, j, num)?),
            _ => return None,
        };
        if end > b.len() {
            return None;
        }
        out.push(Wire { num, wt, start, end });
        i = end;
    }
    Some(out)
}

/// Where a group begun before `i` ends: after its end-group key of number `num` (groups nested inside it read too).
fn group_end(b: &[u8], mut i: usize, num: u64) -> Option<usize> {
    let mut open = vec![num];
    while let Some(&top) = open.last() {
        let (key, j) = varint(b, i)?;
        let (n, wt) = (key >> 3, key & 7);
        i = match wt {
            0 => varint(b, j)?.1,
            1 => j.checked_add(8)?,
            5 => j.checked_add(4)?,
            2 => {
                let (len, k) = varint(b, j)?;
                k.checked_add(usize::try_from(len).ok()?)?
            }
            3 => {
                if open.len() >= MAX_DEPTH {
                    return None;
                }
                open.push(n);
                j
            }
            4 => {
                if n != top {
                    return None;
                }
                open.pop();
                j
            }
            _ => return None,
        };
        if i > b.len() {
            return None;
        }
    }
    Some(i)
}

fn ident(t: &[u8]) -> bool {
    matches!(t.first(), Some(c) if c.is_ascii_alphabetic() || *c == b'_') && t.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn dotted(t: &[u8]) -> bool {
    !t.is_empty() && t.split(|&c| c == b'.').all(ident)
}

fn holds(is: Is, t: &[u8]) -> bool {
    match is {
        Is::Path => {
            t.ends_with(b".proto")
                && t.split(|&c| c == b'/').all(|seg| {
                    !seg.is_empty() && seg != b"." && seg != b".." && seg.iter().all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c))
                })
        }
        Is::Package => t.is_empty() || dotted(t),
        Is::Name => ident(t),
        Is::TypeName => dotted(t.strip_prefix(b".").unwrap_or(t)),
        Is::Syntax => matches!(t, b"proto2" | b"proto3" | b"editions"),
        Is::Text => std::str::from_utf8(t).is_ok(),
        Is::Default => std::str::from_utf8(t).is_ok_and(|x| x.chars().count() <= MAX_DEFAULT),
        _ => false,
    }
}

/// The JSON name protoc gives a field of this name (descriptor.cc's ToJsonName): each `_` dropped and the letter
/// after it upper-cased.
fn json_name(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    let mut upper = false;
    for &c in name {
        if c == b'_' {
            upper = true;
        } else if upper {
            out.push(c.to_ascii_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// Is `b` a message `m` of descriptor.proto, read to its end? A field's JSON name, when it has one, is the one its
/// name gives (B-1: a JSON name of its own is free text; protoc-gen-es keeps the derived one for an extension).
fn message(b: &[u8], m: Msg, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    let Some(fields) = wire(b) else {
        return false;
    };
    let mut names = 0;
    let mut name: Option<&[u8]> = None;
    let mut jsons: Vec<&[u8]> = Vec::new();
    for f in &fields {
        let Some(is) = field(m, f.num) else {
            return false; // a field descriptor.proto does not have
        };
        let body = &b[f.start..f.end];
        if f.num == 1 && named(m) {
            names += 1;
            name = Some(body);
        }
        if m == Msg::Field && f.num == 10 {
            jsons.push(body);
        }
        let ok = match (is, f.wt) {
            (Is::Int | Is::Ints, 0) => true,
            (Is::Ints, 2) => {
                let mut i = 0;
                while i < body.len() {
                    match varint(body, i) {
                        Some((_, j)) => i = j,
                        None => return false,
                    }
                }
                true
            }
            (Is::Sub(sub), 2) => message(body, sub, depth + 1),
            (Is::Options, 2) => wire(body).is_some(),
            (Is::Int | Is::Ints | Is::Sub(_) | Is::Options, _) => false,
            (_, 2) => holds(is, body),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    if !jsons.is_empty() && !name.is_some_and(|n| jsons.iter().all(|j| json_name(n) == *j)) {
        return false;
    }
    !named(m) || names == 1
}

/// Is `b` one protobuf FileDescriptorProto, read to its end by descriptor.proto's structure (see the module's
/// documentation)?
pub fn file_descriptor(b: &[u8]) -> bool {
    !b.is_empty() && message(b, Msg::File, 0)
}

#[cfg(test)]
mod tests;
