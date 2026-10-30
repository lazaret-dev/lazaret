//! Model files read for what they would run (FP-MODEL-FILES, 0.1.9): PyTorch's checkpoints (a zip with a
//! `<archive>/data.pkl`, the legacy pickle stream and tar), pickles of any protocol, joblib's files (plain, or
//! compressed with zlib or gzip), pandas' pickles compressed with zip (a zip of one pickle), numpy's .npy and .npz with
//! object arrays. Loading one (torch.load without
//! weights_only, joblib.load, pickle.load, numpy.load with allow_pickle) unpickles it, and a pickle runs what its
//! globals name and its REDUCE, BUILD, NEWOBJ, INST and OBJ opcodes call. Nothing here unpickles anything: the pickles
//! are read opcode by opcode (`vm`), and each global the file imports is judged by its name and by how it is used.
//!
//! * the globals a tensor checkpoint is rebuilt from (PyTorch's own weights-only unpickler's set:
//!   torch/_weights_only_unpickler.py), numpy's own pickling functions, and constructors of plain data that run nothing
//!   (PICKLE_SAFE_GLOBALS): a model of the formats — what PyTorch itself trusts to load — not an exemption; the
//!   data types of modules of code, named exactly (PICKLE_DATA_GLOBALS: http.HTTPStatus, signal.Signals,
//!   os.stat_result), are data too, while the rest of those modules is code;
//! * a member of the standard library's data enums by the exact name a pickle writes for it (PICKLE_DATA_MEMBERS:
//!   signal.SIGTERM, socket.AF_INET, ssl.CERT_REQUIRED, the module-level aliases Python 3.10 and 3.11.0 to 3.11.4
//!   pickle a converted enum's member as, and ssl.TLSVersion.TLSv1_2, the getattr(ssl.TLSVersion, 'TLSv1_2') those
//!   3.11 releases write for the others) is that data where it is only kept (pushed, stored, put in a container,
//!   handed to a call); called, made, changed (BUILD, SETITEM, APPEND on it) or in a pickle that calls an object it
//!   computed, it is judged as before, as code; its module and name each match exactly (FP-MODEL-FILES-PY311);
//! * getattr(<a global>, '<a name>'), how pickle writes a bound method (zoneinfo's ZoneInfo._unpickle, an Arrow
//!   extension type's deserializer), is read as that dotted global and judged by its name, its call as that global's;
//!   getattr in any other use (on what the pickle computed, a chain, a default, anywhere but as such a callee) stays
//!   builtins.getattr's: CRITICAL;
//! * a global that runs code or touches the system (PICKLE_CODE_MODULES, PICKLE_CODE_GLOBALS, a dotted name through
//!   PICKLE_CODE_ATTRS), in any use, and the shapes that run code whatever the names (a callable given to an object's
//!   __setstate__ or a class's special method, a class or function changed by BUILD, a class made with type(), text
//!   naming code handed to a call): SC-PICKLE-CODE, CRITICAL;
//! * any other global called with text that is not a plain name (a command, code, a path, a URL, a module path,
//!   bytes), or an object the pickle computed called: SC-PICKLE-GLOBAL, MAJOR. Objects remade by NEWOBJ and BUILD,
//!   a reconstructor handed the class it rebuilds, and calls with numbers, plain names and objects the pickle made
//!   (sklearn's trees, pandas' indexes) are what pickles of objects are;
//! * a global of the scanned package's own modules (importing it runs that module's code, which the scan reads, when
//!   the file is loaded: torch.save(model) of the package's own class): SC-PICKLE-GLOBAL, INFO, listed and setting no
//!   verdict, decided once the scan knows the package's files (`own_imports`); a call with text of it stays MAJOR,
//!   whatever its source says (an enum's member lookup too: which file a module name is when the file is loaded is
//!   the loading program's import path, the external re-review of Oct 27);
//! * an extension code (EXT1, EXT2, EXT4) called or made: SC-PICKLE-GLOBAL, MAJOR (the loading program's registry
//!   decides what it is); `__torch__` classes are trusted inside a TorchScript archive only;
//! * a pickle the reader cannot read to its end (cut short, an opcode no protocol has, past the reader's bounds, a
//!   compression it cannot undo, a file other than a zip larger than the scan reads, a nested load past the queue, a
//!   state or arguments it could not look through, an .npy dtype it cannot place, a zip whose count and directory
//!   disagree): SC-TRUNCATED.
//!
//! A zip model file is read by range whatever its size (`read_ranges`, zip::Bytes): its end records, its central
//! directory and the members the reader reads, never its tensor storages, so a checkpoint of hundreds of MB is judged
//! as one of a few KB is. A model file read this way is not an opaque nested archive (no SC-NESTED-ARCHIVE) when
//! every member is the format's by its content (`read_zip`): a member of any other kind keeps the archive opaque, a
//! pickle among them is read whatever its name, a program or an archive among them is reported as it would be at the
//! top (SC-BINARY, SC-NESTED-ARCHIVE), and a TorchScript archive's code is scanned as Python. The external review of
//! Oct 21 (H1–H7, M1–M4) shaped these: an .npy header read as numpy reads it (`npy`), every central directory entry
//! read, every copy of a legacy tar's member, a nested load past the queue said, BUILD state kept and looked through
//! past the reader's bounds (`vm`), byte ranges charged once.

pub mod npy;
pub mod vm;
pub mod zip;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};

use crate::findings::{format, Arg, RuleText};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};
use vm::{Book, End, Machine, V};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Safe,
    Code,
    Other,
}

/// What a global does that the reader models (the format's own helpers, and the few whose arguments matter).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Model {
    None,
    /// copyreg._reconstructor(cls, base, state)
    Reconstructor,
    /// copyreg.__newobj__ / __newobj_ex__(cls, …)
    NewObj,
    /// torch._tensor._rebuild_from_type(_v2)(func, new_type, args, state): func(*args)
    FromType,
    /// numpy's __randomstate_ctor / __generator_ctor(name, ctor): ctor(name)
    RandomCtor,
    /// numpy's __bit_generator_ctor(cls): cls()
    BitCtor,
    /// numpy's _ufunc_reconstruct(module, name): imports module.name
    Ufunc,
    /// bytes(), bytearray(), str(), chr(), _codecs.encode(): text made from other values
    TextMaker,
    /// builtins.type: a class made from three arguments
    TypeCall,
    Object,
    /// torch.storage._load_from_bytes(b): torch.load of the bytes, which are read as a file of their own
    LoadFromBytes,
    /// pickle.loads and the like (code): the bytes they load are read too
    NestedLoad,
    /// numpy.dtype
    Dtype,
    /// joblib's NumpyArrayWrapper: its array's bytes follow its BUILD
    ArrayWrapper,
    /// builtins.getattr: getattr(<a GLOBAL>, '<name>') read as that dotted global
    GetAttr,
}

/// What text a call's arguments hold, worst last.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TextKind {
    Plain,
    Word,
    Text,
    CodeName,
}

/// The pack's tables, read once.
pub struct Classes {
    safe: HashSet<Vec<u8>>,
    /// the data types a module of code defines (an enum, a result's named tuple: http.HTTPStatus, os.stat_result):
    /// the format's, whatever their module
    data: HashSet<Vec<u8>>,
    /// the members of the standard library's data enums by the exact (module, name) a pickle writes for them, in
    /// modules of code (signal, SIGTERM; ssl, TLSVersion.TLSv1_2): data where they are only kept, code where they are
    /// called. The pack writes each as `module.name`, its module the first dotted part
    members: HashSet<(Vec<u8>, Vec<u8>)>,
    safe_prefixes: Vec<Vec<u8>>,
    code_modules: HashSet<Vec<u8>>,
    code_globals: HashSet<Vec<u8>>,
    code_attrs: HashSet<Vec<u8>>,
    module_alias: HashMap<Vec<u8>, Vec<u8>>,
    name_alias: HashMap<Vec<u8>, Vec<u8>>,
    pub exts: Vec<Vec<u8>>,
    storage_sizes: HashMap<Vec<u8>, u64>,
}

fn bytes(s: &[u32]) -> Vec<u8> {
    pystr::to_string(s).into_bytes()
}

fn set_of(p: &Pack, name: &str) -> HashSet<Vec<u8>> {
    p.strs(name).iter().map(|s| bytes(s)).collect()
}

fn map_of(p: &Pack, name: &str) -> HashMap<Vec<u8>, Vec<u8>> {
    p.map_strs(name).iter().filter_map(|(k, v)| Some((bytes(k), bytes(v.first()?)))).collect()
}

/// The models, by the global's name once its module is Python 3's.
fn model_of(full: &[u8]) -> Model {
    match full {
        b"copyreg._reconstructor" => Model::Reconstructor,
        b"copyreg.__newobj__" | b"copyreg.__newobj_ex__" => Model::NewObj,
        b"torch._tensor._rebuild_from_type_v2" | b"torch._tensor._rebuild_from_type" => Model::FromType,
        b"numpy.random._pickle.__randomstate_ctor" | b"numpy.random._pickle.__generator_ctor" => Model::RandomCtor,
        b"numpy.random._pickle.__bit_generator_ctor" => Model::BitCtor,
        b"numpy.core._ufunc_reconstruct" | b"numpy._core._ufunc_reconstruct" => Model::Ufunc,
        b"builtins.bytes" | b"builtins.bytearray" | b"builtins.str" | b"builtins.chr" | b"_codecs.encode"
        | b"codecs.encode" => Model::TextMaker,
        b"builtins.type" => Model::TypeCall,
        b"builtins.getattr" => Model::GetAttr,
        b"builtins.object" => Model::Object,
        b"torch.storage._load_from_bytes" => Model::LoadFromBytes,
        b"pickle.loads" | b"_pickle.loads" | b"pickle._loads" | b"marshal.loads" | b"dill.loads" | b"dill._dill.loads"
        | b"cloudpickle.loads" | b"numpy.loads" | b"joblib.load" => Model::NestedLoad,
        b"numpy.dtype" => Model::Dtype,
        b"joblib.numpy_pickle.NumpyArrayWrapper" | b"sklearn.externals.joblib.numpy_pickle.NumpyArrayWrapper" => {
            Model::ArrayWrapper
        }
        _ => Model::None,
    }
}

fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = a.to_vec();
    v.push(b'.');
    v.extend_from_slice(b);
    v
}

impl Classes {
    pub fn of(p: &Pack) -> &Classes {
        p.derived("PICKLE_SAFE_GLOBALS", |_| Classes {
            safe: set_of(p, "PICKLE_SAFE_GLOBALS"),
            data: set_of(p, "PICKLE_DATA_GLOBALS"),
            members: set_of(p, "PICKLE_DATA_MEMBERS").into_iter()
                .filter_map(|full| {
                    let k = full.iter().position(|&c| c == b'.')?;
                    Some((full[..k].to_vec(), full[k + 1..].to_vec()))
                })
                .collect(),
            safe_prefixes: p.strs("PICKLE_SAFE_PREFIXES").iter().map(|s| bytes(s)).collect(),
            code_modules: set_of(p, "PICKLE_CODE_MODULES"),
            code_globals: set_of(p, "PICKLE_CODE_GLOBALS"),
            code_attrs: set_of(p, "PICKLE_CODE_ATTRS"),
            module_alias: map_of(p, "PICKLE_MODULE_ALIASES"),
            name_alias: map_of(p, "PICKLE_NAME_ALIASES"),
            exts: p.strs("PICKLE_EXTS").iter().map(|s| bytes(s)).collect(),
            storage_sizes: p.raw("PICKLE_STORAGE_SIZES").and_then(|m| m.get("map")).and_then(|m| m.as_obj())
                .map(|o| o.iter().filter_map(|(k, v)| Some((bytes(k), v.get("value")?.as_i64()? as u64))).collect())
                .unwrap_or_default(),
        })
    }

    /// Python 3's module and name for a pickle's (fix_imports: _compat_pickle's IMPORT_MAPPING and NAME_MAPPING).
    fn normalize(&self, module: &[u8], name: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let m = self.module_alias.get(module).cloned().unwrap_or_else(|| module.to_vec());
        if let Some(full) = self.name_alias.get(&join(module, name)).or_else(|| self.name_alias.get(&join(&m, name))) {
            if let Some(k) = full.iter().rposition(|&c| c == b'.') {
                return (full[..k].to_vec(), full[k + 1..].to_vec());
            }
        }
        (m, name.to_vec())
    }

    fn is_code(&self, module: &[u8], name: &[u8]) -> bool {
        // the module or a package it is in; the global, or a dotted path through a module of code
        let full = join(module, name);
        let mut prefix = Vec::new();
        for (k, part) in full.split(|&c| c == b'.').enumerate() {
            if k > 0 {
                prefix.push(b'.');
            }
            prefix.extend_from_slice(part);
            if self.code_modules.contains(&prefix) {
                return true;
            }
        }
        if self.code_globals.contains(&full) {
            return true;
        }
        // a name's own parts: an attribute that reaches code, or a module of code reached as an attribute
        name.split(|&c| c == b'.').any(|c| self.code_attrs.contains(c) || self.code_modules.contains(c))
    }

    /// Whether a global names a member of the standard library's data enums exactly (PICKLE_DATA_MEMBERS: the
    /// module-level alias signal.SIGTERM that Python 3.10 and 3.11.0 to 3.11.4 pickle Signals.SIGTERM as, the dotted
    /// ssl.TLSVersion.TLSv1_2 their getattr(ssl.TLSVersion, 'TLSv1_2') reads as). The module and the name each match
    /// exactly: GLOBAL 'ssl.TLSVersion' 'TLSv1_2' imports a module ssl.TLSVersion, which is none (H3 of the review of
    /// Oct 29). Its kind stays the module's (code): `findings` passes over such a global only when nothing called,
    /// made or changed it (FP-MODEL-FILES-PY311).
    pub fn is_member(&self, module: &[u8], name: &[u8]) -> bool {
        let (m, n) = self.normalize(module, name);
        self.members.contains(&(m, n)) || self.members.contains(&(module.to_vec(), name.to_vec()))
    }

    /// A global's kind and model, outside a TorchScript archive.
    pub fn classify(&self, module: &[u8], name: &[u8]) -> (Kind, Model) {
        self.classify_in(module, name, false)
    }

    /// A global's kind and model; `torchscript`: read in a TorchScript archive, whose `__torch__` classes are its own
    /// (PICKLE_SAFE_PREFIXES: elsewhere such a name is any other global's, M4 of the external review of Oct 21).
    pub fn classify_in(&self, module: &[u8], name: &[u8], torchscript: bool) -> (Kind, Model) {
        let (m, n) = self.normalize(module, name);
        let full = join(&m, &n);
        let model = model_of(&full);
        // (a data type of a module of code, named exactly: an attribute of it, or another member, is the module's)
        if self.data.contains(&full) || self.data.contains(&join(module, name)) {
            return (Kind::Safe, model);
        }
        if self.is_code(module, name) || self.is_code(&m, &n) {
            return (Kind::Code, model);
        }
        if self.safe.contains(&full) || (torchscript && self.safe_prefixes.iter().any(|p| full.starts_with(p))) {
            return (Kind::Safe, model);
        }
        (Kind::Other, model)
    }

    /// What a text handed to a call is: a dotted name or module:name that classifies as code (CodeName); text that
    /// tells code what to run, open or fetch (Text: a URL, an absolute, home or parent path, a command — white space
    /// with a shell or code character, or an option — a module path, bytes, more than 200 characters); other text,
    /// a name or a label (Word: `python`, `America/New_York`, `First Name`, `%Y-%m-%d`, `<f8`); or nothing.
    pub fn text_kind(&self, b: &[u8], len: usize) -> TextKind {
        if len > b.len() || len > 200 {
            return TextKind::Text;
        }
        if b.is_empty() {
            return TextKind::Plain;
        }
        let ident = |s: &[u8]| {
            !s.is_empty() && (s[0].is_ascii_alphabetic() || s[0] == b'_') && s.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        };
        if ident(b) {
            return TextKind::Word;
        }
        // module.name, module:name, module:obj.attr: what an import-by-name helper is handed
        let (path, attr): (&[u8], Option<&[u8]>) = match b.iter().position(|&c| c == b':') {
            Some(k) => (&b[..k], Some(&b[k + 1..])),
            None => (b, None),
        };
        let dotted = |s: &[u8]| s.split(|&c| c == b'.').all(ident);
        if dotted(path) && attr.is_none_or(dotted) && (attr.is_some() || path.contains(&b'.')) {
            let full: Vec<u8> = match attr {
                Some(a) => join(path, a),
                None => path.to_vec(),
            };
            if let Some(k) = full.iter().rposition(|&c| c == b'.') {
                if self.classify(&full[..k], &full[k + 1..]).0 == Kind::Code {
                    return TextKind::CodeName;
                }
            }
            return TextKind::Text;
        }
        let t = String::from_utf8_lossy(b);
        let drive = b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
        let path = t.starts_with('/') || t.starts_with('~') || t.starts_with("\\\\") || t.starts_with("./")
            || t.starts_with("../") || t.contains("/../") || t.contains("..\\") || drive;
        let space = t.chars().any(char::is_whitespace);
        let command = space && (t.chars().any(|c| ";|&$`(){}<>=".contains(c)) || t.contains(" -") || t.contains('\n'));
        if t.contains("://") || path || command {
            return TextKind::Text;
        }
        TextKind::Word
    }
}

// ---- recognition -------------------------------------------------------------------------------------------------

/// The 15 bytes PyTorch's legacy format starts with: its magic number, pickled with protocol 2.
const TORCH_MAGIC: &[u8] = b"\x80\x02\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19\x2e";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// a zip whose first member is `<archive>/data.pkl` (torch.save), an .npy (numpy.savez) or a pickle by its name
    /// (pandas' to_pickle with zip compression: read_pickle reads the zip's one member)
    Zip,
    Npy,
    Legacy,
    /// PyTorch's oldest format: a tar of storages, tensors and pickle
    Tar,
    /// a pickle stream of protocol 2 or later by its PROTO opcode, or a pickle by its name
    Pickle,
    /// text that starts as a protocol 0 pickle's GLOBAL does: a pickle if it reads to its STOP
    Proto0,
    Zlib,
    Gzip,
    /// compressed in a way the reader cannot undo (a pickle by its name)
    Packed(&'static str),
}

fn base_name(path: &[u32], windows: bool) -> Vec<u8> {
    bytes(&crate::binary::ext_and_base(path, windows).1).to_ascii_lowercase()
}

/// A pickle by its name: a pickle extension, or one before a compressor's (model.pkl.gz, model.joblib.bz2).
fn pickle_name(cls: &Classes, base: &[u8]) -> bool {
    cls.exts.iter().any(|e| {
        base.ends_with(e) || {
            let mut mid = e.clone();
            mid.push(b'.');
            base.windows(mid.len()).any(|w| w == mid.as_slice())
        }
    })
}

/// A record of PyTorch's archive (its name below the archive's folder, lower case) and what it must hold to be one:
/// a number, the byte order, a serialization id.
fn torch_record(rel: &[u8]) -> Option<fn(&[u8]) -> bool> {
    fn number(b: &[u8]) -> bool {
        let t = b.trim_ascii();
        !t.is_empty() && t.len() <= 20 && t.iter().all(u8::is_ascii_digit)
    }
    fn order(b: &[u8]) -> bool {
        matches!(b.trim_ascii(), b"little" | b"big")
    }
    fn id(b: &[u8]) -> bool {
        let t = b.trim_ascii();
        !t.is_empty() && t.len() <= 64 && t.iter().all(u8::is_ascii_alphanumeric)
    }
    match rel {
        b"version" | b".format_version" | b".storage_alignment" | b".data/version" => Some(number),
        b"byteorder" => Some(order),
        b".data/serialization_id" => Some(id),
        _ => None,
    }
}

/// A zip member's name after its last folder.
fn member_base(name: &[u8]) -> &[u8] {
    name.rsplit(|&c| c == b'/').next().unwrap_or(name)
}

/// A protocol 0 GLOBAL at the start: "c", a dotted name, "\n", a dotted name, "\n".
fn proto0_global(head: &[u8]) -> bool {
    let Some(rest) = head.strip_prefix(b"c") else { return false };
    let line = |s: &[u8]| -> Option<usize> {
        let k = s.iter().position(|&c| c == b'\n')?;
        let l = &s[..k];
        let ok = !l.is_empty()
            && l.split(|&c| c == b'.').all(|p| {
                !p.is_empty() && (p[0].is_ascii_alphabetic() || p[0] == b'_') && p.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
            });
        ok.then_some(k + 1)
    };
    match line(rest) {
        Some(k) => line(&rest[k..]).is_some(),
        None => false,
    }
}

/// The start of a pickle stream of protocol 2 or later: PROTO, a protocol, and an opcode.
fn proto_start(b: &[u8]) -> bool {
    b.len() >= 2 && b[0] == 0x80 && (2..=5).contains(&b[1]) && b.get(2).is_none_or(|&c| vm::is_opcode(c))
}

fn tar_member_name(h: &[u8]) -> &[u8] {
    let n = &h[..h.len().min(100)];
    &n[..n.iter().position(|&c| c == 0).unwrap_or(n.len())]
}

/// What the first bytes say about a decompressed stream: Some(true) a pickle, Some(false) not, None not enough.
fn inflated_start(format: lazaret_verify::inflate::Format, data: &[u8], named: bool) -> Option<bool> {
    use lazaret_verify::inflate::{Inflater, Limits, Status};
    let mut inf = Inflater::new(format, Limits::new(1 << 20));
    let mut out = [0u8; 16];
    let mut got = 0usize;
    let mut pos = 0usize;
    while got < out.len() {
        match inf.inflate(&data[pos..], &mut out[got..]) {
            Ok(pr) => {
                pos += pr.consumed;
                got += pr.produced;
                if pr.status != Status::NeedOutput && (pr.produced == 0 || pr.status == Status::Done) {
                    break;
                }
            }
            Err(_) => return Some(false),
        }
    }
    if got < 3 {
        return if pos >= data.len() { None } else { Some(false) };
    }
    Some(proto_start(&out[..got]) || (named && vm::is_opcode(out[0])))
}

fn shape(cls: &Classes, base: &[u8], head: &[u8]) -> Option<(Shape, bool)> {
    // (the shape, and whether a prefix of the file decides it)
    let named = pickle_name(cls, base);
    if let Some(first) = zip::first_local_name(head) {
        let low = first.to_ascii_lowercase();
        if low == b"data.pkl" || low.ends_with(b"/data.pkl") || low.ends_with(b".npy") || pickle_name(cls, member_base(&low)) {
            return Some((Shape::Zip, true));
        }
        return None;
    }
    if head.starts_with(b"\x93NUMPY") {
        return Some((Shape::Npy, true));
    }
    if head.starts_with(TORCH_MAGIC) {
        return Some((Shape::Legacy, true));
    }
    if proto_start(head) {
        return Some((Shape::Pickle, true));
    }
    if head.get(257..262) == Some(b"ustar") && matches!(tar_member_name(head), b"storages" | b"tensors" | b"pickle" | b"sys_info") {
        return Some((Shape::Tar, true));
    }
    if head.len() >= 2 && head[0] == 0x78 && (head[0] as u16 * 256 + head[1] as u16) % 31 == 0 {
        return match inflated_start(lazaret_verify::inflate::Format::Zlib, head, named) {
            Some(true) => Some((Shape::Zlib, true)),
            None => Some((Shape::Zlib, false)),
            Some(false) => None,
        };
    }
    if head.starts_with(b"\x1f\x8b\x08") {
        return match inflated_start(lazaret_verify::inflate::Format::Gzip, head, named) {
            Some(true) => Some((Shape::Gzip, true)),
            None => Some((Shape::Gzip, false)),
            Some(false) => None,
        };
    }
    if named {
        let packed = if head.starts_with(b"BZh") {
            Some("bzip2")
        } else if head.starts_with(b"\xfd7zXZ\x00") {
            Some("xz")
        } else if head.starts_with(b"\x5d\x00\x00") {
            Some("lzma")
        } else if head.starts_with(b"\x04\x22\x4d\x18") {
            Some("lz4")
        } else if head.starts_with(b"ZF") {
            Some("joblib's old zlib format")
        } else {
            None
        };
        if let Some(c) = packed {
            return Some((Shape::Packed(c), true));
        }
        if !head.is_empty() {
            return Some((Shape::Pickle, true));
        }
        return None;
    }
    if proto0_global(head) {
        return Some((Shape::Proto0, false));
    }
    None
}

/// Whether a file whose first bytes are `head` may be a model file: one to read whole (up to the scan's size limit).
pub fn sniff(p: &Pack, path: &[u32], head: &[u8], windows: bool) -> bool {
    shape(Classes::of(p), &base_name(path, windows), head).is_some() || short_tar(head)
}

/// A head too short to hold a legacy tar's magic (its bytes 257 to 262) that starts as one of that tar's member headers
/// (a name it reads, ended by NUL): first bytes of a larger file that may be a legacy checkpoint (a scan's member limit
/// set below the 512 bytes a sniff reads; the external review's streamed routes read 129).
fn short_tar(head: &[u8]) -> bool {
    let name = tar_member_name(head);
    head.len() < 262 && name.len() < head.len() && matches!(name, b"storages" | b"tensors" | b"pickle" | b"sys_info")
}

// ---- reading -----------------------------------------------------------------------------------------------------

/// A buffer one part of the file was read from.
enum Buf<'d> {
    Borrowed(&'d [u8]),
    Owned(Vec<u8>),
}

impl std::ops::Deref for Buf<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Buf::Borrowed(b) => b,
            Buf::Owned(v) => v,
        }
    }
}

struct Part<'d> {
    /// how a message names it ("" for the file itself)
    label: String,
    buf: Buf<'d>,
}

struct Reader<'d, 'c> {
    p: &'c Pack,
    cls: &'c Classes,
    book: Book<'c>,
    parts: Vec<Part<'d>>,
    /// why parts could not be read to their end
    cuts: Vec<String>,
    inflated: u64,
    max_inflated: u64,
    /// the zip holds members its format does not
    opaque: bool,
    kind: &'static str,
    /// findings of bytes read as a file of their own (a nested zip): (detail, severity)
    extra: Vec<(String, &'static str)>,
    /// a TorchScript archive's code scanned as Python: its issues
    code_issues: Vec<Value>,
    /// findings past MAX_CODE_ISSUES, and parts that could not be read past MAX_CUTS: not listed, their counts said
    /// (note_dropped)
    issues_dropped: usize,
    cuts_dropped: usize,
}

/// The findings of a model file's members (code_issues) a reading lists, and the parts that could not be read it lists
/// one by one (cut, zip_cut); past them each is counted, and the count said (note_dropped: the external re-review of
/// Oct 28, its LOW).
const MAX_CODE_ISSUES: usize = 64;
const MAX_CUTS: usize = 16;

/// What a model file is to the scan.
/// The answer of the `model_file` call: {"kind", "issues", "imports": [[module, name, how]], "opaque"}.
pub fn report_value(r: &Report) -> Value {
    Value::obj(vec![
        ("kind", Value::str(r.kind)),
        ("issues", Value::Arr(r.issues.clone())),
        ("imports", imports_value(&r.imports)),
        ("opaque", Value::Bool(r.opaque)),
        ("calls", calls_value(&r.calls)),
    ])
}

/// [[module, name, issue]] as `calls` holds them.
pub fn calls_value(calls: &[(String, String, Value)]) -> Value {
    Value::Arr(calls.iter().map(|(m, n, i)| Value::Arr(vec![Value::str(m), Value::str(n), i.clone()])).collect())
}

/// [[module, name, issue]] as calls_value writes them.
pub fn calls_of(v: Option<&Value>) -> Vec<(String, String, Value)> {
    v.and_then(|v| v.as_arr()).unwrap_or(&[]).iter().filter_map(|x| {
        let a = x.as_arr()?;
        let s = |k: usize| a.get(k).and_then(|v| v.as_str()).map(pystr::to_string);
        Some((s(0)?, s(1)?, a.get(2)?.clone()))
    }).collect()
}

pub fn imports_value(imports: &[(String, String, String)]) -> Value {
    Value::Arr(imports.iter().map(|(m, n, h)| Value::Arr(vec![Value::str(m), Value::str(n), Value::str(h)])).collect())
}

/// [[module, name, how]] as `imports` holds them.
pub fn imports_of(v: Option<&Value>) -> Vec<(String, String, String)> {
    v.and_then(|v| v.as_arr()).unwrap_or(&[]).iter().filter_map(|x| {
        let a = x.as_arr()?;
        let s = |k: usize| a.get(k).and_then(|v| v.as_str()).map(pystr::to_string);
        Some((s(0)?, s(1)?, s(2)?))
    }).collect()
}

pub struct Report {
    pub kind: &'static str,
    /// SC-PICKLE-CODE, SC-PICKLE-GLOBAL, SC-TRUNCATED (file-level issues)
    pub issues: Vec<Value>,
    /// the globals of no known kind it imports: [module, name, how], for the own-module check
    pub imports: Vec<(String, String, String)>,
    /// its archive holds more than its format does: SC-NESTED-ARCHIVE stays
    pub opaque: bool,
    /// each global of no known kind called with text it is told to use: (module, name, its SC-PICKLE-GLOBAL, MAJOR),
    /// held for model_own (own_imports), which reports it beside the own module's INFO
    pub calls: Vec<(String, String, Value)>,
}

/// Read `data` as a model file, or None when it is not one: the file whole, or its first bytes when it is larger
/// (`size`) than the scan reads (`limit`, named in the SC-TRUNCATED it gets then).
pub fn read_file(p: &Pack, path: &[u32], data: &[u8], size: u64, limit: Option<u64>, windows: bool) -> Option<Report> {
    let cls = Classes::of(p);
    let base = base_name(path, windows);
    let unread = || match limit {
        Some(l) => format!("{} bytes exceeds the {}-byte file limit, so the model file's pickle was not read",
                           commas(size), commas(l)),
        None => format!("the model file is {} bytes, more than the scan reads, so its pickle was not read", commas(size)),
    };
    let Some((sh, decided)) = shape(cls, &base, data) else {
        if size > data.len() as u64 && short_tar(data) {
            // (first bytes too few to tell a legacy checkpoint by: its pickle unread, said)
            let mut r = Reader::new(p, cls);
            r.kind = kind_name(Shape::Tar);
            r.cuts.push(unread());
            return Some(r.report());
        }
        return None;
    };
    let mut r = Reader::new(p, cls);
    if size > data.len() as u64 {
        // only the first bytes: a model file the scan did not read whole (an .npz, and what they do not decide, stays
        // what it was)
        let npz = sh == Shape::Zip && zip::first_local_name(data).is_some_and(|n| n.to_ascii_lowercase().ends_with(b".npy"));
        if !decided || npz {
            return None;
        }
        r.kind = kind_name(sh);
        r.cuts.push(unread());
        return Some(r.report());
    }
    r.kind = kind_name(sh);
    match sh {
        Shape::Zip => r.read_zip(&zip::Bytes::whole(data)),
        Shape::Npy => {
            let k = r.part(String::new(), Buf::Borrowed(data));
            r.read_npy(k, "the .npy file's object array");
        }
        Shape::Legacy => r.read_legacy(data),
        Shape::Tar => r.read_tar(data),
        Shape::Pickle => {
            let k = r.part(String::new(), Buf::Borrowed(data));
            r.read_pickles(k, 0, true);
        }
        Shape::Proto0 => {
            // text that starts as a pickle: one only if it reads to its STOP
            let mut probe_book = Book::new(cls);
            let mut m = Machine::new(data, 0, false);
            if !matches!(m.run(&mut probe_book), End::Stop(_)) {
                return None;
            }
            let k = r.part(String::new(), Buf::Borrowed(data));
            r.read_pickles(k, 0, true);
        }
        Shape::Zlib | Shape::Gzip => {
            let format = if sh == Shape::Zlib { lazaret_verify::inflate::Format::Zlib } else { lazaret_verify::inflate::Format::Gzip };
            let named = pickle_name(cls, &base);
            match lazaret_verify::inflate::decode_all(format, data, lazaret_verify::inflate::Limits::new(r.max_inflated)) {
                Ok(d) => {
                    if !(proto_start(&d) || (named && d.first().is_some_and(|&c| vm::is_opcode(c)))) {
                        return None;
                    }
                    r.inflated += d.len() as u64;
                    let k = r.part(String::new(), Buf::Owned(d));
                    r.read_pickles(k, 0, true);
                }
                Err(e) => {
                    if !decided {
                        return None;
                    }
                    r.cuts.push(format!("the model file's {} stream could not be decompressed: {e}", if sh == Shape::Zlib { "zlib" } else { "gzip" }));
                }
            }
        }
        Shape::Packed(c) => r.cuts.push(format!("the model file is compressed with {c}, which the reader cannot decompress, so its pickle was not read")),
    }
    r.nested(0);
    Some(r.report())
}

/// What a reading by range came to: not a model file, its report, or the ranges of the file ((offset, length)) it
/// needs read before it can say.
pub enum Ranged {
    Not,
    Report(Report),
    Need(Vec<(u64, u64)>),
}

/// The most bytes of a model file a reading by range reads: its pickles (PICKLE_MAX_INFLATED), its central directory
/// (PICKLE_MAX_DIRECTORY), and a MiB for its end records and the headers of the members read.
pub fn range_cap(p: &Pack) -> u64 {
    (p.int("PICKLE_MAX_INFLATED").max(0) as u64)
        .saturating_add(p.int("PICKLE_MAX_DIRECTORY").max(0) as u64)
        .saturating_add(1 << 20)
}

/// Read a zip model file by range, whatever its size (FP-MODEL-FILES): `src` holds the pieces of it the host read,
/// its first bytes among them. The reading reads its end records, its central directory and the members it reads
/// (every `*pkl` member, an .npy's header and an object array's pickle), never the tensor storages: Need until it has
/// them all, then its report. With `last` (the host reads no more), what it still needs is SC-TRUNCATED. A file whose
/// first bytes are not a zip model file's is Not (a host reads such a file whole or by its first bytes, read_file).
pub fn read_ranges(p: &Pack, path: &[u32], src: &zip::Bytes, windows: bool, last: bool) -> Ranged {
    let cls = Classes::of(p);
    let head = src.peek(0, src.size.min(512)).unwrap_or(&[]);
    if !matches!(shape(cls, &base_name(path, windows), head), Some((Shape::Zip, _))) {
        return Ranged::Not;
    }
    let mut r = Reader::new(p, cls);
    r.kind = kind_name(Shape::Zip);
    r.read_zip(src);
    let need = src.needs();
    if !need.is_empty() {
        if !last {
            return Ranged::Need(need);
        }
        let (at, len) = need[0];
        r.cuts.push(format!("the model file's zip archive could not be read: {} of its parts the reader reads {} not \
                             read (the first: {} bytes at byte {})",
                            commas(need.len() as u64), if need.len() == 1 { "was" } else { "were" }, commas(len), commas(at)));
    }
    r.nested(0);
    Ranged::Report(r.report())
}

fn kind_name(sh: Shape) -> &'static str {
    match sh {
        Shape::Zip => "zip",
        Shape::Npy => "numpy",
        Shape::Legacy | Shape::Tar => "pytorch-legacy",
        Shape::Zlib | Shape::Gzip | Shape::Packed(_) => "compressed-pickle",
        Shape::Pickle | Shape::Proto0 => "pickle",
    }
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

impl<'d, 'c> Reader<'d, 'c> {
    fn new(p: &'c Pack, cls: &'c Classes) -> Reader<'d, 'c> {
        Reader { p, cls, book: Book::new(cls), parts: Vec::new(), cuts: Vec::new(), inflated: 0,
                 max_inflated: p.int("PICKLE_MAX_INFLATED").max(0) as u64, opaque: false, kind: "pickle",
                 extra: Vec::new(), code_issues: Vec::new(), issues_dropped: 0, cuts_dropped: 0 }
    }

    fn part(&mut self, label: String, buf: Buf<'d>) -> usize {
        self.parts.push(Part { label, buf });
        self.parts.len() - 1
    }

    fn where_(&self, part: usize) -> String {
        let l = &self.parts[part].label;
        if l.is_empty() { "the pickle".into() } else { l.clone() }
    }

    fn cut(&mut self, part: usize, at: usize, why: &str) {
        let w = self.where_(part);
        if self.cuts.len() < MAX_CUTS {
            self.cuts.push(format!("{w} could not be read to its end: {why} (byte {at})"));
        } else {
            self.cuts_dropped += 1;
        }
    }

    /// One pickle at `start` of a part; the byte after its STOP, or None (the cut recorded).
    fn read_one(&mut self, part: usize, start: usize, joblib: bool, persistent: bool) -> Option<(usize, Option<V>)> {
        self.book.part = part;
        // (the buffer is the parts', the book is changed: two fields)
        let buf: &[u8] = &self.parts[part].buf;
        let mut m = Machine::new(buf, start, joblib);
        m.persistent = persistent;
        match m.run(&mut self.book) {
            End::Stop(e) => Some((e, m.result())),
            End::Error(at, why) => {
                self.cut(part, at, &why);
                None
            }
        }
    }

    /// A file of pickles: the first, then each that follows it (a second pickle.load reads one; bytes after the last
    /// that do not start a pickle are read as plain pickle.load would read them, and where that stops is not a cut).
    fn read_pickles(&mut self, part: usize, start: usize, joblib: bool) {
        let Some((mut e, _)) = self.read_one(part, start, joblib, false) else { return };
        let limit = self.p.usize("PICKLE_MAX_PICKLES");
        let mut n = 1;
        loop {
            let len = self.parts[part].buf.len();
            if e >= len || self.parts[part].buf[e..].iter().all(|&c| c == 0 || c.is_ascii_whitespace()) {
                return;
            }
            if n >= limit {
                let at = e;
                self.cut(part, at, &format!("more than {limit} pickles one after another"));
                return;
            }
            n += 1;
            if proto_start(&self.parts[part].buf[e..]) {
                match self.read_one(part, e, joblib, false) {
                    Some((next, _)) => e = next,
                    None => return,
                }
            } else {
                // not a pickle's start: what plain pickle.load would read there, its stop not a cut
                self.book.part = part;
                let buf: &[u8] = &self.parts[part].buf;
                let mut m = Machine::new(buf, e, false);
                match m.run(&mut self.book) {
                    End::Stop(next) => e = next,
                    End::Error(..) => return,
                }
            }
        }
    }

    /// A zip's members (`src`: the whole file, or the pieces of it a host read by range; what is not there is noted
    /// in it as needed and its member passed over). A member is the format's only when its content shows it (H6, the
    /// external review of Oct 21): a checkpoint's pickles (read), its tensor storages (`data/<n>`, and a TorchScript
    /// archive's `constants/<n>`: torch reads them as raw bytes, never unpickled), its small records (`version`,
    /// `byteorder` …: read, and held to what they hold), a TorchScript archive's code (`code/**.py`: scanned as Python,
    /// dependency mode), an .npz's arrays (`.npy`: their headers read). Any other member is read for what it is: a
    /// pickle by its bytes, whatever its name, is read as one; whatever it is, the archive holds more than its format
    /// (opaque: SC-NESTED-ARCHIVE stays), as an executable or an archive inside it does.
    fn read_zip(&mut self, src: &zip::Bytes) {
        let max = self.p.usize("PICKLE_MAX_ENTRIES");
        let max_dir = self.p.int("PICKLE_MAX_DIRECTORY").max(0) as u64;
        let listing = match zip::entries(src, max, max_dir) {
            Ok(l) => l,
            Err(zip::Miss::Need) => return,
            Err(zip::Miss::Bad(why)) => {
                self.cuts.push(format!("the model file's zip archive could not be read: {why}"));
                return;
            }
        };
        if let Some(why) = listing.ambiguous.first() {
            // (every member any unpacker finds is read; which one a loader takes the reader cannot say)
            let more = match listing.ambiguous.len() {
                1 => String::new(),
                n => format!(" (and {} more)", n - 1),
            };
            self.cuts.push(format!("the model file's zip archive may not list as a loader lists it: {why}{more}"));
            self.opaque = true;
        }
        let entries = listing.entries;
        let names: Vec<Vec<u8>> = entries.iter().map(|e| e.name.clone()).collect();
        let torch = names.iter().any(|n| {
            let l = n.to_ascii_lowercase();
            l == b"data.pkl" || l.ends_with(b"/data.pkl")
        });
        // pandas' to_pickle(compression="zip"): a zip of one member, the pickle (read_pickle reads that member)
        let pickled = |n: &[u8]| pickle_name(self.cls, member_base(&n.to_ascii_lowercase()));
        let lone = !torch && names.len() == 1 && pickled(&names[0]);
        self.kind = if torch { "pytorch" } else if lone { "compressed-pickle" } else { "numpy" };
        // PyTorch's archive folder: the first entry's (PyTorchStreamReader), and the layout below it
        let folder: Vec<u8> = names.first().map(|n| match n.iter().position(|&c| c == b'/') {
            Some(k) => n[..k + 1].to_vec(),
            None => Vec::new(),
        }).unwrap_or_default();
        let rel = |n: &[u8]| -> Option<Vec<u8>> { n.strip_prefix(folder.as_slice()).map(|r| r.to_vec()) };
        // a TorchScript archive (torch.jit.save: its code/ beside data.pkl and constants.pkl): torch.jit.load reads its
        // pickles with TorchScript's unpickler, whose __torch__ classes are the archive's own (M4)
        let torchscript = torch && names.iter().filter_map(|n| rel(n)).any(|r| r.starts_with(b"code/"));
        self.book.torchscript = torchscript;
        let mut marked: HashSet<u64> = HashSet::new();
        for e in &entries {
            let low = e.name.to_ascii_lowercase();
            let label = String::from_utf8_lossy(&e.name).to_string();
            if low.ends_with(b"/") && e.size == 0 {
                continue;                                    // (a folder's own entry)
            }
            let room = self.max_inflated.saturating_sub(self.inflated);
            let fetch = room.saturating_mul(2).saturating_add(1 << 20);
            // a member whose directory entry's mode (its external attributes' high bits, whatever system made it)
            // makes it other than a regular file (a symlink, a directory, a device, a FIFO, a socket), or a regular
            // file anyone may run, before anything the format owns is passed over (H4 of the external re-review of
            // Oct 27, and H3 and H4 of its second): no member the format holds is one, so the archive holds more than
            // its format (SC-NESTED-ARCHIVE, naming it with its type or mode), or a program (SC-BINARY). (A member only
            // a local header shows has no mode a reader trusts: its listing is ambiguous, SC-TRUNCATED.)
            if let Some(kind) = e.special_kind() {
                if marked.insert(e.local) {
                    self.opaque = true;
                    let mode = e.unix_mode().unwrap_or(0);
                    let found = nested_issue(self.p, &label, &format!("a member of type {kind} (Unix mode {mode:o}), \
                                                                       which the format does not hold."));
                    self.code_issue(found);
                }
            } else if e.executable() && marked.insert(e.local) {
                self.opaque = true;
                self.executable_member(src, e, &label, fetch);
            }
            let r = if torch { rel(&e.name) } else { None };
            let r_low = r.as_ref().map(|r| r.to_ascii_lowercase());
            let digits = |b: &[u8]| !b.is_empty() && b.iter().all(u8::is_ascii_digit);
            if let Some(rl) = &r_low {
                // a tensor storage: raw bytes
                let storage = rl.strip_prefix(b"data/").is_some_and(digits)
                    || (torchscript && rl.strip_prefix(b"constants/").is_some_and(digits));
                if storage {
                    continue;
                }
                // a record of the format: small, and what it holds is what the format writes there
                if let Some(check) = torch_record(rl) {
                    match zip::read(src, e, 64) {
                        Ok(b) if check(&b) => {}
                        Ok(_) => self.opaque = true,
                        Err(zip::Miss::Need) => {}
                        Err(zip::Miss::Bad(_)) => self.opaque = true,
                    }
                    continue;
                }
                if torchscript && rl.starts_with(b"code/") && rl.ends_with(b".py") {
                    self.torchscript_code(src, e, &label, room);
                    continue;
                }
            }
            let named_pkl = low.ends_with(b"pkl") || (!torch && pickled(&e.name));
            let npy = !torch && low.ends_with(b".npy");
            // the pickles the loader reads: a checkpoint's data.pkl; a TorchScript archive's constants.pkl and its
            // code's debug records; an .npz's arrays; pandas' one member
            let format = match &r_low {
                Some(rl) => rl == b"data.pkl"
                    || (torchscript && (rl == b"constants.pkl" || (rl.starts_with(b"code/") && rl.ends_with(b".debug_pkl")))),
                None => !torch && (npy || lone),
            };
            if !format {
                self.opaque = true;
            }
            // what the member's first bytes are (enough for a protocol 0 pickle's first GLOBAL, and a tar's header)
            let head = match zip::read_prefix(src, e, 512, fetch) {
                Ok(h) => h,
                Err(zip::Miss::Need) => continue,
                Err(zip::Miss::Bad(why)) => {
                    self.zip_cut(&label, &why);
                    self.opaque = true;
                    continue;
                }
            };
            self.inflated += head.len() as u64;
            let mut is_pickle = named_pkl || proto_start(&head) || proto0_global(&head) || head.starts_with(TORCH_MAGIC);
            if !is_pickle && !head.starts_with(b"\x93NUMPY") {
                // a program or an archive inside: what it would be at the top (SC-BINARY, SC-NESTED-ARCHIVE), named
                if !format {
                    let path = pystr::u(&label);
                    if let Some(mut bi) = crate::binary::classify(self.p, &path, &head, e.size, "model", false, false) {
                        let rule = bi.as_arr().and_then(|a| a.first()).and_then(|r| r.as_str()).map(pystr::to_string);
                        if matches!(rule.as_deref(), Some("SC-BINARY" | "SC-NESTED-ARCHIVE")) {
                            if let Value::Arr(a) = &mut bi {
                                if let Some(Value::Str(m)) = a.get_mut(4) {
                                    let mut msg = pystr::u(&format!("In {label}, inside the model file: "));
                                    msg.extend_from_slice(m);
                                    *m = msg;
                                }
                            }
                            self.code_issue(bi);
                            continue;
                        }
                    }
                }
                // other bytes: a pickle of protocol 0 or 1 too, when they read to a STOP as one (any member whose bytes
                // are a pickle is read as one, whatever its name)
                if !format && head.first().is_some_and(|&c| vm::is_opcode(c)) {
                    let room = self.max_inflated.saturating_sub(self.inflated);
                    if let Ok(b) = zip::read(src, e, room) {
                        let mut probe = Book::new(self.cls);
                        if matches!(Machine::new(&b, 0, false).run(&mut probe), End::Stop(_)) {
                            is_pickle = true;
                        }
                    }
                }
                if !is_pickle {
                    continue;                                // (data numpy does not read as an array, or other bytes)
                }
            }
            if !is_pickle {
                // an .npy: its header, read to its end (numpy's grammar); only an object array's pickle is read whole
                match npy_header(&head) {
                    Some((off, hl)) => {
                        let end = off.saturating_add(hl);
                        if end as u64 > room {
                            self.zip_cut(&label, "its .npy header is longer than the reader reads");
                            self.opaque = true;
                            continue;
                        }
                        match zip::read_prefix(src, e, end, fetch) {
                            Ok(h) => {
                                self.inflated += h.len() as u64;
                                match h.get(off..end).map(npy::header_has_object) {
                                    Some(Ok(false)) => continue,
                                    Some(Ok(true)) => {}
                                    // (not placed for certain: read whole, and the reading says why; the archive
                                    // is not proven read)
                                    _ => self.opaque = true,
                                }
                            }
                            Err(zip::Miss::Need) => continue,
                            Err(zip::Miss::Bad(why)) => {
                                self.zip_cut(&label, &why);
                                self.opaque = true;
                                continue;
                            }
                        }
                    }
                    None => self.opaque = true,
                }
            }
            let room = self.max_inflated.saturating_sub(self.inflated);
            let body = match zip::read(src, e, room) {
                Ok(b) => b,
                Err(zip::Miss::Need) => continue,
                Err(zip::Miss::Bad(why)) => {
                    self.zip_cut(&label, &why);
                    self.opaque = true;
                    continue;
                }
            };
            self.inflated += body.len() as u64;
            let k = self.part(label, Buf::Owned(body));
            if is_pickle {
                // (a checkpoint's pickles, and any member whose bytes are a pickle: read as one)
                if self.parts[k].buf.starts_with(TORCH_MAGIC) {
                    let mut at = 0;
                    for _ in 0..5 {
                        match self.read_one(k, at, false, true) {
                            Some((end, _)) => at = end,
                            None => break,
                        }
                    }
                } else {
                    self.read_one(k, 0, false, true);
                }
            } else {
                self.read_npy(k, "an object array");
            }
        }
    }

    /// A member a Unix system marked executable: SC-BINARY when its first bytes are a program's, else
    /// SC-NESTED-ARCHIVE (MINOR) naming it and its mode.
    fn executable_member(&mut self, src: &zip::Bytes, e: &zip::Entry, label: &str, fetch: u64) {
        let mode = e.unix_mode().unwrap_or(0);
        let head = match zip::read_prefix(src, e, 512, fetch) {
            Ok(h) => h,
            Err(zip::Miss::Need) => return,
            Err(zip::Miss::Bad(_)) => Vec::new(),
        };
        let prefix = pystr::u(&format!("In {label}, inside the model file: "));
        let program = crate::binary::classify(self.p, &pystr::u(label), &head, e.size, "model", false, false)
            .filter(|bi| bi.as_arr().and_then(|a| a.first()).and_then(|r| r.as_str()).map(pystr::to_string).as_deref()
                == Some("SC-BINARY"));
        let found = match program {
            Some(mut bi) => {
                if let Value::Arr(a) = &mut bi {
                    if let Some(Value::Str(m)) = a.get_mut(4) {
                        let mut msg = prefix;
                        msg.extend_from_slice(m);
                        *m = msg;
                    }
                }
                bi
            }
            None => nested_issue(self.p, label, &format!("a member with Unix mode {mode:o} (executable), which the \
                                                          format does not hold.")),
        };
        self.code_issue(found);
    }

    /// A TorchScript archive's code (`code/**.py`): Python as TorchScript writes it, scanned as a dependency's
    /// Python file is; its findings are the model file's, named for the member.
    fn torchscript_code(&mut self, src: &zip::Bytes, e: &zip::Entry, label: &str, room: u64) {
        let body = match zip::read(src, e, room) {
            Ok(b) => b,
            Err(zip::Miss::Need) => return,
            Err(zip::Miss::Bad(why)) => {
                self.zip_cut(label, &why);
                self.opaque = true;
                return;
            }
        };
        self.inflated += body.len() as u64;
        let text = crate::decode::utf::utf8(&body);
        let opts = crate::scanfile::Options { dep: true, redact: true, neumaier: false };
        for mut issue in crate::scanfile::scan_file(self.p, &text, Some("py"), false, &opts) {
            if let Value::Arr(a) = &mut issue {
                if let Some(Value::Str(m)) = a.get_mut(4) {
                    let mut msg = pystr::u(&format!("In {label}, TorchScript code in the model file: "));
                    msg.extend_from_slice(m);
                    *m = msg;
                }
            }
            self.code_issue(issue);
        }
    }

    fn zip_cut(&mut self, label: &str, why: &str) {
        if self.cuts.len() < MAX_CUTS {
            self.cuts.push(format!("{label} in the model file could not be read: {why}"));
        } else {
            self.cuts_dropped += 1;
        }
    }

    /// A finding of the model file's members, listed while there are fewer than MAX_CODE_ISSUES, else counted.
    fn code_issue(&mut self, found: Value) {
        if self.code_issues.len() < MAX_CODE_ISSUES {
            self.code_issues.push(found);
        } else {
            self.issues_dropped += 1;
        }
    }

    /// What the caps passed over, said with its count (SC-TRUNCATED, as the nested loads past vm::MAX_NESTED are): the
    /// places code runs past vm::MAX_CODE, the members' findings past MAX_CODE_ISSUES, and the parts that could not
    /// be read past MAX_CUTS. Once, before a reading is reported or absorbed.
    fn note_dropped(&mut self) {
        let (code, issues, cuts) = (self.book.code_dropped, self.issues_dropped, self.cuts_dropped);
        if code > 0 {
            self.cuts.push(format!("{code} more places the pickles run code were not listed (more than {})",
                                   vm::MAX_CODE));
        }
        if issues > 0 {
            self.cuts.push(format!("{issues} more findings in the model file's members were not listed (more than \
                                    {MAX_CODE_ISSUES})"));
        }
        if cuts > 0 {
            self.cuts.push(format!("{cuts} more parts of the model file that could not be read were not listed (more \
                                    than {MAX_CUTS})"));
        }
        self.book.code_dropped = 0;
        self.issues_dropped = 0;
        self.cuts_dropped = 0;
    }

    /// An .npy: its header's dtype; an object array's pickle.
    fn read_npy(&mut self, part: usize, what: &str) {
        let buf: &[u8] = &self.parts[part].buf;
        let Some((off, hl)) = npy_header(buf) else {
            self.cut(part, 6, "an .npy header of a version numpy does not write");
            return;
        };
        let Some(header) = off.checked_add(hl).and_then(|end| buf.get(off..end)) else {
            self.cut(part, off, "an .npy header longer than the file");
            return;
        };
        let objects = match npy::header_has_object(header) {
            Ok(o) => o,
            Err(why) => {
                self.cut(part, off, &why);
                return;
            }
        };
        if objects {
            let label = &self.parts[part].label;
            if !label.is_empty() {
                self.parts[part].label = format!("{label}'s object array");
            } else {
                self.parts[part].label = what.to_string();
            }
            self.read_one(part, off + hl, false, false);
        }
    }

    fn read_legacy(&mut self, data: &'d [u8]) {
        // magic number, protocol version, system info, the object (persistent ids), the storage keys; raw storage data
        let k = self.part(String::new(), Buf::Borrowed(data));
        let mut at = 0;
        for _ in 0..5 {
            match self.read_one(k, at, false, true) {
                Some((e, _)) => at = e,
                None => return,
            }
        }
    }

    fn read_tar(&mut self, data: &'d [u8]) {
        let members = match tar_members(data) {
            Ok(m) => m,
            Err(why) => {
                self.cuts.push(format!("the model file's tar archive could not be read: {why}"));
                return;
            }
        };
        // every member of a name (tarfile's getmember takes the last; H3, the external review of Oct 21: a benign
        // first copy hid a later one): each read, and a name twice keeps the archive opaque
        let all = |n: &[u8]| -> Vec<(usize, usize)> {
            members.iter().filter(|(name, _, _)| name == n).map(|&(_, s, l)| (s, l)).collect()
        };
        let mut seen: HashMap<&[u8], usize> = HashMap::new();
        for (name, _, _) in &members {
            if !matches!(name.as_slice(), b"storages" | b"tensors" | b"pickle" | b"sys_info") {
                self.opaque = true;
            }
            *seen.entry(name.as_slice()).or_insert(0) += 1;
        }
        if seen.values().any(|&n| n > 1) {
            self.opaque = true;
        }
        for (what, n) in [("storages", seen.get(b"storages".as_slice())), ("tensors", seen.get(b"tensors".as_slice()))] {
            if n.is_some_and(|&n| n > 1) {
                self.cuts.push(format!("the model file's tar archive has {} members named {what}: which records the \
                                        loader reads (the last) is not one the reader can tell apart", n.copied().unwrap_or(0)));
            }
        }
        let copies = |n: usize, name: &str, k: usize| if n > 1 { format!("{name} (copy {} of {n})", k + 1) } else { name.to_string() };
        // storages: a count, then each storage's (key, location, type) and its numel and bytes; then the views
        let st = all(b"storages");
        for (k, &(s, l)) in st.iter().enumerate() {
            let part = self.part(copies(st.len(), "storages", k), Buf::Borrowed(&data[s..s + l]));
            self.legacy_records(part, true);
        }
        let te = all(b"tensors");
        for (k, &(s, l)) in te.iter().enumerate() {
            let part = self.part(copies(te.len(), "tensors", k), Buf::Borrowed(&data[s..s + l]));
            self.legacy_records(part, false);
        }
        let si = all(b"sys_info");
        for (k, &(s, l)) in si.iter().enumerate() {
            let part = self.part(copies(si.len(), "sys_info", k), Buf::Borrowed(&data[s..s + l]));
            self.read_one(part, 0, false, false);
        }
        let pk = all(b"pickle");
        if pk.is_empty() {
            self.cuts.push("the model file's tar archive has no pickle member".into());
        }
        for (k, &(s, l)) in pk.iter().enumerate() {
            let part = self.part(copies(pk.len(), "pickle", k), Buf::Borrowed(&data[s..s + l]));
            self.read_one(part, 0, false, true);
        }
    }

    /// The legacy tar's storages or tensors member: pickles with raw bytes between them.
    fn legacy_records(&mut self, part: usize, storages: bool) {
        let Some((mut at, count)) = self.read_one(part, 0, false, false) else { return };
        let n = match count {
            Some(V::Num(n)) if n >= 0 => n as u64,
            _ => {
                self.cut(part, 0, "a count that is not a number");
                return;
            }
        };
        let len = self.parts[part].buf.len();
        for _ in 0..n {
            let Some((e, rec)) = self.read_one(part, at, false, false) else { return };
            at = e;
            let raw = |b: &[u8], i: usize, n: usize| b.get(i..i + n).map(|s| s.to_vec());
            if storages {
                // (key, location, storage_type): numel (8 bytes) and numel × the type's element size
                let size = match &rec {
                    Some(V::Seq(t)) => match t.borrow().items.get(2) {
                        Some(V::Global(g)) => self.cls.storage_sizes.get(&self.book.globals[*g as usize].name).copied(),
                        _ => None,
                    },
                    _ => None,
                };
                let Some(size) = size else {
                    self.cut(part, at, "a storage of a type whose element size is not known");
                    return;
                };
                let Some(b) = raw(&self.parts[part].buf, at, 8) else {
                    self.cut(part, at, "a storage cut short");
                    return;
                };
                let numel = u64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
                let next = numel.checked_mul(size).and_then(|x| x.checked_add(at as u64 + 8));
                match next {
                    Some(nx) if nx <= len as u64 => at = nx as usize,
                    _ => {
                        self.cut(part, at, "a storage longer than its member");
                        return;
                    }
                }
            } else {
                // ndim (4 bytes and 4 more), sizes and strides (8 × ndim each), the offset (8)
                let Some(b) = raw(&self.parts[part].buf, at, 4) else {
                    self.cut(part, at, "a tensor cut short");
                    return;
                };
                let ndim = i32::from_le_bytes(b.try_into().unwrap_or([0; 4]));
                if !(0..=64).contains(&ndim) {
                    self.cut(part, at, "a tensor of an impossible rank");
                    return;
                }
                let next = at + 8 + 16 * ndim as usize + 8;
                if next > len {
                    self.cut(part, at, "a tensor cut short");
                    return;
                }
                at = next;
            }
        }
        if storages {
            // the views
            self.read_one(part, at, false, false);
        }
    }

    /// The bytes the pickles handed a loader (torch.storage._load_from_bytes, pickle.loads …), read as a file of
    /// their own: what they would run is what the call runs.
    fn nested(&mut self, depth: usize) {
        let mut done = 0;
        if self.book.nested_dropped > 0 {
            // (H4, the external review of Oct 21: the 65th load was passed over without a word)
            self.cuts.push(format!("{} more byte strings the pickles hand a loader were not read (more than {} \
                                    nested loads)", self.book.nested_dropped, vm::MAX_NESTED));
            self.book.nested_dropped = 0;
        }
        loop {
            let pending: Vec<vm::Nested> = self.book.nested.drain(..).collect();
            if pending.is_empty() {
                return;
            }
            for n in pending {
                done += 1;
                let loader = self.book.qual(n.loader);
                let outer = self.where_(n.part);
                if depth >= 3 || done > 64 {
                    self.cuts.push(format!("bytes {outer} hands {loader} were not read (nested too deep or too many)"));
                    continue;
                }
                if self.inflated.saturating_add(n.len as u64) > self.max_inflated {
                    self.cuts.push(format!("bytes {outer} hands {loader} were not read (past the {} bytes the reader \
                                            reads of a model file)", commas(self.max_inflated)));
                    continue;
                }
                self.inflated += n.len as u64;
                let bytes = self.parts[n.part].buf[n.start..n.start + n.len].to_vec();
                let label = format!("the bytes {outer} hands {loader} (byte {})", n.at);
                if bytes.starts_with(b"PK\x03\x04") {
                    // a zip of its own: read as a checkpoint
                    let mut sub = Reader { p: self.p, cls: self.cls, book: Book::new(self.cls), parts: Vec::new(),
                                           cuts: Vec::new(), inflated: self.inflated, max_inflated: self.max_inflated,
                                           opaque: false, kind: "pytorch", extra: Vec::new(), code_issues: Vec::new(),
                                           issues_dropped: 0, cuts_dropped: 0 };
                    sub.read_zip(&zip::Bytes::whole(&bytes));
                    sub.nested(depth + 1);
                    self.absorb(sub, &label);
                } else if bytes.starts_with(TORCH_MAGIC) {
                    let k = self.part(label, Buf::Owned(bytes));
                    let mut at = 0;
                    for _ in 0..5 {
                        match self.read_one(k, at, false, true) {
                            Some((e, _)) => at = e,
                            None => break,
                        }
                    }
                } else if proto_start(&bytes) || bytes.first().is_some_and(|&c| vm::is_opcode(c)) {
                    let k = self.part(label, Buf::Owned(bytes));
                    self.read_one(k, 0, false, false);
                } else {
                    self.cuts.push(format!("{label}: bytes that are not a pickle the reader knows"));
                }
            }
        }
    }

    /// A nested zip's reading, added to this one's: its globals' uses and its cuts, named for where they were.
    fn absorb(&mut self, mut sub: Reader, label: &str) {
        sub.note_dropped();
        self.inflated = self.inflated.max(sub.inflated);
        for c in sub.cuts.iter().chain(&sub.book.fork_cut).chain(&sub.book.state_cut) {
            self.cuts.push(format!("{label}: {c}"));
        }
        self.code_issues.extend(sub.code_issues.iter().cloned());
        self.opaque |= sub.opaque;
        let (found, calls) = findings(&sub.book, &sub.parts);
        // (a nested reading's calls with text are its findings: no source names what bytes a loader is handed)
        for (why, sev) in found.into_iter().chain(calls.into_iter().map(|(_, _, d)| (d, "MAJOR"))).chain(sub.extra) {
            self.extra.push((format!("{label}: {why}"), sev));
        }
    }

    fn report(mut self) -> Report {
        self.note_dropped();
        let mut issues = Vec::new();
        let max = self.p.usize("PICKLE_MAX_FINDINGS");
        let (mut found, held) = findings(&self.book, &self.parts);
        found.extend(self.extra.iter().cloned());
        found.sort_by_key(|f| f.1 != "CRITICAL");
        let total = found.len();
        for (k, (detail, sev)) in found.into_iter().enumerate() {
            if k >= max {
                break;
            }
            let rule = if sev == "CRITICAL" { "_PICKLE_CODE_RULE" } else { "_PICKLE_GLOBAL_RULE" };
            let mut d = detail;
            if k + 1 == max && total > max {
                d.push_str(&format!("; and {} more", total - max));
            }
            issues.push(issue(self.p, rule, &d));
        }
        issues.extend(self.code_issues.iter().cloned());
        if let Some(c) = &self.book.fork_cut {
            issues.push(crate::manifest::gyp::truncated_issue(self.p, &format!("the pickle could not be read to its end: {c}")));
        }
        if let Some(c) = &self.book.state_cut {
            issues.push(crate::manifest::gyp::truncated_issue(self.p, &format!("the pickle could not be read to its end: {c}")));
        }
        for c in &self.cuts {
            issues.push(crate::manifest::gyp::truncated_issue(self.p, c));
        }
        let mut imports = Vec::new();
        for g in &self.book.globals {
            if g.kind == Kind::Other && g.ext.is_none() && imports.len() < 256 {
                let how = if g.called.is_some() { "called" } else if g.restored.is_some() { "made" } else { "imported" };
                imports.push((String::from_utf8_lossy(&g.module).to_string(), String::from_utf8_lossy(&g.name).to_string(), how.to_string()));
            }
        }
        let total = held.len();
        let calls = held.into_iter().take(max).enumerate().map(|(k, (m, n, mut d))| {
            if k + 1 == max && total > max {
                d.push_str(&format!("; and {} more", total - max));
            }
            (m, n, issue(self.p, "_PICKLE_GLOBAL_RULE", &d))
        }).collect();
        Report { kind: self.kind, issues, imports, opaque: self.opaque, calls }
    }
}

/// SC-NESTED-ARCHIVE (MINOR) for a member of a model file's zip: "In <member>, inside the model file: <what>".
fn nested_issue(p: &Pack, label: &str, what: &str) -> Value {
    let r = RuleText::of(p, "_BIN_NESTED_RULE");
    let msg = pystr::u(&format!("In {label}, inside the model file: {what}"));
    Value::Arr(vec![Value::Str(r.id), Value::Str(r.name), Value::Str(r.typ), Value::Str(r.sev), Value::Str(msg),
                    Value::Str(r.why), Value::Str(r.fix), Value::Str(r.ref_), Value::Int(1), Value::Arr(Vec::new()),
                    Value::Int(1)])
}

fn issue(p: &Pack, rule: &str, detail: &str) -> Value {
    let mut r = RuleText::of(p, rule);
    r.msg = format(&r.msg, &[("detail", Arg::S(pystr::u(detail)))]);
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

fn at_of(parts: &[Part], h: &vm::Hit) -> String {
    let label = parts.get(h.part).map(|p| p.label.as_str()).unwrap_or("");
    let how = if h.how.is_empty() { String::new() } else { format!("{}, ", h.how) };
    if label.is_empty() {
        format!("({how}byte {})", h.at)
    } else {
        format!("({how}byte {} of {label})", h.at)
    }
}

fn with_text(h: &vm::Hit) -> String {
    match &h.text {
        Some(t) => format!(" with {}", vm::quote(&Some(t.clone()))),
        None => String::new(),
    }
}

/// The findings of a book: (detail, severity), in the order of what they name.
/// A reading's findings ((detail, severity)), and apart from them each global of no known kind called with text it is
/// told to use ((module, name, detail): SC-PICKLE-GLOBAL, MAJOR, reported by own_imports).
fn findings(book: &Book, parts: &[Part]) -> (Vec<(String, &'static str)>, Vec<(String, String, String)>) {
    let mut out: Vec<(usize, usize, String, &'static str)> = Vec::new();
    let mut calls: Vec<(usize, usize, String, String, String)> = Vec::new();
    for g in &book.globals {
        let q = format!("{}.{}", String::from_utf8_lossy(&g.module), String::from_utf8_lossy(&g.name));
        match g.kind {
            // builtins.getattr put on the stack only as getattr(<a GLOBAL>, '<name>') each time: the attributes it
            // named are judged as globals (zoneinfo.ZoneInfo._unpickle), not getattr
            Kind::Code if g.model == Model::GetAttr && g.resolved > 0 && g.resolved == g.pushes => {}
            // a member of the standard library's data enums by its exact name (signal.SIGTERM as Python 3.10 and 3.11
            // pickle Signals.SIGTERM), only kept: pushed, stored, put in a container, handed to a call. Called (REDUCE,
            // OBJ, INST, a helper's call), made (NEWOBJ, a reconstructor's class), changed (BUILD, SETITEM(S),
            // APPEND(S), ADDITEMS on it) or given to a special method (those are `book.code`'s), it is code as before;
            // an attribute reached through it is a global of its own name, which is none of these
            // (FP-MODEL-FILES-PY311). Nor where the pickle calls an object it computed: what that object calls is not
            // followed, so a member handed to it may be called (functools.partial(SIGTERM)(),
            // itemgetter(0)((SIGTERM,))(): H1 of the review of Oct 29)
            Kind::Code if g.member && g.ext.is_none() && g.called.is_none() && g.restored.is_none()
                && book.dynamic.is_none() => {}
            Kind::Code => {
                let (h, d) = if let Some((_, h)) = &g.called {
                    (h, format!("it calls {q}{} {}", with_text(h), at_of(parts, h)))
                } else if let Some(h) = &g.restored {
                    (h, format!("it imports {q} and makes one {}", at_of(parts, h)))
                } else {
                    (&g.first, format!("it imports {q} {}", at_of(parts, &g.first)))
                };
                out.push((h.part, h.at, d, "CRITICAL"));
            }
            Kind::Other if g.ext.is_some() => {
                let code = g.ext.unwrap_or(0);
                let why = "which loads the global the loading program registered for it with copyreg.add_extension \
                           (none by default): the file does not say which";
                if let Some((_, h)) = &g.called {
                    out.push((h.part, h.at, format!("it calls extension code {code}{} {}, {why}", with_text(h),
                                                    at_of(parts, h)), "MAJOR"));
                } else if let Some(h) = &g.restored {
                    out.push((h.part, h.at, format!("it makes an object of extension code {code} {}, {why}",
                                                    at_of(parts, h)), "MAJOR"));
                }
            }
            Kind::Other => {
                if let Some((k, h)) = &g.called {
                    if *k >= TextKind::Text {
                        calls.push((h.part, h.at, String::from_utf8_lossy(&g.module).to_string(),
                                    String::from_utf8_lossy(&g.name).to_string(),
                                    format!("it calls {q}{} {}", with_text(h), at_of(parts, h))));
                    }
                }
            }
            Kind::Safe => {}
        }
    }
    for (why, h) in &book.code {
        out.push((h.part, h.at, format!("it {why} {}", at_of(parts, h)), "CRITICAL"));
    }
    if let Some(h) = &book.dynamic {
        let what = h.what.clone().unwrap_or_default();
        out.push((h.part, h.at, format!("it calls {what}{} {}: a call the file builds as it loads", with_text(h), at_of(parts, h)), "MAJOR"));
    }
    out.sort_by(|a, b| (b.3 == "CRITICAL").cmp(&(a.3 == "CRITICAL")).then(a.0.cmp(&b.0)).then(a.1.cmp(&b.1)));
    let mut seen = HashSet::new();
    let found = out.into_iter().filter(|o| seen.insert(o.2.clone())).map(|(_, _, d, s)| (d, s)).collect();
    calls.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    (found, calls.into_iter().map(|(_, _, m, n, d)| (m, n, d)).collect())
}

// ---- the .npy header and the legacy tar ---------------------------------------------------------------------------

/// An .npy's header: where it starts and its length (versions 1, 2 and 3).
fn npy_header(buf: &[u8]) -> Option<(usize, usize)> {
    match buf.get(6)? {
        1 => Some((10, buf.get(8..10).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)?)),
        2 | 3 => Some((12, buf.get(8..12).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)?)),
        _ => None,
    }
}

/// A ustar archive's members: (name, start, length).
fn tar_members(data: &[u8]) -> Result<Vec<(Vec<u8>, usize, usize)>, String> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut long_name: Option<Vec<u8>> = None;
    let mut pax: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    while at + 512 <= data.len() {
        let h = &data[at..at + 512];
        if h.iter().all(|&c| c == 0) {
            break;
        }
        let octal = |f: &[u8]| -> Option<u64> {
            if f.first().is_some_and(|&c| c & 0x80 != 0) {
                let mut v = 0u64;
                for &c in &f[1..] {
                    v = v.checked_mul(256)?.checked_add(c as u64)?;
                }
                return Some(v);
            }
            let s: Vec<u8> = f.iter().copied().take_while(|&c| c != 0 && c != b' ').skip_while(|&c| c == b' ').collect();
            if s.is_empty() {
                return Some(0);
            }
            u64::from_str_radix(std::str::from_utf8(&s).ok()?, 8).ok()
        };
        let mut size = octal(&h[124..136]).ok_or("a member size that is not a number")?;
        if let Some(s) = pax.get(b"size".as_slice()) {
            size = std::str::from_utf8(s).ok().and_then(|t| t.parse().ok()).unwrap_or(size);
        }
        let typ = h[156];
        let start = at + 512;
        // (compared as u64 before it is a position: the same answer on 32 bits)
        if size > (data.len() - start) as u64 {
            return Err("a member past the archive's end".into());
        }
        let end = start + size as usize;
        let mut name = tar_member_name(h).to_vec();
        if &h[257..262] == b"ustar" && h[345] != 0 {
            let prefix = tar_member_name(&h[345..500]);
            name = [prefix, b"/", &name].concat();
        }
        if let Some(n) = long_name.take() {
            name = n;
        }
        if let Some(n) = pax.remove(b"path".as_slice()) {
            name = n;
        }
        match typ {
            b'L' => long_name = Some(data[start..end].split(|&c| c == 0).next().unwrap_or(&[]).to_vec()),
            b'x' => {
                pax.clear();
                let body = &data[start..end];
                let mut i = 0;
                while i < body.len() {
                    let Some(sp) = body[i..].iter().position(|&c| c == b' ') else { break };
                    let Some(n) = std::str::from_utf8(&body[i..i + sp]).ok().and_then(|t| t.parse::<usize>().ok()) else { break };
                    if n == 0 || i + n > body.len() {
                        break;
                    }
                    let rec = &body[i + sp + 1..i + n];
                    let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
                    if let Some(eq) = rec.iter().position(|&c| c == b'=') {
                        pax.insert(rec[..eq].to_vec(), rec[eq + 1..].to_vec());
                    }
                    i += n;
                }
            }
            b'g' => {}
            b'0' | 0 => {
                if out.len() >= 64 {
                    return Err("more members than the reader reads".into());
                }
                out.push((name, start, size as usize));
            }
            _ => {}
        }
        at = start + (size as usize).div_ceil(512) * 512;
    }
    Ok(out)
}

// ---- the package's own modules ------------------------------------------------------------------------------------

/// A model file the scan read, for model_own: its path, whether a dependency's, the globals of no known kind it
/// imports ([module, name, how]) and its held calls with text ([module, name, issue]: Report::calls).
pub type ModelIn = (PyStr, bool, Vec<(String, String, String)>, Vec<(String, String, Value)>);

/// The model files' globals of the scanned package's own modules (`files`: the scan's files, [path, dependency] (a
/// third item, a text, is not read); its Python files are its modules; a dependency's are its package's): importing
/// one runs that module's code, which the scan reads, so it is SC-PICKLE-GLOBAL as INFO, listed (John's decision of
/// Oct 21). And each call a model file holds, an installed function called with text it is told to use: MAJOR,
/// whatever the scan's source says of the class. (The waiver of an own enum's member lookup, Color('https://…'), is
/// gone (H3, the external re-review of Oct 27): which file a module name is when the file is loaded depends on the
/// loading program's import path (sys.path, PYTHONPATH, .pth files, the folder it runs in, what is installed), which
/// a scan of the files cannot establish; a lookup of an enum the scan reads is MAJOR, as one pickled from `__main__`.)
pub fn own_imports(p: &Pack, models: &[ModelIn], files: &[(PyStr, bool, Option<Vec<u32>>)]) -> Vec<(PyStr, Value)> {
    let norm = |s: &[u32]| -> String { pystr::to_string(s).replace('\\', "/") };
    let markers: Vec<String> = p.strs("DEP_MARKERS").iter().map(|m| pystr::to_string(m)).collect();
    let package = |path: &str| -> String {
        // the path up to the folder below the last dependency marker
        let parts: Vec<&str> = path.split('/').collect();
        match parts.iter().rposition(|d| markers.iter().any(|m| m == d)) {
            Some(k) if k + 1 < parts.len() => parts[..k + 2].join("/"),
            _ => String::new(),
        }
    };
    // each Python file: its path, whether a dependency's, and that dependency's package folder
    let py: Vec<(String, bool, String)> = files.iter().map(|(f, dep, _)| (norm(f), *dep)).filter(|(f, _)| f.ends_with(".py"))
        .map(|(f, dep)| {
            let pk = if dep { package(&f) } else { String::new() };
            (f, dep, pk)
        }).collect();
    let mut out = Vec::new();
    for (path, dep, imports, calls) in models {
        let mp = norm(path);
        let pk = if *dep { package(&mp) } else { String::new() };
        // the package's own module file a global's module names
        let module_file = |module: &str| -> Option<usize> {
            let rel = module.replace('.', "/");
            let ends = |f: &str, tail: &str| f == tail || f.ends_with(&format!("/{tail}"));
            py.iter().position(|(f, d, fpk)| {
                *d == *dep && (!*dep || *fpk == pk) && (ends(f, &format!("{rel}.py")) || ends(f, &format!("{rel}/__init__.py")))
            })
        };
        let mut seen = HashSet::new();
        for (module, name, how) in imports {
            if !seen.insert(module.clone()) {
                continue;
            }
            if module_file(module).is_some() {
                // (INFO: the module is the package's own code, which the scan reads; a call of it with text the file
                // tells it to use is SC-PICKLE-GLOBAL, MAJOR, as model_file reports any function's)
                let detail = format!("{module} ({name}, {how} as the file loads), whose code runs when the file is loaded");
                out.push((path.clone(), issue(p, "_PICKLE_OWN_RULE", &detail)));
            }
        }
        for (_, _, iss) in calls {
            out.push((path.clone(), iss.clone()));
        }
    }
    out
}
