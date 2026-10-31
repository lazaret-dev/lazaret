#!/usr/bin/env python3
"""Generate protocol-5 pickle streams with Python's independent compressors."""

import bz2
import lzma
from pathlib import Path
import pickle

HERE = Path(__file__).resolve().parent
value = {
    "format": "Lazaret native compressed pickle",
    "numbers": list(range(100)),
    "nested": {"safe": True, "payload": b"bytes\x00\xff" * 20},
}
raw = pickle.dumps(value, protocol=5)
assert pickle.loads(raw) == value

(HERE / "pickle.pkl").write_bytes(raw)
(HERE / "pickle.bz2").write_bytes(bz2.compress(raw, compresslevel=9))
(HERE / "pickle.xz").write_bytes(lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64))
(HERE / "pickle.lzma").write_bytes(lzma.compress(raw, format=lzma.FORMAT_ALONE))
print(f"pickle: {len(raw)} bytes; bz2/xz/lzma fixtures regenerated")
