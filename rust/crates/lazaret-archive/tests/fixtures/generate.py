#!/usr/bin/env python3
"""Regenerate the tiny archive integration fixtures using only Python's stdlib.

The stored RAR writers below implement the documented container framing directly;
they do not call the Rust code. The two valid RAR files are also checked with
bsdtar by the repository's validation procedure.
"""

from __future__ import annotations

import binascii
import gzip
import io
from pathlib import Path
import struct
import tarfile

HERE = Path(__file__).resolve().parent


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def rar4_block(kind: int, flags: int = 0, body: bytes = b"", payload: bytes = b"") -> bytes:
    header_size = 7 + len(body)
    unchecked = bytes([kind]) + struct.pack("<HH", flags, header_size) + body
    return struct.pack("<H", crc32(unchecked) & 0xFFFF) + unchecked + payload


def rar4_file(name: bytes, payload: bytes, method: int = 0x30) -> bytes:
    body = (
        struct.pack("<II", len(payload), len(payload))
        + b"\0"
        + struct.pack("<I", crc32(payload))
        + struct.pack("<I", 0)  # DOS timestamp
        + bytes([20, method])
        + struct.pack("<HI", len(name), 0)
        + name
    )
    return rar4_block(0x74, 0x8000, body, payload)


def rar4(entries: list[tuple[bytes, bytes]], method: int = 0x30) -> bytes:
    out = bytearray(b"Rar!\x1a\x07\x00")
    out += rar4_block(0x73, 0, b"\0" * 6)
    for name, payload in entries:
        out += rar4_file(name, payload, method)
    out += rar4_block(0x7B)
    return bytes(out)


def rar5_block(kind: int, specific: bytes = b"", extra: bytes = b"", payload: bytes = b"") -> bytes:
    flags = (1 if extra else 0) | (2 if payload else 0)
    body = bytearray(vint(kind) + vint(flags))
    if extra:
        body += vint(len(extra))
    if payload:
        body += vint(len(payload))
    body += specific + extra
    framed = vint(len(body)) + body
    return struct.pack("<I", crc32(framed)) + framed + payload


def rar5_file(name: bytes, payload: bytes, compression: int = 0, extra: bytes = b"") -> bytes:
    specific = (
        vint(4)  # file CRC-32 is present
        + vint(len(payload))
        + vint(0)  # attributes
        + struct.pack("<I", crc32(payload))
        + vint(compression)
        + vint(0)  # host OS
        + vint(len(name))
        + name
    )
    return rar5_block(2, specific, extra, payload)


def rar5(entries: list[tuple[bytes, bytes]], compression: int = 0, extra: bytes = b"") -> bytes:
    out = bytearray(b"Rar!\x1a\x07\x01\x00")
    out += rar5_block(1, vint(0))
    for name, payload in entries:
        out += rar5_file(name, payload, compression, extra)
    out += rar5_block(5, vint(0))
    return bytes(out)


def tar_gzip() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in [("a.txt", b"hello"), ("dir/b.txt", b"world")]:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    return gzip.compress(raw.getvalue(), compresslevel=9, mtime=0)


def main() -> None:
    fixtures = {
        "stored-rar4.rar": rar4([(b"a.txt", b"hello")]),
        "stored-rar5.rar": rar5([(b"a.txt", b"hello")]),
        "duplicate-rar5.rar": rar5([(b"a.txt", b"one"), (b"a.txt", b"two")]),
        "traversal-rar5.rar": rar5([(b"../escape", b"x")]),
        "compressed-rar4.rar": rar4([(b"a.txt", b"hello")], method=0x33),
        "compressed-rar5.rar": rar5([(b"a.txt", b"hello")], compression=1 << 7),
        # Extra record: two-byte record body, encryption type (1), reserved byte.
        "encrypted-rar5.rar": rar5([(b"a.txt", b"hello")], extra=bytes([2, 1, 0])),
        "sample.tar.gz": tar_gzip(),
    }
    for name, data in fixtures.items():
        (HERE / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
