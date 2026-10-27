#!/usr/bin/env python3
"""Generate small 7-Zip fixtures using only Python's standard library.

Compression is performed independently by lzma/zlib, never by the Rust code.
The valid outputs are intended to be cross-checked with bsdtar.
"""

from __future__ import annotations

import binascii
import lzma
from pathlib import Path
import struct
import zlib

HERE = Path(__file__).resolve().parent
SIGNATURE = b"7z\xbc\xaf\x27\x1c"
COPY = b"\x00"
LZMA1 = b"\x03\x01\x01"
LZMA2 = b"\x21"
DEFLATE = b"\x04\x01\x08"
AES = b"\x06\xf1\x07\x01"


def uint(value: int) -> bytes:
    if value < 0:
        raise ValueError(value)
    if value < 0x80:
        return bytes([value])
    used = (value.bit_length() + 7) // 8
    first = (0xFF00 >> used) & 0xFF
    if used < 8:
        first |= (value >> (used * 8)) & ((1 << (7 - used)) - 1)
    return bytes([first]) + value.to_bytes(8, "little")[:used]


def crc(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def digests(values: list[bytes]) -> bytes:
    return b"\x01" + b"".join(struct.pack("<I", crc(value)) for value in values)


def folder(method: bytes, properties: bytes, unpack_size: int) -> bytes:
    flags = len(method) | (0x20 if properties else 0)
    encoded = uint(1) + bytes([flags]) + method
    if properties:
        encoded += uint(len(properties)) + properties
    return encoded, unpack_size


def streams(folders: list[tuple[bytes, int]], packed_sizes: list[int], pack_pos: int = 0,
            substreams: list[list[bytes]] | None = None) -> bytes:
    out = bytearray(b"\x06" + uint(pack_pos) + uint(len(folders)) + b"\x09")
    for size in packed_sizes:
        out += uint(size)
    out += b"\x00\x07\x0b" + uint(len(folders)) + b"\x00"
    for encoded, _ in folders:
        out += encoded
    out += b"\x0c"
    for _, unpack_size in folders:
        out += uint(unpack_size)
    out += b"\x00"
    if substreams is not None:
        out += b"\x08"
        if any(len(values) != 1 for values in substreams):
            out += b"\x0d"
            for values in substreams:
                out += uint(len(values))
            out += b"\x09"
            for values in substreams:
                for value in values[:-1]:
                    out += uint(len(value))
        out += b"\x0a" + digests([value for values in substreams for value in values]) + b"\x00"
    return bytes(out + b"\x00")


def bitset(values: list[bool]) -> bytes:
    out = bytearray((len(values) + 7) // 8)
    for i, value in enumerate(values):
        if value:
            out[i // 8] |= 0x80 >> (i % 8)
    return bytes(out)


def files_info(names: list[str], empty_stream: list[bool] | None = None,
               empty_file: list[bool] | None = None) -> bytes:
    name_data = b"\x00" + b"".join(name.encode("utf-16le") + b"\x00\x00" for name in names)
    out = bytearray(b"\x05" + uint(len(names)) + b"\x11" + uint(len(name_data)) + name_data)
    if empty_stream is not None:
        bits = bitset(empty_stream)
        out += b"\x0e" + uint(len(bits)) + bits
    if empty_file is not None:
        bits = bitset(empty_file)
        out += b"\x0f" + uint(len(bits)) + bits
    return bytes(out + b"\x00")


def plain_header(names: list[str], folders: list[tuple[bytes, int]], packed_sizes: list[int],
                 pack_pos: int = 0, substreams: list[list[bytes]] | None = None,
                 empty_stream: list[bool] | None = None, empty_file: list[bool] | None = None) -> bytes:
    return (b"\x01\x04" + streams(folders, packed_sizes, pack_pos, substreams)
            + files_info(names, empty_stream, empty_file) + b"\x00")


def container(next_header: bytes, packed: bytes) -> bytes:
    start = struct.pack("<QQI", len(packed), len(next_header), crc(next_header))
    return SIGNATURE + b"\x00\x04" + struct.pack("<I", crc(start)) + start + packed + next_header


def single(method: bytes, properties: bytes, packed: bytes, raw: bytes, name: str = "a.txt") -> bytes:
    folders = [folder(method, properties, len(raw))]
    header = plain_header([name], folders, [len(packed)], substreams=[[raw]])
    return container(header, packed)


def raw_lzma1(data: bytes) -> tuple[bytes, bytes]:
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20, "lc": 3, "lp": 0, "pb": 2}]
    return lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters), b"\x5d\x00\x00\x10\x00"


def raw_lzma2(data: bytes) -> tuple[bytes, bytes]:
    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20, "lc": 3, "lp": 0, "pb": 2}]
    return lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters), b"\x10"


def raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(level=6, wbits=-15)
    return compressor.compress(data) + compressor.flush()


def lzma2_multi() -> bytes:
    values = [b"first" * 100, b"second" * 100]
    raw = b"".join(values)
    packed, props = raw_lzma2(raw)
    folders = [folder(LZMA2, props, len(raw))]
    header = plain_header(["first.txt", "second.txt"], folders, [len(packed)], substreams=[values])
    return container(header, packed)


def lzma2_encoded_header() -> bytes:
    raw = b"encoded header\n" * 30
    packed, props = raw_lzma2(raw)
    folders = [folder(LZMA2, props, len(raw))]
    inner = plain_header(["encoded.txt"], folders, [len(packed)], pack_pos=0, substreams=[[raw]])
    encoded_packed, encoded_props = raw_lzma2(inner)
    # The encoded-header pack stream comes before the file pack stream.
    inner = plain_header(["encoded.txt"], folders, [len(packed)], pack_pos=len(encoded_packed), substreams=[[raw]])
    # Pack positions do not change the header length in this fixture, but keep
    # the construction general by recompressing until the position stabilizes.
    for _ in range(4):
        encoded_packed, encoded_props = raw_lzma2(inner)
        updated = plain_header(["encoded.txt"], folders, [len(packed)], pack_pos=len(encoded_packed), substreams=[[raw]])
        if updated == inner:
            break
        inner = updated
    encoded_folders = [folder(LZMA2, encoded_props, len(inner))]
    outer = b"\x17" + streams(encoded_folders, [len(encoded_packed)], substreams=[[inner]])
    return container(outer, encoded_packed + packed)


def empty_entries() -> bytes:
    # A completely empty StreamsInfo is omitted by real 7-Zip writers.
    header = b"\x01" + files_info(["empty-dir", "empty.txt"], [True, True], [False, True]) + b"\x00"
    return container(header, b"")


def main() -> None:
    raw = (b"7-Zip native extraction\n" * 100) + bytes(range(256))
    lzma1_packed, lzma1_props = raw_lzma1(raw)
    lzma2_packed, lzma2_props = raw_lzma2(raw)
    multichunk_raw = bytes(range(256)) * 9000  # 2.25 MiB: forces multiple LZMA2 chunks.
    multichunk_packed, multichunk_props = raw_lzma2(multichunk_raw)
    fixtures = {
        "copy.7z": single(COPY, b"", raw, raw),
        "deflate.7z": single(DEFLATE, b"", raw_deflate(raw), raw),
        "lzma1.7z": single(LZMA1, lzma1_props, lzma1_packed, raw),
        "lzma2.7z": single(LZMA2, lzma2_props, lzma2_packed, raw),
        "lzma2-multichunk.7z": single(LZMA2, multichunk_props, multichunk_packed, multichunk_raw),
        "lzma2-multi.7z": lzma2_multi(),
        "lzma2-encoded-header.7z": lzma2_encoded_header(),
        "empty-entries.7z": empty_entries(),
        "traversal.7z": single(COPY, b"", b"x", b"x", "../escape"),
        "duplicate.7z": container(
            plain_header(["same.txt", "same.txt"], [folder(COPY, b"", 3), folder(COPY, b"", 3)], [3, 3],
                         substreams=[[b"one"], [b"two"]]),
            b"onetwo",
        ),
        "encrypted.7z": single(AES, b"", raw, raw),
    }
    for name, data in fixtures.items():
        (HERE / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
