#!/usr/bin/env python3
"""Check the native engine's library before it ships in a platform wheel.

    python3 scripts/check_native_library.py LIBRARY TAG [--load]
    python3 scripts/check_native_library.py --dist DIR [--expect TAG ...]

The first form checks one built library (rust/crates/lazaret-ffi) against
the wheel platform tag it will ship under. pip installs a wheel wherever its
tag says it runs, so the library must keep the tag's promise:

- manylinux_X_Y_ARCH: a 64-bit ELF shared object for ARCH that needs only
  glibc's own libraries and libgcc_s, no glibc symbol version newer than
  X.Y (a library linked against a newer glibc installs fine on an older
  system and then fails to load there), no GCC_ version newer than the
  manylinux policy's, no C++ runtime, no RPATH or RUNPATH, and no
  executable stack;
- macosx_X_Y_ARCH: a single-architecture Mach-O dylib for ARCH whose
  minimum macOS (LC_BUILD_VERSION, or LC_VERSION_MIN_MACOSX) is at most
  X.Y, and which links only libraries macOS ships (/usr/lib, /System);
- win_amd64, win_arm64: a 64-bit PE DLL for that machine, with ASLR and DEP
  on, that imports no Visual C++ or MinGW runtime DLL (Windows does not
  include those; release CI links the C runtime statically);

and in every case it exports the three functions lazaret/scanner/_native.py
binds (lazaret_engine_call, lazaret_engine_free and lazaret_engine_version)
and the five of the network layer lazaret/scanner/nativenet.py binds
(lazaret_net_request, _open, _read, _close and _configure).

With --load, the library is also loaded here the way
lazaret/scanner/_native.py loads it (so run it on the library's own
platform), must report the package's version (python/src/lazaret), and must
give one call its known answer.

The second form checks the Python release's files in DIR: one sdist, with
the engine's sources (rust/, which pip compiles where no platform wheel
fits) and no library, and the platform wheels, which must be exactly the
--expect tags (when given). There is no pure wheel (py3-none-any): since
the Rust-first refactor the package has no engine without the library.
Each platform wheel holds the sdist's package files (src/lazaret) byte for
byte plus one library at lazaret/_native/<name>, which passes the check
above for the wheel's tag; its METADATA is the sdist's PKG-INFO. The sdist
and every wheel carry the engine's notice (rust/NOTICE) with LICENSE and
LICENSE-UNICODE, name exactly those as License-Files, and declare
"Apache-2.0 AND Unicode-3.0" (the engine is Lazaret's own since P-16, with
Unicode data). Every wheel's RECORD must match its files, and every
License-File it names must be in it.

Standard library only: ELF, Mach-O and PE headers are read here, so one
Linux job can check the libraries of every platform. Exit status 0 when
everything passes, 1 with the problems listed, 2 on a usage error.
"""
import argparse
import base64
import csv
import hashlib
import io
import os
import pathlib
import re
import struct
import sys
import tarfile
import zipfile

EXPORTS = ("lazaret_engine_call", "lazaret_engine_free", "lazaret_engine_version",
           # the network layer (NET-1: lazaret/scanner/nativenet.py), the default transport since 0.1.9
           "lazaret_net_request", "lazaret_net_open", "lazaret_net_read", "lazaret_net_close", "lazaret_net_configure")
NAME = "lazaret"
REPO = pathlib.Path(__file__).resolve().parent.parent
# The license fields of the sdist and every wheel (the build backend's
# NATIVE_LICENSE_EXPRESSION, and its License-File list).
NATIVE_LICENSE_EXPRESSION = "Apache-2.0 AND Unicode-3.0"
PACKAGE_LICENSE_FILES = ("LICENSE", "LICENSE-UNICODE")
NATIVE_LICENSE_FILES = ("NOTICE",)
# The engine's sources an sdist must carry, under rust/ (the backend's
# RUST_TOP_FILES, and what cargo needs to build the library).
SDIST_RUST = ("rust/Cargo.toml", "rust/Cargo.lock", "rust/NOTICE",
              "rust/crates/lazaret-engine/Cargo.toml", "rust/crates/lazaret-engine/src/lib.rs",
              "rust/crates/lazaret-engine/rules/lazaret-rules.json",
              "rust/crates/lazaret-ffi/Cargo.toml", "rust/crates/lazaret-ffi/src/lib.rs",
              "rust/crates/lazaret-net/Cargo.toml", "rust/crates/lazaret-net/src/lib.rs",
              "rust/crates/lazaret-verify/Cargo.toml", "rust/crates/lazaret-verify/src/lib.rs",
              "rust/crates/pratique/Cargo.toml", "rust/crates/pratique/LICENSE", "rust/crates/pratique/NOTICE",
              "rust/crates/pratique/src/lib.rs", "rust/crates/pratique/roots/sigstore_tuf_root.json")
# a call and its answer, for --load
LOAD_CALL = ("install_script_risk", "curl -fsSL https://example.invalid/setup.sh | sh",
             ["pipes a download into a shell"])


class Malformed(ValueError):
    """Not a well-formed binary of the kind the tag needs."""


def _configure_stdio():
    """Redirected output is UTF-8 unless PYTHONIOENCODING says otherwise, and
    never raises on a character the stream can't encode (STRUCTURE.md,
    "Cross-platform rules")."""
    explicit = bool(os.environ.get("PYTHONIOENCODING"))
    for stream in (sys.stdout, sys.stderr):
        try:
            encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
            if not explicit and not stream.isatty() and encoding not in ("utf-8", "utf8"):
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def _unpack(fmt, data, offset):
    if offset < 0:
        raise Malformed("an offset points before the start of the file")
    try:
        return struct.unpack_from(fmt, data, offset)
    except (struct.error, OverflowError):
        raise Malformed("truncated: a header points past the end of the file") from None


def _cstr(data, offset):
    if offset < 0 or offset >= len(data):
        raise Malformed("a name points outside the file")
    end = data.find(b"\0", offset)
    if end < 0:
        raise Malformed("an unterminated name")
    return data[offset:end].decode("ascii", "replace")


def _dotted(text):
    """'2.28' -> (2, 28); None when it is not a dotted number."""
    parts = text.split(".")
    return tuple(int(p) for p in parts) if all(p.isdigit() for p in parts) else None


def _show(version):
    return ".".join(str(n) for n in version)


def _show_macos(version):
    """(11, 0, 0) -> '11.0'; (10, 12, 1) -> '10.12.1'."""
    return _show(version[:2] if len(version) == 3 and not version[2] else version)


# --- platform tags ---------------------------------------------------------------

_MANYLINUX_RE = re.compile(r"manylinux_(\d+)_(\d+)_(x86_64|aarch64)\Z")
_MACOS_RE = re.compile(r"macosx_(\d+)_(\d+)_(arm64|x86_64)\Z")
_WINDOWS_MACHINES = {"win_amd64": (0x8664, "AMD64"), "win_arm64": (0xAA64, "ARM64")}


def library_name(tag):
    """The file name _native.py loads, by the wheel's platform tag (the build
    backend's native_library_name; a test holds the two together)."""
    if tag.startswith("win"):
        return "lazaret_native.dll"
    if tag.startswith("macosx"):
        return "liblazaret_native.dylib"
    return "liblazaret_native.so"


def supported(tag):
    return bool(_MANYLINUX_RE.match(tag) or _MACOS_RE.match(tag) or tag in _WINDOWS_MACHINES)


# --- ELF (Linux) -----------------------------------------------------------------

_EM = {"x86_64": 62, "aarch64": 183}
_ET_DYN = 3
_SHT_DYNAMIC, _SHT_NOBITS, _SHT_DYNSYM, _SHT_VERNEED = 6, 8, 11, 0x6FFFFFFE
_DT_NEEDED, _DT_RPATH, _DT_RUNPATH = 1, 15, 29
_PT_GNU_STACK, _PF_X = 0x6474E551, 1
_STB_GLOBAL, _STB_WEAK, _STT_FUNC = 1, 2, 2
# What a manylinux library may need: glibc's own libraries, its dynamic
# loader, and libgcc_s (PEP 600 policies list more, libX11 and the like, that
# the engine has no use for; a new dependency here is worth a look first).
_GLIBC_LIBS = frozenset({"libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0", "librt.so.1",
                         "libgcc_s.so.1"})
_LOADERS = {"x86_64": "ld-linux-x86-64.so.2", "aarch64": "ld-linux-aarch64.so.1"}


def _gcc_max(glibc):
    """The newest libgcc_s symbol version a manylinux policy of this glibc
    allows (manylinux_2_28: GCC 8's 7.0.0; manylinux2014: 4.8.0). The
    engine's unwinding needs GCC_4.2.0 at most."""
    return (7, 0, 0) if glibc >= (2, 28) else (4, 8, 0)


def read_elf(data):
    """{machine, type, needed, versions {library: {version names}}, exports,
    runpath, exec_stack} of a 64-bit little-endian ELF file."""
    if data[:4] != b"\x7fELF":
        raise Malformed("not an ELF file")
    if data[4:5] != b"\x02" or data[5:6] != b"\x01":
        raise Malformed("not a 64-bit little-endian ELF file")
    (e_type, e_machine, _version, _entry, e_phoff, e_shoff, _flags, _ehsize, e_phentsize, e_phnum,
     e_shentsize, e_shnum, _shstrndx) = _unpack("<HHIQQQIHHHHHH", data, 16)
    if not e_shnum:
        raise Malformed("no section headers")
    sections = [_unpack("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    for sh in sections:
        if sh[1] != _SHT_NOBITS and sh[4] + sh[5] > len(data):
            raise Malformed("truncated: a section ends past the end of the file")

    def linked(sh):
        if sh[6] >= len(sections):
            raise Malformed("a section links to a missing string table")
        strtab = sections[sh[6]]
        return data[strtab[4]:strtab[4] + strtab[5]]

    needed, runpath, exports, versions = [], [], set(), {}
    for sh in sections:
        _name, sh_type, _flags, _addr, offset, size, _link, info, _align, _entsize = sh
        if sh_type == _SHT_DYNAMIC:
            strings = linked(sh)
            for at in range(offset, offset + size, 16):
                tag, value = _unpack("<qQ", data, at)
                if tag == 0:
                    break
                if tag == _DT_NEEDED:
                    needed.append(_cstr(strings, value))
                elif tag in (_DT_RPATH, _DT_RUNPATH):
                    runpath.append(_cstr(strings, value))
        elif sh_type == _SHT_DYNSYM:
            strings = linked(sh)
            for at in range(offset + 24, offset + size, 24):          # entry 0 is the null symbol
                st_name, st_info, _other, st_shndx, _value, _size = _unpack("<IBBHQQ", data, at)
                if st_shndx and st_info >> 4 in (_STB_GLOBAL, _STB_WEAK) and st_info & 0xF == _STT_FUNC:
                    exports.add(_cstr(strings, st_name))
        elif sh_type == _SHT_VERNEED:
            strings = linked(sh)
            at = offset
            for _ in range(info):                                   # sh_info: the number of entries
                _vn_version, vn_cnt, vn_file, vn_aux, vn_next = _unpack("<HHIII", data, at)
                names = versions.setdefault(_cstr(strings, vn_file), set())
                aux = at + vn_aux
                for _ in range(vn_cnt):
                    _hash, _vflags, _other, vna_name, vna_next = _unpack("<IHHII", data, aux)
                    names.add(_cstr(strings, vna_name))
                    if not vna_next:
                        break
                    aux += vna_next
                if not vn_next:
                    break
                at += vn_next
    exec_stack = False
    for i in range(e_phnum):
        p_type, p_flags = _unpack("<II", data, e_phoff + i * e_phentsize)
        if p_type == _PT_GNU_STACK and p_flags & _PF_X:
            exec_stack = True
    return {"machine": e_machine, "type": e_type, "needed": needed, "versions": versions,
            "exports": exports, "runpath": runpath, "exec_stack": exec_stack}


def _check_elf(data, tag):
    major, minor, arch = _MANYLINUX_RE.match(tag).groups()
    glibc, gcc = (int(major), int(minor)), _gcc_max((int(major), int(minor)))
    elf = read_elf(data)
    problems = []
    if elf["type"] != _ET_DYN:
        problems.append(f"not a shared object (ELF type {elf['type']})")
    if elf["machine"] != _EM[arch]:
        problems.append(f"built for ELF machine {elf['machine']}, not {arch} ({_EM[arch]})")
    allowed = _GLIBC_LIBS | {_LOADERS[arch]}
    for lib in elf["needed"]:
        if lib not in allowed:
            problems.append(f"needs {lib}, which is not one of glibc's libraries for {arch} or libgcc_s: "
                            f"a system may lack it")
    newest = {"GLIBC": (), "GCC": ()}
    too_new = {"GLIBC": [], "GCC": []}
    for lib, names in sorted(elf["versions"].items()):
        for version in sorted(names):
            prefix, _, number = version.partition("_")
            dotted = _dotted(number)
            if prefix not in newest or dotted is None:
                problems.append(f"needs symbol version {version} from {lib}: only glibc's GLIBC_ and "
                                f"libgcc_s's GCC_ versions are allowed")
                continue
            newest[prefix] = max(newest[prefix], dotted)
            if dotted > (glibc if prefix == "GLIBC" else gcc):
                too_new[prefix].append(version)
    if too_new["GLIBC"]:
        problems.append(f"needs glibc {_show(newest['GLIBC'])} ({', '.join(too_new['GLIBC'])}), but the tag "
                        f"promises {major}.{minor}: build it in the {tag} image")
    if too_new["GCC"]:
        problems.append(f"needs libgcc_s {', '.join(too_new['GCC'])}, newer than manylinux_{major}_{minor} "
                        f"allows ({_show(gcc)})")
    if elf["runpath"]:
        problems.append(f"has an RPATH/RUNPATH ({', '.join(elf['runpath'])}): it must not load libraries "
                        f"from other places")
    if elf["exec_stack"]:
        problems.append("asks for an executable stack")
    missing = [name for name in EXPORTS if name not in elf["exports"]]
    if missing:
        problems.append(f"does not export {', '.join(missing)}")
    machine = {number: name for name, number in _EM.items()}.get(elf["machine"], f"machine {elf['machine']}")
    summary = (f"ELF {machine}, needs {' '.join(elf['needed']) or 'nothing'}; glibc "
               f"{_show(newest['GLIBC']) or '-'}, libgcc_s {_show(newest['GCC']) or '-'}")
    return summary, problems


# --- Mach-O (macOS) --------------------------------------------------------------

_CPU = {"arm64": 0x0100000C, "x86_64": 0x01000007}
_MH_MAGIC_64, _MH_DYLIB = 0xFEEDFACF, 6
_LC_SYMTAB, _LC_LOAD_DYLIB, _LC_SEGMENT_64, _LC_LAZY_LOAD_DYLIB = 0x2, 0xC, 0x19, 0x20
_LC_LOAD_WEAK_DYLIB, _LC_REEXPORT_DYLIB, _LC_LOAD_UPWARD_DYLIB = 0x80000018, 0x8000001F, 0x80000023
_LC_RPATH, _LC_VERSION_MIN_MACOSX, _LC_BUILD_VERSION = 0x8000001C, 0x24, 0x32
_LC_DYLD_INFO, _LC_DYLD_INFO_ONLY, _LC_DYLD_EXPORTS_TRIE = 0x22, 0x80000022, 0x80000033
_DYLIB_COMMANDS = (_LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB, _LC_REEXPORT_DYLIB, _LC_LAZY_LOAD_DYLIB,
                   _LC_LOAD_UPWARD_DYLIB)
_PLATFORM_MACOS = 1
_N_STAB, _N_TYPE, _N_EXT, _N_SECT = 0xE0, 0x0E, 0x01, 0x0E
_SYSTEM_PREFIXES = ("/usr/lib/", "/System/Library/")


def _uleb(data, pos):
    value = shift = 0
    while True:
        if pos >= len(data):
            raise Malformed("truncated export trie")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return value, pos


def _trie_names(data, start, size):
    """The symbol names in a dyld export trie."""
    names, stack, seen = set(), [(0, b"")], set()
    trie = data[start:start + size]
    while stack:
        node, prefix = stack.pop()
        if node in seen or node >= len(trie):
            raise Malformed("a malformed export trie")
        seen.add(node)
        terminal, pos = _uleb(trie, node)
        if terminal:
            names.add(prefix.decode("ascii", "replace"))
        pos += terminal
        if pos >= len(trie):
            raise Malformed("truncated export trie")
        children = trie[pos]
        pos += 1
        for _ in range(children):
            end = trie.find(b"\0", pos)
            if end < 0:
                raise Malformed("truncated export trie")
            edge = trie[pos:end]
            child, pos = _uleb(trie, end + 1)
            stack.append((child, prefix + edge))
    return names


def _macos_version(encoded):
    return (encoded >> 16, (encoded >> 8) & 0xFF, encoded & 0xFF)


def read_macho(data):
    """{cpu, filetype, minos, platform, dylibs, rpaths, exports} of a 64-bit
    little-endian Mach-O file (not a universal one)."""
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        raise Malformed("a universal (fat) binary: the tag names one architecture")
    magic, cputype, _subtype, filetype, ncmds, _sizeofcmds, _flags, _reserved = _unpack("<IiiIIIII", data, 0)
    if magic != _MH_MAGIC_64:
        raise Malformed("not a 64-bit Mach-O file")
    out = {"cpu": cputype & 0xFFFFFFFF, "filetype": filetype, "minos": None, "platform": None,
           "dylibs": [], "rpaths": [], "exports": set()}

    def within(offset, size):
        if offset + size > len(data):
            raise Malformed("truncated: a load command's data ends past the end of the file")

    at = 32
    for _ in range(ncmds):
        cmd, cmdsize = _unpack("<II", data, at)
        if cmdsize < 8:
            raise Malformed("a load command smaller than its header")
        within(at, cmdsize)
        if cmd == _LC_SEGMENT_64:
            fileoff, filesize = _unpack("<QQ", data, at + 40)
            within(fileoff, filesize)
        elif cmd == _LC_BUILD_VERSION:
            platform, minos = _unpack("<II", data, at + 8)
            out["platform"], out["minos"] = platform, _macos_version(minos)
        elif cmd == _LC_VERSION_MIN_MACOSX and out["minos"] is None:
            (version,) = _unpack("<I", data, at + 8)
            out["platform"], out["minos"] = _PLATFORM_MACOS, _macos_version(version)
        elif cmd in _DYLIB_COMMANDS or cmd == _LC_RPATH:
            (name_offset,) = _unpack("<I", data, at + 8)
            if name_offset >= cmdsize:
                raise Malformed("a load command's name lies outside it")
            name = _cstr(data[at:at + cmdsize], name_offset)
            out["rpaths" if cmd == _LC_RPATH else "dylibs"].append(name)
        elif cmd == _LC_SYMTAB:
            symoff, nsyms, stroff, strsize = _unpack("<IIII", data, at + 8)
            within(symoff, 16 * nsyms)
            within(stroff, strsize)
            strings = data[stroff:stroff + strsize]
            for i in range(nsyms):
                n_strx, n_type, _sect, _desc, _value = _unpack("<IBBHQ", data, symoff + 16 * i)
                if not n_type & _N_STAB and n_type & _N_EXT and n_type & _N_TYPE == _N_SECT:
                    out["exports"].add(_cstr(strings, n_strx))
        elif cmd in (_LC_DYLD_INFO, _LC_DYLD_INFO_ONLY):
            export_off, export_size = _unpack("<II", data, at + 40)
            if export_size:
                within(export_off, export_size)
                out["exports"] |= _trie_names(data, export_off, export_size)
        elif cmd == _LC_DYLD_EXPORTS_TRIE:
            dataoff, datasize = _unpack("<II", data, at + 8)
            if datasize:
                within(dataoff, datasize)
                out["exports"] |= _trie_names(data, dataoff, datasize)
        at += cmdsize
    return out


def _check_macho(data, tag):
    major, minor, arch = _MACOS_RE.match(tag).groups()
    promised = (int(major), int(minor), 0)
    macho = read_macho(data)
    problems = []
    if macho["filetype"] != _MH_DYLIB:
        problems.append(f"not a dylib (Mach-O file type {macho['filetype']})")
    if macho["cpu"] != _CPU[arch]:
        problems.append(f"built for Mach-O CPU type {macho['cpu']:#x}, not {arch} ({_CPU[arch]:#x})")
    if macho["minos"] is None:
        problems.append("names no minimum macOS version (LC_BUILD_VERSION)")
    elif macho["platform"] != _PLATFORM_MACOS:
        problems.append(f"built for Apple platform {macho['platform']}, not macOS")
    elif macho["minos"] > promised:
        problems.append(f"needs macOS {_show_macos(macho['minos'])}, but the tag promises {major}.{minor}: "
                        f"build it with MACOSX_DEPLOYMENT_TARGET={major}.{minor}")
    for lib in macho["dylibs"]:
        if not lib.startswith(_SYSTEM_PREFIXES):
            problems.append(f"links {lib}, which macOS does not ship")
    missing = [name for name in EXPORTS if "_" + name not in macho["exports"]]
    if missing:
        problems.append(f"does not export {', '.join(missing)}")
    minos = _show_macos(macho["minos"]) if macho["minos"] else "-"
    cpu = {number: name for name, number in _CPU.items()}.get(macho["cpu"], f"CPU {macho['cpu']:#x}")
    summary = f"Mach-O {cpu}, macOS {minos} or later, links {' '.join(macho['dylibs']) or 'nothing'}"
    return summary, problems


# --- PE (Windows) ----------------------------------------------------------------

_IMAGE_FILE_DLL = 0x2000
_DYNAMIC_BASE, _NX_COMPAT = 0x0040, 0x0100
_PE32, _PE32_PLUS = 0x10B, 0x20B
# Runtimes Windows does not ship: the Visual C++ redistributable's and MinGW's.
_RUNTIME_DLL_RE = re.compile(r"(?i)^(?:vcruntime|msvcp|msvcr|concrt|vcomp|libgcc|libstdc\+\+|libwinpthread)")


def read_pe(data):
    """{machine, characteristics, magic, dll_characteristics, os_version,
    imports, exports} of a PE file."""
    if data[:2] != b"MZ":
        raise Malformed("not a PE file")
    (pe,) = _unpack("<I", data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise Malformed("not a PE file")
    machine, nsections, _stamp, _symptr, _nsyms, opt_size, characteristics = _unpack("<HHIIIHH", data, pe + 4)
    opt = pe + 24
    (magic,) = _unpack("<H", data, opt)
    if magic not in (_PE32, _PE32_PLUS):
        raise Malformed(f"unknown PE optional header {magic:#x}")
    os_major, os_minor = _unpack("<HH", data, opt + 40)
    (dll_characteristics,) = _unpack("<H", data, opt + 70)
    count_at, directories = (opt + 108, opt + 112) if magic == _PE32_PLUS else (opt + 92, opt + 96)
    (ndirs,) = _unpack("<I", data, count_at)
    sections = [_unpack("<8sIIII", data, opt + opt_size + 40 * i) for i in range(nsections)]
    for _name, _vsize, _vaddr, rawsize, rawptr in sections:
        if rawptr + rawsize > len(data):
            raise Malformed("truncated: a section ends past the end of the file")

    def offset(rva):
        for _name, vsize, vaddr, rawsize, rawptr in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rva - vaddr + rawptr
        raise Malformed(f"address {rva:#x} is in no section")

    def directory(index):
        return _unpack("<II", data, directories + 8 * index) if index < ndirs else (0, 0)

    exports, imports = set(), []
    rva, _size = directory(0)
    if rva:
        fields = _unpack("<IIHHIIIIIII", data, offset(rva))
        nnames, names = fields[7], fields[9]                   # NumberOfNames, AddressOfNames
        for i in range(nnames):
            (name_rva,) = _unpack("<I", data, offset(names) + 4 * i)
            exports.add(_cstr(data, offset(name_rva)))
    rva, _size = directory(1)
    at = offset(rva) if rva else None
    while at is not None:
        _thunks, _stamp, _chain, name_rva, _iat = _unpack("<IIIII", data, at)
        if not name_rva:
            break
        imports.append(_cstr(data, offset(name_rva)))
        at += 20
    rva, _size = directory(13)                                  # delay-load imports
    at = offset(rva) if rva else None
    while at is not None:
        _attrs, name_rva = _unpack("<II", data, at)
        if not name_rva:
            break
        imports.append(_cstr(data, offset(name_rva)))
        at += 32
    return {"machine": machine, "characteristics": characteristics, "magic": magic,
            "dll_characteristics": dll_characteristics, "os_version": (os_major, os_minor),
            "imports": imports, "exports": exports}


def _check_pe(data, tag):
    machine, arch = _WINDOWS_MACHINES[tag]
    pe = read_pe(data)
    problems = []
    if pe["machine"] != machine:
        problems.append(f"built for PE machine {pe['machine']:#x}, not {arch} ({machine:#x})")
    if pe["magic"] != _PE32_PLUS:
        problems.append("not a 64-bit (PE32+) image")
    if not pe["characteristics"] & _IMAGE_FILE_DLL:
        problems.append("not a DLL")
    for flag, what in ((_DYNAMIC_BASE, "ASLR (DYNAMIC_BASE)"), (_NX_COMPAT, "DEP (NX_COMPAT)")):
        if not pe["dll_characteristics"] & flag:
            problems.append(f"is built without {what}")
    for dll in pe["imports"]:
        if _RUNTIME_DLL_RE.match(dll):
            problems.append(f"imports {dll}, a C runtime Windows does not include: link the runtime "
                            f"statically (RUSTFLAGS=-C target-feature=+crt-static)")
    missing = [name for name in EXPORTS if name not in pe["exports"]]
    if missing:
        problems.append(f"does not export {', '.join(missing)}")
    found = {number: name for number, name in _WINDOWS_MACHINES.values()}.get(pe["machine"],
                                                                              f"machine {pe['machine']:#x}")
    summary = (f"PE {found} DLL, Windows {_show(pe['os_version'])} or later, imports "
               f"{' '.join(pe['imports']) or 'nothing'}")
    return summary, problems


# --- the library ------------------------------------------------------------------

def check_library(data, tag):
    """(summary, [problems]) for a library's bytes against a platform tag."""
    if not supported(tag):
        return "", [f"{tag!r} is not a platform tag this check knows (manylinux_X_Y_x86_64/aarch64, "
                    f"macosx_X_Y_arm64/x86_64, win_amd64, win_arm64)"]
    check = _check_elf if tag.startswith("manylinux") else _check_macho if tag.startswith("macosx") else _check_pe
    try:
        return check(data, tag)
    except Malformed as e:
        return "", [str(e)]
    except (ValueError, IndexError, OverflowError, struct.error) as e:      # a header this reader misjudged
        return "", [f"cannot read it: {type(e).__name__}: {e}"]


def load_problems(path):
    """Load the library as lazaret.scanner._native does (from this checkout's
    python/src), and hold its version to the package's and one answer
    (LOAD_CALL) to the one the engine gives."""
    src = pathlib.Path(__file__).resolve().parent.parent / "python" / "src"
    os.environ["LAZARET_NATIVE_LIB"] = os.path.abspath(path)
    sys.path.insert(0, str(src))
    from lazaret import __version__
    from lazaret.scanner import _native
    if not _native.available():
        return [f"does not load: {_native.load_error()}"]
    if _native.version() != __version__:
        return [f"reports version {_native.version()}, but the package is {__version__}: rust/Cargo.toml's "
                f"workspace version must be the package's (scripts/check-versions.sh)"]
    name, text, want = LOAD_CALL
    try:
        got = _native.call(name, {}, text)
    except _native.NativeError as e:
        return [f"loads, but a call fails: {e}"]
    if got != want:
        return [f"answers {name} with {got!r}, not {want!r}"]
    return []


# --- the release's files ---------------------------------------------------------

_WHEEL_RE = re.compile(re.escape(NAME) + r"-([^-]+)-py3-none-([a-z0-9_]+)\.whl\Z")
_SDIST_RE = re.compile(re.escape(NAME) + r"-([^-]+)\.tar\.gz\Z")
_BINARY_SUFFIXES = (".so", ".dylib", ".dll", ".pyd", ".exe")


def _record_problems(members, dist_info):
    """RECORD must list every member with its sha256 and size (RECORD itself
    without them)."""
    record = f"{dist_info}/RECORD"
    if record not in members:
        return [f"has no {record}"]
    problems, listed = [], set()
    for row in csv.reader(io.StringIO(members[record].decode("utf-8"))):
        if not row:
            continue
        name, digest, size = (row + ["", ""])[:3]
        listed.add(name)
        if name == record:
            continue
        if name not in members:
            problems.append(f"RECORD lists {name}, which is not in the wheel")
            continue
        data = members[name]
        want = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        if digest != want or size != str(len(data)):
            problems.append(f"RECORD's hash or size for {name} does not match the file")
    problems += [f"{name} is not in RECORD" for name in sorted(set(members) - listed)]
    return problems


def _read_wheel(path):
    with zipfile.ZipFile(path) as z:
        return {info.filename: z.read(info) for info in z.infolist() if not info.is_dir()}


def _license_fields(metadata):
    """(License-Expression values, License-File values, the other header
    lines, the description) of a METADATA text."""
    head, _, body = metadata.partition("\n\n")
    expressions, files, other = [], [], []
    for line in head.split("\n"):
        key, _, value = line.partition(": ")
        (expressions if key == "License-Expression" else files if key == "License-File" else other).append(
            value if key in ("License-Expression", "License-File") else line)
    return expressions, files, other, body


def _license_problems(members, prefix, metadata, root=None):
    """The license fields of a wheel (its license files under
    `prefix` = <dist-info>/licenses/) or of the sdist (at `prefix` = its
    root): the expression, and every License-File named and present; for the
    native engine's files, the same bytes as rust/'s here and as `root`'s
    (the sdist's, when a wheel is checked against it)."""
    problems = []
    expressions, files, _other, _body = _license_fields(metadata)
    for name in files:
        if f"{prefix}{name}" not in members:
            problems.append(f"names License-File {name}, which is not at {prefix}{name}")
    for name in PACKAGE_LICENSE_FILES:
        if name not in files:
            problems.append(f"does not name {name} as a License-File")
    others = [name for name in files if name not in PACKAGE_LICENSE_FILES + NATIVE_LICENSE_FILES]
    if others:
        problems.append(f"names License-Files the release does not ship: {', '.join(others)}")
    if expressions != [NATIVE_LICENSE_EXPRESSION]:
        problems.append(f"its License-Expression is {' '.join(expressions) or 'missing'}, not "
                        f"{NATIVE_LICENSE_EXPRESSION}")
    for name in NATIVE_LICENSE_FILES:
        data = members.get(f"{prefix}{name}")
        if name not in files or data is None:
            problems.append(f"does not carry {name} (rust/{name}) as a license file")
            continue
        source = REPO / "rust" / name
        if source.is_file() and data != source.read_bytes().replace(b"\r\n", b"\n"):
            problems.append(f"its {name} is not rust/{name}")
    for name in PACKAGE_LICENSE_FILES + NATIVE_LICENSE_FILES:
        if root is not None and name in root and members.get(f"{prefix}{name}") not in (None, root[name]):
            problems.append(f"its {name} is not the sdist's")
    return problems


def _read_sdist(path):
    """({name under the sdist's top directory: bytes} of its files, [problems])."""
    members, problems = {}, []
    with tarfile.open(path) as tar:
        for info in tar.getmembers():
            top, _, rest = info.name.partition("/")
            if not info.isfile():
                if not info.isdir():
                    problems.append(f"{info.name} is not a regular file")
                continue
            members[rest] = tar.extractfile(info).read()
    return members, problems


def check_dist(directory, expect=()):
    """(summaries, [problems]) for the release's files in a directory."""
    directory = pathlib.Path(directory)
    if not directory.is_dir():
        return [], [f"{directory} is not a directory"]
    problems, summaries = [], []
    sdists, platform = [], {}
    for path in sorted(p for p in directory.iterdir() if p.is_file()):
        wheel, sdist = _WHEEL_RE.match(path.name), _SDIST_RE.match(path.name)
        if wheel and wheel.group(2) == "any":
            problems.append(f"{path.name}: a pure (py3-none-any) wheel, which would install a package with no "
                            f"engine: every wheel carries the native library")
        elif wheel:
            platform[wheel.group(2)] = (wheel.group(1), path)
        elif sdist:
            sdists.append((sdist.group(1), path))
        else:
            problems.append(f"{path.name}: not a file of this release")
    if len(sdists) != 1:
        problems.append(f"{len(sdists)} sdists; expected one")
    if not platform:
        problems.append("no platform wheels")
    versions = {v for v, _ in sdists + list(platform.values())}
    if len(versions) > 1:
        problems.append(f"the files are of different versions: {', '.join(sorted(versions))}")
    if expect:
        for tag in sorted(set(expect) - set(platform)):
            problems.append(f"no platform wheel for {tag}")
        for tag in sorted(set(platform) - set(expect)):
            problems.append(f"a platform wheel for {tag}, which is not expected")
    if len(sdists) != 1:
        return summaries, problems
    version, sdist_path = sdists[0]
    sdist, errors = _read_sdist(sdist_path)
    errors += [f"carries {n}" for n in sorted(sdist) if "/_native/" in n or n.endswith(_BINARY_SUFFIXES)]
    errors += [f"lacks {n}, the native engine's source (pip compiles it where no platform wheel fits)"
               for n in SDIST_RUST if n not in sdist]
    pkg_info = sdist.get("PKG-INFO", b"").decode("utf-8")
    errors += _license_problems(sdist, "", pkg_info)
    problems += [f"{sdist_path.name}: {e}" for e in errors]
    if not errors:
        summaries.append(f"{sdist_path.name}: {len(sdist)} members, the engine's sources and no library")
    package = {name[len("src/"):]: data for name, data in sdist.items() if name.startswith(f"src/{NAME}/")}
    dist_info = f"{NAME}-{version}.dist-info"
    wheel_file, record_file, metadata_file, entry_points = (
        f"{dist_info}/WHEEL", f"{dist_info}/RECORD", f"{dist_info}/METADATA", f"{dist_info}/entry_points.txt")
    licenses = {f"{dist_info}/licenses/{name}" for name in PACKAGE_LICENSE_FILES + NATIVE_LICENSE_FILES}
    first_entry_points = None
    for tag, (_v, path) in sorted(platform.items()):
        members = _read_wheel(path)
        errors = _record_problems(members, dist_info)
        library = f"{NAME}/_native/{library_name(tag)}"
        for name in sorted(set(package) - set(members)):
            errors.append(f"lacks {name}, which the sdist has (src/{name})")
        for name in sorted(set(members) - set(package) - {wheel_file, record_file, metadata_file, entry_points,
                                                          library} - licenses):
            errors.append(f"has {name}, which the sdist does not")
        for name in sorted(set(package) & set(members)):
            if members[name] != package[name]:
                errors.append(f"{name} differs from the sdist's src/{name}")
        metadata = members.get(metadata_file, b"").decode("utf-8")
        if metadata != pkg_info:
            errors.append("its METADATA is not the sdist's PKG-INFO")
        errors += _license_problems(members, f"{dist_info}/licenses/", metadata, sdist)
        want = f"Wheel-Version: 1.0\nGenerator: lazaret_build\nRoot-Is-Purelib: false\nTag: py3-none-{tag}\n"
        if members.get(wheel_file, b"").decode("utf-8") != want:
            errors.append(f"its WHEEL is not the backend's for py3-none-{tag} (Root-Is-Purelib: false)")
        if first_entry_points is None:
            first_entry_points = members.get(entry_points)
        if entry_points not in members:
            errors.append(f"has no {entry_points}")
        elif members[entry_points] != first_entry_points:
            errors.append(f"its {entry_points} differs from the other wheels'")
        if library not in members:
            errors.append(f"has no {library}")
            summary = ""
        else:
            summary, found = check_library(members[library], tag)
            errors += [f"{library}: {p}" for p in found]
        problems += [f"{path.name}: {e}" for e in errors]
        if not errors:
            summaries.append(f"{path.name}: the sdist's package files and {library} ({summary})")
    return summaries, problems


def main(argv=None):
    _configure_stdio()
    parser = argparse.ArgumentParser(
        prog="check_native_library.py",
        description="Check the native engine's library against the platform tag of its wheel, or the "
                    "release's Python files against each other (--dist).")
    parser.add_argument("library", nargs="?", help="the built library")
    parser.add_argument("tag", nargs="?", help="the platform tag of the wheel it will ship in")
    parser.add_argument("--load", action="store_true",
                        help="also load LIBRARY here, as lazaret.scanner._native does, and check the version "
                             "it reports and one answer")
    parser.add_argument("--dist", metavar="DIR", help="check the sdist and wheels in DIR instead")
    parser.add_argument("--expect", action="append", default=[], metavar="TAG",
                        help="with --dist: a platform wheel that must be there (repeat; no others allowed)")
    args = parser.parse_args(argv)
    if args.dist:
        if args.library or args.tag or args.load:
            parser.error("give either LIBRARY TAG [--load] or --dist DIR")
        summaries, problems = check_dist(args.dist, args.expect)
    else:
        if not (args.library and args.tag) or args.expect:
            parser.error("give LIBRARY TAG [--load], or --dist DIR [--expect TAG ...]")
        path = pathlib.Path(args.library)
        if not path.is_file():
            print(f"error: {args.library}: no such file", file=sys.stderr)
            return 1
        summary, problems = check_library(path.read_bytes(), args.tag)
        if args.load and not problems:
            problems = load_problems(path)
            summary += "; loads here and answers as it should" if not problems else ""
        summaries = [f"{args.library} for {args.tag}: {summary}"] if not problems else []
        problems = [f"{args.library} for {args.tag}: {p}" for p in problems]
    for line in summaries:
        print(f"ok: {line}")
    for line in problems:
        print(f"error: {line}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
