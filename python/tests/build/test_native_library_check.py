"""scripts/check_native_library.py: a platform wheel's library keeps the
promise of the wheel's tag, and the release's wheels agree with each other.

pip installs a platform wheel wherever its tag says it runs. A Linux
library linked against a newer glibc than its manylinux tag promises
installs fine on an older system and then cannot load there; a macOS dylib
built for a newer macOS, or a Windows DLL that needs the Visual C++
runtime, fails the same way. The check reads the headers itself (ELF,
Mach-O, PE), so it is tested here on synthetic libraries built to the
formats' layouts, on the library `cargo build` made when there is one, and
on a real Windows executable when pip's launchers are at hand.
"""

import importlib.util
import io
import os
import pathlib
import platform as platform_module
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
import zipfile

from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "check_native_library.py")
BACKEND = os.path.join(_support.PY_ROOT, "_build", "lazaret_build.py")
check = _support.load_script(SCRIPT, "check_native_library")
EXPORTS = check.EXPORTS


def _align(n, to=8):
    return (n + to - 1) // to * to


class _Strings:
    """A string table: add(name) -> its offset."""

    def __init__(self):
        self.data = bytearray(b"\0")

    def add(self, name):
        offset = len(self.data)
        self.data += name.encode("ascii") + b"\0"
        return offset


# --- ELF: header, a PT_GNU_STACK program header, .dynstr, .dynamic, .dynsym, .gnu.version_r

GOOD_GLIBC = {"libc.so.6": ["GLIBC_2.2.5", "GLIBC_2.3", "GLIBC_2.28"], "libgcc_s.so.1": ["GCC_3.0", "GCC_4.2.0"]}


def elf(machine=62, etype=3, needed=("libgcc_s.so.1", "libc.so.6", "ld-linux-x86-64.so.2"), versions=None,
        exports=EXPORTS, runpath=None, stack_flags=6):
    versions = GOOD_GLIBC if versions is None else versions
    strings = _Strings()
    dynamic = b"".join(struct.pack("<qQ", 1, strings.add(n)) for n in needed)
    if runpath:
        dynamic += struct.pack("<qQ", 29, strings.add(runpath))
    dynamic += struct.pack("<qQ", 0, 0)
    symbols = bytes(24)                                           # the null symbol
    for name in exports:                                          # defined, global functions
        symbols += struct.pack("<IBBHQQ", strings.add(name), (1 << 4) | 2, 0, 9, 0x1000, 16)
    symbols += struct.pack("<IBBHQQ", strings.add("memcpy"), (1 << 4) | 2, 0, 0, 0, 0)   # an import
    symbols += struct.pack("<IBBHQQ", strings.add("helper"), 2, 0, 9, 0x2000, 16)        # a local
    verneed = b""
    items = list(versions.items())
    for i, (lib, names) in enumerate(items):
        following = 16 + 16 * len(names) if i < len(items) - 1 else 0
        verneed += struct.pack("<HHIII", 1, len(names), strings.add(lib), 16, following)
        for j, name in enumerate(names):
            verneed += struct.pack("<IHHII", 0, 0, 2 + j, strings.add(name), 16 if j < len(names) - 1 else 0)
    blobs, offset = [], 64 + 56
    for data in (bytes(strings.data), dynamic, symbols, verneed):
        offset = _align(offset)
        blobs.append((offset, data))
        offset += len(data)
    shoff = _align(offset)
    image = bytearray(shoff + 64 * 5)
    image[0:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, etype, machine, 1, 0, 64, shoff, 0, 64, 56, 1, 64, 5, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 0x6474E551, stack_flags, 0, 0, 0, 0, 0, 16)
    for off, data in blobs:
        image[off:off + len(data)] = data
    (s_off, s_data), (d_off, d_data), (y_off, y_data), (v_off, v_data) = blobs
    headers = [(0, 0, 0, 0, 0, 0), (3, s_off, len(s_data), 0, 0, 0), (6, d_off, len(d_data), 1, 0, 16),
               (11, y_off, len(y_data), 1, 1, 24), (0x6FFFFFFE, v_off, len(v_data), 1, len(items), 0)]
    for i, (sh_type, off, size, link, info, entsize) in enumerate(headers):
        struct.pack_into("<IIQQQQIIQQ", image, shoff + 64 * i, 0, sh_type, 0, 0, off, size, link, info, 8, entsize)
    return bytes(image)


# --- Mach-O: header, LC_BUILD_VERSION or LC_VERSION_MIN_MACOSX, dylibs, rpaths, LC_SYMTAB, an export trie

def _uleb(n):
    out = bytearray()
    while True:
        byte, n = n & 0x7F, n >> 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def export_trie(names):
    """A dyld export trie as ld64 writes one: the names' shared prefix on one
    edge from the root, then an edge per name (offsets in ULEB128, one byte
    or more: each node's place depends on the lengths before it, so they are
    settled by going round until they hold)."""
    prefix = os.path.commonprefix(list(names)) if len(names) > 1 else ""
    leaf = b"\x02\x00\x10\x00"                  # terminal: flags 0, address 0x10; no children
    tails = [n[len(prefix):] for n in names]
    root, inner_at = b"", 0
    if prefix:
        while True:
            root = b"\x00\x01" + prefix.encode() + b"\0" + _uleb(inner_at)
            if len(root) == inner_at:
                break
            inner_at = len(root)
    leaves_at = inner_at
    while True:
        inner = b"\x00" + bytes([len(tails)])
        for i, tail in enumerate(tails):
            inner += tail.encode() + b"\0" + _uleb(leaves_at + 4 * i)
        if inner_at + len(inner) == leaves_at:
            break
        leaves_at = inner_at + len(inner)
    return root + inner + leaf * len(tails)


def _encode_version(version):
    major, minor, patch = (tuple(version) + (0, 0))[:3]
    return major << 16 | minor << 8 | patch


def macho(cpu=0x0100000C, filetype=6, minos=(11, 0), platform=1, version_min=None,
          dylibs=("/usr/lib/libSystem.B.dylib",), rpaths=(), exports=EXPORTS, symtab=True, trie=None,
          magic=0xFEEDFACF):
    commands = []
    if minos is not None:
        commands.append(struct.pack("<IIIIII", 0x32, 24, platform, _encode_version(minos), 0x000E0000, 0))
    if version_min is not None:
        commands.append(struct.pack("<IIII", 0x24, 16, _encode_version(version_min), 0x000E0000))
    for lib in dylibs:
        name = lib.encode() + b"\0"
        size = _align(24 + len(name))
        commands.append(struct.pack("<IIIIII", 0xC, size, 24, 2, 0x10000, 0x10000) + name.ljust(size - 24, b"\0"))
    for path in rpaths:
        name = path.encode() + b"\0"
        size = _align(12 + len(name))
        commands.append(struct.pack("<III", 0x8000001C, size, 12) + name.ljust(size - 12, b"\0"))
    exported = ["_" + n for n in exports]
    trie_data = export_trie(exported) if (trie if trie is not None else not symtab) and exported else b""
    fixed = sum(len(c) for c in commands) + (24 if symtab else 0) + (16 if trie_data else 0)
    at = 32 + fixed
    tail = bytearray()
    if symtab:
        strings = _Strings()
        entries = [(strings.add(n), 0x0F, 1) for n in exported]           # N_SECT | N_EXT
        entries += [(strings.add("_malloc"), 0x01, 0), (strings.add("_helper"), 0x0E, 1)]   # import, local
        symoff = at
        nlist = b"".join(struct.pack("<IBBHQ", strx, ntype, sect, 0, 0x1000) for strx, ntype, sect in entries)
        stroff = symoff + len(nlist)
        commands.append(struct.pack("<IIIIII", 0x2, 24, symoff, len(entries), stroff, len(strings.data)))
        tail += nlist + strings.data
    if trie_data:
        commands.append(struct.pack("<IIII", 0x80000033, 16, at + len(tail), len(trie_data)))
        tail += trie_data
    body = b"".join(commands)
    header = struct.pack("<IIIIIIII", magic, cpu, 0, filetype, len(commands), len(body), 0x00100085, 0)
    return header + body + bytes(tail)


# --- PE: DOS stub, COFF header, optional header, one section with exports and imports

def pe(machine=0x8664, magic=0x20B, characteristics=0x2022, dll_characteristics=0x0160,
       imports=("KERNEL32.dll", "ntdll.dll", "api-ms-win-core-synch-l1-2-0.dll", "bcryptprimitives.dll"),
       delay_imports=(), exports=EXPORTS):
    base, raw = 0x1000, 0x400
    section = bytearray()

    def put(data):
        at = len(section)
        section.extend(data)
        return base + at

    def name(text):
        return put(text.encode("ascii") + b"\0")

    export_dir = put(bytes(40)) if exports else 0
    dll_name = name("lazaret_native.dll")
    name_rvas = [name(n) for n in exports]
    names_at = put(b"".join(struct.pack("<I", r) for r in name_rvas)) if exports else 0
    if exports:
        struct.pack_into("<IIHHIIIIIII", section, export_dir - base, 0, 0, 0, 0, dll_name, 1, len(exports),
                         len(exports), 0, names_at, 0)
    import_names = [name(n) for n in imports]
    import_dir = put(b"".join(struct.pack("<IIIII", 0, 0, 0, r, 0) for r in import_names) + bytes(20))
    delay_names = [name(n) for n in delay_imports]
    delay_dir = put(b"".join(struct.pack("<IIIIIIII", 1, r, 0, 0, 0, 0, 0, 0) for r in delay_names) + bytes(32))
    optional = bytearray(240 if magic == 0x20B else 224)
    struct.pack_into("<H", optional, 0, magic)
    struct.pack_into("<HH", optional, 40, 6, 0)
    struct.pack_into("<H", optional, 70, dll_characteristics)
    count_at, directories = (108, 112) if magic == 0x20B else (92, 96)
    struct.pack_into("<I", optional, count_at, 16)
    for index, (rva, size) in {0: (export_dir, 40 if exports else 0), 1: (import_dir, 20 * (len(imports) + 1)),
                               13: (delay_dir if delay_imports else 0, 32 * (len(delay_imports) + 1))}.items():
        struct.pack_into("<II", optional, directories + 8 * index, rva, size)
    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, len(optional), characteristics)
    header = bytearray(64)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 64)
    header += b"PE\0\0" + coff + optional
    header += struct.pack("<8sIIIIIIHHI", b".rdata", len(section), base, len(section), raw, 0, 0, 0, 0, 0x40000040)
    return bytes(header.ljust(raw, b"\0") + section)


def run_check(data, tag):
    return check.check_library(data, tag)


class LinuxTests(unittest.TestCase):
    TAG = "manylinux_2_28_x86_64"

    def assertRefused(self, data, words, tag=None):
        summary, problems = run_check(data, tag or self.TAG)
        self.assertTrue(problems, f"accepted: {summary}")
        self.assertTrue(any(all(w in p for w in words) for p in problems), problems)

    def test_a_library_that_keeps_the_promise(self):
        summary, problems = run_check(elf(), self.TAG)
        self.assertEqual(problems, [])
        self.assertIn("glibc 2.28", summary)
        aarch64 = elf(machine=183, needed=("libc.so.6", "ld-linux-aarch64.so.1"),
                      versions={"libc.so.6": ["GLIBC_2.17"]})
        self.assertEqual(run_check(aarch64, "manylinux_2_28_aarch64")[1], [])

    def test_a_newer_glibc_than_the_tag(self):
        newer = dict(GOOD_GLIBC, **{"libc.so.6": ["GLIBC_2.2.5", "GLIBC_2.34", "GLIBC_2.30"]})
        self.assertRefused(elf(versions=newer), ["glibc 2.34", "GLIBC_2.30", "GLIBC_2.34", "promises 2.28"])
        self.assertEqual(run_check(elf(versions=newer), "manylinux_2_34_x86_64")[1], [])

    def test_versions_and_libraries_manylinux_does_not_allow(self):
        self.assertRefused(elf(versions={"libgcc_s.so.1": ["GCC_12.0.0"]}), ["GCC_12.0.0"])
        self.assertRefused(elf(needed=("libc.so.6", "libstdc++.so.6"),
                               versions={"libstdc++.so.6": ["GLIBCXX_3.4"]}), ["libstdc++.so.6"])
        self.assertRefused(elf(versions={"libstdc++.so.6": ["GLIBCXX_3.4"]}), ["GLIBCXX_3.4"])
        self.assertRefused(elf(versions={"libc.so.6": ["GLIBC_PRIVATE"]}), ["GLIBC_PRIVATE"])
        self.assertRefused(elf(needed=("libc.so.6", "libssl.so.3")), ["libssl.so.3"])
        self.assertRefused(elf(), ["ld-linux-x86-64.so.2", "aarch64"], tag="manylinux_2_28_aarch64")

    def test_the_wrong_machine_or_kind_of_file(self):
        self.assertRefused(elf(machine=183), ["machine 183", "x86_64"])
        self.assertRefused(elf(etype=2), ["not a shared object"])
        self.assertRefused(b"\x7fELF\x01\x01" + bytes(60), ["64-bit"])
        self.assertRefused(macho(), ["not an ELF file"])

    def test_rpath_executable_stack_and_exports(self):
        self.assertRefused(elf(runpath="$ORIGIN/../lib"), ["RUNPATH", "$ORIGIN/../lib"])
        self.assertRefused(elf(stack_flags=7), ["executable stack"])
        self.assertRefused(elf(exports=EXPORTS[:1]), ["lazaret_engine_free", "lazaret_engine_version"])
        info = check.read_elf(elf())
        self.assertEqual(info["exports"], set(EXPORTS))             # not the import, not the local


class MuslTests(unittest.TestCase):
    """musllinux: musl's libc alone (Alpine names it libc.musl-<arch>.so.1, a
    musl-gcc elsewhere libc.so: musl's loader answers for both), no symbol
    versions, and no libgcc_s, which a minimal Alpine doesn't have."""
    TAG = "musllinux_1_2_x86_64"

    def assertRefused(self, data, words, tag=None):
        summary, problems = run_check(data, tag or self.TAG)
        self.assertTrue(problems, f"accepted: {summary}")
        self.assertTrue(any(all(w in p for w in words) for p in problems), problems)

    def test_a_library_that_needs_only_musl(self):
        for needed in (("libc.musl-x86_64.so.1",), ("libc.so",), ()):
            with self.subTest(needed=needed):
                summary, problems = run_check(elf(needed=needed, versions={}), self.TAG)
                self.assertEqual(problems, [])
                self.assertIn("musl", summary)
        aarch64 = elf(machine=183, needed=("libc.musl-aarch64.so.1",), versions={})
        self.assertEqual(run_check(aarch64, "musllinux_1_2_aarch64")[1], [])

    def test_libgcc_s_and_other_libraries(self):
        self.assertRefused(elf(needed=("libgcc_s.so.1", "libc.musl-x86_64.so.1"), versions={}),
                           ["libgcc_s.so.1", "unwinder"])
        for lib in ("libstdc++.so.6", "libssl.so.3", "ld-linux-x86-64.so.2"):
            with self.subTest(lib=lib):
                self.assertRefused(elf(needed=("libc.musl-x86_64.so.1", lib), versions={}), [lib])

    def test_a_library_linked_against_glibc(self):
        self.assertRefused(elf(), ["GLIBC_2.28", "linked against glibc"])
        self.assertRefused(elf(needed=("libc.so",), versions={"libc.so": ["GLIBC_2.17"]}), ["GLIBC_2.17"])

    def test_the_wrong_machine_rpath_stack_and_exports(self):
        good = {"needed": ("libc.musl-x86_64.so.1",), "versions": {}}
        self.assertRefused(elf(machine=183, **good), ["machine 183", "x86_64"])
        self.assertRefused(elf(etype=2, **good), ["not a shared object"])
        self.assertRefused(elf(runpath="$ORIGIN", **good), ["RUNPATH"])
        self.assertRefused(elf(stack_flags=7, **good), ["executable stack"])
        self.assertRefused(elf(exports=EXPORTS[1:], **good), ["lazaret_engine_call"])
        self.assertRefused(macho(), ["not an ELF file"])


class MacTests(unittest.TestCase):
    TAG = "macosx_11_0_arm64"

    def assertRefused(self, data, words, tag=None):
        summary, problems = run_check(data, tag or self.TAG)
        self.assertTrue(problems, f"accepted: {summary}")
        self.assertTrue(any(all(w in p for w in words) for p in problems), problems)

    def test_a_dylib_that_keeps_the_promise(self):
        summary, problems = run_check(macho(), self.TAG)
        self.assertEqual(problems, [])
        self.assertIn("macOS 11.0 or later", summary)
        intel = macho(cpu=0x01000007, minos=None, version_min=(10, 12))       # the older load command
        self.assertEqual(run_check(intel, "macosx_10_12_x86_64")[1], [])
        self.assertEqual(run_check(macho(minos=(10, 9)), "macosx_11_0_arm64")[1], [])

    def test_exports_from_the_symbol_table_or_the_export_trie(self):
        for kwargs in ({"symtab": True, "trie": False}, {"symtab": False, "trie": True},
                       {"symtab": True, "trie": True}):
            with self.subTest(**kwargs):
                info = check.read_macho(macho(**kwargs))
                self.assertEqual(info["exports"], {"_" + n for n in EXPORTS})
        self.assertEqual(check._trie_names(export_trie(["_a", "_ab", "_b"]), 0, 64), {"_a", "_ab", "_b"})
        self.assertRefused(macho(exports=EXPORTS[1:]), ["lazaret_engine_call"])

    def test_a_newer_macos_than_the_tag(self):
        self.assertRefused(macho(minos=(12, 0)), ["macOS 12.0", "promises 11.0", "MACOSX_DEPLOYMENT_TARGET=11.0"])
        self.assertRefused(macho(cpu=0x01000007, minos=(10, 13)), ["macOS 10.13", "promises 10.12"],
                           tag="macosx_10_12_x86_64")
        self.assertRefused(macho(minos=None), ["no minimum macOS"])
        self.assertRefused(macho(platform=2), ["platform 2"])            # iOS

    def test_libraries_macos_does_not_ship(self):
        for lib in ("/opt/homebrew/lib/libssl.3.dylib", "@rpath/libfoo.dylib", "/usr/local/lib/libz.dylib"):
            with self.subTest(lib=lib):
                self.assertRefused(macho(dylibs=("/usr/lib/libSystem.B.dylib", lib)), [lib])
        system = ("/usr/lib/libSystem.B.dylib", "/usr/lib/libiconv.2.dylib",
                  "/System/Library/Frameworks/Security.framework/Versions/A/Security")
        self.assertEqual(run_check(macho(dylibs=system, rpaths=("@loader_path",)), self.TAG)[1], [])

    def test_the_wrong_cpu_or_kind_of_file(self):
        self.assertRefused(macho(cpu=0x01000007), ["CPU type", "arm64"])
        self.assertRefused(macho(filetype=8), ["not a dylib"])                 # a bundle
        self.assertRefused(b"\xca\xfe\xba\xbe" + bytes(60), ["universal"])
        self.assertRefused(macho(magic=0xFEEDFACE), ["64-bit Mach-O"])
        self.assertRefused(elf(), ["64-bit Mach-O"])


class WindowsTests(unittest.TestCase):
    TAG = "win_amd64"

    def assertRefused(self, data, words, tag=None):
        summary, problems = run_check(data, tag or self.TAG)
        self.assertTrue(problems, f"accepted: {summary}")
        self.assertTrue(any(all(w in p for w in words) for p in problems), problems)

    def test_a_dll_that_needs_only_windows(self):
        summary, problems = run_check(pe(), self.TAG)
        self.assertEqual(problems, [])
        self.assertIn("KERNEL32.dll", summary)
        self.assertEqual(run_check(pe(machine=0xAA64), "win_arm64")[1], [])
        info = check.read_pe(pe(delay_imports=("USERENV.dll",)))
        self.assertEqual(info["imports"][-1], "USERENV.dll")
        self.assertEqual(info["exports"], set(EXPORTS))

    def test_a_c_runtime_windows_does_not_include(self):
        for dll in ("VCRUNTIME140.dll", "vcruntime140_1.dll", "MSVCP140.dll", "libgcc_s_seh-1.dll",
                    "libwinpthread-1.dll"):
            with self.subTest(dll=dll):
                self.assertRefused(pe(imports=("KERNEL32.dll", dll)), [dll, "crt-static"])
        self.assertRefused(pe(delay_imports=("MSVCP140.dll",)), ["MSVCP140.dll"])
        ucrt = pe(imports=("KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "ucrtbase.dll"))
        self.assertEqual(run_check(ucrt, self.TAG)[1], [])              # the UCRT is part of Windows 10

    def test_the_wrong_machine_or_kind_of_file(self):
        self.assertRefused(pe(machine=0x14C, magic=0x10B), ["machine 0x14c"])
        self.assertRefused(pe(magic=0x10B), ["PE32+"])
        self.assertRefused(pe(characteristics=0x0022), ["not a DLL"])
        self.assertRefused(pe(dll_characteristics=0x0100), ["ASLR"])
        self.assertRefused(pe(dll_characteristics=0x0040), ["DEP"])
        self.assertRefused(pe(exports=()), ["does not export"])
        self.assertRefused(elf(), ["not a PE file"])

    def test_a_real_windows_executable(self):
        """pip's script launchers are real PE files (the check refuses them:
        executables, not DLLs), where pip ships them."""
        spec = importlib.util.find_spec("pip")
        launcher = (pathlib.Path(spec.origin).parent / "_vendor" / "distlib" / "t64.exe"
                    if spec and spec.origin else None)
        if not (launcher and launcher.is_file()):
            self.skipTest("no pip launcher here")
        info = check.read_pe(launcher.read_bytes())
        self.assertEqual(info["machine"], 0x8664)
        self.assertIn("kernel32.dll", [d.lower() for d in info["imports"]])
        self.assertIn("not a DLL", run_check(launcher.read_bytes(), self.TAG)[1])


class TagAndInputTests(unittest.TestCase):
    def test_tags_this_check_does_not_know(self):
        for tag in ("linux_x86_64", "musllinux_1_2_i686", "macosx_11_0_universal2", "win32", "any", ""):
            with self.subTest(tag=tag):
                self.assertIn("not a platform tag this check knows", run_check(elf(), tag)[1][0])

    def test_the_library_names_are_the_backends(self):
        backend = _support.load_script(BACKEND, "lazaret_build_for_check")
        for tag in ("manylinux_2_28_x86_64", "manylinux_2_28_aarch64", "musllinux_1_2_x86_64",
                    "musllinux_1_2_aarch64", "macosx_11_0_arm64", "macosx_10_12_x86_64", "win_amd64", "win_arm64"):
            with self.subTest(tag=tag):
                self.assertEqual(check.library_name(tag), backend.native_library_name(tag))

    def test_damaged_files_are_problems_not_crashes(self):
        for tag, good in (("manylinux_2_28_x86_64", elf()), ("musllinux_1_2_x86_64", elf(needed=("libc.so",),
                                                                                              versions={})),
                          ("macosx_11_0_arm64", macho()), ("win_amd64", pe())):
            for cut in range(0, len(good), 5):
                with self.subTest(tag=tag, cut=cut):
                    self.assertTrue(run_check(good[:cut], tag)[1])
            for at in range(0, min(len(good), 400), 3):             # flipped header bytes
                damaged = bytearray(good)
                damaged[at] ^= 0xFF
                run_check(bytes(damaged), tag)                         # a list of problems, or none; never a crash

    def test_the_command_line(self):
        with tempfile.TemporaryDirectory() as d:
            good, bad = pathlib.Path(d, "good.so"), pathlib.Path(d, "bad.so")
            good.write_bytes(elf())
            bad.write_bytes(elf(versions={"libc.so.6": ["GLIBC_2.34"]}))
            with unittest.mock.patch("sys.stdout"), unittest.mock.patch("sys.stderr"):
                self.assertEqual(check.main([str(good), "manylinux_2_28_x86_64"]), 0)
                self.assertEqual(check.main([str(bad), "manylinux_2_28_x86_64"]), 1)
                self.assertEqual(check.main([str(pathlib.Path(d, "missing.so")), "manylinux_2_28_x86_64"]), 1)
                for args in ([str(good)], [], ["--dist", d, str(good)], [str(good), "win_amd64", "--expect", "x"]):
                    with self.subTest(args=args), self.assertRaises(SystemExit) as cm:
                        check.main(args)
                    self.assertEqual(cm.exception.code, 2)


def _built_library():
    """The library cargo built here (LAZARET_NATIVE_LIB, else rust/target/release), or None."""
    names = {"win32": "lazaret_native.dll", "darwin": "liblazaret_native.dylib"}
    name = names.get(sys.platform, "liblazaret_native.so")
    built = os.path.join(_support.REPO_ROOT, "rust", "target", "release", name)
    for path in (os.environ.get("LAZARET_NATIVE_LIB"), built):
        if path and os.path.isfile(path):
            return pathlib.Path(path)
    return None


@unittest.skipUnless(_built_library(), "the native library is not built here")
class BuiltLibraryTests(unittest.TestCase):
    """The library this machine built: it exports the three functions, and on
    Linux and macOS it passes for the oldest tag its own headers allow and
    fails for anything older."""

    def test_the_library_built_here(self):
        data = _built_library().read_bytes()
        machine = platform_module.machine().lower()
        if data[:4] == b"\x7fELF":
            info = check.read_elf(data)
            self.assertEqual(info["exports"] & set(EXPORTS), set(EXPORTS))
            arch = {62: "x86_64", 183: "aarch64"}.get(info["machine"])
            if arch is None:
                self.skipTest(f"ELF machine {info['machine']}")
            versions = [check._dotted(v.partition("_")[2]) for names in info["versions"].values()
                        for v in names if v.startswith("GLIBC_")]
            if versions:
                glibc = max(versions)
                tag = f"manylinux_{glibc[0]}_{glibc[1]}_{arch}"
                self.assertEqual(run_check(data, tag)[1], [])
                if glibc[1] > 17:
                    older = run_check(data, f"manylinux_{glibc[0]}_{glibc[1] - 1}_{arch}")[1]
                    self.assertTrue(any(f"glibc {glibc[0]}.{glibc[1]}" in p for p in older), older)
            else:                       # musl's (wheels.yml's musllinux build): no symbol versions at all
                tag = f"musllinux_1_2_{arch}"
                self.assertEqual(run_check(data, tag)[1], [])
                self.assertTrue(run_check(data, f"manylinux_2_28_{arch}")[1])
        elif data[:4] == b"\xcf\xfa\xed\xfe":
            info = check.read_macho(data)
            self.assertEqual({"_" + n for n in EXPORTS} - info["exports"], set())
            arch = {0x0100000C: "arm64", 0x01000007: "x86_64"}[info["cpu"]]
            major, minor, _patch = info["minos"]
            tag = f"macosx_{major}_{minor}_{arch}"
            self.assertEqual(run_check(data, tag)[1], [])
        elif data[:2] == b"MZ":
            info = check.read_pe(data)       # CI's test build links the C runtime dynamically: no policy here
            self.assertEqual(info["exports"] & set(EXPORTS), set(EXPORTS))
            self.assertEqual(info["machine"], {"amd64": 0x8664, "arm64": 0xAA64}.get(machine, info["machine"]))
            return
        else:
            self.fail("not an ELF, Mach-O or PE file")
        # --load, in a process of its own (_native keeps the first library it loads): the
        # library loads here, reports the package's version and gives its known answer
        env = {k: v for k, v in os.environ.items() if not k.startswith("LAZARET_")}
        p = subprocess.run([sys.executable, SCRIPT, str(_built_library()), tag, "--load"], capture_output=True,
                           encoding="utf-8", errors="replace", env=env, timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("loads here and answers as it should", p.stdout)


class DistTests(unittest.TestCase):
    """The release's Python files: built here by the backend, with synthetic
    libraries that keep their tags' promises."""
    TAGS = ("manylinux_2_28_x86_64", "musllinux_1_2_x86_64", "macosx_11_0_arm64", "win_amd64")

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.backend = _support.load_script(BACKEND, "lazaret_build_for_dist")
        cls.version = cls.backend.version()
        root = pathlib.Path(cls._tmp.name)
        cls.libraries = {"manylinux_2_28_x86_64": elf(), "macosx_11_0_arm64": macho(), "win_amd64": pe(),
                         "musllinux_1_2_x86_64": elf(needed=("libc.musl-x86_64.so.1",), versions={})}
        cls.dist = root / "dist"
        cls.dist.mkdir()
        cls.backend.build_sdist(str(cls.dist))
        for tag, data in cls.libraries.items():
            lib = root / f"{tag}.bin"
            lib.write_bytes(data)
            cls.backend.build_platform_wheel(str(cls.dist), tag, str(lib))

    def copy(self, skip=()):
        """A copy of the good dist to damage, without the files named."""
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        for path in self.dist.iterdir():
            if path.name not in skip:
                pathlib.Path(d.name, path.name).write_bytes(path.read_bytes())
        return pathlib.Path(d.name)

    def wheel(self, tag):
        return f"lazaret-{self.version}-py3-none-{tag}.whl"

    def sdist(self):
        return f"lazaret-{self.version}.tar.gz"

    def rewrite(self, directory, tag, change):
        """Rewrite a wheel with change({name: bytes}) applied to its members."""
        path = directory / self.wheel(tag)
        with zipfile.ZipFile(path) as z:
            members = {n: z.read(n) for n in z.namelist()}
        change(members)
        with zipfile.ZipFile(path, "w") as z:
            for name, data in members.items():
                z.writestr(name, data)

    def rewrite_sdist(self, directory, change):
        """Rewrite the sdist with change({name: bytes}) applied to its members."""
        path = directory / self.sdist()
        with tarfile.open(path) as t:
            members = {i.name: t.extractfile(i).read() for i in t.getmembers() if i.isfile()}
        change(members)
        with tarfile.open(path, "w:gz") as t:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))

    def assertProblem(self, directory, words, expect=TAGS):
        _summaries, problems = check.check_dist(directory, expect)
        self.assertTrue(any(all(w in p for w in words) for p in problems), problems)

    def test_the_release_as_built(self):
        summaries, problems = check.check_dist(self.dist, self.TAGS)
        self.assertEqual(problems, [])
        self.assertEqual(len(summaries), 1 + len(self.TAGS))
        with unittest.mock.patch("sys.stdout"), unittest.mock.patch("sys.stderr"):
            args = ["--dist", str(self.dist)] + [a for t in self.TAGS for a in ("--expect", t)]
            self.assertEqual(check.main(args), 0)

    def test_the_expected_platforms_exactly(self):
        self.assertProblem(self.copy(skip=(self.wheel("win_amd64"),)), ["no platform wheel for win_amd64"])
        self.assertProblem(self.dist, ["manylinux_2_28_x86_64", "not expected"], expect=self.TAGS[1:])
        self.assertEqual(check.check_dist(self.dist, ())[1], [])       # no --expect: any platforms

    def test_no_pure_wheel(self):
        """A py3-none-any wheel would install a package with no engine."""
        d = self.copy()
        (d / self.wheel("win_amd64")).rename(d / self.wheel("any"))
        self.assertProblem(d, ["py3-none-any", "no engine"], expect=())
        d = self.copy(skip=tuple(self.wheel(t) for t in self.TAGS))
        self.assertProblem(d, ["no platform wheels"], expect=())

    def test_a_platform_wheel_is_the_sdists_package_plus_its_library(self):
        d = self.copy()
        self.rewrite(d, "win_amd64", lambda m: m.update({"lazaret/extra.py": b"x = 1\n"}))
        self.assertProblem(d, ["win_amd64", "has lazaret/extra.py"])
        d = self.copy()
        self.rewrite(d, "macosx_11_0_arm64", lambda m: m.update({"lazaret/__init__.py": b"# changed\n"}))
        self.assertProblem(d, ["macosx_11_0_arm64", "lazaret/__init__.py differs"])
        d = self.copy()
        self.rewrite(d, "win_amd64", lambda m: m.pop("lazaret/__init__.py"))
        self.assertProblem(d, ["win_amd64", "lacks lazaret/__init__.py"])
        d = self.copy()
        self.rewrite(d, "manylinux_2_28_x86_64", lambda m: m.pop("lazaret/_native/liblazaret_native.so"))
        self.assertProblem(d, ["manylinux_2_28_x86_64", "has no lazaret/_native/liblazaret_native.so"])
        d = self.copy()
        wheel_file = f"lazaret-{self.version}.dist-info/WHEEL"
        self.rewrite(d, "win_amd64", lambda m: m.update({wheel_file: m[wheel_file].replace(b"false", b"true")}))
        self.assertProblem(d, ["win_amd64", "WHEEL"])

    def test_the_sdist_carries_the_engines_source_and_no_library(self):
        base = f"lazaret-{self.version}/"
        d = self.copy()
        self.rewrite_sdist(d, lambda m: m.pop(base + "rust/Cargo.lock"))
        self.assertProblem(d, [self.sdist(), "lacks rust/Cargo.lock"])
        d = self.copy()
        self.rewrite_sdist(d, lambda m: m.update({base + "src/lazaret/_native/liblazaret_native.so": elf()}))
        self.assertProblem(d, [self.sdist(), "carries src/lazaret/_native/liblazaret_native.so"])
        d = self.copy()
        self.rewrite_sdist(d, lambda m: m.update({base + "src/lazaret/__init__.py": b"# changed\n"}))
        self.assertProblem(d, ["lazaret/__init__.py differs from the sdist's"])

    def test_a_library_that_breaks_its_tags_promise(self):
        d = self.copy()
        newer = elf(versions={"libc.so.6": ["GLIBC_2.2.5", "GLIBC_2.34"]})
        self.rewrite(d, "manylinux_2_28_x86_64",
                     lambda m: m.update({"lazaret/_native/liblazaret_native.so": newer}))
        self.assertProblem(d, ["manylinux_2_28_x86_64", "glibc 2.34"])
        d = self.copy()
        self.rewrite(d, "musllinux_1_2_x86_64", lambda m: m.update({"lazaret/_native/liblazaret_native.so": elf()}))
        self.assertProblem(d, ["musllinux_1_2_x86_64", "linked against glibc"])
        d = self.copy()
        self.rewrite(d, "win_amd64", lambda m: m.update({"lazaret/_native/lazaret_native.dll": pe(machine=0xAA64)}))
        self.assertProblem(d, ["win_amd64", "machine 0xaa64"])

    def test_every_file_carries_the_native_engines_notices(self):
        dist_info = f"lazaret-{self.version}.dist-info"
        meta = f"{dist_info}/METADATA"

        def plain_apache(m):
            m[meta] = m[meta].replace(b"Apache-2.0 AND Unicode-3.0", b"Apache-2.0")

        def names_cpythons_license(m):
            m[meta] = m[meta].replace(b"License-File: NOTICE\n", b"License-File: NOTICE\nLicense-File: LICENSE-PYTHON\n")
            m[f"{dist_info}/licenses/LICENSE-PYTHON"] = b"a license the release does not ship\n"

        for change, words in (
                (plain_apache, ["License-Expression is Apache-2.0", "Unicode-3.0"]),
                (names_cpythons_license, ["License-Files the release does not ship", "LICENSE-PYTHON"]),
                (lambda m: m.pop(f"{dist_info}/licenses/NOTICE"), ["NOTICE", "not at"]),
                (lambda m: m.update({f"{dist_info}/licenses/NOTICE": b"edited\n"}), ["NOTICE is not rust/NOTICE"]),
                (lambda m: m.update({meta: m[meta].replace(b"Summary: ", b"Summary: Changed ")}),
                 ["METADATA is not the sdist's PKG-INFO"])):
            with self.subTest(words=words):
                d = self.copy()
                self.rewrite(d, "win_amd64", change)
                self.assertProblem(d, ["win_amd64"] + words)
        base = f"lazaret-{self.version}/"
        d = self.copy()
        self.rewrite_sdist(d, lambda m: m.pop(base + "NOTICE"))
        self.assertProblem(d, [self.sdist(), "NOTICE"])
        d = self.copy()
        self.rewrite_sdist(d, lambda m: m.update({base + "PKG-INFO": m[base + "PKG-INFO"].replace(
            b"Apache-2.0 AND Unicode-3.0", b"Apache-2.0")}))
        self.assertProblem(d, [self.sdist(), "License-Expression is Apache-2.0"])

    def test_records_and_stray_files(self):
        d = self.copy()
        self.rewrite(d, "win_amd64", lambda m: m.update({"lazaret/__init__.py": m["lazaret/__init__.py"] + b"\n"}))
        self.assertProblem(d, ["win_amd64", "RECORD", "lazaret/__init__.py"])
        d = self.copy()
        (d / ".env").write_text("TOKEN=dummy\n", encoding="utf-8")
        self.assertProblem(d, [".env", "not a file of this release"])
        d = self.copy(skip=(self.sdist(),))
        self.assertProblem(d, ["0 sdists"])
        d = self.copy()
        (d / self.wheel("win_amd64")).rename(d / "lazaret-9.9.9-py3-none-win_amd64.whl")
        self.assertProblem(d, ["different versions", "9.9.9"])


if __name__ == "__main__":
    unittest.main()
