"""The files of FP-BINARY-BY-NAME's tests, inert: text named as compiled code, and compiled code's bytes as its
formats lay them out (headers only, then filler: nothing here runs)."""
import struct

DOCKERFILE = ("FROM node:22-slim\nWORKDIR /sandbox\nCOPY package.json ./\nRUN npm ci --omit=dev\nCOPY . .\n"
              "USER node\nCMD [\"node\", \"index.js\"]\n")
LINKER_SCRIPT = "/* GNU ld script */\nOUTPUT_FORMAT(elf64-x86-64)\nGROUP ( /lib/libc.so.6 /usr/lib/libc_nonshared.a )\n"


def filler(n, seed=7):
    x = seed
    out = bytearray()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(x >> 16 & 0xFF)
    return bytes(out)


def elf():
    """An ELF 64-bit shared object's header, then filler."""
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    return ident + struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 0, 64, 0, 0) + filler(2000)


def macho_object():
    """A Mach-O 64-bit object file (MH_OBJECT, arm64): what clang writes a precompiled module (.pcm) as for an Apple
    target with module debugging on (-gmodules, which passes -fmodule-format=obj), its AST in a __CLANG,__clangast
    section."""
    return struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 1, 0, 0, 0, 0) + filler(2000, 8)


def macho_fat():
    """A universal Mach-O: 0xCAFEBABE, two architectures."""
    return struct.pack(">II", 0xCAFEBABE, 2) + struct.pack(">IIIII", 0x01000007, 3, 4096, 2000, 12) * 2 + bytes(40) + filler(2000, 9)


def java_class():
    """A Java class file's header (Java 17: major version 61)."""
    return struct.pack(">IHH", 0xCAFEBABE, 0, 61) + struct.pack(">H", 20) + filler(600, 10)


def dex():
    return b"dex\n035\x00" + filler(1000, 11)


def ar_archive():
    """A static library: an ar archive whose first member is an object file (a text header per member)."""
    member = elf()
    head = b"lib.o/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"644".ljust(8)
    head += str(len(member)).encode().ljust(10) + b"`\n"
    return b"!<arch>\n" + head + member


LAUNCHER = "".join(f"# line {k}: a launch script, as Spring Boot's fully executable jars begin\n" for k in range(60)) + \
    'exec java -jar "$0" "$@"\n'


def zip_of(name, data):
    """A zip of one member, stored (its local header, data, central directory and end record)."""
    import zlib
    crc = zlib.crc32(data)
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0, crc, len(data), len(data), len(name), 0) + name + data
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0, crc, len(data), len(data), len(name),
                          0, 0, 0, 0, 0, 0) + name
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def launcher_jar():
    """A launch script, then a jar (the review of Oct 27: `java -jar` runs it; its first 2 KB read as text)."""
    return LAUNCHER.encode() + zip_of(b"Main.class", struct.pack(">IHH", 0xCAFEBABE, 0, 61) + filler(400, 12))


def text_then_elf():
    """Text, then an ELF shared object after the first 2 KB."""
    return LAUNCHER.encode() + elf()


def ar_text_first():
    """A static library whose first 2 KB read as text: GNU ar's table of long member names first, then an object
    file (looks_binary samples 2,048 bytes: an ar archive's are not always binary)."""
    names = b"".join(f"a_rather_long_object_file_name_number_{k:03d}.o/\n".encode() for k in range(45))
    table = b"//".ljust(48) + str(len(names)).encode().ljust(10) + b"`\n" + names
    member = elf()
    head = b"/0".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"644".ljust(8)
    head += str(len(member)).encode().ljust(10) + b"`\n"
    return b"!<arch>\n" + table + head + member
