#!/usr/bin/env python3
"""Generate the Python parser's character data from Python 3.13's unicodedata.

    python3.13 scripts/make_pyparse_tables.py            # (re)write the file
    python3.13 scripts/make_pyparse_tables.py --check    # exit 1 if it is stale

rust/crates/lazaret-engine/src/pyparse/unidata.rs holds what the parser
(rust/crates/lazaret-engine/src/pyparse/) needs of Unicode 15.1, the version
Python 3.13 reads source text with, beyond the engine's Unicode 13.0 tables
(generated/unicode13.rs, scripts/make_rust_tables.py):

* the characters an identifier may start and go on with (str.isidentifier()),
  from U+0080 up;
* NFKC for the characters assigned since Unicode 13.0: their canonical
  combining classes, decompositions and primary composites (Python
  normalizes a non-ASCII identifier to NFKC; for a character Unicode 13.0
  assigns, the 13.0 tables give the same answer, by Unicode's normalization
  stability policy);
* the character names a \\N{...} escape may give, as unicodedata.lookup()
  reads them (any case; aliases too, not named sequences): every name
  unicodedata.name() gives and every alias, front-coded in name order, and
  the names made by rule (Hangul syllables; CJK unified and compatibility
  ideographs, Tangut ideographs, Khitan small script and Nushu characters:
  a prefix and the code point in hexadecimal) as ranges.

Only Python 3.13 (Unicode 15.1) writes or checks it. The aliases are listed
here (unicodedata cannot list them): each is checked against
unicodedata.lookup() when the script runs, and so is every name, every
range and the Hangul rule.
"""
import os
import re
import sys
import unicodedata

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "rust", "crates", "lazaret-engine", "src", "pyparse", "unidata.rs")
UNICODE13 = os.path.join(REPO, "rust", "crates", "lazaret-engine", "src", "generated", "unicode13.rs")
VERSION = "15.1.0"
MAX_CP = 0x110000

# NameAliases.txt (Unicode 15.1), less the variation selectors' (VS1 to VS256,
# made by rule below): code point;alias
ALIASES = """
0000;NUL|0000;NULL|0001;SOH|0001;START OF HEADING|0002;START OF TEXT|0002;STX|0003;END OF TEXT|0003;ETX
0004;END OF TRANSMISSION|0004;EOT|0005;ENQ|0005;ENQUIRY|0006;ACK|0006;ACKNOWLEDGE|0007;ALERT|0007;BEL
0008;BACKSPACE|0008;BS|0009;CHARACTER TABULATION|0009;HORIZONTAL TABULATION|0009;HT|0009;TAB|000A;END OF LINE
000A;EOL|000A;LF|000A;LINE FEED|000A;NEW LINE|000A;NL|000B;LINE TABULATION|000B;VERTICAL TABULATION|000B;VT
000C;FF|000C;FORM FEED|000D;CARRIAGE RETURN|000D;CR|000E;LOCKING-SHIFT ONE|000E;SHIFT OUT|000E;SO
000F;LOCKING-SHIFT ZERO|000F;SHIFT IN|000F;SI|0010;DATA LINK ESCAPE|0010;DLE|0011;DC1|0011;DEVICE CONTROL ONE
0012;DC2|0012;DEVICE CONTROL TWO|0013;DC3|0013;DEVICE CONTROL THREE|0014;DC4|0014;DEVICE CONTROL FOUR|0015;NAK
0015;NEGATIVE ACKNOWLEDGE|0016;SYN|0016;SYNCHRONOUS IDLE|0017;END OF TRANSMISSION BLOCK|0017;ETB|0018;CAN
0018;CANCEL|0019;EM|0019;END OF MEDIUM|0019;EOM|001A;SUB|001A;SUBSTITUTE|001B;ESC|001B;ESCAPE
001C;FILE SEPARATOR|001C;FS|001C;INFORMATION SEPARATOR FOUR|001D;GROUP SEPARATOR|001D;GS
001D;INFORMATION SEPARATOR THREE|001E;INFORMATION SEPARATOR TWO|001E;RECORD SEPARATOR|001E;RS
001F;INFORMATION SEPARATOR ONE|001F;UNIT SEPARATOR|001F;US|0020;SP|007F;DEL|007F;DELETE|0080;PAD
0080;PADDING CHARACTER|0081;HIGH OCTET PRESET|0081;HOP|0082;BPH|0082;BREAK PERMITTED HERE|0083;NBH
0083;NO BREAK HERE|0084;IND|0084;INDEX|0085;NEL|0085;NEXT LINE|0086;SSA|0086;START OF SELECTED AREA
0087;END OF SELECTED AREA|0087;ESA|0088;CHARACTER TABULATION SET|0088;HORIZONTAL TABULATION SET|0088;HTS
0089;CHARACTER TABULATION WITH JUSTIFICATION|0089;HORIZONTAL TABULATION WITH JUSTIFICATION|0089;HTJ
008A;LINE TABULATION SET|008A;VERTICAL TABULATION SET|008A;VTS|008B;PARTIAL LINE DOWN|008B;PARTIAL LINE FORWARD
008B;PLD|008C;PARTIAL LINE BACKWARD|008C;PARTIAL LINE UP|008C;PLU|008D;REVERSE INDEX|008D;REVERSE LINE FEED
008D;RI|008E;SINGLE SHIFT TWO|008E;SINGLE-SHIFT-2|008E;SS2|008F;SINGLE SHIFT THREE|008F;SINGLE-SHIFT-3|008F;SS3
0090;DCS|0090;DEVICE CONTROL STRING|0091;PRIVATE USE ONE|0091;PRIVATE USE-1|0091;PU1|0092;PRIVATE USE TWO
0092;PRIVATE USE-2|0092;PU2|0093;SET TRANSMIT STATE|0093;STS|0094;CANCEL CHARACTER|0094;CCH|0095;MESSAGE WAITING
0095;MW|0096;SPA|0096;START OF GUARDED AREA|0096;START OF PROTECTED AREA|0097;END OF GUARDED AREA
0097;END OF PROTECTED AREA|0097;EPA|0098;SOS|0098;START OF STRING|0099;SGC
0099;SINGLE GRAPHIC CHARACTER INTRODUCER|009A;SCI|009A;SINGLE CHARACTER INTRODUCER
009B;CONTROL SEQUENCE INTRODUCER|009B;CSI|009C;ST|009C;STRING TERMINATOR|009D;OPERATING SYSTEM COMMAND|009D;OSC
009E;PM|009E;PRIVACY MESSAGE|009F;APC|009F;APPLICATION PROGRAM COMMAND|00A0;NBSP|00AD;SHY
01A2;LATIN CAPITAL LETTER GHA|01A3;LATIN SMALL LETTER GHA|034F;CGJ|0616;ARABIC SMALL HIGH LIGATURE ALEF WITH YEH BARREE
061C;ALM|0709;SYRIAC SUBLINEAR COLON SKEWED LEFT|0CDE;KANNADA LETTER LLLA|0E9D;LAO LETTER FO FON
0E9F;LAO LETTER FO FAY|0EA3;LAO LETTER RO|0EA5;LAO LETTER LO|0FD0;TIBETAN MARK BKA- SHOG GI MGO RGYAN
11EC;HANGUL JONGSEONG YESIEUNG-KIYEOK|11ED;HANGUL JONGSEONG YESIEUNG-SSANGKIYEOK|11EE;HANGUL JONGSEONG SSANGYESIEUNG
11EF;HANGUL JONGSEONG YESIEUNG-KHIEUKH|180B;FVS1|180C;FVS2|180D;FVS3|180E;MVS|180F;FVS4|1BBD;SUNDANESE LETTER ARCHAIC I
200B;ZWSP|200C;ZWNJ|200D;ZWJ|200E;LRM|200F;RLM|202A;LRE|202B;RLE|202C;PDF|202D;LRO|202E;RLO|202F;NNBSP|205F;MMSP
2060;WJ|2066;LRI|2067;RLI|2068;FSI|2069;PDI|2118;WEIERSTRASS ELLIPTIC FUNCTION|2448;MICR ON US SYMBOL
2449;MICR DASH SYMBOL|2B7A;LEFTWARDS TRIANGLE-HEADED ARROW WITH DOUBLE VERTICAL STROKE
2B7C;RIGHTWARDS TRIANGLE-HEADED ARROW WITH DOUBLE VERTICAL STROKE|A015;YI SYLLABLE ITERATION MARK
AA6E;MYANMAR LETTER KHAMTI LLA|FE18;PRESENTATION FORM FOR VERTICAL RIGHT WHITE LENTICULAR BRACKET|FEFF;BOM
FEFF;BYTE ORDER MARK|FEFF;ZWNBSP|122D4;CUNEIFORM SIGN NU11 TENU|122D5;CUNEIFORM SIGN NU11 OVER NU11 BUR OVER BUR
16E56;MEDEFAIDRIN CAPITAL LETTER H|16E57;MEDEFAIDRIN CAPITAL LETTER NG|16E76;MEDEFAIDRIN SMALL LETTER H
16E77;MEDEFAIDRIN SMALL LETTER NG|1B001;HENTAIGANA LETTER E-1|1D0C5;BYZANTINE MUSICAL SYMBOL FTHORA SKLIRON CHROMA VASIS
"""

# the names made by rule: a prefix, then the code point in hexadecimal ("%04X")
RULE_PREFIXES = ("CJK UNIFIED IDEOGRAPH-", "CJK COMPATIBILITY IDEOGRAPH-", "TANGUT IDEOGRAPH-",
                 "KHITAN SMALL SCRIPT CHARACTER-", "NUSHU CHARACTER-")
RULE_NAME = re.compile("(" + "|".join(re.escape(p) for p in RULE_PREFIXES) + r")[0-9A-F]{4,5}$")

# Hangul syllables (Unicode 15.1, section 3.12)
JAMO_L = ["G", "GG", "N", "D", "DD", "R", "M", "B", "BB", "S", "SS", "", "J", "JJ", "C", "K", "T", "P", "H"]
JAMO_V = ["A", "AE", "YA", "YAE", "EO", "E", "YEO", "YE", "O", "WA", "WAE", "OE", "YO", "U", "WEO", "WE", "WI",
          "YU", "EU", "YI", "I"]
JAMO_T = ["", "G", "GG", "GS", "N", "NJ", "NH", "D", "L", "LG", "LM", "LB", "LS", "LT", "LP", "LH", "M", "B", "BS",
          "S", "SS", "NG", "J", "C", "K", "T", "P", "H"]

# the name table's encoding (pyparse/unicode.rs reads it)
BLOCK = 16                       # entries per block; a block's first entry is whole
LITERAL = set(b" -0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
ONE_BYTE = list(range(0x80, 0x100))          # a word in one byte
TWO_BYTE = list(range(0x01, 0x20))           # this byte and the next: a word


def _configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def ranges(cps):
    out = []
    for c in sorted(cps):
        if out and out[-1][1] == c - 1:
            out[-1][1] = c
        else:
            out.append([c, c])
    return [tuple(r) for r in out]


def assigned_13():
    """The code points Unicode 13.0 assigns (generated/unicode13.rs: ASSIGNED_RUNS)."""
    with open(UNICODE13, encoding="utf-8") as f:
        text = f.read()
    runs = [int(x) for x in re.search(r"pub const ASSIGNED_RUNS: &\[u32\] = &\[([^\]]*)\]", text).group(1).split(",")
            if x.strip()]
    out = bytearray(MAX_CP)
    cp, on = 0, True
    for n in runs:
        if on:
            out[cp:cp + n] = b"\x01" * n
        cp += n
        on = not on
    return out


def identifier_data():
    start = [c for c in range(0x80, MAX_CP) if chr(c).isidentifier()]
    cont = [c for c in range(0x80, MAX_CP) if ("a" + chr(c)).isidentifier()]
    return ranges(start), ranges(cont)


def normalization_data():
    old = assigned_13()
    ccc, decomp, compose = [], [], []
    for c in range(0x80, MAX_CP):
        if old[c] or unicodedata.category(chr(c)) == "Cn":
            continue
        k = unicodedata.combining(chr(c))
        if k:
            ccc.append((c, k))
        d = unicodedata.decomposition(chr(c))
        if d:
            parts = d.split()
            compat = parts[0].startswith("<")
            if compat:
                parts = parts[1:]
            cps = [int(p, 16) for p in parts]
            decomp.append((c, compat, cps))
            if not compat and len(cps) == 2 and unicodedata.normalize("NFC", chr(cps[0]) + chr(cps[1])) == chr(c):
                compose.append((cps[0], cps[1], c))
    compose.sort()
    return ccc, decomp, compose


def hangul_name(c):
    s = c - 0xAC00
    return "HANGUL SYLLABLE " + JAMO_L[s // 588] + JAMO_V[(s % 588) // 28] + JAMO_T[s % 28]


def hangul_lookup(name):
    """The syllable a name gives, read the way pyparse/unicode.rs reads it."""
    if not name.startswith("HANGUL SYLLABLE "):
        return None
    rest = name[16:]
    def longest(table):
        best = -1
        for i, j in enumerate(table):
            if rest.startswith(j) and (best < 0 or len(j) > len(table[best])):
                best = i
        return best
    li = longest(JAMO_L)
    rest = rest[len(JAMO_L[li]):]
    vi = longest(JAMO_V)
    if vi < 0:
        return None
    rest = rest[len(JAMO_V[vi]):]
    if rest not in JAMO_T:
        return None
    return 0xAC00 + (li * 21 + vi) * 28 + JAMO_T.index(rest)


def lookup(name):
    try:
        ch = unicodedata.lookup(name)
    except KeyError:
        return None
    return ord(ch) if len(ch) == 1 else None


def name_data():
    entries = {}
    rule = {p: [] for p in RULE_PREFIXES}
    for c in range(MAX_CP):
        n = unicodedata.name(chr(c), None)
        if n is None:
            continue
        if 0xAC00 <= c <= 0xD7A3:
            assert n == hangul_name(c), hex(c)
            continue
        m = RULE_NAME.match(n)
        if m:
            assert n == m.group(1) + "%04X" % c, n
            continue
        entries[n] = c
    # the names made by rule, as lookup() reads them (Tangut ideographs have
    # no unicodedata.name() but are looked up)
    for p in RULE_PREFIXES:
        rule[p] = [c for c in range(MAX_CP) if lookup(p + "%04X" % c) == c]
        for c in (rule[p][0], rule[p][-1]):
            assert lookup(p + "0%04X" % c) is None and lookup(p.lower() + ("%04x" % c)) == c, (p, hex(c))
    aliases = []
    for chunk in ALIASES.strip().split("\n"):
        for item in chunk.split("|"):
            cp, alias = item.split(";", 1)
            aliases.append((alias, int(cp, 16)))
    aliases += [("VS%d" % (i + 1), 0xFE00 + i) for i in range(16)]
    aliases += [("VS%d" % (i + 17), 0xE0100 + i) for i in range(240)]
    for alias, cp in aliases:
        assert lookup(alias) == cp, alias
        assert alias not in entries, alias
        entries[alias] = cp
    for n, c in entries.items():
        assert lookup(n) == c and lookup(n.lower()) == c, n
        assert all(ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -" for ch in n), n
    for c in range(0xAC00, 0xD7A4):
        assert hangul_lookup(hangul_name(c)) == c == lookup(hangul_name(c))
    for bad in ("HANGUL SYLLABLE ", "HANGUL SYLLABLE GGGA", "HANGUL SYLLABLE GAX", "HANGUL SYLLABLE X"):
        assert hangul_lookup(bad) is None and lookup(bad) is None, bad
    return sorted(entries.items()), {p: ranges(v) for p, v in rule.items()}


def words_of(s):
    return re.findall(r"[^ -]+[ -]?|[ -]", s)


def encode_names(entries):
    """The names, front-coded in name order: blocks of BLOCK entries, each entry
    [shared prefix length][suffix: literal characters and word codes][0], a
    block's first entry whole; the code points apart, 3 bytes each."""
    from collections import Counter
    count = Counter()
    for n, _ in entries:
        for w in words_of(n):
            if len(w) > 1:
                count[w] += 1
    ranked = [w for w, k in sorted(count.items(), key=lambda wk: (-(wk[1] * (len(wk[0]) - 1)), wk[0])) if k > 1]
    one = ranked[:len(ONE_BYTE)]
    two = ranked[len(ONE_BYTE):len(ONE_BYTE) + len(TWO_BYTE) * 256]
    code = {w: bytes([ONE_BYTE[i]]) for i, w in enumerate(one)}
    for i, w in enumerate(two):
        code[w] = bytes([TWO_BYTE[i // 256], i % 256])
    data = bytearray()
    blocks = []
    cps = bytearray()
    prev = ""
    for i, (n, c) in enumerate(entries):
        if i % BLOCK == 0:
            blocks.append(len(data))
            k = 0
        else:
            k = 0
            while k < min(len(n), len(prev)) and n[k] == prev[k]:
                k += 1
            while k > 0 and n[k - 1] not in " -":
                k -= 1
        assert k < 256
        data.append(k)
        for w in words_of(n[k:]):
            if w in code:
                data += code[w]
            else:
                data += w.encode("ascii")
        data.append(0)
        cps += c.to_bytes(3, "little")
        prev = n
    return one + two, bytes(data), blocks, bytes(cps)


def decode_entry(words, data, at, prev):
    """(the name of the entry at `at` after `prev`, where the next entry starts)."""
    k = data[at]
    out = prev[:k]
    at += 1
    while data[at] != 0:
        b = data[at]
        if b >= 0x80:
            out += words[b - 0x80]
            at += 1
        elif 0x01 <= b < 0x20:
            out += words[len(ONE_BYTE) + (b - 1) * 256 + data[at + 1]]
            at += 2
        else:
            out += chr(b)
            at += 1
    return out, at + 1


def check_encoding(entries, words, data, blocks, cps):
    prev = ""
    at = 0
    for i, (n, c) in enumerate(entries):
        if i % BLOCK == 0:
            assert at == blocks[i // BLOCK]
            prev = ""
        got, at = decode_entry(words, data, at, prev)
        assert got == n and int.from_bytes(cps[3 * i:3 * i + 3], "little") == c, (got, n)
        prev = got


def rust_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rust_bytes(b):
    """A byte string literal, in lines of about 100 characters (a line ending in
    a backslash goes on with the next line's first non-blank character, so a
    line never starts with a blank: it is escaped)."""
    tokens = [chr(x) if 0x20 <= x < 0x7F and x not in (0x22, 0x5C) else "\\x%02x" % x for x in b]
    lines, line, width = [], [], 0
    for t in tokens:
        if not line and t == " ":
            t = "\\x20"
        line.append(t)
        width += len(t)
        if width >= 100:
            lines.append("".join(line))
            line, width = [], 0
    if line:
        lines.append("".join(line))
    return 'b"\\\n' + "\\\n".join(lines) + '"'


def numbers(values, per_line=16):
    rows = []
    for i in range(0, len(values), per_line):
        rows.append("    " + ", ".join(values[i:i + per_line]) + ",")
    return "\n".join(rows)


def render():
    start, cont = identifier_data()
    ccc, decomp, compose = normalization_data()
    entries, rule = name_data()
    words, data, blocks, cps = encode_names(entries)
    check_encoding(entries, words, data, blocks, cps)
    out = []
    out.append("// Generated by scripts/make_pyparse_tables.py from Python 3.13's unicodedata — do not edit.\n")
    out.append("//\n// Data of the Unicode Character Database 15.1, distributed under the Unicode\n"
               "// License v3 (rust/LICENSE-UNICODE):\n//   Copyright © 1991-2026 Unicode, Inc.\n\n")
    out.append("//! The Python parser's Unicode 15.1 data (see scripts/make_pyparse_tables.py).\n\n")
    out.append('/// The Unicode version of this data (unicodedata.unidata_version).\npub const VERSION: &str = "%s";\n\n'
               % VERSION)
    out.append("/// The characters from U+0080 up that may start an identifier: [first, last] runs.\n")
    out.append("pub const ID_START: &[(u32, u32)] = &[\n" + numbers(["(0x%X, 0x%X)" % r for r in start], 6) + "\n];\n\n")
    out.append("/// The characters from U+0080 up that may go on with one.\n")
    out.append("pub const ID_CONTINUE: &[(u32, u32)] = &[\n" + numbers(["(0x%X, 0x%X)" % r for r in cont], 6)
               + "\n];\n\n")
    out.append("/// The canonical combining classes (not 0) of the characters assigned since Unicode 13.0.\n")
    out.append("pub const NEW_CCC: &[(u32, u8)] = &[\n" + numbers(["(0x%X, %d)" % x for x in ccc], 8) + "\n];\n\n")
    out.append("/// The decompositions of the characters assigned since Unicode 13.0: (character,\n"
               "/// a compatibility mapping?, its characters).\n")
    out.append("pub const NEW_DECOMP: &[(u32, bool, &[u32])] = &[\n"
               + numbers(["(0x%X, %s, &[%s])" % (c, "true" if k else "false", ", ".join("0x%X" % p for p in cps_))
                          for c, k, cps_ in decomp], 3) + "\n];\n\n")
    out.append("/// The primary composites of the characters assigned since Unicode 13.0: (first, second, composite).\n")
    out.append("pub const NEW_COMPOSE: &[(u32, u32, u32)] = &[\n" + numbers(["(0x%X, 0x%X, 0x%X)" % x for x in compose], 4)
               + "\n];\n\n")
    out.append("/// The names made by rule: a prefix, then the code point in hexadecimal (`%04X`),\n"
               "/// for the code points of these runs.\n")
    out.append("pub const RULE_NAMES: &[(&str, &[(u32, u32)])] = &[\n")
    for p in RULE_PREFIXES:
        out.append("    (%s, &[%s]),\n" % (rust_str(p), ", ".join("(0x%X, 0x%X)" % r for r in rule[p])))
    out.append("];\n\n")
    out.append("/// The Hangul syllables' jamo (L, V, T): HANGUL SYLLABLE and L V T.\n")
    for name, table in (("JAMO_L", JAMO_L), ("JAMO_V", JAMO_V), ("JAMO_T", JAMO_T)):
        out.append("pub const %s: &[&str] = &[%s];\n" % (name, ", ".join(rust_str(j) for j in table)))
    out.append("\n/// Entries per block of NAMES.\npub const NAME_BLOCK: usize = %d;\n\n" % BLOCK)
    out.append("/// The words of NAMES: a byte from 0x80 up is word (byte - 0x80); a byte b from\n"
               "/// 0x01 to 0x1F and the byte c after it are word (128 + (b - 1) * 256 + c).\n")
    out.append("pub const NAME_WORDS: &[&str] = &[\n" + numbers([rust_str(w) for w in words], 8) + "\n];\n\n")
    out.append("/// The %d names and aliases, in order: each entry is the length of the prefix it\n"
               "/// shares with the entry before it (0 for a block's first), the rest (characters\n"
               "/// and words), and 0.\n" % len(entries))
    out.append("pub const NAMES: &[u8] = " + rust_bytes(data) + ";\n\n")
    out.append("/// Where each block of NAME_BLOCK entries starts in NAMES.\n")
    out.append("pub const NAME_BLOCKS: &[u32] = &[\n" + numbers([str(b) for b in blocks], 12) + "\n];\n\n")
    out.append("/// Each entry's code point: 3 bytes, little-endian.\n")
    out.append("pub const NAME_CODES: &[u8] = " + rust_bytes(cps) + ";\n")
    stats = (len(data), len(cps), len(blocks), len(words))
    return "".join(out), stats


def main(argv):
    _configure_stdio()
    if unicodedata.unidata_version != VERSION:
        print(f"make_pyparse_tables.py needs Python 3.13 (Unicode {VERSION}); this is "
              f"{sys.version.split()[0]} (Unicode {unicodedata.unidata_version})", file=sys.stderr)
        return 2
    text, (names, codes, blocks, words) = render()
    if "--check" in argv:
        current = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if current != text:
            print(f"{os.path.relpath(OUT, REPO)} is stale: run python3.13 scripts/make_pyparse_tables.py",
                  file=sys.stderr)
            return 1
        return 0
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {os.path.relpath(OUT, REPO)}: names {names} bytes, codes {codes}, {blocks} blocks, {words} words")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
