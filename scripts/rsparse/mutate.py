#!/usr/bin/env python3
"""Make broken Rust files from good ones, for the differential check of the Rust item reader.

    mutate.py LIST OUTDIR [--count N] [--seed S] [--max-size BYTES] [--root DIR]

LIST names Rust files, one per line (relative to --root, default the working directory). N mutants (default 1000) are
written to OUTDIR as m00000.rs, m00001.rs, ...; the paths are listed in OUTDIR/list.txt, to feed to `diff.py --list`,
which asks `rustc` and `rsparse_dump` about each. Each mutant is a good file with one to three changes: a span deleted,
a token (a keyword, an operator, a name, a literal) inserted, a character replaced, a line deleted, copied or swapped
with the next, the text cut short, or an odd character (a NUL, a byte order mark, a carriage return, a non-ASCII
letter) put in. Most of what comes out is refused by `rustc`; some is still Rust, and the point is to compare what the
two readers find in those (`diff.py` counts the refused ones apart). The same seed gives the same files. Standard
library only."""
import argparse
import os
import random
import sys

WORDS = ["as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "fn", "for", "if", "impl",
         "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super",
         "trait", "type", "unsafe", "use", "where", "while", "union", "auto", "default", "macro_rules", "safe", "try", "gen",
         "x", "_", "T", "u8", "r#type", "r#fn", "ñ", "世界"]
PUNCT = ["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", "+=", "-=", "&&", "||", "==", "<", ">", "=", "!", "!=", "<=", ">=",
         "->", "=>", "::", "..", "..=", "...", "(", ")", "[", "]", "{", "}", ",", ".", ";", ":", "#", "#!", "#[", "$", "?", "@",
         "'", "<", ">", "\n", "\t", " "]
LITERALS = ["0", "1", "0x", "0b2", "0o8", "1_", "1__0", "0x1p", "1e", "1e+", "1u8", "1.0f32", "1.", ".5", "'a'", "''", "'ab'",
            "'\\n'", "'\\u{110000}'", "\"s\"", "\"\\q\"", "\"\\", "\"unterminated", "r\"raw\"", "r#\"raw", "r##\"x\"#", "b'a'",
            "b\"x\"", "c\"x\"", "'a", "'static", "/*", "*/", "//", "/* x */", "/// doc", "//! doc", "/** d */", "/*! d */",
            "r#", "r#abc", "br#\"x\"#"]
ODD = ["\x00", "\ufeff", "\r", "\u00e9", "\u2028", "\u0660", "\x7f", "\x01", "\u200b", "\u202e", "\\", "`"]


def mutate(text, rnd):
    for _ in range(rnd.choice([1, 1, 1, 2, 2, 3])):
        if not text:
            break
        kind = rnd.randrange(9)
        n = len(text)
        i = rnd.randrange(n)
        if kind == 0:                                    # delete a span
            text = text[:i] + text[i + rnd.randint(1, 6):]
        elif kind == 1:                                  # insert a word
            text = text[:i] + " " + rnd.choice(WORDS) + " " + text[i:]
        elif kind == 2:                                  # insert punctuation
            text = text[:i] + rnd.choice(PUNCT) + text[i:]
        elif kind == 3:                                  # insert a literal
            text = text[:i] + " " + rnd.choice(LITERALS) + " " + text[i:]
        elif kind == 4:                                  # replace a character
            text = text[:i] + rnd.choice(PUNCT + ODD) + text[i + 1:]
        elif kind == 5 or kind == 6:                     # delete, copy or swap lines
            lines = text.split("\n")
            if len(lines) > 2:
                j = rnd.randrange(len(lines) - 1)
                if kind == 5:
                    del lines[j]
                elif rnd.random() < 0.5:
                    lines.insert(j, lines[j])
                else:
                    lines[j], lines[j + 1] = lines[j + 1], lines[j]
                text = "\n".join(lines)
        elif kind == 7:                                  # cut short
            text = text[:i]
        else:                                            # an odd character
            text = text[:i] + rnd.choice(ODD) + text[i:]
    return text


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("list")
    ap.add_argument("outdir")
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--max-size", type=int, default=20000)
    ap.add_argument("--root", default=".")
    args = ap.parse_args(argv)
    rnd = random.Random(args.seed)
    sources = []
    with open(args.list, encoding="utf-8") as fh:
        for line in fh:
            path = os.path.join(args.root, line.strip())
            if line.strip().endswith(".rs") and os.path.isfile(path) and os.path.getsize(path) <= args.max_size:
                try:
                    with open(path, encoding="utf-8") as src:
                        sources.append(src.read())
                except (OSError, UnicodeDecodeError):
                    pass
    if not sources:
        print("no source files", file=sys.stderr)
        return 2
    os.makedirs(args.outdir, exist_ok=True)
    names = []
    for k in range(args.count):
        name = os.path.join(args.outdir, "m%05d.rs" % k)
        with open(name, "w", encoding="utf-8", newline="") as out:
            out.write(mutate(rnd.choice(sources), rnd))
        names.append(name)
    with open(os.path.join(args.outdir, "list.txt"), "w", encoding="utf-8", newline="\n") as out:
        out.write("\n".join(names) + "\n")
    print("%d mutants of %d files in %s" % (args.count, len(sources), args.outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
