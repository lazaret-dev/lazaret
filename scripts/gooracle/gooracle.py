#!/usr/bin/env python3
"""The Go oracle (0.1.9, G-1): check `registry/ecosystems/golang.py` against Go's own code, and write the golden tables the
tests read.

    gooracle.py build  [--out DIR]                  build the oracle from the Go toolchain's own copy of golang.org/x/mod
    gooracle.py diff   --oracle PATH [--scale N]    run N thousand cases of every kind through Go and through Python; exit 1 on a difference
    gooracle.py golden --oracle PATH --clone DIR    write python/tests/registry/recorded/go/ (golden.json and two real module zips)

`build` needs `go` (1.22 or later) and nothing from the network: every Go toolchain carries x/mod under
`$GOROOT/src/cmd/vendor`, and `main.go` here is a program over its module, semver, modfile, zip and sumdb packages. The
tests never run Go; they read what `golden` wrote. `golden` needs `git` and the network (three small repositories at
tags) and checks the module zips it builds against the hashes real go.sum files carry (PUBLISHED below), so what is
committed is real data and a drift in either tool is found.

The cases are seeded and do not change from run to run, so `golden` writes the same file every time for the same Go."""

import argparse
import collections
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PYTHON_DIR = os.path.join(REPO, "python")
RECORDED = os.path.join(PYTHON_DIR, "tests", "registry", "recorded", "go")
sys.path.insert(0, os.path.join(PYTHON_DIR, "src"))

ROOT = "example.com/m@v1.0.0/"

# Real modules at real tags and the `h1:` hashes that published go.sum files carry for them (the checksum database's
# answers): github.com/stretchr/testify v1.8.4 go.sum for the first three, github.com/prometheus/prometheus,
# hashicorp/terraform, moby/moby and cli/cli go.sum for pkg/errors (the same line in all four).
PUBLISHED = (
    # module, version, git url, h1 of the zip, h1 of the go.mod, the go.mod text when the tag has none (the proxy writes it)
    ("github.com/pmezard/go-difflib", "v1.0.0", "https://github.com/pmezard/go-difflib",
     "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=", "h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4="),
    ("github.com/pkg/errors", "v0.9.1", "https://github.com/pkg/errors",
     "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=", "h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0="),
    ("github.com/davecgh/go-spew", "v1.1.1", "https://github.com/davecgh/go-spew",
     "h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=", "h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38="),
)
KEEP_ZIPS = ("github.com/pmezard/go-difflib", "github.com/pkg/errors")           # (small enough to commit)


# ---------------------------------------------------------------- the oracle
class Oracle:
    def __init__(self, path):
        self.path = path

    def run(self, requests):
        if not requests:
            return []
        data = "".join(json.dumps(r) + "\n" for r in requests)
        done = subprocess.run([self.path], input=data, capture_output=True, encoding="utf-8", errors="replace", timeout=900)
        if done.returncode != 0:
            raise SystemExit("the oracle failed: " + done.stderr[:500])
        out = [json.loads(line) for line in done.stdout.split("\n") if line]
        if len(out) != len(requests):
            raise SystemExit("the oracle answered %d of %d" % (len(out), len(requests)))
        return out


def hexof(text):
    return text.encode("utf-8", "surrogatepass").hex()


def build(out):
    go = shutil.which("go")
    if not go:
        raise SystemExit("go is not installed")
    goroot = subprocess.run([go, "env", "GOROOT"], capture_output=True, encoding="utf-8", errors="replace").stdout.strip()
    vendored = os.path.join(goroot, "src", "cmd", "vendor", "golang.org", "x", "mod")
    if not os.path.isdir(vendored):
        raise SystemExit("no golang.org/x/mod under " + vendored)
    work = tempfile.mkdtemp(prefix="gooracle-")
    shutil.copytree(vendored, work, dirs_exist_ok=True)
    with open(os.path.join(work, "go.mod"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("module golang.org/x/mod\n\ngo 1.22\n")
    os.makedirs(os.path.join(work, "cmd", "ref"))
    shutil.copy(os.path.join(HERE, "main.go"), os.path.join(work, "cmd", "ref", "main.go"))
    target = os.path.join(out, "gooracle")
    os.makedirs(out, exist_ok=True)
    env = dict(os.environ, GOFLAGS="-mod=mod")
    done = subprocess.run([go, "build", "-o", target, "./cmd/ref"], cwd=work, env=env, capture_output=True, encoding="utf-8",
                          errors="replace")
    if done.returncode != 0:
        raise SystemExit("go build failed:\n" + done.stderr[:2000])
    print(target)


# ---------------------------------------------------------------- the cases
PATH_ATOMS = ["github.com", "golang.org", "x", "y", "v2", "v1", "v0", "v10", "v02", "v2.0", "v", "gopkg.in", "yaml.v3", "yaml.v1",
              "yaml.v0", "yaml.v02", "yaml.v3-unstable", "yaml", ".x", "x.", "..", ".", "...", "CON", "con.txt", "LPT1", "lpt9.x",
              "x~1", "x~a", "x~", "~1", "~", "A", "Azure", "é", "a b", "a_b", "a-b", "-a", "a%", "a+b", "a@b", "UPPER", "k8s.io",
              "Example.com", "example.com", "ex-ample.com", "-ex.com", "ex.com-", "1.2.3", "a.b", "foo.bar.baz", "x_y", "x--y",
              "COM1", "com10", "aux", "NUL", "Nul.txt", "prn", "x.v2", "x/v2", "unstable", "v2-unstable", "a.v2", "K",
              "中", "x​y", "x\ty", "x\ny", "a:b", "a;b", "a?b", "a#b", "a*b", "a\\b", "a'b", 'a"b', "a`b", "a|b"]
PATH_CHARS = list("abcXYZ019-._~+@%:/\\ !#$&'()*,;<=>?[]^`{|}") + ["é", "K", "中", "​", "\x7f", "‮"]


def path_cases(rnd, n):
    out = {"example.com/" + a for a in PATH_ATOMS} | set(PATH_ATOMS) | {"github.com/x/" + a for a in PATH_ATOMS}
    for _ in range(n):
        parts = [rnd.choice(PATH_ATOMS) for _ in range(rnd.randint(1, 5))]
        if rnd.random() < 0.7:
            parts[0] = rnd.choice(["github.com", "golang.org", "example.com", "gopkg.in", "k8s.io", "x.io"])
        path = "/".join(parts)
        if rnd.random() < 0.3:
            i = rnd.randrange(len(path) + 1)
            path = path[:i] + rnd.choice(PATH_CHARS) + path[i:]
        out.add(path)
    out.update(["", " ", "/", "//", "..", "a/..", "x" * 300, "github.com/" + "a" * 300, "a\x00b", "\x00"])
    return sorted(out)


def version_cases(rnd, n):
    nums = ["0", "1", "2", "10", "01", "00", "007", "123456789012345678901234567890", "", "x", "-1"]
    pres = ["", "-alpha", "-alpha.1", "-0", "-00", "-01", "-1.2", "-a..b", "-", "-.a", "-a.", "-rc1", "-RC1", "-x-y", "-A.B-c",
            "-0.20190101000000-abcdefabcdef", "-20190101000000-abcdefabcdef", "-pre.0.20190101000000-abcdefabcdef", "-é",
            "-a_b", "-a+b"]
    builds = ["", "+incompatible", "+meta", "+incompatible+incompatible", "+", "+a.b", "+a..b", "+INCOMPATIBLE", "+01", "+-"]
    out = {"v0.0.0-20190101000000-abcdefabcdef", "v1.2.3-0.20190101000000-abcdefabcdef", "v2.0.0-rc.1", "v1.0.0-RC1",
           "v1.0.0+incompatible", "v1.0.0", "v0.1.0", "v1", "v1.2", "1.0.0", "latest", "master", "", " "}
    for _ in range(n):
        pick = lambda: rnd.choice(nums[:6] if rnd.random() < 0.8 else nums)
        shape = rnd.random()
        core = ".".join([pick(), pick(), pick()] if shape < 0.8 else [pick(), pick()] if shape < 0.9 else [pick()])
        out.add(rnd.choice(["v", "v", "v", "V", "", "go", "vv"]) + core + rnd.choice(pres) + rnd.choice(builds))
    return sorted(out)


MEMBER_ATOMS = ["a.go", "go.mod", "GO.MOD", "Go.Mod", "go.mod.bak", "LICENSE", "a b", "a\\b", "a:b", "CON", "con.txt", "aux.go", "NUL",
                "com1", "COM10", "x~1", "x~1.go", "é.go", "中.go", ".hidden", "..", "...", ".", "a.", "a.b.", "a?b", "a*b",
                'a"b', "a<b", "a>b", "a|b", "a'b", "a`b", "a+b", "a,b", "a!b", "a#b", "a$b", "a%b", "a&b", "a(b)", "a=b", "a@b",
                "a[b]", "a^b", "a_b", "a{b}", "a~b", "-a", "_a", "vendor", "x" * 300, "é́", "K.go", "a​b",
                "a\tb", "a\x7fb", "a\x1bb", "‮", " ", "　", "a b", "﻿a", "Ａ.go"]


def member_cases(rnd, n):
    out = set()
    for atom in MEMBER_ATOMS:
        out.update([atom, "sub/" + atom, atom + "/", "sub/" + atom + "/"])
    for _ in range(n):
        name = "/".join(rnd.choice(MEMBER_ATOMS) for _ in range(rnd.randint(1, 4)))
        if rnd.random() < 0.15:
            name += "/"
        if rnd.random() < 0.1:
            name = "/" + name
        if rnd.random() < 0.1:
            name = name.replace("/", "//", 1)
        out.add(name)
    return sorted(x for x in out if "\x00" not in x)


GOMOD_MODS = ["example.com/m", "github.com/a/b", "golang.org/x/net", "gopkg.in/yaml.v3", "github.com/x/y/v2", "k8s.io/api", "a.b/c", "bad",
              "x.y/v1", '"quoted.com/m"', "`raw.com/m`", "A.com/Upper"]
GOMOD_VERS = ["v1.2.3", "v0.0.0-20190101000000-abcdefabcdef", "v2.0.0", "v2.0.0+incompatible", "v1.0.0-rc.1", "v3.1.0", "v0.1.0",
              "1.2.3", "v1", "latest", "v1.2.3+meta"]
GOMOD_COMMENTS = ["", " // indirect", " // indirect; foo", " // foo", "//x", " // Deprecated: no", " //indirect", "  //\tindirect  "]


def gomod_cases(rnd, n):
    spaces = [" ", "  ", "\t", " \t "]
    quote = lambda s: s if rnd.random() < 0.85 else '"%s"' % s.strip('"`')
    req = lambda: rnd.choice(spaces).join([quote(rnd.choice(GOMOD_MODS)), rnd.choice(GOMOD_VERS)]) + rnd.choice(GOMOD_COMMENTS)

    def directive():
        k = rnd.random()
        if k < 0.4:
            return "require" + rnd.choice(spaces) + req()
        if k < 0.55:
            return "require (\n" + "\n".join(rnd.choice(["\t", "  ", ""]) + req() for _ in range(rnd.randint(0, 4))) + "\n)"
        if k < 0.62:
            return "replace " + rnd.choice(GOMOD_MODS) + " => ./local"
        if k < 0.67:
            return "replace (\n\t" + rnd.choice(GOMOD_MODS) + " v1.0.0 => " + rnd.choice(GOMOD_MODS) + " v1.0.1\n)"
        if k < 0.72:
            return "exclude " + rnd.choice(GOMOD_MODS) + " " + rnd.choice(GOMOD_VERS)
        if k < 0.77:
            return "retract v1.0.0 // oops"
        if k < 0.8:
            return "retract [v1.0.0, v1.1.0]"
        if k < 0.83:
            return "godebug x=y"
        if k < 0.86:
            return "toolchain go1.22.1"
        if k < 0.88:
            return "unknown thing here"
        if k < 0.9:
            return "// a comment line"
        if k < 0.92:
            return ""
        if k < 0.94:
            return "go " + rnd.choice(["1.22", "1.21.0", "1.2", "v1", "1.22rc1", "1"])
        if k < 0.96:
            return "module " + quote(rnd.choice(GOMOD_MODS))
        if k < 0.98:
            return "require (\n\t" + req() + "\n)" + rnd.choice(GOMOD_COMMENTS)
        return rnd.choice(["require", "require (", ")", "(", "require a b c", "module", "module a b", 'require "x', 'x "\\q"',
                           "require a.b/c v1.0.0 extra"])
    out = ["", "\n", "module", "module\n", "﻿module a.b/c\n", "module a.b/c\x00\n", "module a.b/c  \n",
           "module a.b/c \n", "require (\nrequire a.b/c v1.0.0\n)\n"]
    for _ in range(n):
        lines = []
        if rnd.random() < 0.9:
            lines.append("module " + quote(rnd.choice(GOMOD_MODS[:9])))
        lines += [directive() for _ in range(rnd.randint(0, 6))]
        out.append(rnd.choice(["\n", "\n", "\r\n", "\n\n"]).join(lines) + rnd.choice(["", "\n"]))
    return out


# ---------------------------------------------------------------- zips, written by hand so that any name, flag and method can be said
def build_zip(entries, comment=b""):
    """entries: (name bytes, data bytes, flags, method) -> a zip. Method 0 stores, 8 deflates; flag 0x08 writes a data descriptor."""
    out, central = bytearray(), bytearray()
    for name, data, flags, method in entries:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        if method == 8:
            packer = zlib.compressobj(6, zlib.DEFLATED, -15)
            body = packer.compress(data) + packer.flush()
        else:
            body = data
        offset = len(out)
        if flags & 0x08:
            out += struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, flags, method, 0, 0x21, 0, 0, 0, len(name), 0) + name + body
            out += struct.pack("<IIII", 0x08074b50, crc, len(body), len(data))
        else:
            out += struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, flags, method, 0, 0x21, crc, len(body), len(data), len(name), 0) + name + body
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20, 20, flags, method, 0, 0x21, crc, len(body), len(data), len(name),
                               0, 0, 0, 0, 0, offset) + name
    start = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(entries), len(entries), len(central), start, len(comment)) + comment
    return bytes(out)


ZIP_NAMES = [b"a.go", b"b/c.go", b"go.mod", b"LICENSE", b"z", b"A", b"a b", b"\xc3\xa9.go", b"\xe4\xb8\xad.go", b"caf\xe9", b"\xff\xfe",
             b"a\\b", b"d/", b"d/e/", b"", b"x\ty", b"\x00z", b"a\nb", b"..", b"a/../b", b"\xe2\x80\xae", b"sp ace.go", b"Z", b"a.go ",
             b"\x80", b"\xc3", b"A/b", b"a/B"]
ZIP_BODIES = [b"", b"x", b"hello\n", bytes(range(64)), b"\x00" * 100, b"abc" * 40, b"package a\n"]


def zip_cases(rnd, n):
    """[{"label", "entries": [[name hex, data hex, flags, method]], "comment": hex}] (data is not random, so the file is stable)."""
    cases = [{"label": "empty", "entries": [], "comment": ""}]
    for i in range(n):
        entries = []
        for _ in range(rnd.randint(1, 6)):
            name = ZIP_NAMES[rnd.randrange(len(ZIP_NAMES))]
            name = (ROOT.encode() + name) if rnd.random() < 0.8 else name
            entries.append([name.hex(), rnd.choice(ZIP_BODIES).hex(), rnd.choice([0, 0x800, 0x800, 0x08]), rnd.choice([0, 8, 8])])
        cases.append({"label": "rand%d" % i, "entries": entries, "comment": rnd.choice(["", "63", "504b0506" + "00" * 18])})
    return cases


def zip_of(case):
    return build_zip([(bytes.fromhex(n), bytes.fromhex(d), f, m) for n, d, f, m in case["entries"]], bytes.fromhex(case["comment"]))


def zip_is_strict(case):
    """A zip a module could really be: one comment of no consequence, no repeated name, no newline in a name, valid UTF-8 where the
    UTF-8 flag says so. For these Python and Go must give the same `h1:` or both refuse; for the others they may differ."""
    if case["comment"] not in ("", "63"):
        return False
    seen = set()
    for n, d, flags, method in case["entries"]:
        name = bytes.fromhex(n)
        if name in seen or b"\n" in name:
            return False
        seen.add(name)
        if flags & 0x800:
            try:
                name.decode("utf-8")
            except UnicodeDecodeError:
                return False
    return True


# ---------------------------------------------------------------- Python's answers, and the comparison
def python_answers(golang, base):
    eco = golang.Go()

    def zip_h1(data):
        try:
            return golang.zip_h1(data)
        except base.DigestError:
            return None
    return eco, zip_h1


def is_surrogate(text):
    return any("\ud800" <= c <= "\udfff" for c in text)


def gather(oracle, scale, seed=20261003):
    """Every case with Go's answer: the rows `diff` compares and `golden` selects from."""
    rnd = random.Random(seed)
    n = scale * 1000
    paths, versions, members = path_cases(rnd, n), version_cases(rnd, n), member_cases(rnd, max(n // 10, 500))
    gomods, zips = gomod_cases(rnd, max(n // 4, 500)), zip_cases(rnd, max(n // 30, 100))
    data = {"paths": paths, "versions": versions, "members": members, "gomods": gomods, "zips": zips}
    with tempfile.TemporaryDirectory(prefix="gooracle-") as tmp:
        data["check"] = oracle.run([{"op": "checkpath", "hex": hexof(p)} for p in paths])
        data["escape"] = oracle.run([{"op": "escapepath", "hex": hexof(p)} for p in paths])
        data["split"] = oracle.run([{"op": "split", "hex": hexof(p)} for p in paths])
        data["canon"] = oracle.run([{"op": "canonver", "v": v} for v in versions])
        data["semver"] = oracle.run([{"op": "semver", "v": v} for v in versions])
        majors = ["github.com/x/y", "github.com/x/y/v2", "github.com/x/y/v3", "gopkg.in/yaml.v3", "gopkg.in/yaml.v2",
                  "gopkg.in/yaml.v3-unstable", "gopkg.in/yaml.v1", "gopkg.in/x.v10", "example.com/v2", "example.com/x/v10"]
        from lazaret.registry.ecosystems import golang
        good = [v for v in versions if golang.VERSION_RE.fullmatch(v)][:600] + ["v0.0.0-20190101000000-abcdefabcdef", "v2.0.0+incompatible"]
        rows = [(p, golang.split_path_version(p)[1], v) for p in majors for v in good]
        data["major_rows"] = rows
        data["major"] = oracle.run([{"op": "checkmajor", "v": v, "path": m} for _, m, v in rows])
        reqs = []
        for i, name in enumerate(members):
            path = os.path.join(tmp, "m%d.zip" % i)
            with open(path, "wb") as fh:
                fh.write(build_zip([((ROOT + name).encode("utf-8"), b"x\n", 0, 8)]))
            reqs.append({"op": "checkzip", "module": "example.com/m", "version": "v1.0.0", "file": path})
        data["checkzip"] = oracle.run(reqs)
        data["parsemod"] = oracle.run([{"op": "parsemodlax", "hex": hexof(t)} for t in gomods])
        reqs = []
        for i, case in enumerate(zips):
            path = os.path.join(tmp, "h%d.zip" % i)
            with open(path, "wb") as fh:
                fh.write(zip_of(case))
            reqs.append({"op": "hashzip", "file": path})
        data["hashzip"] = oracle.run(reqs)
    return data


def compare(data):
    """-> (counts by kind, list of mismatches as text)."""
    from lazaret.registry.ecosystems import base, golang
    eco, h1_of = python_answers(golang, base)
    bad, count = [], collections.Counter()

    def miss(kind, what, go, py):
        bad.append("%s %s go=%s py=%s" % (kind, what[:70], go, py))

    for p, c, e, s in zip(data["paths"], data["check"], data["escape"], data["split"]):
        count["paths"] += 1
        mine = golang.check_module_path(p)
        if (mine is None) != c["ok"]:
            miss("path", repr(p), c["err"][:60], mine)
        elif c["ok"] and golang.escape(p) != e["out"]:
            miss("escape", repr(p), e["out"], golang.escape(p))
        if not is_surrogate(p) and golang.split_path_version(p) != (s["prefix"], s["major"], s["ok"]):
            miss("split", repr(p), (s["prefix"], s["major"], s["ok"]), golang.split_path_version(p))
    for v, c, s in zip(data["versions"], data["canon"], data["semver"]):
        count["versions"] += 1
        go_ok = s["valid"] and c["canonical"] == v
        if (golang.VERSION_RE.fullmatch(v) is not None and len(v) <= golang.MAX_VERSION) != go_ok and len(v) <= golang.MAX_VERSION:
            miss("version", repr(v), go_ok, "")
        if golang.is_pseudo_version(v) != c["pseudo"]:
            miss("pseudo", repr(v), c["pseudo"], "")
        if golang.canonical_version(v) != c["canonical"]:
            miss("canonical", repr(v), c["canonical"], golang.canonical_version(v))
    for (p, m, v), r in zip(data["major_rows"], data["major"]):
        count["path majors"] += 1
        if golang.check_path_major(v, m) != r["ok"]:
            miss("major", "%s %s" % (p, v), r["ok"], "")
    for name, r in zip(data["members"], data["checkzip"]):
        count["zip members"] += 1
        _, problem = eco.member_path("gomod", ROOT + name, ROOT)
        if (r["err"] == "") != (problem is None):
            miss("member", repr(name), r["err"][:70], problem)
        if eco.member_path("gomod", ROOT + name) != (eco.member_path("gomod", ROOT + name, ROOT)):
            miss("derived root", repr(name), "", "")
    for text, r in zip(data["gomods"], data["parsemod"]):
        count["go.mod files"] += 1
        if not r["ok"]:
            continue
        count["go.mod files Go accepts"] += 1
        mine = golang.parse_gomod(text)
        if mine["module"] != r.get("module") or [list(x) for x in mine["require"]] != [list(x) for x in (r.get("require") or [])]:
            miss("go.mod", repr(text), (r.get("module"), r.get("require")), (mine["module"], mine["require"]))
    for case, r in zip(data["zips"], data["hashzip"]):
        count["zips"] += 1
        mine = h1_of(zip_of(case))
        if r["ok"] and mine == r["h1"]:
            count["zips equal"] += 1
        elif not r["ok"] and mine is None:
            count["zips both refuse"] += 1
        elif zip_is_strict(case):
            miss("zip", case["label"], r.get("h1") or r.get("err", "")[:60], mine)
        else:
            count["zips that differ where parsers may (not a module's zip)"] += 1
    return count, bad


def diff(oracle, scale):
    data = gather(oracle, scale)
    count, bad = compare(data)
    for kind, n in sorted(count.items()):
        print("%8d  %s" % (n, kind))
    for line in bad[:40]:
        print("MISMATCH", line)
    print("%d mismatches" % len(bad))
    return 1 if bad else 0


# ---------------------------------------------------------------- the golden file
def pick(rows, key, per, rnd):
    """At most `per` rows of each group, in order of appearance: every kind of answer stays in the file."""
    groups = collections.OrderedDict()
    for row in rows:
        groups.setdefault(key(row), []).append(row)
    out = []
    for group in groups.values():
        rnd.shuffle(group)
        out += group[:per]
    return out


def reason(err):
    """The kind of a Go error: its message after the quoted path, with every quoted character taken out."""
    return re.sub(r"'.*?'|\".*?\"", "Q", err.rsplit('": ', 1)[-1])[:60]


def golden(oracle, clone, out_dir):
    from lazaret.registry.ecosystems import base, golang
    data = gather(oracle, 8)
    count, bad = compare(data)
    if bad:
        raise SystemExit("Python and Go differ; fix that before writing golden files:\n" + "\n".join(bad[:10]))
    rnd = random.Random(7)
    why = {p: reason(c["err"]) for p, c in zip(data["paths"], data["check"])}
    paths = [[p, c["ok"], e.get("out") if c["ok"] else None] for p, c, e in zip(data["paths"], data["check"], data["escape"])]
    paths = pick(paths, lambda r: (r[1], why[r[0]]), 14, rnd)
    splits = [[p, s["prefix"], s["major"], s["ok"]] for p, s in zip(data["paths"], data["split"]) if not is_surrogate(p)]
    splits = pick(splits, lambda r: (r[2], r[3]), 30, rnd)
    versions = [[v, bool(s["valid"] and c["canonical"] == v), c["canonical"], c["pseudo"]]
                for v, c, s in zip(data["versions"], data["canon"], data["semver"])]
    versions = pick(versions, lambda r: (r[1], r[2] == "", r[3], r[0][:1] == "v"), 40, rnd)
    majors = [[v, m, r["ok"]] for (p, m, v), r in zip(data["major_rows"], data["major"])]
    majors = pick(majors, lambda r: (r[1][:2], r[2]), 25, rnd)
    members = [[n, r["err"] == ""] for n, r in zip(data["members"], data["checkzip"])]
    members = pick(members, lambda r: (r[1], r[0][:1], len(r[0]) > 100), 40, rnd)
    gomods = [[t, r["module"] if "module" in r else None, r.get("require") or []] for t, r in zip(data["gomods"], data["parsemod"]) if r["ok"]]
    gomods = pick(gomods, lambda r: (r[1] is None, len(r[2])), 12, rnd)
    zips = []
    for case, r in zip(data["zips"], data["hashzip"]):
        if len(zips) < 100 and zip_is_strict(case):
            zips.append(dict(case, h1=r["h1"] if r["ok"] else None))
    real, lookups = [], []
    os.makedirs(out_dir, exist_ok=True)
    work = tempfile.mkdtemp(prefix="gooracle-real-")
    for module, version, url, h1_zip, h1_mod in PUBLISHED:
        target = os.path.join(clone, module.replace("/", "_"))
        if not os.path.isdir(target):
            subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", version, url, target], check=True, encoding="utf-8")
        zpath = os.path.join(work, module.replace("/", "_") + ".zip")
        made = oracle.run([{"op": "vcszip", "module": module, "version": version, "dir": target, "rev": version, "out": zpath},
                           {"op": "hashzip", "file": zpath}])
        if not made[0]["ok"] or made[1]["h1"] != h1_zip:
            raise SystemExit("the zip built from %s %s hashes to %r, not the published %s" % (module, version, made[1], h1_zip))
        with open(zpath, "rb") as fh:
            blob = fh.read()
        if golang.zip_h1(blob) != h1_zip:
            raise SystemExit("Python's h1 of %s differs from the published one" % module)
        gomod = ("module %s\n" % module).encode("utf-8")
        if golang.file_h1(gomod) != h1_mod:
            raise SystemExit("the go.mod hash of %s is not the published one" % module)
        row = {"module": module, "version": version, "h1": h1_zip, "gomod_h1": h1_mod, "gomod": gomod.decode("utf-8")}
        if module in KEEP_ZIPS:
            fname = module.rsplit("/", 1)[-1] + "@" + version + ".zip"
            with open(os.path.join(out_dir, fname), "wb") as fh:
                fh.write(blob)
            row["zip"] = fname
        real.append(row)
    served = oracle.run([{"op": "sumdbserve", "module": r["module"], "version": r["version"], "h1zip": r["h1"], "h1mod": r["gomod_h1"], "seed": 7}
                         for r in real])
    for r, s in zip(real, served):
        lookups.append({"module": r["module"], "version": r["version"], "body": bytes.fromhex(s["body"]).decode("utf-8")})
    document = {"oracle": "golang.org/x/mod (the copy in the Go toolchain: cmd/vendor), main.go in this directory; go version "
                          + subprocess.run([shutil.which("go"), "version"], capture_output=True, encoding="utf-8").stdout.strip(),
                "counts": dict(count), "paths": paths, "splits": splits, "versions": versions, "majors": majors, "members": members,
                "gomods": gomods, "zips": zips, "real": real, "lookups": lookups, "vkey": served[0]["vkey"]}
    with open(os.path.join(out_dir, "golden.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(document, fh, ensure_ascii=True, indent=0, sort_keys=False)
        fh.write("\n")
    print("wrote", os.path.join(out_dir, "golden.json"), {k: len(v) for k, v in document.items() if isinstance(v, list)})
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", default=os.path.join(tempfile.gettempdir(), "gooracle-bin"))
    d = sub.add_parser("diff")
    d.add_argument("--oracle", required=True)
    d.add_argument("--scale", type=int, default=10, help="thousands of cases of each kind")
    g = sub.add_parser("golden")
    g.add_argument("--oracle", required=True)
    g.add_argument("--clone", required=True, help="a directory for the three git checkouts (reused if present)")
    g.add_argument("--out", default=RECORDED)
    args = parser.parse_args(argv)
    if args.command == "build":
        build(args.out)
        return 0
    oracle = Oracle(args.oracle)
    if args.command == "diff":
        return diff(oracle, args.scale)
    return golden(oracle, args.clone, args.out)


if __name__ == "__main__":
    sys.exit(main())
