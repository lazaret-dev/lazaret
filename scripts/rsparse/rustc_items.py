#!/usr/bin/env python3
"""rustc_items.py [--edition E] FILE...: the items of each Rust file as `rustc` reads them, in the format of
`examples/rsparse_dump.rs` (see `rsparse/out.rs`): `== path`, then `item …` and `use …` lines, or `!! message` for a file
`rustc` does not parse. The tree is the one `rustc -Zunpretty=ast-tree` prints (the parser's tree, before macro expansion
and before `cfg` is applied, which is what the item reader sees). `RUSTC_BOOTSTRAP=1` lets a stable compiler print it."""

import os
import re
import subprocess
import sys
import threading

# rustc's dumps nest deeply, so the reading runs on a thread with a large stack and a recursion limit to match
# (`deep`); both are put back after, never set when the module is imported: the tests load this file, and a raised
# limit there was every later test's (tomllib then read TOML nested 200,000 deep, which a test expects it to refuse).
DEEP_RECURSION = 1_000_000
DEEP_STACK = 512 * 1024 * 1024

TOKEN = re.compile(r'\s*(?:(?P<span>\S+?:\d+:\d+: \d+:\d+ \(#\d+\))|(?P<str>"(?:[^"\\]|\\.)*")|(?P<root>\{\{root\}\}#\d+)|(?P<p>[{}()\[\],:])|(?P<atom>[^\s{}()\[\],:"]+))')


class N:
    """A value of the Debug output: `Name`, `Name(args)` or `Name { fields }`."""

    __slots__ = ("name", "args", "fields")

    def __init__(self, name, args=None, fields=None):
        self.name, self.args, self.fields = name, args, fields

    def __repr__(self):
        if self.fields is not None:
            return f"{self.name} {{{', '.join(f'{k}: {v!r}' for k, v in self.fields.items())}}}"
        if self.args is not None:
            return f"{self.name}({', '.join(map(repr, self.args))})"
        return self.name

    def get(self, key, default=None):
        return self.fields.get(key, default) if self.fields else default


class Span(str):
    pass


def tokenize(text):
    pos, n = 0, len(text)
    out = []
    match = TOKEN.match
    while pos < n:
        m = match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            raise ValueError(f"cannot read the dump at {pos}: {text[pos:pos + 40]!r}")
        pos = m.end()
        k = m.lastgroup
        out.append((k, m.group(k)))
    return out


def parse_debug(text):
    toks = tokenize(text)
    i = 0
    n = len(toks)

    def value():
        nonlocal i
        k, v = toks[i]
        i += 1
        if k == "root":
            return N(v)
        if k == "span":
            return Span(v)
        if k == "str":
            return v
        if k == "p":
            if v == "[":
                items = []
                while toks[i][1] != "]" or toks[i][0] != "p":
                    items.append(value())
                    if toks[i] == ("p", ","):
                        i += 1
                i += 1
                return items
            if v == "(":
                items = []
                while not (toks[i][0] == "p" and toks[i][1] == ")"):
                    items.append(value())
                    if toks[i] == ("p", ","):
                        i += 1
                i += 1
                return tuple(items)
            raise ValueError(f"unexpected {v} after {[t[1] for t in toks[max(0, i - 8):i]]}")
        # an atom
        if i < n and toks[i][0] == "p":
            c = toks[i][1]
            if c == "{":
                i += 1
                fields = {}
                while not (toks[i][0] == "p" and toks[i][1] == "}"):
                    key = toks[i][1]
                    i += 1
                    if not (toks[i][0] == "p" and toks[i][1] == ":"):
                        raise ValueError(f"expected : after {key}")
                    i += 1
                    fields[key] = value()
                    if toks[i] == ("p", ","):
                        i += 1
                i += 1
                return N(v, fields=fields)
            if c == "(":
                i += 1
                items = []
                while not (toks[i][0] == "p" and toks[i][1] == ")"):
                    x = value()
                    if toks[i] == ("p", ":"):
                        i += 1
                        x = (x, value())
                    items.append(x)
                    if toks[i] == ("p", ","):
                        i += 1
                i += 1
                return N(v, args=items)
        return N(v)

    return value()


# ---------------------------------------------------------------------------------------------- the items

ITEM_KIND = {"Type": "TyAlias"}
SPAN = re.compile(r"^.*?:(\d+):(\d+): (\d+):(\d+) \(#\d+\)$")


class Lines:
    def __init__(self, text):
        self.starts = [0]
        for k, ch in enumerate(text):
            if ch == "\n":
                self.starts.append(k + 1)
        self.n = len(text)

    def offset(self, line, col):
        return self.starts[line - 1] + col - 1

    def span(self, s):
        m = SPAN.match(s)
        a, b, c, d = map(int, m.groups())
        return self.offset(a, b), self.offset(c, d)


def ident(v):
    """`name#0` -> `name`; `r#type#0` -> `type` (a raw identifier is the same name as the plain one)."""
    if isinstance(v, N) and v.args is None and v.fields is None:
        m = re.match(r"^(.*)#\d+$", v.name)
        if m:
            return m.group(1)[2:] if m.group(1).startswith("r#") else m.group(1)
    return None


def first_ident(payload):
    if isinstance(payload, N):
        if payload.fields and "ident" in payload.fields:
            return ident(payload.fields["ident"])
        for a in payload.args or []:
            if ident(a) is not None:
                return ident(a)
            if isinstance(a, N) and a.fields and "ident" in a.fields:
                return ident(a.fields["ident"])
    return None


def is_variant(v, *names):
    return isinstance(v, N) and v.name in names


def attr_paths(attrs, style):
    out = []
    for a in attrs:
        if not (isinstance(a, N) and a.fields):
            continue
        kind = a.fields.get("kind")
        if not (isinstance(kind, N) and kind.name == "Normal"):
            continue
        if a.fields.get("style").name != style:
            continue
        item = kind.args[0].fields["item"]
        segs = item.fields["path"].fields["segments"]
        names = [ident(s.fields["ident"]) for s in segs]
        out.append(("::" if names and names[0] == "{{root}}" else "") + "::".join(n for n in names if n != "{{root}}"))
    return out


def flags_of(kind_name, payload):
    f = set()
    fields = payload.fields if isinstance(payload, N) and payload.fields else {}

    def look(d):
        if not d:
            return
        if is_variant(d.get("safety"), "Unsafe"):
            f.add("u")
        if is_variant(d.get("safety"), "Safe"):
            f.add("s")
        if is_variant(d.get("defaultness"), "Default"):
            f.add("d")
        if is_variant(d.get("constness"), "Yes"):
            f.add("c")
        if d.get("coroutine_kind") is not None and is_variant(d.get("coroutine_kind"), "Some"):
            f.add("a")
        if d.get("ext") is not None and not is_variant(d.get("ext"), "None"):
            f.add("e")
        if is_variant(d.get("is_auto"), "Yes"):
            f.add("t")
        if is_variant(d.get("mutability"), "Mut"):
            f.add("m")
        if is_variant(d.get("polarity"), "Negative") or d.get("polarity") == '"negative"':
            f.add("n")

    look(fields)
    sig = fields.get("sig")
    if isinstance(sig, N) and sig.fields:
        look(sig.fields.get("header").fields if sig.fields.get("header") else None)
    ot = fields.get("of_trait")
    if isinstance(ot, N) and ot.args:
        for a in ot.args:
            if isinstance(a, N) and a.fields:
                look(a.fields)
    if kind_name == "Mod" and is_variant(payload.args[0], "Unsafe"):
        f.add("u")
    if kind_name == "ForeignMod":
        f.add("e")
    return "".join(sorted(f, key="ucadetsmn".index)) or "-"


def abi_of(kind_name, payload):
    fields = payload.fields if isinstance(payload, N) and payload.fields else {}
    lit = None
    if kind_name == "ForeignMod":
        a = fields.get("abi")
        if isinstance(a, N) and a.args:
            lit = a.args[0]
    elif kind_name == "Fn":
        ext = fields.get("sig").fields["header"].fields.get("ext")
        if isinstance(ext, N) and ext.name == "Explicit":
            lit = ext.args[0]
    if isinstance(lit, N) and lit.fields:
        return word(lit.fields["symbol"])
    return "-"


def word(text):
    """`text` as one word of a line, as `rsparse/out.rs` writes the ABI: whitespace, control characters and `%` as `%XX` bytes."""
    return "".join("".join("%%%02X" % b for b in c.encode("utf-8")) if c.isspace() or not c.isprintable() or c == "%" else c for c in text)


def use_leaves(tree, prefix, out, lines_info=None):
    """The leaves of a use tree: (path, alias) with the glob as a `*` segment."""
    segs = [ident(s.fields["ident"]) for s in tree.fields["prefix"].fields["segments"] if ident(s.fields["ident"]) != "{{root}}"]
    kind = tree.fields["kind"]
    full = prefix + segs
    if kind.name == "Simple":
        alias = kind.args[0]
        out.append(("::".join(full), ident(alias.args[0]) if isinstance(alias, N) and alias.name == "Some" else None))
    elif kind.name == "Glob":
        out.append(("::".join(full + ["*"]) if full else "*", None))
    elif kind.name == "Nested":
        for sub, _id in kind.fields["items"]:
            use_leaves(sub, full, out)
    return out


def items_of(root, lines):
    """Every item in the tree, in the order written: [(kind, payload, item node, parent index)]."""
    found = []
    stack = [(root, -1)]
    # an explicit stack (the tree is deep); children are pushed in reverse so they come out in order
    while stack:
        node, parent = stack.pop()
        if isinstance(node, N):
            idx = parent
            if node.name == "Item" and node.fields and "kind" in node.fields and "vis" in node.fields:
                idx = len(found)
                found.append((node, parent))
            kids = []
            if node.fields:
                kids = list(node.fields.values())
            elif node.args:
                kids = list(node.args)
            for k in reversed(kids):
                stack.append((k, idx))
        elif isinstance(node, (list, tuple)):
            for k in reversed(node):
                stack.append((k, parent))
    return found


def render(path_label, text, root):
    lines = Lines(text)
    out = []
    found = items_of(root, lines)
    for n, (item, parent) in enumerate(found):
        kind = item.fields["kind"]
        kname = ITEM_KIND.get(kind.name, kind.name)
        payload = kind.args[0] if kind.args else kind
        start, end = lines.span(item.fields["span"])
        vis = item.fields["vis"].fields["kind"]
        vname = {"Inherited": "inherited", "Public": "pub"}.get(vis.name, "restricted")
        name = "-"
        if kname == "ExternCrate":
            orig = kind.args[0]
            name = orig.args[0].strip('"') if isinstance(orig, N) and orig.name == "Some" else ident(kind.args[1])
        elif kname == "MacCall":
            name = ident(payload.fields["path"].fields["segments"][-1].fields["ident"])
        elif kname in ("Use", "ForeignMod", "Impl", "GlobalAsm"):
            name = "-"
        else:
            name = first_ident(kind if kname in ("Mod", "Struct", "Enum", "Union", "MacroDef") else payload) or "-"
        attrs = attr_paths(item.fields["attrs"], "Outer")
        inner = attr_paths(item.fields["attrs"], "Inner")
        out.append(
            "item %d %s %s %d %d %s %s %s %s %s %s"
            % (n, kname, name, start, end, vname, parent if parent >= 0 else "-", flags_of(kname, payload if kname != "Mod" else kind), abi_of(kname, payload),
               ",".join(attrs) or "-", ",".join(inner) or "-")
        )
    for n, (item, parent) in enumerate(found):
        kind = item.fields["kind"]
        if kind.name == "Use":
            leaves = []
            use_leaves(kind.args[0], [], leaves)
            for path, alias in leaves:
                out.append(f"use {n} {path}" + (f" as {alias}" if alias else ""))
    return out


def crate_attrs(root):
    return attr_paths(root.fields["attrs"], "Inner")


def run_rustc(path, edition):
    env = dict(os.environ, RUSTC_BOOTSTRAP="1")
    p = subprocess.run(["rustc", "--edition", edition, "-Zunpretty=ast-tree", "--crate-type", "lib", path], capture_output=True, env=env, timeout=120)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def deep(work):
    """Run `work()` on a thread with DEEP_STACK and DEEP_RECURSION, and put the process's recursion limit and thread
    stack size back after."""
    limit = sys.getrecursionlimit()
    size = threading.stack_size(DEEP_STACK)
    try:
        sys.setrecursionlimit(max(limit, DEEP_RECURSION))
        t = threading.Thread(target=work)
        t.start()
        t.join()
    finally:
        sys.setrecursionlimit(limit)
        threading.stack_size(size)


def items_for_file(path, edition="2021"):
    """-> (lines, error): `lines` as `render` gives them, or an error text if rustc does not take the file."""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "illegal UTF-8"
    if text.startswith("﻿"):
        text = text[1:]
    code, out, err = run_rustc(path, edition)
    if code != 0 or not out.startswith("Crate {"):
        first = next((l for l in err.splitlines() if l.startswith("error")), err.strip().splitlines()[0] if err.strip() else "rustc failed")
        return None, first
    box = {}

    def work():
        try:
            root = parse_debug(out)
            box["lines"] = render(path, text, root)
            box["crate_attrs"] = crate_attrs(root)
        except Exception as exc:  # the dump is not what this script reads
            box["error"] = f"cannot read the dump: {type(exc).__name__}: {exc}"

    deep(work)
    if "error" in box:
        return None, box["error"]
    lines = box["lines"]
    if box["crate_attrs"]:
        lines.append("crate " + ",".join(box["crate_attrs"]))
    return lines, None


def main(argv):
    edition = "2021"
    if argv[:1] == ["--edition"]:
        edition, argv = argv[1], argv[2:]
    files = argv or [l.rstrip("\n") for l in sys.stdin]
    for path in files:
        print(f"== {path}")
        lines, err = items_for_file(path, edition)
        if err:
            print(f"!! {err}")
        else:
            print("\n".join(lines))


if __name__ == "__main__":
    main(sys.argv[1:])
