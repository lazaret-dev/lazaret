#!/usr/bin/env python3
"""Build the browser dashboard, python/src/lazaret/web/lazaret.html, from its sources (BR-7 step 5).

    python3 scripts/make_dashboard.py                  # rebuild the page, keeping the engine it carries
    python3 scripts/make_dashboard.py --engine WASM    # ... with WASM as its engine (cd js && npm run build:
                                                       #     js/native/lazaret.wasm)
    python3 scripts/make_dashboard.py --check          # exit 1 when the page is not what its sources make

The page is js/dashboard/page.html with four things put in it:

* its script: js/dashboard/page.js and every module it imports, which are the npm package's (js/src/), but
  src/lib/wasmload.js, which reads native/lazaret.wasm from disk: js/dashboard/wasmload.js takes its place. Each
  module becomes a function of its own, run once, in the order of the imports: its imports become names taken
  from the modules it imports, its exports the names it returns. So the page runs the package's own code, and the
  modules it imports must not use Node: no node: or package imports (checked here), and nothing of Node's unless
  they look first (as native.js looks for Buffer).
* its content-security policy: the script allowed by its hash and nothing else, and 'wasm-unsafe-eval', which
  lets the page compile the engine.
* the engine: a build of the Rust engine as WebAssembly, gzipped and in base64, in a data block the page reads and
  never runs (<script type="application/octet-stream" id="lazaret-engine">, before the script, which reads it as
  the page opens), with the SHA-256 of the WebAssembly
  (data-sha256), its length (data-bytes) and the digest of the sources it was built from (data-sources: the Rust
  workspace's manifest and lock file, the files git tracks in the crates the WebAssembly build compiles, and
  js/scripts/build-wasm.js).
  Built by `npm run build` from those sources; the page keeps the one it has until they change, and --check fails
  once they have.
* the engine's notices: rust/NOTICE and rust/LICENSE-UNICODE, which go wherever the engine goes.

The page is committed, so the dashboard needs nothing but itself. python/tests/scanner/test_dashboard.py runs
--check's comparisons.
"""
import base64
import gzip
import hashlib
import html
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS = os.path.join(REPO, "js")
TEMPLATE = os.path.join(JS, "dashboard", "page.html")
ENTRY = os.path.join(JS, "dashboard", "page.js")
PAGE = os.path.join(REPO, "python", "src", "lazaret", "web", "lazaret.html")
DEFAULT_ENGINE = os.path.join(JS, "native", "lazaret.wasm")
# the npm package's loader (reads native/lazaret.wasm) -> the page's (the engine it carries)
SUBSTITUTES = {os.path.join(JS, "src", "lib", "wasmload.js"): os.path.join(JS, "dashboard", "wasmload.js")}
RUST = os.path.join(REPO, "rust")
WASM_CRATE = "lazaret-ffi"            # the crate the WebAssembly build builds (js/scripts/build-wasm.js)
NOTICES = [os.path.join(RUST, "NOTICE"), os.path.join(RUST, "LICENSE-UNICODE")]
BASE64_LINE = 100

CSP = ("default-src 'none'; script-src {hash} 'wasm-unsafe-eval'; style-src 'unsafe-inline'; img-src data:; "
       "base-uri 'none'; form-action 'none'")
ENGINE_RE = re.compile(r'<script type="application/octet-stream" id="lazaret-engine"([^>]*)>\n(.*?)\n</script>', re.S)
ATTR_RE = re.compile(r'\s(data-[a-z0-9-]+)="([^"]*)"')


class BuildError(Exception):
    pass


def rel(path):
    """`path` as the build names it: relative to the repository, '/'-separated; a path on another drive than the
    repository's (Windows), which has no relative form, whole."""
    try:
        return os.path.relpath(path, REPO).replace(os.sep, "/")
    except ValueError:                          # (os.path.relpath: "path is on mount 'C:', start on mount 'D:'")
        return os.path.abspath(path).replace(os.sep, "/")


def read_text(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n").replace("\r", "\n")


# ---- the script ------------------------------------------------------------------------------------------------
IDENT = r"[A-Za-z_$][\w$]*"
# a module's import and export statements: at the start of a line, at the top level
IMPORT_RE = re.compile(r'^import\s+(?P<what>[^;"]*?)\s+from\s+"(?P<spec>[^"]+)";[ \t]*(?://[^\n]*)?$', re.M)
EXPORT_FROM_RE = re.compile(r'^export\s+\{(?P<names>[^}]*)\}\s+from\s+"(?P<spec>[^"]+)";[ \t]*(?://[^\n]*)?$', re.M)
EXPORT_LIST_RE = re.compile(r'^export\s+\{(?P<names>[^}]*)\};[ \t]*(?://[^\n]*)?$', re.M)
EXPORT_DECL_RE = re.compile(r"^export\s+(?P<kind>async\s+function\s*\*?|function\s*\*?|class|const|let|var)\s+"
                            rf"(?P<name>{IDENT})", re.M)
ANY_MODULE_LINE_RE = re.compile(r"^(?:import|export)\b", re.M)


def _names(clause, where):
    """[(name, local)] of `a, b as c`."""
    out = []
    for part in clause.split(","):
        part = " ".join(part.split())
        if not part:
            continue
        m = re.fullmatch(rf"({IDENT})(?: as ({IDENT}))?", part)
        if not m:
            raise BuildError(f"{where}: can't read the import or export list {clause!r}")
        out.append((m.group(1), m.group(2) or m.group(1)))
    return out


def _resolve(spec, importer):
    if spec.startswith("node:") or not spec.startswith("."):
        raise BuildError(f"{rel(importer)} imports {spec!r}: the page's modules may import only each other "
                         "(nothing of Node's, no packages)")
    path = os.path.normpath(os.path.join(os.path.dirname(importer), spec))
    path = SUBSTITUTES.get(path, path)
    if not os.path.isfile(path):
        raise BuildError(f"{rel(importer)} imports {spec!r}, which is not there ({rel(path)})")
    return path


def parse_module(path):
    """(body, imports, exports): the module's text without its import and export statements' syntax; imports:
    [(path, [(name, local)] or ("*", local))]; exports: [(exported, local or (path, name))]."""
    text = read_text(path)
    where = rel(path)
    if re.search(r"\bimport\.meta\b|\bimport\s*\(", re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S)):
        raise BuildError(f"{where} uses import.meta or import(): the page has no module loader")
    imports, exports = [], []

    def on_import(m):
        what, spec = " ".join(m.group("what").split()), m.group("spec")
        target = _resolve(spec, path)
        if what.startswith("{") and what.endswith("}"):
            imports.append((target, _names(what[1:-1], where)))
        elif (ns := re.fullmatch(rf"\*\s+as\s+({IDENT})", what)):
            imports.append((target, ("*", ns.group(1))))
        else:
            raise BuildError(f"{where}: import {what} from {spec!r}: only named and namespace imports are read")
        return ""

    def on_export_from(m):
        target = _resolve(m.group("spec"), path)
        imports.append((target, []))
        for name, exported in _names(m.group("names"), where):
            exports.append((exported, (target, name)))
        return ""

    def on_export_list(m):
        for local, exported in _names(m.group("names"), where):
            exports.append((exported, local))
        return ""

    def on_export_decl(m):
        kind = " ".join(m.group("kind").split())
        if kind in ("let", "var"):
            raise BuildError(f"{where}: export {kind} {m.group('name')}: a page module's exports are read once "
                             "(export a const, or a function that reads it)")
        exports.append((m.group("name"), m.group("name")))
        return m.group(0)[len("export"):].lstrip()

    body = IMPORT_RE.sub(on_import, text)
    body = EXPORT_FROM_RE.sub(on_export_from, body)
    body = EXPORT_LIST_RE.sub(on_export_list, body)
    body = EXPORT_DECL_RE.sub(on_export_decl, body)
    left = [line for line in body.split("\n") if ANY_MODULE_LINE_RE.match(line)]
    if left:
        raise BuildError(f"{where}: can't read {left[0]!r} (import, export default and export * are not read)")
    return body, imports, exports


def module_order(entry):
    """Every module the entry imports, each after those it imports; a cycle is an error."""
    order, state, parsed = [], {}, {}

    def visit(path, chain):
        if state.get(path) == "done":
            return
        if state.get(path) == "open":
            raise BuildError("the page's modules import each other in a cycle: "
                             + " -> ".join(rel(p) for p in chain + [path]))
        state[path] = "open"
        parsed[path] = parse_module(path)
        for target, _ in parsed[path][1]:
            visit(target, chain + [path])
        state[path] = "done"
        order.append(path)

    visit(entry, [])
    return order, parsed


def build_script(entry=ENTRY):
    order, parsed = module_order(entry)
    var = {path: f"M${k}" for k, path in enumerate(order)}
    out = ['"use strict";\n',
           "/* The Lazaret dashboard's script, built by scripts/make_dashboard.py from js/dashboard/page.js and the\n"
           "   npm package's modules it imports (js/src/), one function each, run in the order they import each other.\n"
           "   Edit those and rebuild the page: an edit here is overwritten (and the CSP allows this text alone). */\n"]
    for path in order:
        body, imports, exports = parsed[path]
        lines = []
        for target, names in imports:
            if isinstance(names, tuple):
                lines.append(f"const {names[1]} = {var[target]};")
            elif names:
                lines.append("const { " + ", ".join(n if n == local else f"{n}: {local}" for n, local in names)
                             + f" }} = {var[target]};")
        ret = []
        for exported, local in exports:
            if isinstance(local, tuple):
                ret.append(f"{exported}: {var[local[0]]}.{local[1]}")
            else:
                ret.append(exported if exported == local else f"{exported}: {local}")
        out.append(f"\n/* ======== {rel(path)} ======== */\nconst {var[path]} = (() => {{\n")
        if lines:
            out.append("\n".join(lines) + "\n")
        out.append(body.rstrip("\n") + "\n")
        out.append(f"return {{ {', '.join(ret)} }};\n}})();\n" if ret else "})();\n")
    return "".join(out)


def script_hash(body):
    """The CSP source expression for an inline script: SHA-256 over its text between <script> and </script>."""
    return "'sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii") + "'"


# ---- the engine ------------------------------------------------------------------------------------------------
def _wasm_path_deps(manifest):
    """The path dependencies a WebAssembly build of a crate compiles: its [dependencies] and [build-dependencies],
    and those of a [target.'cfg(…)'] section that names wasm32 and is not a not(…) of it."""
    out, section = [], ""
    for line in manifest.split("\n"):
        head = re.match(r"\s*\[([^\]]+(?:\][^\]]*)?)\]\s*$", line)
        if head:
            section = head.group(1)
            continue
        plain = section in ("dependencies", "build-dependencies")
        wasm = (section.startswith("target.") and section.endswith(".dependencies") and "wasm32" in section
                and "not(" not in section)
        if plain or wasm:
            out += [p for p in re.findall(r'\bpath\s*=\s*"([^"]+)"', line)]
    return out


def _crate_dirs():
    """The crates the WebAssembly build compiles: lazaret-ffi and its path dependencies, as it builds them."""
    seen, todo = [], [os.path.join(RUST, "crates", WASM_CRATE)]
    while todo:
        crate = os.path.normpath(todo.pop())
        if crate in seen:
            continue
        seen.append(crate)
        todo += [os.path.join(crate, p) for p in _wasm_path_deps(read_text(os.path.join(crate, "Cargo.toml")))]
    return sorted(seen)


def _tracked(paths):
    """The files git tracks under `paths` (None outside a git checkout, or without git): a crate's untracked files
    (a fuzzer's corpus, an editor's backup) are not its sources."""
    try:
        out = subprocess.run(["git", "-C", REPO, "ls-files", "-z", "--"] + [rel(p) for p in paths],
                             capture_output=True, timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return [os.path.join(REPO, *name.split("/")) for name in out.decode("utf-8").split("\0") if name]


def source_files():
    """The engine's sources: the workspace's manifest and lock file, the build script, and the crates' files (those
    git tracks, in a checkout; else every file but those in a .git or target directory, which in a clean checkout
    are the same)."""
    files = [os.path.join(RUST, "Cargo.toml"), os.path.join(RUST, "Cargo.lock"),
             os.path.join(JS, "scripts", "build-wasm.js")]
    crates = _crate_dirs()
    tracked = _tracked(crates)
    if tracked:
        files += tracked
    else:
        for crate in crates:
            for dirpath, dirnames, filenames in os.walk(crate):
                dirnames[:] = sorted(d for d in dirnames if d not in ("target", ".git"))
                files += [os.path.join(dirpath, f) for f in filenames]
    return sorted(set(files), key=rel)


def sources_digest():
    """SHA-256 over the engine's sources: each file's path and bytes (CRLF read as LF, as a checkout may write
    them), in path order."""
    h = hashlib.sha256()
    for path in source_files():
        with open(path, "rb") as f:
            data = f.read().replace(b"\r\n", b"\n")
        name = rel(path).encode("utf-8")
        h.update(len(name).to_bytes(8, "little") + name + len(data).to_bytes(8, "little") + data)
    return h.hexdigest()


def engine_block(wasm, digest):
    """The data block's attributes and text for the WebAssembly `wasm`."""
    gz = gzip.compress(wasm, compresslevel=9, mtime=0)
    b64 = base64.b64encode(gz).decode("ascii")
    text = "\n".join(b64[k:k + BASE64_LINE] for k in range(0, len(b64), BASE64_LINE))
    attrs = f'data-sha256="{hashlib.sha256(wasm).hexdigest()}" data-bytes="{len(wasm)}" data-sources="{digest}"'
    return attrs, text


def read_engine_block(page):
    """(attrs text, {attr: value}, base64 text) of the page's engine, or None when it has none."""
    m = ENGINE_RE.search(page)
    if not m:
        return None
    return m.group(1).strip(), dict(ATTR_RE.findall(m.group(1))), m.group(2)


def check_engine_block(attrs, text):
    """The WebAssembly the block holds; BuildError when it is not what its attributes say."""
    try:
        wasm = gzip.decompress(base64.b64decode("".join(text.split()), validate=True))
    except (ValueError, OSError, EOFError) as e:
        raise BuildError(f"the page's engine can't be read ({e})") from None
    if hashlib.sha256(wasm).hexdigest() != attrs.get("data-sha256") or str(len(wasm)) != attrs.get("data-bytes"):
        raise BuildError("the page's engine is not the one its data-sha256 and data-bytes name")
    if wasm[:4] != b"\0asm":
        raise BuildError("the page's engine is not WebAssembly")
    return wasm


# ---- the page --------------------------------------------------------------------------------------------------
def notices_text():
    return "\n\n".join(read_text(p).rstrip("\n") for p in NOTICES)


def build_page(engine_attrs, engine_text):
    template = read_text(TEMPLATE)
    if template.startswith("<!--"):                      # the template's own note
        template = template[template.index("-->") + 3:].lstrip("\n")
    for marker in ("@CSP@", "@SCRIPT@", "@ENGINE_ATTRS@", "@ENGINE@", "@NOTICES@"):
        if template.count(marker) != 1:
            raise BuildError(f"{rel(TEMPLATE)} must hold {marker} once")
    head, tail = template.replace("@NOTICES@", html.escape(notices_text(), quote=False)).split("@SCRIPT@")
    if "@CSP@" not in head or not head.rstrip(" \n").endswith("<script>") or not tail.startswith("</script>"):
        raise BuildError(f"{rel(TEMPLATE)}: @CSP@ goes before the script, and @SCRIPT@ is the script's text")
    script = build_script()
    if "</script" in script.lower():
        raise BuildError("the script holds '</script', which would end it early in the page")
    # the script and the engine go in last: nothing in them is read as a marker
    head, tail = (part.replace("@ENGINE_ATTRS@", engine_attrs).replace("@ENGINE@", engine_text)
                  for part in (head, tail))
    body = head[head.rindex("<script>") + len("<script>"):] + script       # the text the browser hashes
    head = head.replace("@CSP@", CSP.format(hash=script_hash(body)))
    return head + script + tail


def _configure_stdio():
    """Same policy as lazaret.scanner.core.configure_stdio (STRUCTURE.md, "Cross-platform rules"): redirected output
    is UTF-8 on every platform unless PYTHONIOENCODING says otherwise; nothing ever raises on a character the stream
    can't encode."""
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


def main(argv=None):
    _configure_stdio()
    args = sys.argv[1:] if argv is None else list(argv)
    check = "--check" in args
    engine_path = None
    if "--engine" in args:
        k = args.index("--engine")
        engine_path = args[k + 1] if k + 1 < len(args) and not args[k + 1].startswith("--") else DEFAULT_ENGINE
    try:
        current = read_text(PAGE) if os.path.exists(PAGE) else ""
        digest = sources_digest()
        block = read_engine_block(current)
        if engine_path and not check:
            with open(engine_path, "rb") as f:
                wasm = f.read()
            if wasm[:4] != b"\0asm":
                raise BuildError(f"{engine_path} is not WebAssembly")
            attrs, text = engine_block(wasm, digest)
        else:
            if block is None:
                raise BuildError(f"{rel(PAGE)} carries no engine: build one (cd js && npm run build) and run "
                                 "python3 scripts/make_dashboard.py --engine")
            attrs, values, text = block
            check_engine_block(values, text)
            if values.get("data-sources") != digest:
                raise BuildError(f"the engine {rel(PAGE)} carries was built from other sources than the engine's "
                                 "now: build it (cd js && npm run build) and run "
                                 "python3 scripts/make_dashboard.py --engine")
        page = build_page(attrs, text)
    except BuildError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if page == current:
        print(f"{rel(PAGE)} is up to date")
        return 0
    if check:
        print(f"{rel(PAGE)} is not what its sources make: run python3 scripts/make_dashboard.py", file=sys.stderr)
        return 1
    with open(PAGE, "w", encoding="utf-8", newline="") as f:
        f.write(page)
    print(f"wrote {rel(PAGE)} ({len(page.encode('utf-8')):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
