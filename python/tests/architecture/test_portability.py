"""Cross-platform rules, enforced (STRUCTURE.md, "Cross-platform rules").

Code and tests must behave the same on Linux, macOS and Windows on every
supported Python, so nothing may rely on a host default for correctness. The
rules a machine can check are checked here, over the package, the build
backend, the scripts and the tests (scan fixtures excluded: they are inputs,
not code we run):

1. Text I/O names its encoding. open()/io.open() in text mode,
   Path.read_text()/write_text(), and subprocess calls with text= or
   universal_newlines= all pass encoding=. Without it Python uses the host's
   default: the ANSI code page on Windows (cp1252), ASCII under a bare C
   locale.
2. Nothing asks the host what its encoding is (locale.getpreferredencoding /
   locale.getencoding): that is the default rule 1 forbids depending on.
3. Every CLI entry point calls configure_stdio(), which makes redirected
   output UTF-8 everywhere; the MCP server also sets UTF-8 on stdin/stdout.
4. No hard-coded /tmp or /var/... directory is used as a filesystem path
   (they don't exist on Windows, and /var is a symlink on macOS); use
   tempfile.
"""

import ast
import os
import unittest

from tests import _support

PY_ROOT = os.path.dirname(_support.SRC)             # python/
REPO = os.path.dirname(PY_ROOT)
TREES = [
    _support.SRC,                                   # python/src
    os.path.join(PY_ROOT, "_build"),
    os.path.join(REPO, "scripts"),
    os.path.join(PY_ROOT, "tests"),
]
FIXTURES = os.path.join(PY_ROOT, "tests", "fixtures")
SUBPROCESS_CALLS = {"run", "Popen", "check_output", "call", "check_call"}
PATH_CALLS = {"open", "makedirs", "mkdir", "listdir", "scandir", "chdir", "rmtree",
              "TemporaryDirectory", "mkdtemp", "mkstemp", "NamedTemporaryFile", "Path"}


def python_files():
    for tree in TREES:
        for dirpath, dirnames, filenames in os.walk(tree):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"
                           and os.path.join(dirpath, d) != FIXTURES]
            for name in filenames:
                if name.endswith(".py"):
                    yield os.path.join(dirpath, name)


def call_name(node):
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr, f.value
    if isinstance(f, ast.Name):
        return f.id, None
    return "", None


def text_mode(node):
    """The mode of an open() call: its string, 'r' when omitted, None when
    it isn't a literal (checked by hand; the lint only accepts literals)."""
    mode = node.args[1] if len(node.args) >= 2 else next(
        (k.value for k in node.keywords if k.arg == "mode"), ast.Constant("r"))
    return mode.value if isinstance(mode, ast.Constant) else None


def violations():
    found = []
    for path in python_files():
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        try:
            rel = os.path.relpath(path, REPO).replace(os.sep, "/")
        except ValueError:          # another drive on Windows (the self-test's temp dir)
            rel = path
        for node in ast.walk(ast.parse(source, filename=path)):
            if not isinstance(node, ast.Call):
                continue
            name, owner = call_name(node)
            kw = {k.arg for k in node.keywords}
            where = f"{rel}:{node.lineno}"
            is_builtin_open = name == "open" and (
                owner is None or (isinstance(owner, ast.Name) and owner.id in ("io", "builtins")))
            if is_builtin_open and "encoding" not in kw and len(node.args) < 4:
                mode = text_mode(node)
                if mode is None:
                    found.append(f"{where}: open() with a non-literal mode (make it a literal "
                                 "so this check can see whether it is text)")
                elif "b" not in mode:
                    found.append(f"{where}: text-mode open() without encoding=")
            elif name in SUBPROCESS_CALLS and ({"text", "universal_newlines"} & kw) \
                    and "encoding" not in kw:
                found.append(f"{where}: subprocess {name}() decodes with the host default; "
                             "pass encoding=\"utf-8\", errors=\"replace\"")
            elif name in ("read_text", "write_text") and owner is not None \
                    and "encoding" not in kw \
                    and not (name == "read_text" and node.args) \
                    and not (name == "write_text" and len(node.args) > 1):
                found.append(f"{where}: {name}() without encoding=")
            elif name in ("getpreferredencoding", "getencoding"):
                found.append(f"{where}: locale.{name}() (depends on the host)")
            if name in PATH_CALLS and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str) \
                        and first.value.startswith(("/tmp", "/var/", "/private/")):
                    found.append(f"{where}: hard-coded {first.value!r} used as a path; use tempfile")
    return found


class CrossPlatformRulesTests(unittest.TestCase):
    def test_no_host_default_encodings_or_paths(self):
        self.assertEqual(violations(), [])

    def test_every_cli_entry_point_configures_stdio(self):
        entry_points = {
            "lazaret/scanner/core.py": "main",
            "lazaret/scanner/sca.py": "main",
            "lazaret/registry/repo.py": "main",
            "lazaret/mcp/server.py": "main",
        }
        for rel, func in entry_points.items():
            with self.subTest(module=rel):
                with open(os.path.join(_support.SRC, *rel.split("/")), encoding="utf-8") as fh:
                    tree = ast.parse(fh.read())
                funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
                self.assertIn(func, funcs, f"{rel}: no top-level {func}()")
                # main() itself, or a module function it calls (sca: main -> _main)
                called, frontier = set(), [func]
                for _ in range(3):
                    nxt = []
                    for name in frontier:
                        for node in ast.walk(funcs[name]):
                            if isinstance(node, ast.Call):
                                callee = call_name(node)[0]
                                if callee not in called:
                                    called.add(callee)
                                    if callee in funcs:
                                        nxt.append(callee)
                    frontier = nxt
                self.assertIn("configure_stdio", called, f"{rel}:{func}() never calls configure_stdio()")

    def test_every_script_entry_point_configures_stdio(self):
        scripts = os.path.join(REPO, "scripts")
        for name in sorted(os.listdir(scripts)):
            if not name.endswith(".py"):
                continue
            with self.subTest(script=name):
                with open(os.path.join(scripts, name), encoding="utf-8") as fh:
                    tree = ast.parse(fh.read())
                main = next((n for n in tree.body if isinstance(n, ast.FunctionDef)
                             and n.name == "main"), None)
                if main is None:
                    continue
                called = {call_name(n)[0] for n in ast.walk(main) if isinstance(n, ast.Call)}
                self.assertTrue({"configure_stdio", "_configure_stdio"} & called,
                                f"scripts/{name}: main() never configures stdio")

    def test_the_mcp_server_sets_utf8_on_its_protocol_streams(self):
        with open(os.path.join(_support.SRC, "lazaret", "mcp", "server.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        utf8 = [n for n in ast.walk(main) if isinstance(n, ast.Call) and call_name(n)[0] == "reconfigure"
                and any(k.arg == "encoding" and isinstance(k.value, ast.Constant)
                        and k.value.value.lower().replace("-", "") == "utf8" for k in n.keywords)]
        self.assertTrue(utf8, "mcp main() must reconfigure stdin/stdout to UTF-8 (MCP is UTF-8)")

    def test_the_lint_catches_what_it_should(self):
        # guard against a lint that silently checks nothing
        bad = ('import subprocess, io, locale\n'
               'open("x")\nopen("x", "w")\nio.open("x", "r")\n'
               'subprocess.run(["x"], text=True)\n'
               'p.read_text()\nlocale.getpreferredencoding()\nopen("/tmp/x", "wb")\n')
        ok = ('import subprocess\nopen("x", "rb")\nopen("x", encoding="utf-8")\n'
              'subprocess.run(["x"], text=True, encoding="utf-8")\np.read_text(encoding="utf-8")\n')
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            global TREES
            saved = TREES
            try:
                TREES = [d]
                with open(os.path.join(d, "bad.py"), "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(bad)
                with open(os.path.join(d, "ok.py"), "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(ok)
                got = violations()
            finally:
                TREES = saved
        self.assertEqual(len(got), 7, "\n".join(got))
        self.assertTrue(all("bad.py" in g for g in got), got)


if __name__ == "__main__":
    unittest.main()
