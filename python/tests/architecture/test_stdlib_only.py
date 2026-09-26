"""Lazaret must never import anything outside the Python standard library:
a supply-chain tool with dependencies is itself a supply-chain risk. This
covers the product (src/lazaret) and the build backend (_build), so neither
running nor building Lazaret downloads anything."""

import ast
import pathlib
import sys
import unittest

from tests import _support

ROOTS = [pathlib.Path(_support.PKG), pathlib.Path(_support.PY_ROOT) / "_build"]
FIRST_PARTY = {"lazaret", "lazaret_build", "__future__"}


def imported_modules(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0], node.lineno
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split(".")[0], node.lineno


class StdlibOnlyTests(unittest.TestCase):
    def test_only_stdlib_imports(self):
        offenders = [
            f"{path}:{line} imports {name}"
            for root in ROOTS
            for path in sorted(root.rglob("*.py"))
            for name, line in imported_modules(path)
            if name not in sys.stdlib_module_names and name not in FIRST_PARTY
        ]
        self.assertEqual(offenders, [], "non-stdlib imports found")

    def test_guard_catches_a_violation(self):
        """Control: the check really fires on a third-party import."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            bad = pathlib.Path(d) / "bad.py"
            bad.write_text("import requests\nfrom yaml import safe_load\n", encoding="utf-8", newline="\n")
            names = {name for name, _ in imported_modules(bad)}
        self.assertEqual({n for n in names if n not in sys.stdlib_module_names}, {"requests", "yaml"})


if __name__ == "__main__":
    unittest.main()
