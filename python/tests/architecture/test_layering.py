"""Dependencies inside Lazaret only point inward.

    mcp  ->  registry  ->  scanner  ->  pg, safexml

pg and safexml are leaf libraries: they import nothing else from Lazaret, so
either can later be split into its own distribution with a copy and a rename.
Nothing imports upward (the scanner never imports the registry or the MCP
server)."""

import ast
import pathlib
import unittest

from tests import _support

PKG = pathlib.Path(_support.PKG)

# component -> the Lazaret components it may import (itself always allowed)
ALLOWED = {
    "pg": set(),
    "safexml": set(),
    "scanner": {"pg", "safexml"},
    "registry": {"scanner", "pg", "safexml"},
    "mcp": {"registry", "scanner", "pg", "safexml"},
}


def lazaret_imports(path):
    """Absolute imports of lazaret.<component>, with line numbers."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module] if node.module != "lazaret" else [f"lazaret.{a.name}" for a in node.names]
        for name in names:
            parts = name.split(".")
            if parts[0] == "lazaret" and len(parts) > 1:
                yield parts[1], node.lineno


class LayeringTests(unittest.TestCase):
    def test_every_component_is_classified(self):
        """A new subpackage must be given a place in ALLOWED. (web/ holds the
        dashboard HTML; it has no Python and no __init__.py.)"""
        components = {p.name for p in PKG.iterdir() if (p / "__init__.py").exists()}
        self.assertEqual(components, set(ALLOWED))

    def test_dependencies_point_inward(self):
        violations = []
        for component, allowed in ALLOWED.items():
            for path in sorted((PKG / component).rglob("*.py")):
                for target, line in lazaret_imports(path):
                    if target != component and target not in allowed:
                        violations.append(f"{path.relative_to(PKG)}:{line} ({component}) imports lazaret.{target}")
        self.assertEqual(violations, [])

    def test_leaf_libraries_use_relative_imports_only(self):
        """pg and safexml refer to themselves relatively, so a future split
        into lazaret_pg / lazaret_safexml is a rename, not a rewrite."""
        for component in ("pg", "safexml"):
            for path in sorted((PKG / component).rglob("*.py")):
                with self.subTest(file=str(path.relative_to(PKG))):
                    self.assertEqual(list(lazaret_imports(path)), [])


if __name__ == "__main__":
    unittest.main()
