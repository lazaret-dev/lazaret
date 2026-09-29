"""The `lazaret` command: `lazaret guard <npm|pnpm|pip|uv> …` checks what a
package manager is about to install (lazaret.registry.guard); anything else
scans a project (lazaret.scanner.core). This module sits above the layers: it
imports only the one it hands the command line to."""
import os
import sys

GUARD_TOOLS = ("npm", "pnpm", "pip", "pip3", "uv")


def is_guard(argv):
    """Is this command line `lazaret guard …`? `guard` followed by a package
    manager (after any options), or by options only or nothing at all when
    there is no file or folder named guard here to scan."""
    if not argv or argv[0] != "guard":
        return False
    rest = argv[1:]
    if any(a in GUARD_TOOLS for a in rest):
        return True
    return all(a.startswith("-") for a in rest) and not os.path.exists("guard")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if is_guard(argv):
        from lazaret.registry import guard
        return guard.main(argv[1:])
    from lazaret.scanner import core
    return core.main(argv)
