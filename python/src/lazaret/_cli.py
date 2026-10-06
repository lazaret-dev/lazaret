"""The `lazaret` command: `lazaret guard <npm|pnpm|yarn|bun|pip|uv|uvx|go|cargo> …` checks what a
package manager is about to install (lazaret.registry.guard); `lazaret hook [FILE …]` checks what a
commit holds (lazaret.scanner.hook); `lazaret [scan] FILE.vsix …` and `lazaret [scan] --extensions
[PATH …]` scan VS Code extensions (lazaret.registry.extensions); `lazaret [scan] github:owner/repo[@ref]`
(or `gitlab:`) scans a repository at a commit (lazaret.registry.sourcescan); anything else scans a
project (lazaret.scanner.core). This module sits above the layers: it imports only the
one it hands the command line to."""
import os
import sys

GUARD_TOOLS = ("npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "uvx", "go", "cargo")
SOURCE_PREFIXES = ("github:", "gitlab:")


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


def is_hook(argv):
    """Is this command line `lazaret hook …`? `hook` first, when there is no
    file or folder named hook here to scan, or when what follows is files
    (pre-commit's call) or --staged."""
    if not argv or argv[0] != "hook":
        return False
    return not os.path.exists("hook") or any(
        a == "--staged" or (not a.startswith("-") and os.path.isfile(a)) for a in argv[1:])


def is_extensions(argv):
    """Is this command line a scan of VS Code extensions? `--extensions`
    among its words, or a word that names a `.vsix` file."""
    return "--extensions" in argv or any(
        a.lower().endswith(".vsix") and not a.startswith("-") and os.path.isfile(a) for a in argv)


def is_source(argv):
    """Does any argument name a GitHub or GitLab source (and no file or folder
    of that name)? Only a first look, with nothing imported: whether it is the
    thing to scan or the value of an option is for `sourcescan` to say."""
    return any(a[:7].lower() in SOURCE_PREFIXES and not os.path.exists(a) for a in argv)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if is_guard(argv):
        from lazaret.registry import guard
        return guard.main(argv[1:])
    if is_hook(argv):
        from lazaret.scanner import hook
        return hook.main(argv[1:])
    if is_extensions(argv):
        from lazaret.registry import extensions
        return extensions.main(argv)
    if is_source(argv):
        from lazaret.registry import sourcescan
        return sourcescan.main(argv)
    from lazaret.scanner import core
    return core.main(argv)
