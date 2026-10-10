"""What the fuzzers share (0.1.9, X-1): where the checkout is, and output that survives a redirect.

The scripts import `lazaret` from this checkout, not from an installed copy, so a fuzz run is of the code
in the tree. Standard library only."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "python", "src")


def configure_stdio():
    """Redirected output is UTF-8, and never raises on a character the stream cannot encode
    (STRUCTURE.md, "Cross-platform rules")."""
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


def use_source_tree():
    """Make `import lazaret` this checkout's."""
    if SRC not in sys.path:
        sys.path.insert(0, SRC)
