#!/usr/bin/env python3
"""Sync the received-code shared spec into the npm package.

The Python core and the npm engine both load the same data (name sets,
character sets, limits) for the received-code detector, but the two packages
ship separately, so each needs its own copy of the file. The Python copy is
the source of truth:

    python/src/lazaret/scanner/received_spec.json   (source, edited by hand)
    js/src/lib/received-spec.json                    (copy, written by this script)

Run with no arguments to update the npm copy after editing the source. Run
with --check to verify the copy is current (exit 1 if it drifted); CI and
tests/architecture/test_received_spec.py use that. Standard library only.
"""
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "python" / "src" / "lazaret" / "scanner" / "received_spec.json"
COPY = ROOT / "js" / "src" / "lib" / "received-spec.json"


def _configure_stdio():
    """Same policy as lazaret.scanner.core.configure_stdio (STRUCTURE.md,
    "Cross-platform rules"): redirected output is UTF-8 on every platform
    unless PYTHONIOENCODING says otherwise; nothing ever raises on a
    character the stream can't encode."""
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


def main(argv):
    _configure_stdio()
    check = "--check" in argv[1:]
    source = SOURCE.read_bytes()
    current = COPY.read_bytes() if COPY.exists() else None
    if check:
        if current == source:
            return 0
        print(f"received-spec.json is out of date: {COPY} differs from {SOURCE}.\n"
              f"Run: python3 scripts/sync-received-spec.py", file=sys.stderr)
        return 1
    if current == source:
        print("received-spec.json already up to date.")
        return 0
    COPY.write_bytes(source)
    print(f"Updated {COPY} from {SOURCE}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
