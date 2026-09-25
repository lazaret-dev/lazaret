"""Lazaret's test suite. Runs on a stock interpreter with no installs:

    cd python && python -m unittest discover -s tests -t .

Importing this package puts src/ on sys.path and PYTHONPATH, so tests and
every subprocess they start run against this source tree.
"""
import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
_existing = os.environ.get("PYTHONPATH", "")
if _SRC not in _existing.split(os.pathsep):
    os.environ["PYTHONPATH"] = os.pathsep.join(p for p in (_SRC, _existing) if p)
