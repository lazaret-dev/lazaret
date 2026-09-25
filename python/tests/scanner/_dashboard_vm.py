"""Drive the dashboard's page script from Python tests (not a test module).

Runs python/src/lazaret/web/lazaret.html's inline <script> in node:vm with a
minimal DOM stub (_dashboard_vm.js) and returns its answers. Tests that use
it skip when node isn't installed."""

import json
import os
import shutil
import subprocess
import unittest

from tests import _support

NODE = shutil.which("node")
HTML = os.path.join(_support.PKG, "web", "lazaret.html")
HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_dashboard_vm.js")

requires_node = unittest.skipUnless(NODE, "node not installed")


def run(requests, html=HTML, timeout=40):
    """Answer each request (see _dashboard_vm.js) in one page instance."""
    p = subprocess.run([NODE, HARNESS, html], input=json.dumps(requests), capture_output=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    if p.returncode != 0:
        raise AssertionError(f"dashboard harness failed:\n{p.stderr[-3000:]}")
    return json.loads(p.stdout)


def scan(name, content, lang=None, size=None, html=HTML):
    """The dashboard's issues for one file."""
    f = {"name": name, "content": content}
    if lang:
        f["lang"] = lang
    if size is not None:
        f["size"] = size
    return run([{"op": "scanFile", "file": f}], html=html)[0]
