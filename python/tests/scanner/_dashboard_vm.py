"""Drive the dashboard from Python tests (not a test module).

Runs python/src/lazaret/web/lazaret.html in node:vm with a minimal DOM stub (_dashboard_vm.js): its script, on the
engine it carries, through its controls. Tests that use it skip when node isn't installed."""

import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from lazaret.scanner import core
from tests import _support

NODE = shutil.which("node")
HTML = os.path.join(_support.PKG, "web", "lazaret.html")
HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_dashboard_vm.js")
#: what the page's result has that a CLI result has not, and the reverse
PAGE_ONLY = ("generatedBy", "files", "scannedAt")
CLI_ONLY = ("project", "scannedAt", "warnings")

requires_node = unittest.skipUnless(NODE, "node not installed")


def run(requests, html=HTML, timeout=40):
    """Answer each request (see _dashboard_vm.js) in one page instance."""
    p = subprocess.run([NODE, HARNESS, html], input=json.dumps(requests), capture_output=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    if p.returncode != 0:
        raise AssertionError(f"dashboard harness failed:\n{p.stderr[-3000:]}")
    return json.loads(p.stdout)


def upload(rel, data, size=None):
    """An upload request's file: `rel` with the bytes `data` (or text, as UTF-8)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    f = {"name": rel, "b64": base64.b64encode(data).decode("ascii")}
    if size is not None:
        f["size"] = size
    return f


def scan_request(files=(), paste=None, lang=None):
    """A "scan" request: `files` [(rel, bytes or text)] picked in the upload control (or [(rel, bytes, size)]: a
    file of `size` bytes only `bytes` of can be read), `paste` pasted."""
    req = {"op": "scan", "files": [upload(*f) for f in files]}
    if paste is not None:
        req["paste"] = {"text": paste, "lang": lang or "auto"}
    return req


def folder_request(files, name="project", unreadable=()):
    """A "scan" request of a folder upload: `files` [(rel, bytes or text)] in the folder `name` picked in the folder
    control; the files in `unreadable` (rels) can't be read."""
    folder = []
    for rel, data in files:
        f = upload(f"{name}/{rel}", data)
        f["path"] = f.pop("name")
        if rel in unreadable:
            f["unreadable"] = True
        folder.append(f)
    return {"op": "scan", "folder": folder}


def tree_files(root):
    """[(rel, bytes)] of the regular files under `root` (no link followed), as a browser uploads the folder."""
    out = []
    for top, dirs, names in os.walk(root):
        dirs.sort()
        for name in sorted(names):
            full = os.path.join(top, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            with open(full, "rb") as f:
                out.append((os.path.relpath(full, root).replace(os.sep, "/"), f.read()))
    return out


def scan(files=(), paste=None, lang=None, html=HTML):
    """The page's result for `files` and `paste` (see scan_request)."""
    return run([scan_request(files, paste, lang)], html=html)[0]


def cli_result(files):
    """lazaret.scanner.core's project scan of a directory holding `files` [(rel, bytes or text)]."""
    with tempfile.TemporaryDirectory() as root:
        for rel, data in files:
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data.encode("utf-8") if isinstance(data, str) else data)
        return core.scan_project(root)


def comparable(result, drop):
    return {k: v for k, v in result.items() if k not in drop}
