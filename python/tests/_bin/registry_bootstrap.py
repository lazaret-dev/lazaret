#!/usr/bin/env python3
"""Child-process bootstrap for test_crash_guards_registry.py.

Spawned as:  python3 registry_bootstrap.py lazaret_repo.py <args...>

Reads CG_FAKE_REGISTRY (JSON: {"tarballs": {"name@version": <hex>}}),
monkeypatches lazaret_repo's network seam (resolve_npm / resolve_pypi /
http_bytes / verify_digest) to serve the local tarballs, then runs the REAL
lazaret_repo.py main() with the given argv — argparse, Store, DB writes,
print_scan, exit codes all real. Only the network is faked.

This is test scaffolding; lazaret.registry.repo itself is not modified.
"""
import io
import json
import os
import sys
import tarfile


def _sha256_hex(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def main():
    target, argv = sys.argv[1], sys.argv[2:]
    here = os.path.dirname(os.path.abspath(__file__))
    from lazaret.registry import repo as lazaret_repo

    cfg = json.loads(os.environ["CG_FAKE_REGISTRY"])
    # {(name, version): tgz bytes}
    tarballs = {}
    for key, hexdata in cfg["tarballs"].items():
        name, _, ver = key.partition("@")
        tarballs[(name, ver)] = bytes.fromhex(hexdata)

    def fake_resolve(name, version=None):
        for (n, v), _data in tarballs.items():
            if n == name and (version is None or v == version):
                return (v, f"file://fake/{n}", "tgz", "fake-artifact", (n, v))
        raise LookupError(f"fake registry: no entry for {name}@{version}")

    def fake_http_bytes(url):
        name = url.rsplit("/", 1)[-1]
        for (n, _v), data in tarballs.items():
            if n == name:
                return data
        raise LookupError(f"fake registry: no artifact for {url}")

    def fake_verify_digest(data, meta_entry, eco, name, version):
        return ("sha256", _sha256_hex(data))

    lazaret_repo.resolve_npm = fake_resolve
    lazaret_repo.resolve_pypi = fake_resolve
    lazaret_repo.http_bytes = fake_http_bytes
    lazaret_repo.verify_digest = fake_verify_digest

    # Run the REAL main() of the module we just patched (NOT runpy, which
    # would re-execute the file in a fresh namespace and lose the patches).
    sys.argv = [os.path.join(here, target)] + argv
    code = 0
    try:
        code = lazaret_repo.main()
    except SystemExit as e:
        code = e.code
        if code is None:
            code = 0
    sys.exit(code)


if __name__ == "__main__":
    main()
