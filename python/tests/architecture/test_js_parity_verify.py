"""`--verify-secrets` in both packages (V-1 stage 2, step 4): the Python CLI and the npm CLI scan the same project and ask the
same stub provider over TLS on 127.0.0.1 (each through the stub's CONNECT proxy, from HTTPS_PROXY, trusting the stub's root:
SSL_CERT_FILE for the Python package's transports, NODE_EXTRA_CA_CERTS for node), and must report the same: each finding's
rule, place, severity, type, message and `verified`, the `verification` block, the counts, the ratings, the gate and the exit
code; and both must have asked each provider the same. No real service is called. Skipped without node and the npm engine's
WebAssembly build, the native library, or `openssl`."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from lazaret.scanner import _native
from tests import _support
from tests.architecture.test_js_parity import JS_BIN, NPM_READY, NPM_SKIP
from tests.scanner import _verify_stub as vs
from tests.scanner.test_verifyscan import APP, ENV, SCRIPT, VALUES

PYTHON_SRC = os.path.join(_support.REPO_ROOT, "python", "src")


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
@unittest.skipUnless(vs.have_openssl(), "the stub provider needs the openssl command")
class VerifyParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.stub = vs.ProviderStub()
        cls.addClassCleanup(cls.stub.close)
        cls.proxy = cls.stub.proxy()

    def setUp(self):
        self.stub.reset()
        for host, (status, body) in SCRIPT.items():
            self.stub.script[host] = vs.Answer(status, body)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, "proj")
        os.mkdir(self.root)
        with open(os.path.join(self.root, "app.py"), "w", encoding="utf-8") as f:
            f.write(APP)
        with open(os.path.join(self.root, ".env"), "w", encoding="utf-8") as f:
            f.write(ENV)

    def env(self):
        env = {k: v for k, v in os.environ.items() if k.lower() not in ("https_proxy", "http_proxy", "all_proxy", "no_proxy",
                                                                        "lazaret_network", "ssl_cert_file", "node_extra_ca_certs")}
        env.update(HTTPS_PROXY=f"http://127.0.0.1:{self.proxy.address[1]}", SSL_CERT_FILE=self.stub.cafile,
                   NODE_EXTRA_CA_CERTS=self.stub.cafile, PYTHONPATH=PYTHON_SRC, PYTHONDONTWRITEBYTECODE="1")
        if os.environ.get("LAZARET_NATIVE_LIB"):
            env["LAZARET_NATIVE_LIB"] = os.environ["LAZARET_NATIVE_LIB"]
        return env

    def scan(self, argv, name):
        report = os.path.join(self.tmp.name, f"{name}.json")
        p = subprocess.run([*argv, self.root, "--verify-secrets", "--no-html", "--json", report, "-q"], env=self.env(),
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        with open(report, encoding="utf-8") as f:
            text = f.read()
        return p.returncode, json.loads(text), p.stdout + p.stderr + text

    @staticmethod
    def comparable(report):
        issues = sorted((i["rule"], i["file"], i["line"], i["sev"], i["type"], i["msg"], json.dumps(i.get("verified"), sort_keys=True))
                        for i in report["issues"])
        return {"issues": issues, "verification": report["verification"], "counts": report["counts"],
                "ratings": report["ratings"], "pass": report["pass"], "conditions": report["conditions"]}

    def test_both_packages_verify_alike(self):
        py_code, py, py_text = self.scan([sys.executable, "-m", "lazaret"], "py")
        with self.stub.lock:
            py_asked = sorted((s.host, s.path) for s in self.stub.requests)
        self.stub.reset()
        for host, (status, body) in SCRIPT.items():
            self.stub.script[host] = vs.Answer(status, body)
        js_code, js, js_text = self.scan([NPM_READY, JS_BIN], "js")
        with self.stub.lock:
            js_asked = sorted((s.host, s.path) for s in self.stub.requests)
        self.assertEqual(len(py_asked), 5)
        self.assertEqual(py_asked, js_asked)
        self.assertEqual(self.comparable(js), self.comparable(py))
        self.assertEqual(js_code, py_code)
        self.assertEqual(py["verification"]["credentials"], {"live": 2, "rejected": 2, "unknown": 1})
        for text in (py_text, js_text):
            for value in VALUES:
                self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
