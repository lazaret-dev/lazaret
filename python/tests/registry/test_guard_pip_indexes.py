"""lazaret guard with the real pip, against a fake PyPI on 127.0.0.1 (tests/registry/_guard_support.py) (0.1.8): the
indexes of the command line and of pip's settings relayed with their credentials, and a PEP 503 (HTML) index.
(Split from test_guard_python.py; MAC-TESTS.)

A blocked package is never handed to the tool, so its code never runs."""

import base64
import unittest

from tests.registry import _guard_support as gs


class PipIndexGuardTests(gs.PipCase):
    def test_an_index_of_the_command_line_is_relayed(self):
        """(0.1.7 refused it.) pip is still pointed at the guard alone; the
        guard fetches from the index named, and scans what it serves."""
        side = gs.PypiIndex({"side-only": gs.default_pypi_files()["good-py"],
                             "evil-py": gs.default_pypi_files()["evil-py"]})
        self.addCleanup(side.close)
        code, out = self.guard(self.tmp, self.pip_env, "pip", "install", "--extra-index-url", side.url, "evil-py")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-py@1.0", out)
        self.assertIn(f"relaying {self.index.url}, {side.url}", out)
        self.assertTrue(side.requests)
        self.assertEqual({ua.split("/")[0] for ua, _p, _a in side.requests}, {"lazaret-guard"})

    def test_a_pep_503_index(self):
        """An index that serves HTML pages (no upload times: --min-age can't
        hold its new releases back, and the report says so)."""
        html_index = gs.PypiIndex(html=True)
        self.addCleanup(html_index.close)
        env = dict(self.pip_env, LAZARET_GUARD_PYPI_URL=html_index.url)
        code, out = self.guard(self.tmp, env, "pip", "install", "--force-reinstall", "good-py")
        self.assertEqual(code, 0, out)
        self.assertIn("good-py: the index gives no upload times", out)

    def test_a_private_index_with_credentials_in_pips_settings(self):
        auth = "Basic " + base64.b64encode(b"reader:" + b"s3cr" + b"et-pw").decode()
        private = gs.PypiIndex(auth=auth)
        self.addCleanup(private.close)
        env = dict(self.pip_env)
        del env["LAZARET_GUARD_PYPI_URL"]
        env["PIP_INDEX_URL"] = private.url.replace("http://", "http://reader:" + "s3cr" + "et-pw@")
        code, out = self.guard(self.tmp, env, "pip", "install", "--force-reinstall", "good-py")
        self.assertEqual(code, 0, out)
        self.assertNotIn("et-pw", out)
        self.assertIn(f"relaying {private.url}", out)
        self.assertEqual({(ua.split("/")[0], a) for ua, _p, a in private.requests}, {("lazaret-guard", auth)})


if __name__ == "__main__":
    unittest.main()
