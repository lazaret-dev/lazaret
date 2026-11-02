"""The private macOS pool is selected only for trusted, native ARM64 work."""

import os
import re
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def workflow(name):
    with open(os.path.join(ROOT, ".github", "workflows", name), encoding="utf-8") as f:
        return f.read()


def job(text, name):
    start = text.index(f"  {name}:\n")
    match = re.search(r"(?m)^  [a-zA-Z0-9_-]+:\n", text[start + len(name) + 4:])
    return text[start:] if match is None else text[start:start + len(name) + 4 + match.start()]


class SelfHostedRoutingTests(unittest.TestCase):
    TRUST = (
        "github.event.pull_request.head.repo.full_name == github.repository",
        "github.actor == 'johnabooth-afk'",
    )
    LABELS = "fromJSON('[\"self-hosted\",\"macOS\",\"ARM64\"]')"

    def assert_trusted_arm_pool(self, text, fallback):
        self.assertIn(self.LABELS, text)
        self.assertIn("github.event_name == 'push'", text)
        for guard in self.TRUST:
            self.assertIn(guard, text)
        self.assertNotIn("github.event_name == 'workflow_call'", text)
        self.assertIn(fallback, text)

    def test_native_ci_lanes_use_the_pool(self):
        text = workflow("ci.yml")
        for name in ("python-unit", "js", "rust"):
            section = job(text, name)
            self.assertIn("matrix.os == 'macos-latest'", section)
            self.assert_trusted_arm_pool(section, "matrix.os")
            self.assertIn("dtolnay/rust-toolchain@", section)

    def test_the_arm_wheel_build_and_install_use_the_pool(self):
        text = workflow("wheels.yml")
        for name in ("macos-windows", "install"):
            section = job(text, name)
            self.assertIn("matrix.tag == 'macosx_11_0_arm64'", section)
            self.assertNotIn("matrix.tag == 'macosx_10_12_x86_64'", section)
            self.assert_trusted_arm_pool(section, "matrix.runner")

    def test_the_intel_wheel_stays_on_an_intel_runner(self):
        text = workflow("wheels.yml")
        self.assertIn("tag: macosx_10_12_x86_64", text)
        self.assertIn("runner: macos-15-intel", text)


if __name__ == "__main__":
    unittest.main()
