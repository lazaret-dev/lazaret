"""The private macOS pool is selected only for trusted, non-release work.

The assertions exercise the actual ``runs-on`` expressions as a truth table.
Looking only for guard-shaped text missed that a reusable release workflow
inherits its caller's tag-push context and therefore satisfied the old push
guard.
"""

import json
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


def runner_expression(section):
    match = re.search(r"(?ms)^    runs-on: >-\n      \$\{\{(.*?)^      \}\}", section)
    if match is None:
        raise AssertionError("job has no multiline runs-on expression")
    return " ".join(match.group(1).split())


def route(expression, *, event, ref, actor="johnabooth-afk", head="lazaret-dev/lazaret",
          os_name="macos-latest", tag="macosx_11_0_arm64", fallback="macos-15"):
    """Evaluate the small GitHub-expression subset the routing policy uses."""
    values = {
        "github.event.pull_request.head.repo.full_name": head,
        "github.event_name": event,
        "github.repository": "lazaret-dev/lazaret",
        "github.actor": actor,
        "github.ref": ref,
        "matrix.runner": fallback,
        "matrix.os": os_name,
        "matrix.tag": tag,
    }
    translated = expression
    for name in sorted(values, key=len, reverse=True):
        translated = translated.replace(name, repr(values[name]))
    translated = translated.replace("&&", " and ").replace("||", " or ")
    translated = re.sub(r"!(?!=)", " not ", translated)
    return eval(translated, {"__builtins__": {}, "fromJSON": json.loads,
                             "startsWith": lambda value, prefix: value.startswith(prefix)}, {})


class SelfHostedRoutingTests(unittest.TestCase):
    LABELS = ["self-hosted", "macOS", "ARM64", "lazaret-tart"]

    def assert_ci_policy(self, expression):
        self.assertEqual(route(expression, event="push", ref="refs/heads/integration"), self.LABELS)
        self.assertEqual(route(expression, event="push", ref="refs/tags/v0.1.9"), "macos-latest")
        self.assertEqual(route(expression, event="pull_request", ref="refs/pull/44/merge"), self.LABELS)
        self.assertEqual(route(expression, event="pull_request", ref="refs/pull/44/merge",
                               head="outsider/lazaret"), "macos-latest")
        self.assertEqual(route(expression, event="pull_request", ref="refs/pull/44/merge",
                               actor="someone-else"), "macos-latest")
        self.assertEqual(route(expression, event="workflow_dispatch", ref="refs/heads/integration"),
                         "macos-latest")
        self.assertEqual(route(expression, event="push", ref="refs/heads/integration",
                               os_name="ubuntu-latest"), "ubuntu-latest")

    def assert_wheel_policy(self, expression):
        self.assertEqual(route(expression, event="push", ref="refs/heads/main"), self.LABELS)
        self.assertEqual(route(expression, event="push", ref="refs/tags/v0.1.9"), "macos-15")
        self.assertEqual(route(expression, event="pull_request", ref="refs/pull/44/merge"), self.LABELS)
        self.assertEqual(route(expression, event="pull_request", ref="refs/pull/44/merge",
                               head="outsider/lazaret"), "macos-15")
        self.assertEqual(route(expression, event="pull_request", ref="refs/pull/44/merge",
                               actor="someone-else"), "macos-15")
        self.assertEqual(route(expression, event="push", ref="refs/heads/main",
                               tag="macosx_10_12_x86_64", fallback="macos-15-intel"), "macos-15-intel")

    def test_native_ci_lanes_use_the_pool(self):
        text = workflow("ci.yml")
        self.assertIn("branches: [main, integration]", text)
        for name in ("python-unit", "js", "rust"):
            section = job(text, name)
            self.assert_ci_policy(runner_expression(section))

    def test_the_arm_wheel_build_and_install_use_the_pool(self):
        text = workflow("wheels.yml")
        for name in ("macos-windows", "install"):
            section = job(text, name)
            self.assert_wheel_policy(runner_expression(section))

    def test_release_calls_both_hosted_workflows(self):
        release = workflow("release.yml")
        self.assertIn("uses: ./.github/workflows/ci.yml", release)
        self.assertIn("uses: ./.github/workflows/wheels.yml", release)
        for name in ("python-unit", "js", "rust"):
            expression = runner_expression(job(workflow("ci.yml"), name))
            self.assertEqual(route(expression, event="push", ref="refs/tags/v0.1.9"), "macos-latest")
        for name in ("macos-windows", "install"):
            expression = runner_expression(job(workflow("wheels.yml"), name))
            self.assertEqual(route(expression, event="push", ref="refs/tags/v0.1.9"), "macos-15")

    def test_ci_uses_the_release_compiler(self):
        text = workflow("ci.yml")
        self.assertIn('RUST_VERSION: "1.95.0"', text)
        self.assertNotIn("rustup target add", text)
        for name in ("python-unit", "python-integration", "js", "rust"):
            section = job(text, name)
            self.assertIn("toolchain: ${{ env.RUST_VERSION }}", section)

        # GitHub's Windows default is PowerShell, where $RUST_VERSION is not
        # environment-variable syntax. Keep every explicitly versioned cargo
        # command in bash so Windows cannot silently turn `+1.95.0` into `+`.
        steps = re.findall(r"(?ms)^      - .*?(?=^      - |\Z)", text)
        cargo_steps = [step for step in steps if 'cargo +"$RUST_VERSION"' in step]
        self.assertEqual(len(cargo_steps), 6)
        for step in cargo_steps:
            self.assertIn("shell: bash", step)


if __name__ == "__main__":
    unittest.main()
