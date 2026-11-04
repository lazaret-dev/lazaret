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
TOKEN = re.compile(
    r"\s*(?:(?P<string>'[^'\\]*')|(?P<operator>&&|\|\||==|!=|[!(),])|"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.]*))"
)


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


class Expression:
    """Parser for the deliberately small GitHub-expression subset we use."""

    def __init__(self, source, values):
        self.values = values
        self.tokens = []
        position = 0
        while position < len(source):
            match = TOKEN.match(source, position)
            if match is None:
                raise ValueError(f"unsupported expression at {source[position:position + 20]!r}")
            self.tokens.append((match.lastgroup, match.group(match.lastgroup)))
            position = match.end()
        self.position = 0

    def peek(self, value=None):
        if self.position == len(self.tokens):
            return None if value is None else False
        token = self.tokens[self.position]
        return token if value is None else token[1] == value

    def take(self, value=None):
        token = self.peek()
        if token is None or (value is not None and token[1] != value):
            raise ValueError(f"expected {value!r}, got {token!r}")
        self.position += 1
        return token

    def parse(self):
        answer = self.parse_or()
        if self.peek() is not None:
            raise ValueError(f"unexpected token {self.peek()!r}")
        return answer

    def parse_or(self):
        answer = self.parse_and()
        while self.peek("||"):
            self.take("||")
            other = self.parse_and()
            answer = answer or other
        return answer

    def parse_and(self):
        answer = self.parse_equality()
        while self.peek("&&"):
            self.take("&&")
            other = self.parse_equality()
            answer = answer and other
        return answer

    def parse_equality(self):
        answer = self.parse_unary()
        while self.peek("==") or self.peek("!="):
            operator = self.take()[1]
            other = self.parse_unary()
            answer = answer == other if operator == "==" else answer != other
        return answer

    def parse_unary(self):
        if self.peek("!"):
            self.take("!")
            return not self.parse_unary()
        return self.parse_primary()

    def parse_primary(self):
        if self.peek("("):
            self.take("(")
            answer = self.parse_or()
            self.take(")")
            return answer
        kind, value = self.take()
        if kind == "string":
            return value[1:-1]
        if kind != "name":
            raise ValueError(f"expected a value, got {(kind, value)!r}")
        if not self.peek("("):
            if value not in self.values:
                raise ValueError(f"unknown expression value {value!r}")
            return self.values[value]
        self.take("(")
        arguments = []
        if not self.peek(")"):
            arguments.append(self.parse_or())
            while self.peek(","):
                self.take(",")
                arguments.append(self.parse_or())
        self.take(")")
        if value == "fromJSON" and len(arguments) == 1:
            return json.loads(arguments[0])
        if value == "startsWith" and len(arguments) == 2:
            return arguments[0].startswith(arguments[1])
        raise ValueError(f"unsupported function {value!r} with {len(arguments)} arguments")


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
    return Expression(expression, values).parse()


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
        self.assertEqual(route(expression, event="schedule", ref="refs/heads/integration"),
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

        boundaries = job(text, "python-boundaries")
        self.assertIn("if: github.event_name == 'schedule'", boundaries)
        self.assertIn("runs-on: ${{ matrix.os }}", boundaries)
        self.assertIn('{ os: macos-latest, python: "3.14" }', boundaries)
        self.assertIn('{ os: windows-latest, python: "3.10" }', boundaries)
        for name in ("versions", "python-unit", "python-integration", "js", "rust"):
            self.assertIn("if: github.event_name != 'schedule'", job(text, name))

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

    def test_routing_policy_rejects_the_regressions_it_guards(self):
        expression = runner_expression(job(workflow("ci.yml"), "python-unit"))
        mutations = (
            expression.replace(" && !startsWith(github.ref, 'refs/tags/')", "", 1),
            expression.replace(" && github.actor == 'johnabooth-afk'", "", 1),
            expression.replace(',"lazaret-tart"', "", 1),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(AssertionError):
                    self.assert_ci_policy(mutation)
        with self.assertRaises(ValueError):
            route(expression[:-1], event="push", ref="refs/heads/integration")

    def test_every_workflow_keeps_the_repository_security_defaults(self):
        directory = os.path.join(ROOT, ".github", "workflows")
        forbidden = re.compile(r"(?m)^\s{0,2}(pull_request_target|workflow_run|issue_comment):")
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith((".yml", ".yaml")):
                continue
            text = workflow(filename)
            with self.subTest(workflow=filename):
                self.assertIsNone(forbidden.search(text))
                self.assertRegex(text, r"(?m)^permissions:\n  contents: read$")
                steps = re.findall(r"(?ms)^      - .*?(?=^      - |^  [A-Za-z0-9_-]+:|\Z)", text)
                checkouts = [step for step in steps if "uses: actions/checkout@" in step]
                self.assertTrue(checkouts)
                for step in checkouts:
                    self.assertIn("persist-credentials: false", step)

    def test_release_docs_record_the_private_runner_boundary(self):
        with open(os.path.join(ROOT, "docs", "RELEASING.md"), encoding="utf-8") as f:
            releasing = f.read()
        for required in ("Published artifacts are built only on GitHub-hosted infrastructure",
                         "lazaret-tart", "fresh ephemeral JIT runner", "no access to the",
                         "untrusted job before it creates"):
            self.assertIn(required, releasing)

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
        self.assertEqual(len(cargo_steps), 7)
        for step in cargo_steps:
            self.assertIn("shell: bash", step)


if __name__ == "__main__":
    unittest.main()
