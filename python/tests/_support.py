"""Paths shared by the tests. Nothing here is a test."""
import importlib.util
import os

TESTS = os.path.dirname(os.path.abspath(__file__))
PY_ROOT = os.path.dirname(TESTS)                  # python/
SRC = os.path.join(PY_ROOT, "src")
PKG = os.path.join(SRC, "lazaret")
REPO_ROOT = os.path.dirname(PY_ROOT)
FIXTURES = os.path.join(TESTS, "fixtures")
EXAMPLES = os.path.join(REPO_ROOT, "examples")

# Launchers equivalent to the installed console scripts (lazaret, lazaret-mcp,
# lazaret-registry, lazaret-sca). Run as `python <launcher> args...`.
_BIN = os.path.join(TESTS, "_bin")
CLI = os.path.join(_BIN, "cli_main.py")
MCP = os.path.join(_BIN, "mcp_main.py")
REGISTRY = os.path.join(_BIN, "registry_main.py")
SCA = os.path.join(_BIN, "sca_main.py")
BOOTSTRAP = os.path.join(_BIN, "registry_bootstrap.py")   # registry with a faked network

MAKE_BUNDLE = os.path.join(REPO_ROOT, "scripts", "make_bundle.py")
FLOW_SRC = os.path.join(PKG, "scanner", "flow.py")


def load_script(path, name):
    """Import a standalone script (e.g. scripts/make_bundle.py) as a module."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def requires_env(var):
    """Skip a test or class unless environment variable `var` is set. Used for
    tests that need a live service (Postgres) or the private samples checkout."""
    import unittest
    return unittest.skipUnless(os.environ.get(var), f"{var} not set")
