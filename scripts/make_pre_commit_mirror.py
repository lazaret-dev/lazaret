#!/usr/bin/env python3
"""Write the pre-commit mirror of a Lazaret release.

    python3 scripts/make_pre_commit_mirror.py 0.1.9 ../lazaret-pre-commit

pre-commit installs a Python hook with `pip install .` at the root of the
hook's repository, and Lazaret's Python project is in python/, with an engine
that is compiled per platform: this repository can't be that hook. The mirror
(github.com/lazaret-dev/lazaret-pre-commit, as ruff's ruff-pre-commit) is a
repository with a hook definition and a package that holds nothing but a
pinned dependency on this release, so pre-commit installs Lazaret's platform
wheel from PyPI by version and runs `lazaret hook` (the commit-time gate:
lazaret/scanner/hook.py) on the files being committed.

The script writes .pre-commit-hooks.yaml, pyproject.toml, README.md and
LICENSE into the folder, which must be empty or a mirror already (only these
four files are rewritten). After a release is on PyPI, commit them in the
mirror and tag the commit vX.Y.Z (docs/RELEASING.md). Standard library only;
nothing is fetched."""
import argparse
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIRROR_URL = "https://github.com/lazaret-dev/lazaret-pre-commit"
FILES = (".pre-commit-hooks.yaml", "pyproject.toml", "README.md", "LICENSE")
VERSION_RE = re.compile(r"\d+\.\d+\.\d+")

HOOKS = """\
# Lazaret's commit-time gate: credentials, vulnerabilities and supply-chain
# threats in the files being committed (`lazaret hook`). Written by
# scripts/make_pre_commit_mirror.py in github.com/lazaret-dev/lazaret.
- id: lazaret
  name: lazaret
  description: Credentials, vulnerabilities and supply-chain threats in the files being committed
  entry: lazaret hook
  language: python
  require_serial: true
  minimum_pre_commit_version: "2.9.2"
"""

PYPROJECT = """\
# The pre-commit mirror of Lazaret {version}: pre-commit installs this
# repository with pip, and with it Lazaret's wheel for the platform, from
# PyPI. It holds no code of its own.
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "lazaret-pre-commit"
version = "{version}"
description = "pre-commit hook for Lazaret: credentials, vulnerabilities and supply-chain threats in the files being committed"
license = {{text = "Apache-2.0"}}
requires-python = ">=3.10"
dependencies = ["lazaret=={version}"]

[tool.setuptools]
py-modules = []
"""

README = """\
# Lazaret for pre-commit

[Lazaret](https://github.com/lazaret-dev/lazaret) {version}'s commit-time gate as a
[pre-commit](https://pre-commit.com) hook. It checks the files being committed,
as they are staged, for credentials, vulnerabilities and supply-chain threats (an
install hook that downloads and runs code, a workflow that sends out the
repository's secrets, obfuscated or decoded code that runs), and fails the commit
on `lazaret --ci`'s security and supply-chain conditions: no BLOCKER finding, no
CRITICAL vulnerability, no supply-chain indicator, no cross-file taint flow.
Duplication and maintainability are not checked.

```yaml
repos:
  - repo: {url}
    rev: v{version}
    hooks:
      - id: lazaret
```

pre-commit installs Lazaret {version} from PyPI (a wheel with the engine for your
platform). To leave files out, use pre-commit's `exclude`; to accept a finding,
mark its line (`# nosec`, `// NOSONAR`, `lazaret-ignore: RULE-ID`).

Without pre-commit, the same check is `lazaret hook`, in a git hook or by hand:
with no file named, it checks the files staged for commit.

This repository is written by `scripts/make_pre_commit_mirror.py` in Lazaret's
repository, one tag per release. Issues go to
https://github.com/lazaret-dev/lazaret/issues.
"""


def _configure_stdio():
    """Redirected output is UTF-8 unless PYTHONIOENCODING says otherwise, and
    never raises on a character the stream can't encode (STRUCTURE.md,
    "Cross-platform rules")."""
    explicit = bool(os.environ.get("PYTHONIOENCODING"))
    for stream in (sys.stdout, sys.stderr):
        try:
            encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
            if not explicit and not stream.isatty() and encoding not in ("utf-8", "utf8"):
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def write_mirror(version, out):
    """Write the mirror's files for `version` into the folder `out`."""
    if not VERSION_RE.fullmatch(version):
        raise ValueError(f"not a release version (X.Y.Z): {version!r}")
    os.makedirs(out, exist_ok=True)
    present = set(os.listdir(out)) - {".git"}
    if present and ".pre-commit-hooks.yaml" not in present:
        raise ValueError(f"{out} is neither empty nor a pre-commit mirror")
    with open(os.path.join(REPO, "LICENSE"), encoding="utf-8") as f:
        license_text = f.read()
    texts = {
        ".pre-commit-hooks.yaml": HOOKS,
        "pyproject.toml": PYPROJECT.format(version=version),
        "README.md": README.format(version=version, url=MIRROR_URL),
        "LICENSE": license_text,
    }
    for name in FILES:
        with open(os.path.join(out, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(texts[name])
    return [os.path.join(out, name) for name in FILES]


def main(argv=None):
    _configure_stdio()
    ap = argparse.ArgumentParser(description="Write the pre-commit mirror of a Lazaret release.")
    ap.add_argument("version", help="the release, X.Y.Z (on PyPI before the mirror is tagged)")
    ap.add_argument("folder", help="the mirror's checkout (empty, or a mirror already)")
    args = ap.parse_args(argv)
    try:
        for path in write_mirror(args.version, args.folder):
            print(path)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
