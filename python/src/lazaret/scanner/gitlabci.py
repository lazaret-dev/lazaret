"""GitLab CI files: the supply-chain checks of the CI/CD review, in GitLab's terms (0.1.9, S-3; SC-GITLAB-*).

`.gitlab-ci.yml` runs whatever it includes, pulls, downloads and expands with the project's variables: an
`include:` of a URL, of another project's file at a branch, a tag or no ref, or of a component not at a commit; an
image or a service without a digest; a script that fetches a script and runs it unread; a script that hands text
anyone can write (a merge request's title, a commit message, a branch name) to `eval`, `sh -c` or the place of a
command; a job that holds a publishing credential and installs dependencies.

The reading is the native engine's since 0.1.9 (BR-7: `rust/crates/lazaret-engine/src/ci/gitlab.rs`), on the
outline of the YAML that ghworkflow reads; until then this module and js/src/lib/gitlabci.js were twins. This module
asks the engine and keeps the names the rest of the package calls.
"""
from . import _native

#: The keys that hold a job's commands
SCRIPT_KEYS = ("before_script", "script", "after_script")


def is_gitlab_ci(path):
    """Is `path` ('/' or os separators) a GitLab CI file: `.gitlab-ci.yml`, a `*.gitlab-ci.yml`, or a .yml/.yaml
    under a `.gitlab` directory (the usual place of included files)?"""
    return _native.call("ci_kind", {}, path) == "gitlab"


def hardening(text):
    """-> [(kind, line, detail)], by line, for a GitLab CI file's text: 'include-remote' {"url", "http"};
    'include-project' {"project", "ref", "tag"}; 'include-component' {"component", "ref", "exact"}; 'image' {"job",
    "image", "where", "tag", "official"}; 'pipe-to-shell' {"job", "command"}; 'mr-text' {"job", "variable", "how"};
    'token-install' {"job", "grant", "command"}."""
    return [tuple(f) for f in _native.call("ci_gitlab", {}, text)["hardening"]]


def hardening_rule(kind, d):
    """The issue rule — id, name, type, sev, msg, why, fix, ref, as core.mk_issue takes them — for one finding."""
    return _native.call("ci_rule", {"ci": "gitlab", "kind": kind, "detail": d})


def flow_items(text):
    """The items of a flow collection written on one line: `[a, {k: v}]` gives "a" and a dict of the map's values;
    `{k: v}` gives that dict; a scalar gives itself."""
    return _native.call("ci_check", {"check": "flow_items"}, text)


def parse_image(value):
    """(name, tag, digest) of an image reference: `registry:5000/app:1.2@sha256:…` gives ("registry:5000/app",
    "1.2", "sha256:…")."""
    return tuple(_native.call("ci_check", {"check": "parse_image"}, value))


def mr_text(text):
    """(variable, how) for a script line that hands text anyone can write to code — "eval", "a `sh -c` string" or
    "the place of a command" — or None. A variable inside single quotes, or an argument of an ordinary command, is
    data and does not count."""
    got = _native.call("ci_check", {"check": "mr_text"}, text)
    return tuple(got) if got is not None else None
