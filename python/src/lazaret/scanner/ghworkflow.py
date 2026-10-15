"""GitHub Actions workflows: the worms' shapes and the hardening checks (SC-WORKFLOW-*).

The reading is the native engine's since 0.1.9 (BR-7: `rust/crates/lazaret-engine/src/ci/`, the `ci_*` calls),
as it is for the npm package; until then this module and js/src/lib/ghworkflow.js were twins held equal by parity
tests. This module asks the engine and keeps the names the rest of the package calls: the outline of a YAML file
(`outline`, `records`, which the registry's Actions check reads action.yml with), the findings (`findings`: the
worms' shapes, SC-WORKFLOW-SECRETS and SC-WORKFLOW-BACKDOOR; `hardening`: the practices a pipeline should follow),
the rule of a finding, a workflow's `uses:` and the line checks the hardening reads (`install_command`,
`publish_command`, `pipe_to_shell`, `logical_lines`). docs/DESIGN.md says what each reads.
"""
from . import _native, engine

#: Code points between `${{` and `}}` an expression may have
EXPR_MAX = 500

# The pack's values the rest of the package names, read when first asked (importing never needs the engine):
# FIRST_PARTY (GitHub's own action owners), OUTSIDER_EVENTS ((event, who can start it)), COMMAND_START (where a
# command can start in a script line), PIPE_SHELL_WHY and PIPE_SHELL_FIX (the words of a script run unread).
_LAZY = {
    "FIRST_PARTY": lambda: tuple(engine.pack_value("_WF_FIRST_PARTY")),
    "OUTSIDER_EVENTS": lambda: tuple(zip(engine.pack_value("_WF_OUTSIDER_EVENTS"),
                                         engine.pack_value("_WF_OUTSIDER_ACTS"))),
    "COMMAND_START": lambda: engine.pack_value("_WF_COMMAND_START"),
    "PIPE_SHELL_WHY": lambda: engine.pack_value("_WF_PIPE_SHELL_RULE")["why"],
    "PIPE_SHELL_FIX": lambda: engine.pack_value("_WF_PIPE_SHELL_RULE")["fix"],
}


def __getattr__(name):
    if name in _LAZY:
        value = _LAZY[name]()
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def is_workflow(path):
    """Is `path` ('/' or os separators) a workflow: .github/workflows/*.yml|yaml?"""
    return _native.call("ci_kind", {}, path) == "workflow"


def _records(answer):
    for r in answer:
        r["path"] = tuple(r["path"])
        r["block"] = [tuple(b) for b in r["block"]]
    return answer


def outline(text):
    """The workflow's lines as records {line, path, key, value, block}: path the tuple of keys above ('-' for a
    sequence item), key the line's key (None for a scalar line), value its value's text, block the (line, text) of
    a block scalar (`run: |`)."""
    return _records(_native.call("ci_outline", {}, text))


def records(text, items=True, seq_blocks=False):
    """outline(text) for the other YAML files read the same way: `items` adds each record's "item" flag (it is the
    first of a sequence item), `seq_blocks` reads a block scalar that is a sequence item (`- |`) as one."""
    return _records(_native.call("ci_outline", {"items": bool(items), "seq_blocks": bool(seq_blocks)}, text))


def _found(answer):
    return [tuple(f) for f in answer]


def findings(text):
    """-> [(kind, line, detail)] for a workflow's text: kind 'secrets' (detail {"where", "how"}: how None when
    nothing sends them out) or 'backdoor' (detail {"job", "expr", "event", "act"})."""
    return _found(_native.call("ci_workflow", {}, text)["findings"])


def hardening(text):
    """-> [(kind, line, detail)], by line: 'unpinned' {"uses", "kind", "ref", "first", "tag"}; 'pr-checkout' {"job",
    "via", "expr"}; 'cache' {"job", "what", "explicit", "why"}; 'perms' {"scopes"}; 'perms-missing' {"jobs"};
    'oidc-install' {"job", "from", "command"}; 'pipe-to-shell' {"job", "command"}."""
    return _found(_native.call("ci_workflow", {}, text)["hardening"])


def hardening_rule(kind, d):
    """The issue rule — id, name, type, sev, msg, why, fix, ref, as core.mk_issue takes them — for one finding."""
    return _native.call("ci_rule", {"ci": "workflow", "kind": kind, "detail": d})


def parse_uses(value):
    """(kind, name, ref, pinned) of a `uses:` value (kind 'action', 'docker' or 'workflow'; ref is '' for none);
    None for a local path. The registry's action checks read the values with it."""
    got = _native.call("ci_parse_uses", {}, value)
    return tuple(got) if got is not None else None


def uses(text):
    """[(line, value)] of every `uses:` of a workflow: a step's, and a job's (a reusable workflow)."""
    return [tuple(u) for u in _native.call("ci_uses", {}, text)]


def install_command(text):
    """The dependency install in a script line (`npm ci`, `pip install`), or None (`--ignore-scripts` is not one)."""
    return _native.call("ci_check", {"check": "install"}, text)


def publish_command(text):
    """The command in a script line that publishes a release (`npm publish`, `twine upload`), or None."""
    return _native.call("ci_check", {"check": "publish"}, text)


def pipe_to_shell(text):
    """A script line that fetches a script and runs it unread, as `curl … | sh`, or None."""
    return _native.call("ci_check", {"check": "pipe_to_shell"}, text)


def logical_lines(lines):
    """[(line, text)] with a script's continued lines (`… \\` at the end) joined to the line they continue."""
    return [tuple(x) for x in _native.call("ci_logical_lines", {"lines": [list(x) for x in lines]}, "")]
