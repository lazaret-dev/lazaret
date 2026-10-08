"""`lazaret scan --verify-secrets` (0.1.9, V-1 stage 2): a scan's secret findings asked about, after the scan.

John's decision 4 (Oct 7): "Let's follow trufflehog behavior. Verify is an explicit flag -- detection of secret is default
without verification it is live." Nothing is asked without the flag; with it, any target's secrets are (a folder, a `github:`
or `gitlab:` repository, whoever's it is). The guard, the registry auditor, the MCP server and the pre-commit hook never ask.

Each secret finding (`core.SECRET_RULES`) is read again: its line, from the file, as the scan numbered it, in memory only. The
engine says which credentials the providers name on a file's lines (`secrets.find`: a word that is all of one provider's
format; an AWS key id and a secret key on the lines of one file, paired nearest first), and `secretverify.Verifier` asks each
provider once for each credential (its budgets: 120 seconds and 500 calls for the run, two calls at once to one provider).
Before the first call, a note on stderr says which providers will be asked and where each credential goes (`notice`).

A finding gets `verified` ({"outcome", "provider", "label", "who", "detail"}: of the credentials on its line, the one that
says most: live, then unknown, then rejected):

- **live**: a BLOCKER vulnerability (an S-ENTROPY hotspot too), its message saying the provider accepts it, and as whose;
- **rejected**: as it was, its message saying to revoke it anyway: the history keeps it;
- **unknown**: as it was, its message saying why.

The result is graded again (`core.regrade`) and says what was asked and what came of it (`verification`). A finding whose line
holds no credential a provider names (a Google API key, a JWT, a private key, a database's password) is not verified, and is
counted (`verification.findings.notVerified`). The values are never kept: not in an issue, a report, a log or a file; the
verifier's cache is the run's, in memory, keyed by the SHA-256 of the credential."""

import collections
import os
import sys

from . import _native, core, secretverify

__all__ = ["verify_findings", "notice", "lines_of"]

#: which of a line's results a finding takes: the one that says most
RANK = {secretverify.LIVE: 0, secretverify.UNKNOWN: 1, secretverify.REJECTED: 2}


def lines_of(root, rel, wanted):
    """{n: text} of the lines `wanted` (1-based) of the file `rel` under `root`, read and numbered as the scan read it; {}
    when it cannot be read so (not a regular file, under a symbolic link, outside the root, larger than the scan reads)."""
    path = os.path.join(root, rel)
    try:
        top = os.path.realpath(root)
        if os.path.commonpath([top, os.path.realpath(path)]) != top:
            return {}
        data = core._read_prefix(path, core.SOURCE_SIZE_CAP + 1)
    except (OSError, ValueError):
        return {}
    if len(data) > core.SOURCE_SIZE_CAP:
        return {}
    ext = os.path.splitext(rel)[1].lower()
    lang = core.EXTS.get(ext) or core.script_source_lang(data[:core.HEADER_SAMPLE_BYTES])
    text = core.decode_source(data, lang)[0] if lang else core.decode_source(data)[0]
    lines = core.source_lines(text, lang or "cfg")
    return {n: lines[n - 1] for n in wanted if 0 < n <= len(lines)}


def notice(asked, out=None):
    """The note before the first call: which providers will be asked, how many credentials each, and where they go."""
    out = out if out is not None else sys.stderr
    total = sum(a["credentials"] for a in asked)
    where = ", ".join(f"{a['label']} at {a['host']} ({a['credentials']})" for a in asked)
    print(f"note: --verify-secrets: asking {len(asked)} provider{'s' if len(asked) != 1 else ''} whether "
          f"{total} credential{'s are' if total != 1 else ' is'} live, each sent to its own provider alone, over HTTPS: "
          f"{where}", file=out, flush=True)


def _mark(issue, result, label):
    issue["verified"] = {"outcome": result.outcome, "provider": result.provider, "label": label, "who": result.who,
                         "detail": result.detail}
    if result.outcome == secretverify.LIVE:
        issue["sev"], issue["type"] = "BLOCKER", "VULN"
        whose = f" (the account: {result.who})" if result.who else ""
        issue["msg"] += f" Verified live: the provider accepts this {label}{whose}. Revoke it now."
    elif result.outcome == secretverify.REJECTED:
        issue["msg"] += f" Verified rejected: {result.detail}. Revoke it anyway: the history keeps it."
    else:
        issue["msg"] += f" Not verified: {result.detail}."


def verify_findings(root, res, verifier=None, out=None):
    """Verify the secret findings of `res` (a project scan's result, its files under `root`), in place: each finding of a
    credential a provider names gets `verified`, the result is graded again and gets `verification`. `verifier` is a
    `secretverify.Verifier` (a test's; by default one for this run, over lazaret-net); `out` takes the note before the first
    call (stderr). Returns `res["verification"]`."""
    findings = [i for i in res.get("issues", ()) if i.get("rule") in core.SECRET_RULES and isinstance(i.get("file"), str)
                and isinstance(i.get("line"), int) and not isinstance(i.get("line"), bool)]
    by_file = collections.defaultdict(list)
    for issue in findings:
        by_file[issue["file"]].append(issue)
    credentials = []                                            # (file, {"provider", "parts", "lines"})
    for rel, issues in by_file.items():
        texts = lines_of(root, rel, sorted({i["line"] for i in issues}))
        if texts:
            numbers = sorted(texts)
            credentials += [(rel, f) for f in _native.call("secrets.find", {"lines": numbers}, "\n".join(texts[n] for n in numbers))]
    labels = {pid: (label, host) for pid, label, host in secretverify.provider_info()}
    asked = collections.Counter(f["provider"] for _, f in credentials)
    summary = {"providers": [{"provider": pid, "label": labels[pid][0], "host": labels[pid][1], "credentials": n}
                             for pid, n in asked.items()],
               "credentials": dict.fromkeys(secretverify.OUTCOMES, 0),
               "findings": dict(dict.fromkeys(secretverify.OUTCOMES, 0), notVerified=0)}
    results = []
    if credentials:
        notice(summary["providers"], out)
        verifier = verifier if verifier is not None else secretverify.Verifier()
        results = verifier.verify_all([(f["provider"], f["parts"]["secret"] if list(f["parts"]) == ["secret"] else dict(f["parts"]))
                                       for _, f in credentials])
    best = {}
    for (rel, found), result in zip(credentials, results):
        summary["credentials"][result.outcome] += 1
        for n in found["lines"]:
            held = best.get((rel, n))
            if held is None or RANK[result.outcome] < RANK[held.outcome]:
                best[(rel, n)] = result
    for issue in findings:
        result = best.get((issue["file"], issue["line"]))
        if result is None:
            summary["findings"]["notVerified"] += 1
        else:
            summary["findings"][result.outcome] += 1
            _mark(issue, result, labels.get(result.provider, (result.provider, ""))[0])
    res["verification"] = summary
    core.regrade(res)
    return summary
