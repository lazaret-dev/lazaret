"""Engine parity for following install hooks and the install-script and
import-time tests: the npm engine's js/src/lib/hooks.js against
lazaret.scanner.core (follow_hook, install_script_risk,
import_time_risk, node_candidates, shebang_lang, and what they rest on:
_hook_tokens, a shlex tokenizer with a regex fallback, and the `node -e`
pattern).

The JS module re-implements Python's shlex (posix, punctuation_chars,
whitespace_split, no commenters: read_token is the same in CPython 3.10 to
3.14) and compiles core's patterns with Python `re` semantics, so the two
must agree on every input. They are compared case by case, in one node
process, on realistic hook commands and scripts and on a seeded random
corpus built from pieces the functions look at: quotes, backslashes,
operators and redirections, cd, wrappers, interpreters, node flags,
require() calls, download commands, credential and exfiltration markers,
non-ASCII letters (é; ſ and the Kelvin sign, which re.I folds to s and k;
İ and ı), Python-only whitespace (U+001C, U+0085). Each function's result
is compared, and shlex's own tokens (None where it raises) apart from the
fallback. The JS module's copies of core's pattern text and name sets are
compared with core's too.

Characters are those of Unicode 13.0, which the scanner pins source text
to: for a later one (a digit Unicode 14 added, say) core's own answer
depends on the Python version.

All text is inert: hosts are .invalid, TEST-NET or private addresses, and
nothing is executed. Skipped where node is missing.
"""
import collections
import json
import os
import re
import shutil
import subprocess
import threading
import unittest

from lazaret.scanner import core
from tests import _support
from tests.architecture.hooks_corpus import EXFIL_REASONS, FIELDS, SVC_REASONS, core_view, corpus, shard

NODE = shutil.which("node")
HOOKS_JS = os.path.join(_support.REPO_ROOT, "js", "src", "lib", "hooks.js")
NPM_HOOKS = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const h = await import(pathToFileURL(process.argv[1]).href);
const cases = JSON.parse(readFileSync(0, "utf8"));
const results = cases.map((s) => [h.shlexSplit(s), h.hookTokens(s), h.followHook(s),
  h.installScriptRisk(s), h.importTimeRisk(s), h.nodeCandidates(s), h.nodeECodes(s), h.shebangLang(s),
  h.importTimeRisk(s, "py"), h.importTimeRisk(s, "js"),
  ((at) => (at < 0 ? -1 : [...s.slice(0, at)].length))(h.selfPublishAt(s)), h.runsDll(s), h.joinStringPieces(s),
  h.decodedView(s), h.spawnedScripts(s)]);
process.stdout.write(JSON.stringify({ twins: h.PY_TWINS, results }));
"""


def start_npm(cases):
    """Start js/src/lib/hooks.js on the cases in the background (it runs while
    core reads them: the suite's time is the slower engine's, not the sum);
    finish_npm collects its answer."""
    p = subprocess.Popen([NODE, "--input-type=module", "-e", NPM_HOOKS, HOOKS_JS], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8", errors="replace")
    box = {}
    worker = threading.Thread(target=lambda: box.update(out=p.communicate(json.dumps(cases), timeout=60)))
    worker.start()
    return p, worker, box


def finish_npm(started):
    """(PY_TWINS, [results per case]) from the node process start_npm began."""
    p, worker, box = started
    worker.join()
    stdout, stderr = box["out"]
    if p.returncode:
        raise AssertionError(f"node exited {p.returncode}: {stderr[-2000:]}")
    out = json.loads(stdout)
    return out["twins"], out["results"]


def run_npm(cases):
    """(PY_TWINS, [results per case]) from js/src/lib/hooks.js."""
    return finish_npm(start_npm(cases))


def mismatches(cases, views, results, limit=20):
    """[(case, field, core's, npm's)] for the first `limit` differences."""
    found = []
    for text, view, got in zip(cases, views, results):
        for field, want, have in zip(FIELDS, view, got):
            if want != have:
                found.append((text, field, want, have))
                if len(found) >= limit:
                    return found
    return found


@unittest.skipUnless(NODE, "node is not installed")
class HookParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.cases = shard(corpus())
        started = start_npm(cls.cases)
        cls.views = [core_view(text) for text in cls.cases]
        cls.twins, cls.results = finish_npm(started)

    def test_every_case_agrees(self):
        self.assertEqual(len(self.results), len(self.cases))
        self.assertTrue(all(len(r) == len(FIELDS) for r in self.results))
        self.assertEqual(mismatches(self.cases, self.views, self.results), [])

    def test_pattern_text_and_names_are_cores(self):
        """The JS module carries core's pattern text verbatim, with the same
        flags, and the same name sets (flags: i = re.I, m = re.M)."""
        for name, (src, flags) in self.twins["patterns"].items():
            with self.subTest(pattern=name):
                rx = getattr(core, name)
                self.assertEqual(src, rx.pattern)
                self.assertEqual(flags, ("i" if rx.flags & re.I else "") + ("m" if rx.flags & re.M else ""))
                self.assertFalse(rx.flags & re.S)
        for name, names in self.twins["sets"].items():
            with self.subTest(names=name):
                self.assertEqual(sorted(names), sorted(getattr(core, name)))
        for name, table in self.twins["maps"].items():
            with self.subTest(options=name):
                self.assertEqual(table, {k: sorted(v) for k, v in getattr(core, name).items()})
        self.assertEqual(self.twins["limits"], {k: getattr(core, k) for k in
                                                ("HOOK_MAX_CHARS", "HOOK_MAX_COMMANDS", "HOOK_MAX_TARGETS", "HOOK_MAX_PATH",
                                                 "_DL_LONG_ROW", "_DL_WINDOW", "_DL_ARG_SPAN", "_DL_LOOKBACK",
                                                 "_DL_NAMED_SEARCHES", "_DL_PHASES", "_DL_JOIN_ROWS", "_DL_JOIN_CHARS",
                                                 "_DL_LOGICAL_MAX_CHARS",
                                                 "_DL_ALIAS_MAX",
                                                 "_PS_ENCODED_MAX", "_STAGER_MIN", "_STAGER_MAX_LITERALS",
                                                 "_PS_EXEC_BACK", "_PS_EXEC_MAX_NAMES", "_SELF_READ_PASSES",
                                                 "_SELF_READ_MAX_CALLS", "_SELF_READ_ARG_SPAN", "_SELF_READ_MAX_ASSIGNS",
                                                 "_SELF_READ_THEN_SPAN",
                                                 "_LITERAL_SPANS_MAX", "_PERSIST_MAX_LINES", "_SELF_PUB_SPAN",
                                                 "_SELF_PUB_MAX", "_DV_MAX_LITERAL", "_DV_BODY", "_DV_MAX_HELPERS",
                                                 "_DV_MAX_ARRAYS", "_DV_MAX_CHARS", "_DV_XOR_MIN_CALLS", "_DV_XOR_MAX_CALLS",
                                                 "_DV_XOR_MIN_BYTES", "_DV_XOR_MAX_KEYS", "_DV_XOR_KEY_MAX", "_SPAWN_MAX_DEPTH",
                                                 "_SPAWN_MAX_FILES", "_SPAWN_NAME_DEPTH", "_SPAWN_MAX_TARGETS", "_SPAWN_MAX_NAMED",
                                                 "_SE_MIN_DISTINCT", "_SE_MAX", "_CRED_SWEEP_SPAN",
                                                 "_CRED_SWEEP_MIN", "_CRED_SWEEP_MAX",
                                                 "_RAW_CONNECT_SPAN", "_IP_LITERAL_MAX", "_DNS_LOOKUP_MAX",
                                                 "_DNS_ARG_SPAN", "_DNS_ASSIGN_SPAN", "_DNS_SHELL_SPAN", "_DD_PASSES",
                                                 "_DD_MAX_CALLS", "_DD_ARG_SPAN", "_DD_MAX_ASSIGNS", "_DD_THEN_MAX",
                                                 "_SVC_LINE_MAX", "_SVC_RUNKEY_SPAN", "_DV_CC_BODY",
                                                 "_DV_CC_MAX_PARAMS", "_DV_CC_MAX_DECODERS", "_DV_CC_MAX_CALLS",
                                                 "_DV_CC_MAX_CODES", "_DV_CC_MAX_WORK", "_DV_CC_MAX_TOKENS",
                                                 "_DV_CC_MAX_DEPTH", "_DV_CC_INT_MAX", "_SH_MAX_DEPTH", "_LD_MAX",
                                                 "_LD_MAX_CALLS", "_LD_STATEMENT_SPAN", "_SH_EXEC_MAX", "_SH_CONCAT_MAX",
                                                 "_SH_SCRIPT_MAX_CHARS", "_SA_MAX_CHARS", "_SA_MAX_ARRAYS",
                                                 "_SA_MAX_ITEMS", "_SA_MAX_CALLS", "_SA_DEPTH", "_SA_BODY",
                                                 "_SA_LOOP_BACK", "_SA_HEX_MAX", "_SA_DEC_MAX", "_PX_MAX_ENTRIES",
                                                 "_PX_MAX_USES", "_PX_DEPTH", "_PX_ARGS")})
        for name, text in self.twins["strings"].items():
            with self.subTest(text=name):
                self.assertEqual(text, getattr(core, name))
        for name, table in self.twins["tables"].items():
            with self.subTest(table=name):
                value = getattr(core, name)
                self.assertEqual(table, list(value) if isinstance(value, tuple) else value)
        self.assertEqual(len(self.twins["strings"]), 25)
        self.assertEqual(len(self.twins["tables"]), 11)
        self.assertEqual(len(self.twins["patterns"]), 301)
        self.assertEqual(len(self.twins["sets"]), 80)
        self.assertEqual(len(self.twins["maps"]), 5)



def _core_views(chunk):
    """core's views of a chunk of the corpus (in a worker process)."""
    return [core_view(text) for text in chunk]


class CorpusReachTests(unittest.TestCase):
    """The corpus itself, counted over all of it with core alone (in
    parallel processes, so that a machine that limits each run's time reads
    it whole): each path the engines are compared on is reached."""

    @classmethod
    def setUpClass(cls):
        from concurrent.futures import ProcessPoolExecutor
        cls.cases = corpus()
        n = max(1, min(os.cpu_count() or 1, 8))
        size = -(-len(cls.cases) // n)
        chunks = [cls.cases[i:i + size] for i in range(0, len(cls.cases), size)]
        with ProcessPoolExecutor(max_workers=n) as pool:
            cls.views = [v for part in pool.map(_core_views, chunks) for v in part]

    def test_the_corpus_reaches_every_path(self):
        """Guards the comparison against a corpus that stopped exercising
        something: each count is well above zero for this seed."""
        counts = collections.Counter()
        for text, view in zip(self.cases, self.views):
            tokens, _, (targets, complete), install, (on_import, _), _, codes, lang, py, js = view[:10]
            counts["self-publishing"] += view[10] >= 0
            counts["runs a DLL"] += view[11] is not None
            counts["prose read out (py)"] += py[0] != on_import
            counts["prose read out (js)"] += js[0] != on_import
            counts["shlex raises"] += tokens is None
            if lang:
                counts[f"#! {lang}"] += 1
            counts["targets"] += bool(targets)
            counts["not followed completely"] += not complete
            counts["node -e codes"] += bool(codes)
            counts["decoded view"] += view[13] != text
            counts["spawned scripts"] += bool(view[14])
            if "fromCharCode" in text or "chr" in text or "byte" in text:
                read = core._dv_char_codes(text)
                counts["character codes read"] += read != text
                counts["a character-code decoder of the file's own read"] += (
                    read != core._DV_CC_LITERAL_RE.sub(core._cc_literal_sub, text))
            for reason in install + on_import:
                key = reason.split(" (")[0]                 # (the exfiltration reason names the address)
                counts["a reason in decoded strings"] += reason.endswith(core._DV_NOTE)
                for head in ("downloads a script and runs it with", "writes code it decodes to a file and runs it with"):
                    if key.startswith(head) and key != "downloads a script and runs it with Python":
                        key = head + " a shell or an interpreter"
                counts[key] += 1
        # 10 install-script reasons (the environment, an exfiltration address, a pipe, received code in
        # three kinds, encoded PowerShell with and without a download-run, PowerShell that downloads and
        # runs, a stager, a reverse shell, host information) and the import-time ones (a harvest sent over
        # the network or to a service, a download run by a shell, received code, a download run with or
        # without Python, a beacon to a capture service; several share the install-script text), the
        # targets, shlex, node -e and completeness counters, and 3 #! languages
        # and the cases where reading a file without its prose (import_time_risk with a language)
        # changes the answer, for Python and for JavaScript, and code read back from the file itself;
        # and the 6 persistence reasons (0.1.7); and (0.1.8) the 3 reasons for publishing, npm tokens and a
        # DLL run, with the self-publishing and DLL counters; a script downloaded or decoded, written and run
        # with a shell or an interpreter, a decoded file run, the decoded view and a reason only it shows
        # and (0.1.8, exfiltration) a webhook's secret, a credential sweep, the host name hidden in base64 or
        # sent in a DNS name or to an address fetched at run time, a miner and programs' shortcuts rewritten;
        # local data read, followed and sent (the environment, the user or host name, what commands report,
        # a file uploaded or read outside the package, the public IP address, the instance's metadata) and
        # a beacon; at import time, the environment, files, the user or host name, what commands report and
        # the public IP address sent to a capture service or an IP address (and a harvest to an exfiltration
        # service or over the network); and (0.1.8) the 7 ways a program is set to start at login or boot;
        # and character codes read, literal and by a decoder of the file's own
        self.assertEqual(len(counts), 74, counts)
        # these reasons are rarer in the random stream but present (curated) and well above zero
        rare = {"not followed completely", "deserializes data it receives over the network",
                "loads a module named by data it receives over the network", "downloads a file and then runs it",
                "downloads a script and runs it with Python", "runs an encoded PowerShell command",
                "runs an encoded PowerShell command that downloads and runs code",
                "runs PowerShell that downloads and runs code",
                "carries a GitHub Actions workflow that dumps every repository secret",
                "self-publishing",
                "downloads a script and runs it with a shell or an interpreter", "writes a file it decodes and runs it",
                "a reason in decoded strings", *EXFIL_REASONS, *SVC_REASONS}
        self.assertEqual({k: n for k, n in counts.items() if n < 100 and k not in rare}, {}, counts)
        self.assertGreaterEqual(counts["not followed completely"], 7, counts)   # the curated limit cases
        self.assertGreaterEqual(counts["deserializes data it receives over the network"], 25, counts)
        self.assertGreaterEqual(counts["loads a module named by data it receives over the network"], 25, counts)
        self.assertGreaterEqual(counts["downloads a file and then runs it"], 4, counts)
        self.assertGreaterEqual(counts["downloads a script and runs it with a shell or an interpreter"], 20, counts)
        self.assertGreaterEqual(counts["writes a file it decodes and runs it"], 10, counts)
        self.assertGreaterEqual(counts["a reason in decoded strings"], 6, counts)
        self.assertGreaterEqual(counts["carries a GitHub Actions workflow that dumps every repository secret"], 30, counts)
        self.assertGreaterEqual(counts["self-publishing"], 30, counts)
        for reason in EXFIL_REASONS + SVC_REASONS:
            self.assertGreaterEqual(counts[reason], 5, (reason, counts))


if __name__ == "__main__":
    unittest.main()
