"""The package readers' findings, held to their recorded outputs (_snapshots.py): what the engine's Go reader and Rust
reader (`go_package`, `rs_crate`) answer for a module or a crate, with the findings it makes of that answer when asked
whose code it is (rust/crates/lazaret-engine/src/readers.rs: SC-INSTALL-HOOK for a build script and a procedural
macro, the import-time test of what runs at start, SC-USE-RISK, SC-GO-GENERATE).

Until BR-7's step 3 f (0.1.9) both packages made those findings themselves from the readers' answers
(core.package_reader_issues; js/src/deps.js packageReaderIssues). The engine took them over; the step's gate held
these readings, and every one the reader tests make, to the Python it replaced, finding for finding (no difference),
and these hashes were recorded from the engine then.

The readings: modules and crates of one to four files put together from test_package_code's samples (init code,
package-level initializers, what runs when called, cgo, build scripts, procedural macros, #[ctor], clean code), with
//go:generate lines (spaced, longer than a message shows, several), under names of every kind, as a module's, a
crate's and an sdist's, redacted and not.

All content is inert text: the samples are never built, their addresses are documentation addresses and .invalid
hosts, and nothing is executed or contacted.
"""
import random
import unittest

from lazaret.scanner import _native
from tests.architecture import _snapshots

SHOWN = ["a.go", "pkg/x.go", "vendor/example.test/m/y.go", "d\\e.go", "café.go", "\U0001F600/z.go", "sp ace.go"]
GENERATE = ["//go:generate stringer -type=Pill", "//go:generate   go   run   ./gen  -o\tx.go",
            "//go:generate sh -c " + "'echo " + "x" * 260 + "'", "//go:generate protoc --go_out=. a.proto"]


def reading_calls(seed=20261017, count=400):
    from tests.registry import test_package_code as pc
    go_texts = [pc.INIT_GO, pc.VAR_GO, pc.USE_GO, pc.CGO_GO, pc.CLEAN_GO]
    rs_texts = [pc.BUILD_RS, pc.MACRO_RS, pc.CTOR_RS, pc.USE_RS, pc.CLEAN_RS, pc.PROBE_RS]
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        redact = rnd.random() < 0.7
        if rnd.random() < 0.5:
            files = []
            for j in range(rnd.randint(1, 4)):
                text = rnd.choice(go_texts)
                if rnd.random() < 0.4:
                    lines = "\n".join(rnd.sample(GENERATE, rnd.randint(1, 4)))
                    text = text.replace("package m\n", "package m\n\n" + lines + "\n", 1)
                files.append((f"f{j}.go" if j else "m.go", text))
            call, args, what = "go_package", {"module": "example.test/m"}, "module"
        else:
            files = [("src/lib.rs", rnd.choice(rs_texts))]
            args = {"lib": "src/lib.rs", "proc_macro": rnd.random() < 0.3}
            if rnd.random() < 0.6:
                files.append(("build.rs", rnd.choice(rs_texts)))
                args["build"] = "build.rs"
            for j in range(rnd.randint(0, 2)):
                files.append((f"src/m{j}.rs", rnd.choice(rs_texts)))
            call, what = "rs_crate", None
        names = [f"{rnd.choice(SHOWN)}#{j}" for j in range(len(files))]
        what = what or rnd.choice(["crate", "sdist"])
        args.update(files=[[p, len(t)] for p, t in files], what=what, names=names, redact=redact, neumaier=False)
        out.append((call, args, "".join(t for _p, t in files)))
    return out


def snapshot_sets():
    return {"reader_issues": reading_calls}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ReaderSnapshotTests(unittest.TestCase):
    def test_the_readings(self):
        answers = _snapshots.run(reading_calls())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, "reader_issues", answers)
        rules = {}
        for a in answers:
            for _k, issue in a["ok"]["issues"]:
                rules[issue[0]] = rules.get(issue[0], 0) + 1
        self.assertGreater(rules.get("SC-INSTALL-HOOK", 0), 150)
        self.assertGreater(rules.get("SC-IMPORT-RISK", 0), 250)
        self.assertGreater(rules.get("SC-USE-RISK", 0), 120)
        self.assertGreater(rules.get("SC-GO-GENERATE", 0), 100)


if __name__ == "__main__":
    unittest.main()
