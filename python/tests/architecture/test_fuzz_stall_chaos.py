"""The macOS python-unit flake, as a regression lock (card 3cccf3e7, PR #22).

CI's python-unit matrix kept failing ONE random macOS leg per run on code unrelated to
the PR under test (PR #21: macos/3.10; byte-identical PR #20: macos/3.13; earlier stack8
commits: macos/3.12 + 3.14). The failing test was DriverTests.
test_a_run_over_the_limit_is_a_slow_finding_and_the_slowest_is_kept, whose assert
compared two MEASURED wall-clock times: a single ~45 ms scheduler pause inside the
smaller sleep (seed b"S", 0.03 s, against seed b"SS", 0.06 s) made the driver — correctly,
by its own rule — keep b"S", and the assert failed. macOS runners are shared VMs; which
leg eats the pause is chance, hence the rotation. That test now advances a clock the test
holds, so no pause can change what it observes (see test_fuzz_scripts.py, DriverTests).

This module guards the class of failure, not just the instance: it runs the whole
DriverTests module under the runner's condition — a background thread injecting random
5–450 ms scheduler stalls — in a subprocess of its own, and it must stay green. The
pre-fix file failed 7/7 under a single targeted stall with the exact CI signature;
this module is the "and it stays fixed" check, for the days the runner pauses again.

It is opt-in (LAZARET_STALL_CHAOS_ROUNDS) because each round takes a fresh ~10 s pass
over the module; CI's own budget stays untouched. With the variable unset the suite
is unchanged, so the default run keeps its time.
"""
import os
import random
import subprocess
import sys
import threading
import time
import unittest

from tests import _support

MODULE = "tests.architecture.test_fuzz_scripts"
ROUNDS = os.environ.get("LAZARET_STALL_CHAOS_ROUNDS")


def _stall(stop, rng):
    """The shared-runner condition: random scheduling pauses, 5–450 ms, until stopped."""
    while not stop.is_set():
        time.sleep(rng.uniform(0.0005, 0.02))
        time.sleep(rng.uniform(0.005, 0.45))          # the pause itself


@_support.requires_env("LAZARET_STALL_CHAOS_ROUNDS")
class StallChaosTests(unittest.TestCase):
    """DriverTests must stay green while the machine stalls at random.

    Each round takes one subprocess of its own (a stalled interpreter stays stalled),
    and the stall thread runs for the whole run, not just the slow-finding test: any
    timed comparison in the module must survive the runner's pauses.
    """

    def test_the_fuzz_driver_tests_survive_random_scheduler_stalls(self):
        rounds = int(ROUNDS)
        self.assertGreaterEqual(rounds, 1, "LAZARET_STALL_CHAOS_ROUNDS must be a positive int")
        failures = []
        for r in range(rounds):
            stop = threading.Event()
            thread = threading.Thread(target=_stall, args=(stop, random.Random(1000 + r)), daemon=True)
            thread.start()
            try:
                out = subprocess.run(
                    [sys.executable, "-m", "unittest", "-v", MODULE],
                    cwd=os.path.join(_support.REPO_ROOT, "python"),
                    env=dict(os.environ, PYTHONPATH="src"),
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=1800)
            finally:
                stop.set()
                thread.join(timeout=1)
            if out.returncode != 0:
                failures.append((r, out.stdout[-4000:] + out.stderr[-4000:]))
        if failures:
            for r, tail in failures:
                print(f"--- round {r + 1} ---\n{tail}", file=sys.stderr)
            self.fail(f"{len(failures)} of {rounds} stalled rounds failed; the tail of each is above")


if __name__ == "__main__":
    unittest.main(verbosity=2)
