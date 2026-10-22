"""GitHub discovery's runs again at eight GraphQL calls at once (GH-SCAN-GQL-SPEED, 0.1.9: ghdiscover's
GRAPHQL_CONCURRENCY_MAX, --graphql-concurrency 8).

test_ghdiscover, test_ghdiscover_archive and test_ghdiscover_graphql run at the default, one call at a time, as
before. Here every test class of theirs that runs discovery (a subclass of test_ghdiscover.Case) runs again,
unchanged, at the most calls at once: each call's HTTP on a thread of its own, the answers handed back to the run's
thread, read and stored there, a batch's follow-up after its answer, the window that opens once an answer was read,
the pacing for GitHub's CPU-time limit. Their fakes answer at once, and which call a thread reaches first would then
be the scheduler's choice, so each call is answered before the run goes on (`answered_in_turn`): the order a GitHub
faster than the run answers in, the same for every run of the tests. Calls overlapping, answered in any order, are
test_ghdiscover_concurrency's, whose fakes hold each call until the run waits for one. After each test no call's
thread is left.
"""

import threading
import unittest
from unittest import mock

from tests import _support  # noqa: F401
from lazaret.registry import ghdiscover
from tests.registry import test_ghdiscover, test_ghdiscover_archive, test_ghdiscover_graphql

WIDTH = ghdiscover.GRAPHQL_CONCURRENCY_MAX


def answered_in_turn(work, name):
    """ghdiscover._spawn's stand-in: the call's thread started, and its answer there before the run goes on."""
    thread = threading.Thread(target=work, name=name, daemon=True)
    thread.start()
    thread.join()
    return thread


class AtEight:
    """A discovery test class's tests at eight calls at once, each call answered in turn; and no call's thread left
    after a test."""

    def setUp(self):
        self.spawned = getattr(self, "spawned", [])          # (a test that calls setUp again keeps its list)

        def spawn(work, name):
            self.spawned.append(answered_in_turn(work, name))
            return self.spawned[-1]
        for patcher in (mock.patch.object(ghdiscover, "DEFAULT_GRAPHQL_CONCURRENCY", WIDTH),
                        mock.patch.object(ghdiscover, "_spawn", spawn)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(lambda: self.assertEqual([t.name for t in self.spawned if t.is_alive()], []))
        super().setUp()


def _variants():
    """Every test class of the three modules that runs discovery, again here at eight calls at once."""
    made = {}
    for module, short in ((test_ghdiscover, "Discover"), (test_ghdiscover_archive, "Archive"),
                          (test_ghdiscover_graphql, "Graphql")):
        for name, cls in sorted(vars(module).items()):
            if (isinstance(cls, type) and issubclass(cls, test_ghdiscover.Case) and cls.__module__ == module.__name__
                    and any(attr.startswith("test") for attr in dir(cls))):
                variant = f"{short}{name}AtEight"
                made[variant] = type(variant, (AtEight, cls), {"__module__": __name__, "__qualname__": variant})
    return made


VARIANTS = _variants()
globals().update(VARIANTS)


class TheVariantsTests(unittest.TestCase):
    def test_every_discovery_class_runs_again_at_eight_and_the_default_is_one(self):
        names = sorted(VARIANTS)
        self.assertEqual((ghdiscover.DEFAULT_GRAPHQL_CONCURRENCY, WIDTH), (1, 8))
        self.assertEqual(len(names), 19, names)
        for want in ("GraphqlIsolationTestsAtEight", "GraphqlRateLimitTestsAtEight", "ArchiveScanAllTestsAtEight",
                     "DiscoverContentTestsAtEight", "GraphqlCommandLineTestsAtEight"):
            self.assertIn(want, names)

    def test_their_calls_go_through_threads(self):
        case = VARIANTS["GraphqlFirstAskTestsAtEight"](
            "test_a_listing_page_is_one_call_and_its_answer_queues_keeps_and_drops")
        result = unittest.TestResult()
        case.run(result)
        self.assertEqual((result.wasSuccessful(), [t.name for t in case.spawned]), (True, ["lazaret-graphql-1"]))

if __name__ == "__main__":
    unittest.main()
