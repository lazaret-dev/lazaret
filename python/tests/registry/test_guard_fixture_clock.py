"""The guard's fake registries date fresh releases when each server starts."""

import datetime
import unittest

from tests.registry import _guard_support as gs


class FixtureClockTests(unittest.TestCase):
    def test_registry_ages_are_derived_from_each_fixture_start(self):
        started = datetime.datetime(2031, 2, 3, 4, 5, 6, tzinfo=datetime.timezone.utc)
        npm = gs.default_npm_packages(started)
        pypi = gs.default_pypi_files(started)
        npm_fresh = npm["fresh-pkg"]["1.1.0"][2]
        pypi_fresh = next(published for filename, _data, published in pypi["fresh-py"]
                          if "-1.1-" in filename)
        self.assertEqual(npm_fresh, started - datetime.timedelta(hours=1))
        self.assertEqual(pypi_fresh, started - datetime.timedelta(hours=1))


if __name__ == "__main__":
    unittest.main()
