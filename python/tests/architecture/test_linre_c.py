"""linre against Python's re: the rule pack on texts sampled from each
pattern, the other half of the patterns (see test_linre_b.py). Skipped where
the native library is not built.
"""
import unittest

from tests.architecture import test_linre_b as first


class LinreSampledTestsC(first.LinreSampledTests):
    PART = 1


if __name__ == "__main__":
    unittest.main()
