"""Engine parity for following install hooks and the install-script and
import-time tests, the other half of the hooks corpus: see
test_rust_parity_hooks.py, which reads every other case from the first;
this module reads the rest. Skipped where the native library is not built.
"""
import unittest

from tests.architecture import test_rust_parity_hooks as first


class RustHookParityTestsB(first.RustHookParityTests):
    PART = 1


if __name__ == "__main__":
    unittest.main()
