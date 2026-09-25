"""Review fix: server errors survive pickle and copy (e.g. crossing a
multiprocessing boundary or being copied by a test framework)."""

import copy
import pickle
import unittest

from lazaret import pg
from lazaret.pg.errors import error_from_fields

FIELDS = {"S": "ERROR", "V": "ERROR", "C": "23505", "M": "duplicate key value",
          "D": "Key (id)=(1) already exists.", "t": "lz_t", "n": "lz_t_pkey"}


class ErrorPickleTests(unittest.TestCase):
    def assert_same(self, a, b):
        self.assertIs(type(a), type(b))
        self.assertEqual(str(a), str(b))
        self.assertEqual(a.fields, b.fields)
        for attr in ("severity", "sqlstate", "message", "detail", "hint", "table", "constraint"):
            self.assertEqual(getattr(a, attr), getattr(b, attr), attr)

    def test_every_mapped_class_round_trips(self):
        for code in ("22012", "23505", "28P01", "40001", "42P01", "57014", "XX000"):
            err = error_from_fields(dict(FIELDS, C=code))
            with self.subTest(code=code, cls=type(err).__name__):
                self.assert_same(err, pickle.loads(pickle.dumps(err)))
                self.assert_same(err, copy.copy(err))
                self.assert_same(err, copy.deepcopy(err))

    def test_copy_does_not_share_the_fields_dict(self):
        err = pg.IntegrityError(dict(FIELDS))
        clone = copy.copy(err)
        clone.fields["M"] = "changed"
        self.assertEqual(err.fields["M"], "duplicate key value")

    def test_client_side_errors_round_trip(self):
        for err in (pg.InterfaceError("x"), pg.OperationalError("y"), pg.AuthenticationError("z")):
            with self.subTest(cls=type(err).__name__):
                clone = pickle.loads(pickle.dumps(err))
                self.assertIs(type(clone), type(err))
                self.assertEqual(clone.args, err.args)


if __name__ == "__main__":
    unittest.main()
