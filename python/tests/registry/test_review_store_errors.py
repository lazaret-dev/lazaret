"""A --db file that is not a SQLite database.

sqlite3.connect() opens any file lazily, so `lazaret-registry list --db
notes.txt` first failed while creating the tables: an uncaught
sqlite3.DatabaseError ("file is not a database") and a traceback. The
Store now reports it as StoreConfigError, which the CLI prints as one line
(exit 1) and the MCP tools return as a tool error, and it closes the
connection it opened.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from lazaret.registry import repo
from tests import _support


class Tracked(repo.Store):
    opened = []

    def __init__(self, *args, **kwargs):
        Tracked.opened.append(self)
        super().__init__(*args, **kwargs)


class NotADatabaseTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.path = os.path.join(d.name, "notadb.db")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("these are my notes, not a database\n" * 200)

    def test_store_raises_a_config_error_and_closes(self):
        Tracked.opened = []
        with self.assertRaises(repo.StoreConfigError) as cm:
            Tracked(self.path)
        self.assertIn("file is not a database", str(cm.exception))
        self.assertIn("--db", str(cm.exception))
        self.assertEqual([getattr(s, "_closed", False) for s in Tracked.opened], [True])

    def test_sqlite_prefix_too(self):
        with self.assertRaises(repo.StoreConfigError):
            repo.Store("sqlite:" + self.path)

    def test_cli_prints_one_line_not_a_traceback(self):
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(
            filter(None, [_support.SRC, os.environ.get("PYTHONPATH")])))
        env.pop("LAZARET_DB", None)
        out = subprocess.run([sys.executable, "-m", "lazaret.registry", "list", "--db", self.path],
                             capture_output=True, text=True, encoding="utf-8", errors="replace",
                             env=env, timeout=40)
        self.assertEqual(out.returncode, 1, out.stderr)
        self.assertNotIn("Traceback", out.stderr)
        self.assertIn("file is not a database", out.stderr)

    def test_other_schema_errors_are_unchanged(self):
        # only SQLite's own errors are a configuration problem
        with mock.patch.object(repo.Store, "_init_schema", side_effect=KeyError("x")):
            with self.assertRaises(KeyError):
                repo.Store(os.path.join(os.path.dirname(self.path), "fresh.db"))

    def test_a_fresh_file_still_works(self):
        with repo.Store(os.path.join(os.path.dirname(self.path), "fresh.db")) as store:
            self.assertEqual(list(store.status()), [])


if __name__ == "__main__":
    unittest.main()
