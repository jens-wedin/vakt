"""Adding `announced` to an existing registry must not turn every device
already in it into a new-device alert on the next poll."""
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import config  # noqa: E402
import store  # noqa: E402

OLD_SCHEMA = """
CREATE TABLE devices (
  mac TEXT PRIMARY KEY, name TEXT, first_seen TEXT, last_seen TEXT,
  last_network TEXT, last_ip TEXT, is_wired INTEGER);
"""


class Migration(unittest.TestCase):
    def setUp(self):
        self._saved_path, self._saved_conn = config.DB_PATH, store._conn

    def tearDown(self):
        config.DB_PATH, store._conn = self._saved_path, self._saved_conn

    def _open_old_db_with(self, *macs):
        path = os.path.join(tempfile.mkdtemp(), "old.db")
        con = sqlite3.connect(path)
        con.executescript(OLD_SCHEMA)
        for m in macs:
            con.execute("INSERT INTO devices(mac,name,last_network,last_ip) "
                        "VALUES(?,?,?,?)", (m, "known thing", "Default", "192.168.1.5"))
        con.commit()
        con.close()
        store._conn = None          # force a fresh connection, which migrates
        config.DB_PATH = path
        store.db()

    def test_devices_already_in_the_registry_are_marked_announced(self):
        self._open_old_db_with("aa:11:22:33:44:55", "bb:11:22:33:44:55")
        for row in store.get_devices().values():
            self.assertEqual(row["announced"], 1, row["mac"])

    def test_a_device_added_after_the_migration_starts_unannounced(self):
        self._open_old_db_with("aa:11:22:33:44:55")
        store.upsert_device("cc:11:22:33:44:55", "newcomer", "Default", "", 0,
                            store.now_iso())
        self.assertEqual(store.get_devices()["cc:11:22:33:44:55"]["announced"], 0)


if __name__ == "__main__":
    unittest.main()
