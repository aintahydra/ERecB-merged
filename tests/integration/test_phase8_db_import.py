from __future__ import annotations

import sqlite3
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from erecb_triage.config import load_config
from erecb_triage.db_import import import_database_set
from erecb_triage.sqlite_snapshots import create_snapshot


ROOT = Path(__file__).parents[2]
for provider in ("ERecB-FileIntel", "ErecB-IPIntel", "ERecB-GHIntel"):
    sys.path.insert(0, str(ROOT / "providers" / provider / "src"))

from erecb_fileintel.db.repository import Repository as FileRepository  # noqa: E402
from erecb_ipintel.db import Database as IpDatabase  # noqa: E402
from ghintel.database import initialize as init_gh  # noqa: E402
from ghintel.database import database as gh_database, upsert_requested_repository  # noqa: E402
from ghintel.snapshots import create_snapshot as gh_snapshot  # noqa: E402


class DatabaseImportTests(unittest.TestCase):
    def test_three_snapshot_set_dry_run_import_and_replay(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            producer = base / "producer"
            producer.mkdir()
            file_db, ip_db, gh_db = (producer / part for part in ("file.sqlite3", "ip.sqlite3", "gh.sqlite3"))
            connection = sqlite3.connect(file_db)
            connection.row_factory = sqlite3.Row
            FileRepository(connection).initialize_schema()
            connection.close()
            ip = IpDatabase(ip_db)
            ip.initialize()
            ip.close()
            init_gh(gh_db)
            copied = base / "copied"
            copied.mkdir()
            file_copy, ip_copy, gh_copy = (copied / part for part in ("file.sqlite3", "ip.sqlite3", "gh.sqlite3"))
            create_snapshot(file_db, file_copy, producer="fileintel", version_table="schema_version")
            create_snapshot(ip_db, ip_copy, producer="ipintel", version_table="schema_migrations")
            gh_snapshot(gh_db, gh_copy)
            config = load_config("config/watcher_all.yaml")
            dry = import_database_set(config, base, fileintel=file_copy, ipintel=ip_copy,
                                      ghintel=gh_copy, dry_run=True)
            self.assertTrue(dry["dry_run"])
            self.assertFalse((base / "dbs").exists())
            applied = import_database_set(config, base, fileintel=file_copy, ipintel=ip_copy, ghintel=gh_copy)
            self.assertFalse(applied["dry_run"])
            self.assertEqual(len(applied["destinations"]), 3)
            repeated = import_database_set(config, base, fileintel=file_copy, ipintel=ip_copy, ghintel=gh_copy)
            self.assertTrue(repeated["applied"]["ghintel"]["already_imported"])
            self.assertTrue(repeated["applied"]["ipintel"]["already_imported"])
            original_replace = os.replace
            failed = False

            def interrupt_second_activation(source, destination):
                nonlocal failed
                if (not failed and Path(source).name == "activate.sqlite3"
                        and Path(destination).name == "ipintel.sqlite3"):
                    failed = True
                    raise OSError("injected activation failure")
                return original_replace(source, destination)

            with patch("erecb_triage.db_import.os.replace", side_effect=interrupt_second_activation):
                with self.assertRaisesRegex(OSError, "injected activation failure"):
                    import_database_set(config, base, fileintel=file_copy, ipintel=ip_copy, ghintel=gh_copy)
            self.assertTrue(failed)
            for destination in applied["destinations"].values():
                with sqlite3.connect(destination) as connection:
                    self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_missing_only_export_distinguishes_known_indicators_from_all(self):
        import hashlib
        import zipfile

        from erecb_triage.dispatcher import Dispatcher
        from erecb_triage.events import WatchEvent
        from erecb_triage.exchange import read_bundle
        from erecb_triage.request_export import export_requests

        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            dbs = base / "dbs"
            dbs.mkdir()
            known = b"MZ 8.8.8.8 https://github.com/Owner/Known\n"
            unknown = b"MZ 1.1.1.1 https://github.com/Other/Missing\n"
            file_conn = sqlite3.connect(dbs / "fileintel.sqlite3")
            file_conn.row_factory = sqlite3.Row
            files = FileRepository(file_conn)
            files.initialize_schema()
            files.upsert_hash_only(hashlib.sha256(known).hexdigest(), hashlib.md5(known).hexdigest())
            file_conn.close()
            ip_db = IpDatabase(dbs / "ipintel.sqlite3")
            ip_db.initialize()
            ip_db.ensure_ip_entity("8.8.8.8")
            ip_db.close()
            init_gh(dbs / "ghintel.sqlite3")
            with gh_database(dbs / "ghintel.sqlite3") as connection:
                upsert_requested_repository(connection, "https://github.com/Owner/Known")
            incoming = base / "in"
            incoming.mkdir()
            archive = incoming / "capture.zip.en_dec"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("known.exe", known)
                bundle.writestr("unknown.exe", unknown)
            config = load_config()
            config["processors"]["file_retriever"]["classifier"] = {"use_magic": False, "extension_fallback": True}
            with Dispatcher(config, base_dir=base) as dispatcher:
                dispatcher.dispatch(WatchEvent.added(incoming, archive))
                capture_id = dispatcher.list_captures()[0]["id"]
                missing = base / "missing.json"
                export_requests(dispatcher, capture_id, missing)
                self.assertEqual(read_bundle(missing)["counts"], {"files": 1, "ips": 1, "repositories": 1})
                all_items = base / "all.json"
                export_requests(dispatcher, capture_id, all_items, selection="all")
                self.assertEqual(read_bundle(all_items)["counts"], {"files": 2, "ips": 2, "repositories": 2})


if __name__ == "__main__":
    unittest.main()
