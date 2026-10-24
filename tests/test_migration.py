import json
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

import storage_tools
from database import Database
from state import Store, StewardError, encode
from storage_tools import backup_database, export_dataset, migrate_json


class MigrationStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.limits = {
            "file_bytes": 1024 * 1024,
            "total_bytes": 8 * 1024 * 1024,
            "scan_seconds": 5,
        }

    def tearDown(self):
        self.temporary.cleanup()

    def _legacy(self):
        directory = self.base / "state"
        store = Store(directory, self.limits)
        payloads = {
            "current.json": b'{"version":1,"future_state":{"keep":true}}\n',
            "inventory.json": b'{"version":1,"resources":{}}\n',
            "operations.json": (
                b'[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
                b'"kind":"future_operation","status":"recorded",'
                b'"future_field":{"keep":1}}]\n'
            ),
        }
        for name, payload in payloads.items():
            store.target(name).write_bytes(payload)
        return store, payloads

    def _initialized(self):
        store = Store(self.base / "state", self.limits)
        store.initialize_database()
        return store

    def test_new_init_without_legacy_json_is_already_sqlite(self):
        store = self._initialized()

        with store.lock():
            report = migrate_json(store, apply=True)

        self.assertEqual(report["status"], "already_sqlite")
        self.assertFalse(store.target("current.json").exists())
        self.assertEqual(store.export_data(), {
            "current.json": None,
            "inventory.json": None,
            "operations.json": None,
        })

    def test_valid_legacy_data_round_trips_and_source_bytes_stay_unchanged(self):
        store, payloads = self._legacy()

        with store.lock():
            report = migrate_json(store, apply=True)

        self.assertEqual(report["status"], "migrated")
        self.assertTrue(store.database_exists())
        self.assertEqual(store.read("current.json"), {
            "version": 1,
            "future_state": {"keep": True},
        })
        self.assertEqual(store.read("operations.json")[0]["kind"], "future_operation")
        for name, payload in payloads.items():
            self.assertEqual(store.target(name).read_bytes(), payload)
        self.assertFalse(store.target(storage_tools.STAGING).exists())
        self.assertTrue(store.target(storage_tools.RECEIPT).exists())

    def test_migration_preview_does_not_write_or_change_legacy_bytes(self):
        store, payloads = self._legacy()
        before = {name: store.target(name).read_bytes() for name in payloads}

        with store.lock():
            report = migrate_json(store, apply=False)

        self.assertEqual(report["status"], "migration_plan")
        self.assertFalse(report["applied"])
        self.assertFalse(store.database_exists())
        self.assertFalse(store.target(storage_tools.STAGING).exists())
        self.assertFalse(store.target(storage_tools.RECEIPT).exists())
        self.assertEqual({name: store.target(name).read_bytes() for name in payloads}, before)

    def test_invalid_json_and_invalid_typed_state_are_not_published(self):
        cases = [
            (b'{"version":1', "旧状态不是有效 JSON"),
            (b'{"version":"wrong"}\n', "current.json 结构错误"),
        ]
        for payload, message in cases:
            with self.subTest(message=message):
                store, payloads = self._legacy()
                store.target("current.json").write_bytes(payload)

                with store.lock(), self.assertRaisesRegex(StewardError, message):
                    migrate_json(store, apply=True)

                self.assertFalse(store.database_exists())
                self.assertFalse(store.target(storage_tools.STAGING).exists())
                self.assertFalse(store.target(storage_tools.RECEIPT).exists())
                self.assertEqual(store.target("current.json").read_bytes(), payload)
                self.assertEqual(store.target("inventory.json").read_bytes(), payloads["inventory.json"])

    def test_repeated_migration_does_not_overwrite_new_sqlite_records(self):
        store, _ = self._legacy()
        with store.lock():
            migrate_json(store, apply=True)
        new_current = {"version": 1, "new_generation": {"value": 2}}
        store.write("current.json", new_current)

        with store.lock():
            report = migrate_json(store, apply=True)

        self.assertEqual(report["status"], "already_sqlite")
        self.assertEqual(store.read("current.json"), new_current)

    def test_missing_database_with_receipt_blocks_without_reimporting_legacy(self):
        store, payloads = self._legacy()
        with store.lock():
            migrate_json(store, apply=True)
        store.database_path.unlink()

        with store.lock(), self.assertRaises(StewardError):
            migrate_json(store, apply=True)

        self.assertFalse(store.database_exists())
        for name, payload in payloads.items():
            self.assertEqual(store.target(name).read_bytes(), payload)

    def test_source_change_after_staging_blocks_publication(self):
        store, payloads = self._legacy()
        first = storage_tools.LegacyInput(store)
        changed = storage_tools.LegacyInput(store)
        changed.fingerprints = dict(changed.fingerprints)
        changed.fingerprints["current.json"] = "0" * 64

        with patch.object(storage_tools, "LegacyInput", side_effect=[first, changed]):
            with store.lock(), self.assertRaisesRegex(StewardError, "旧 JSON 已变化"):
                migrate_json(store, apply=True)

        self.assertFalse(store.database_exists())
        self.assertTrue(store.target(storage_tools.STAGING).exists())
        self.assertFalse(store.target(storage_tools.RECEIPT).exists())
        self.assertEqual(store.target("current.json").read_bytes(), payloads["current.json"])

    def test_policy_guard_blocks_before_receipt_and_formal_publish(self):
        store, _ = self._legacy()
        guard = Mock(side_effect=StewardError("policy changed"))

        with store.lock(), self.assertRaisesRegex(StewardError, "policy changed"):
            migrate_json(store, apply=True, policy_guard=guard)

        guard.assert_called_once_with()
        self.assertFalse(store.database_exists())
        self.assertTrue(store.target(storage_tools.STAGING).exists())
        self.assertFalse(store.target(storage_tools.RECEIPT).exists())

    def test_receipt_and_staging_resume_after_publish_interruption(self):
        store, _ = self._legacy()
        real_link = os.link
        interrupted = False

        def link_once_at_formal_database(source, destination, *args, **kwargs):
            nonlocal interrupted
            if Path(destination) == store.database_path and not interrupted:
                interrupted = True
                raise OSError("interrupted")
            return real_link(source, destination, *args, **kwargs)

        with patch.object(storage_tools.os, "link", side_effect=link_once_at_formal_database):
            with store.lock(), self.assertRaisesRegex(StewardError, "发布未能确认"):
                migrate_json(store, apply=True)
            self.assertFalse(store.database_exists())
            self.assertTrue(store.target(storage_tools.STAGING).exists())
            self.assertTrue(store.target(storage_tools.RECEIPT).exists())

            with store.lock():
                report = migrate_json(store, apply=True)

        self.assertEqual(report["status"], "migrated")
        self.assertEqual(store.read("current.json")["future_state"], {"keep": True})
        self.assertFalse(store.target(storage_tools.STAGING).exists())

    def test_published_database_is_readable_when_directory_sync_is_interrupted(self):
        store, _ = self._legacy()

        with patch.object(storage_tools, "_sync_directory", side_effect=OSError("sync interrupted")):
            with store.lock(), self.assertRaisesRegex(StewardError, "发布未能确认"):
                migrate_json(store, apply=True)

        self.assertTrue(store.database_exists())
        store.check_database()
        self.assertEqual(store.read("current.json")["future_state"], {"keep": True})
        self.assertTrue(store.target(storage_tools.STAGING).exists())
        self.assertTrue(store.target(storage_tools.RECEIPT).exists())

        with store.lock():
            report = migrate_json(store, apply=True)
        self.assertEqual(report["status"], "already_sqlite")
        self.assertTrue(report["applied"])
        self.assertFalse(report["publication_cleanup_pending"])
        self.assertFalse(store.target(storage_tools.STAGING).exists())

    def test_preview_reports_same_inode_cleanup_without_removing_it(self):
        store, _ = self._legacy()
        with patch.object(storage_tools, "_sync_directory", side_effect=OSError("sync interrupted")):
            with store.lock(), self.assertRaises(StewardError):
                migrate_json(store, apply=True)

        with store.lock():
            report = migrate_json(store, apply=False)
        self.assertEqual(report["status"], "already_sqlite")
        self.assertFalse(report["applied"])
        self.assertTrue(report["publication_cleanup_pending"])
        self.assertTrue(store.target(storage_tools.STAGING).exists())

    def test_different_inode_staging_is_preserved_and_rejected(self):
        store = self._initialized()
        formal = {"version": 1, "formal": True}
        store.write("current.json", formal)
        staging = store.target(storage_tools.STAGING)
        Database.initialize(staging)
        Database(staging, self.limits["file_bytes"]).write(
            "current.json", {"version": 1, "staging": True})

        with store.lock(), self.assertRaisesRegex(StewardError, "不是同一对象"):
            migrate_json(store, apply=True)

        self.assertTrue(staging.exists())
        self.assertEqual(store.read("current.json"), formal)

    def test_lock_blocks_concurrent_migration(self):
        store, _ = self._legacy()
        second = Store(store.path, self.limits)
        with store.lock():
            with self.assertRaisesRegex(StewardError, "已有巡检或操作运行"):
                with second.lock():
                    pass

    def test_export_returns_envelope_and_uses_exclusive_external_output(self):
        store = self._initialized()
        data = {"version": 1, "future_state": {"keep": True}}
        store.write("current.json", data)

        report = export_dataset(store, "current")
        self.assertEqual(report["status"], "exported")
        self.assertEqual(report["dataset"], "current")
        self.assertEqual(report["data"], data)
        self.assertEqual(export_dataset(store, "inventory")["data"],
                         {"version": 1, "resources": {}})

        output = (self.base / "current-export.json").resolve()
        written = export_dataset(store, "current", output)
        self.assertEqual(written["output"], str(output))
        envelope = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(envelope["data"], data)
        with self.assertRaises(FileExistsError):
            export_dataset(store, "current", output)

    def test_export_and_backup_reject_state_paths_and_symlink_targets(self):
        store = self._initialized()
        store.write("current.json", {"version": 1, "value": True})
        inside = store.target("exports")
        inside.mkdir()
        inside_export = inside / "current.json"
        inside_backup = inside / "backup.sqlite3"
        outside = (self.base / "outside-target").resolve()
        outside.write_bytes(b"existing")
        symlink = (self.base / "output-link").resolve()
        symlink.symlink_to(outside)

        for operation, destination in [
            (export_dataset, inside_export),
            (backup_database, inside_backup),
            (export_dataset, symlink),
            (backup_database, symlink),
        ]:
            with self.subTest(operation=operation.__name__, destination=str(destination)):
                with self.assertRaisesRegex(StewardError, "(输出|导出与备份)"):
                    if operation is export_dataset:
                        operation(store, "current", destination)
                    else:
                        operation(store, destination)
        self.assertEqual(outside.read_bytes(), b"existing")

    def test_backup_creates_external_readable_snapshot_without_overwrite(self):
        store = self._initialized()
        data = {"version": 1, "future_state": {"keep": True}}
        store.write("current.json", data)
        output = (self.base / "backup.sqlite3").resolve()

        report = backup_database(store, output)

        self.assertEqual(report["status"], "backed_up")
        self.assertTrue(report["verified"])
        backup = Database(output, self.limits["file_bytes"])
        backup.check()
        self.assertEqual(backup.read("current.json"), data)
        with self.assertRaises(FileExistsError):
            backup_database(store, output)

    def test_backup_checks_source_before_creating_output(self):
        store = self._initialized()
        output = (self.base / "invalid-source.sqlite3").resolve()
        with patch.object(store, "check_database", side_effect=StewardError("源库完整性检查失败")) as check:
            with self.assertRaisesRegex(StewardError, "源库完整性检查失败"):
                backup_database(store, output)
        check.assert_called_once_with()
        self.assertFalse(output.exists())

    def test_backup_preserves_existing_companion_files(self):
        store = self._initialized()
        output = (self.base / "backup.sqlite3").resolve()
        companion = Path(str(output) + "-journal")
        companion.write_bytes(b"existing journal")

        with self.assertRaisesRegex(StewardError, "伴随文件"):
            backup_database(store, output)

        self.assertFalse(output.exists())
        self.assertEqual(companion.read_bytes(), b"existing journal")

    def test_backup_ignores_state_budget_but_checks_destination_space(self):
        store = self._initialized()
        store.write("current.json", {"version": 1, "value": True})
        limited = Store(store.path, dict(self.limits, total_bytes=store.usage()))
        output = (self.base / "at-budget.sqlite3").resolve()

        report = backup_database(limited, output)

        self.assertEqual(report["status"], "backed_up")
        Database(output, self.limits["file_bytes"]).check()

        destination = (self.base / "no-space.sqlite3").resolve()
        with patch.object(storage_tools.shutil, "disk_usage", return_value=Mock(free=0)):
            with self.assertRaisesRegex(StewardError, "备份目标空间不足"):
                backup_database(store, destination)
        self.assertFalse(destination.exists())

    def test_migration_result_is_writable_or_cleanly_refused(self):
        limits = {"file_bytes": 1024 * 1024, "total_bytes": 300_000}

        def baseline(count):
            records = {f"/root/data/entry-{index:05d}.json": {"id": f"1:{index}", "kind": "file",
                                                              "size": index, "mtime": 1792377000}
                       for index in range(count)}
            return {"version": 1, "baselines": {"/root": {"complete": True, "root_id": "1:2",
                                                         "records": records, "directories": {}}}}

        for count in (5, 100, 1000, 4000):
            with self.subTest(count=count):
                store = Store(self.base / f"limited-{count}", limits)
                payload = encode(baseline(count))
                store.target("current.json").write_bytes(payload)
                store.target("inventory.json").write_bytes(b'{"version":1,"resources":{}}\n')
                try:
                    with store.lock():
                        report = migrate_json(store, apply=True)
                except StewardError:
                    # 容量不足时必须在发布前停下，旧数据保持原样。
                    self.assertFalse(store.database_exists())
                    self.assertEqual(store.target("current.json").read_bytes(), payload)
                    continue
                self.assertEqual(report["status"], "migrated")
                # 迁移成功后必须还能写入，否则容量判据在发布前没有生效。
                store.write("current.json", {"version": 1, "probe": count})


if __name__ == "__main__":
    unittest.main()
