import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / "tools"))

from database import Database, DatabaseError
from state import Store, StewardError


class DatabaseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.limits = {"file_bytes": 1024 * 1024, "total_bytes": 8 * 1024 * 1024}
        self.store = Store(self.directory, self.limits)
        self.store.initialize_database()

    def test_operations_can_be_updated_twice(self):
        first = [{"id": "a" * 32, "kind": "x", "status": "planned"}]
        second = first + [{"id": "b" * 32, "kind": "y", "status": "planned"}]
        self.store.write("operations.json", first)
        self.store.write("operations.json", second)
        self.assertEqual(self.store.read("operations.json"), second)

    def test_transaction_rolls_back_all_datasets(self):
        self.store.import_data({"current.json": {"before": True}})
        with self.assertRaises(StewardError):
            self.store.import_data({"current.json": {"before": False}, "operations.json": 1})
        self.assertEqual(self.store.read("current.json"), {"before": True})
        self.assertEqual(self.store.read("operations.json", "missing"), "missing")

    def test_mid_transaction_sqlite_failure_rolls_back_dataset(self):
        self.store.write("current.json", {"keep": True})
        connection = sqlite3.connect(self.store.database_path)
        try:
            connection.execute(
                "CREATE TRIGGER force_write_failure AFTER INSERT ON rows "
                "WHEN NEW.value_json='2' BEGIN SELECT RAISE(ABORT, 'forced full'); END")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StewardError):
            self.store.write("current.json", {"first": 1, "boom": 2})
        self.assertEqual(self.store.read("current.json"), {"keep": True})

    def test_baselines_and_unknown_key_round_trip(self):
        value = {
            "baselines": {
                "/empty": {"records": {}, "directories": {}},
                "/root": {"records": {"a/b": {"size": 1}}, "directories": {"a": {"bytes": 2}}},
            },
            "baselines.records": {"unknown": True},
            "": {"future_field": True},
        }
        self.store.write("current.json", value)
        self.assertEqual(self.store.read("current.json"), value)

    def test_read_preserves_section_order_and_field_selection(self):
        value = {"z": 0, "a": 1,
                 "baselines": {"/z": {"complete": False}, "/a": {"complete": False}}, "middle": 2}
        self.store.write("current.json", value)

        loaded = self.store.read("current.json")
        self.assertEqual(list(loaded), list(value))
        self.assertEqual(list(loaded["baselines"]), list(value["baselines"]))
        selected = self.store.read("current.json", fields=("a", "baselines"))
        self.assertEqual(list(selected), ["a", "baselines"])
        self.assertEqual(selected, {"a": 1, "baselines": value["baselines"]})

    def test_cross_process_read(self):
        self.store.write("current.json", {"value": [1, 2, 3]})
        script = (
            "import json,sys; sys.path.insert(0, sys.argv[2]); "
            "from state import Store; "
            "print(json.dumps(Store(sys.argv[1], {'file_bytes':1048576, 'total_bytes':8388608}).read('current.json'), sort_keys=True))"
        )
        result = subprocess.run([sys.executable, "-c", script, str(self.directory),
                                 str(Path(__file__).parents[1] / "tools")],
                                check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout), {"value": [1, 2, 3]})

    def test_unchanged_row_does_not_fire_write_trigger(self):
        old = [{"id": "a" * 32, "value": 1}, {"id": "b" * 32, "value": 2}]
        new = [{"id": "a" * 32, "value": 9}, {"id": "b" * 32, "value": 2}]
        self.store.write("operations.json", old)
        connection = sqlite3.connect(self.store.database_path)
        try:
            connection.execute("CREATE TABLE row_changes (item_key TEXT, action TEXT)")
            connection.execute(
                "CREATE TRIGGER rows_update AFTER UPDATE ON rows BEGIN "
                "INSERT INTO row_changes VALUES (NEW.item_key, 'update'); END")
            connection.execute(
                "CREATE TRIGGER rows_insert AFTER INSERT ON rows BEGIN "
                "INSERT INTO row_changes VALUES (NEW.item_key, 'insert'); END")
            connection.execute(
                "CREATE TRIGGER rows_delete AFTER DELETE ON rows BEGIN "
                "INSERT INTO row_changes VALUES (OLD.item_key, 'delete'); END")
            connection.commit()
        finally:
            connection.close()
        self.store.write("operations.json", new)
        connection = sqlite3.connect(self.store.database_path)
        try:
            changes = connection.execute("SELECT item_key, action FROM row_changes").fetchall()
        finally:
            connection.close()
        self.assertEqual(changes, [(json.dumps("a" * 32), "update")])

    def test_capacity_rejects_before_database_growth(self):
        before = self.store.database_path.stat().st_size
        limited = Store(self.directory, dict(self.limits, total_bytes=self.store.usage() + 1))
        with self.assertRaises(StewardError):
            limited.write("current.json", {"large": "x" * 1000})
        self.assertEqual(limited.database_path.stat().st_size, before)
        self.assertEqual(limited.read("current.json", "missing"), "missing")

    def test_read_limit_uses_utf8_bytes_before_fetching_rows(self):
        self.store.write("current.json", {"中文": "界" * 100})
        limited = Store(self.directory, dict(self.limits, file_bytes=64))
        with self.assertRaises(StewardError):
            limited.read("current.json")

    def test_large_baselines_use_total_budget_after_small_record_limit(self):
        limits = {"file_bytes": 4096, "total_bytes": 4 * 1024 * 1024}
        store = Store(self.directory / "large", limits)
        store.initialize_database()
        baselines = {}
        for root_number in range(4):
            records = {
                (f"/workspace/project-{root_number}/output/collected/session-2026-10-19/"
                 f"generated-items/entry-{entry:05d}-with-a-long-name.json"):
                    {"id": f"16777234:{entry + 100000000}", "kind": "file", "size": entry,
                     "mtime": 1792377000123456789, "birth": 1792300000.123456}
                for entry in range(1250)
            }
            baselines[f"/root-{root_number}"] = {
                "complete": True,
                "records": records,
                "directories": {},
            }
        value = {"version": 1, "baselines": baselines}
        self.assertGreater(len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")),
                           1024 * 1024)
        store.write("current.json", value)
        self.assertEqual(store.read("current.json"), value)
        changed = dict(value)
        changed["baselines"] = dict(baselines)
        changed["baselines"]["/root-2"] = dict(baselines["/root-2"])
        changed["baselines"]["/root-2"]["records"] = dict(baselines["/root-2"]["records"])
        changed_path = next(iter(baselines["/root-2"]["records"]))
        changed["baselines"]["/root-2"]["records"][changed_path] = {"size": 999999}
        store.write("current.json", changed)
        self.assertEqual(store.read("current.json"), changed)

    def test_scan_progress_is_partitioned_and_round_trips(self):
        root = "/workspace/root"
        entry = {
            "root_id": "16777234:42",
            "scope": {"version": 2, "root": root, "device": 16777234,
                      "exclude_names": [".git"], "state_path": "/state", "volume_policy": "root_device_only",
                      "max_depth": 8, "exclude_paths": [], "other_volumes": {
                          "count": 0, "digest": "0" * 64, "samples": [], "truncated": False}},
            "records": {f"{root}/dir/file-{index}.txt": {
                "id": f"16777234:{index}", "kind": "file", "size": index,
                "mtime": 1792377000123456789, "birth": 1792300000.5} for index in range(20)},
            "allocated": {f"{root}/dir/file-{index}.txt": index * 512 for index in range(20)},
            "queue": [{"path": f"{root}/dir", "depth": 1, "cursor": "file-9.txt",
                       "dir_id": {"id": "16777234:7", "mtime": 1792377000123456789}, "restarts": 1}],
            "excluded": {"configured": 2},
            "excluded_by_dir": {root: {"configured": 2}, f"{root}/dir": {"other_volume": 1}},
            "boundaries": [[f"{root}/mount", 42]],
            "rounds": 3,
            "entries": 22,
            "gaps": ["扫描达到时间或条目预算，本轮结果不用于判断删除"],
            "vanished": [f"{root}/gone"],
        }
        value = {"version": 1, "before": True, "scan_progress": {root: entry, "next_index": 0},
                 "after": False}
        self.store.write("current.json", value)
        self.assertEqual(self.store.read("current.json"), value)
        selected = self.store.read("current.json", fields=("scan_progress",))
        self.assertEqual(selected, {"scan_progress": value["scan_progress"]})

        connection = sqlite3.connect(self.store.database_path)
        try:
            sections = [row[0] for row in connection.execute(
                "SELECT section FROM sections WHERE dataset='current.json' ORDER BY ordinal")]
            progress_rows = connection.execute(
                "SELECT section, item_key FROM rows WHERE dataset='current.json' "
                "AND section LIKE '[\"scan_progress\"%' ORDER BY section, item_key").fetchall()
        finally:
            connection.close()
        self.assertIn('["scan_progress"]', sections)
        for child in ["snapshot", "records", "allocated", "excluded_by_dir"]:
            self.assertIn(json.dumps(["scan_progress", root, child], ensure_ascii=False, separators=(",", ":")), sections)
        self.assertIn(('["scan_progress","/workspace/root","records"]',
                       f"{root}/dir/file-0.txt"), progress_rows)
        self.assertIn(('["scan_progress"]', "next_index"), progress_rows)
        self.assertLess(sections.index('["scan_progress"]'),
                        sections.index(json.dumps(["scan_progress", root, "snapshot"], ensure_ascii=False, separators=(",", ":"))))

        changed = copy.deepcopy(value)
        changed["scan_progress"] = {"next_index": 0}
        self.store.write("current.json", changed)
        self.assertEqual(self.store.read("current.json"), changed)
        connection = sqlite3.connect(self.store.database_path)
        try:
            removed = connection.execute(
                "SELECT COUNT(*) FROM sections WHERE dataset='current.json' "
                "AND section LIKE '[\"scan_progress\",%'").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(removed, 0)

    def test_large_scan_progress_rows_stay_below_single_record_limit(self):
        limits = {"file_bytes": 1024 * 1024, "total_bytes": 32 * 1024 * 1024}
        store = Store(self.directory / "progress-rows", limits)
        store.initialize_database()
        root = "/workspace/root"
        names = [f"{root}/目录组 {index // 60}/子目录 {index}/资料 {index:05d}.txt" for index in range(9000)]
        entry = {
            "root_id": "16777234:42",
            "scope": {"version": 2, "root": root, "device": 16777234, "exclude_names": [],
                      "state_path": "/state", "volume_policy": "root_device_only", "max_depth": 8,
                      "exclude_paths": [], "other_volumes": {
                          "count": 0, "digest": "0" * 64, "samples": [], "truncated": False}},
            "records": {path: {"id": f"16777234:{index}", "kind": "file", "size": index,
                               "mtime": 1792377000123456789, "birth": 1792300000.5}
                        for index, path in enumerate(names)},
            "allocated": {path: index * 512 for index, path in enumerate(names)},
            "queue": [{"path": f"{root}/目录组 {index // 60}", "depth": 1, "cursor": None, "dir_id": None}
                      for index in range(60)],
            "excluded": {}, "excluded_by_dir": {}, "boundaries": [],
            "rounds": 4, "entries": 9120, "gaps": [], "vanished": [],
        }
        value = {"version": 1, "scan_progress": {root: entry, "next_index": 0}}
        store.write("current.json", value)
        self.assertEqual(store.read("current.json"), value)
        connection = sqlite3.connect(store.database_path)
        try:
            sections = [row[0] for row in connection.execute(
                "SELECT section FROM sections WHERE dataset='current.json'")]
            payloads = [row[0] for row in connection.execute(
                "SELECT value_json FROM rows WHERE dataset='current.json'")]
        finally:
            connection.close()
        self.assertIn(json.dumps(["scan_progress", root, "records"], ensure_ascii=False, separators=(",", ":")), sections)
        largest = max(len(payload.encode("utf-8")) for payload in payloads)
        self.assertLessEqual(largest, limits["file_bytes"])
        self.assertGreater(len(json.dumps(entry["records"], ensure_ascii=False).encode("utf-8")),
                           limits["file_bytes"])
        self.assertEqual(len(store.read("current.json")["scan_progress"][root]["records"]), 9000)

    def test_single_record_limit_preserves_previous_state(self):
        limits = {"file_bytes": 256, "total_bytes": 4 * 1024 * 1024}
        store = Store(self.directory / "record-limit", limits)
        store.initialize_database()
        previous = {"version": 1, "baselines": {"/root": {"records": {"a": {"size": 1}}}}}
        store.write("current.json", previous)
        oversized = {"version": 1, "baselines": {
            "/root": {"records": {"a": {"detail": "x" * 1024}}}
        }}
        with self.assertRaises(StewardError):
            store.write("current.json", oversized)
        self.assertEqual(store.read("current.json"), previous)

    def test_sqlite_full_during_write_rolls_back(self):
        self.store.write("operations.json", [{"id": "a" * 32, "value": "old"}])
        old = self.store.read("operations.json")
        # 把总预算设在“当前库 + 一页”附近，写入大记录会在提交时撞上 SQLite full。
        limit = self.store.database_path.stat().st_size + 4096
        total_bytes = limit * 65 // 32 + 65536
        database = Database(self.store.database_path)
        large = [{"id": f"{item:032x}", "value": "x" * 600} for item in range(2000)]
        with self.assertRaises(DatabaseError) as raised:
            database.write("operations.json", large, total_bytes=total_bytes, outside_bytes=0)
        self.assertIn("容量", str(raised.exception))
        self.assertIn("full", str(raised.exception.__cause__).lower())
        self.assertEqual(self.store.read("operations.json"), old)

    def test_capacity_reports_limit_and_write_never_freezes_state(self):
        limits = {"file_bytes": 1024 * 1024, "total_bytes": 200_000}
        store = Store(self.directory / "steady", limits)
        store.initialize_database()
        capacity = store.capacity()
        self.assertTrue(capacity["writable"])
        self.assertEqual(capacity["total_bytes"], limits["total_bytes"])
        self.assertGreaterEqual(capacity["database_headroom_bytes"], 0)

        def baseline(count):
            records = {f"/workspace/entry-{index:05d}.data": {"id": f"1:{index}", "kind": "file",
                                                              "size": index, "mtime": 1792377000}
                       for index in range(count)}
            return {"version": 1, "baselines": {"/root": {"complete": True, "root_id": "1:2",
                                                         "records": records, "directories": {}}}}

        for count in [10, 200, 800, 2000, 4000]:
            try:
                store.write("current.json", baseline(count))
            except StewardError:
                pass
            # 无论本次写入成功还是被容量拒绝，状态都必须还能再写入。
            store.write("current.json", {"version": 1, "probe": count})
            self.assertTrue(store.capacity()["writable"])

    def test_export_uses_one_wal_snapshot_across_datasets(self):
        self.store.import_data({"current.json": {"state": "old"},
                                "inventory.json": {"resources": {"old": {"value": 1}}},
                                "operations.json": []})
        connection = sqlite3.connect(self.store.database_path)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.commit()
        finally:
            connection.close()
        database_path = self.store.database_path

        class SnapshotProbe(Database):
            def _read_dataset(self, connection, dataset, default):
                result = super()._read_dataset(connection, dataset, default)
                if dataset == "current.json":
                    writer = sqlite3.connect(database_path)
                    try:
                        writer.execute("UPDATE rows SET item_key='new', value_json=? "
                                       "WHERE dataset='inventory.json' AND item_key='old'",
                                       (json.dumps({"value": 2}),))
                        writer.commit()
                    finally:
                        writer.close()
                return result

        exported = SnapshotProbe(self.store.database_path).export_data()
        self.assertEqual(exported["inventory.json"], {"resources": {"old": {"value": 1}}})
        self.assertEqual(self.store.read("inventory.json"), {"resources": {"new": {"value": 2}}})

    def test_path_sidecar_and_legacy_json_boundaries(self):
        sidecar = Path(str(self.store.database_path) + "-wal")
        os.mkfifo(sidecar)
        try:
            with self.assertRaises(StewardError):
                self.store.read("current.json", {})
        finally:
            sidecar.unlink()
        legacy = self.directory / "legacy"
        legacy.mkdir()
        (legacy / "current.json").write_text('{"old":true}', encoding="utf-8")
        old_store = Store(legacy, self.limits)
        with self.assertRaises(StewardError):
            old_store.read("current.json", {})

    def test_strict_json_is_rejected(self):
        self.store.write("current.json", {"value": 1})
        connection = sqlite3.connect(self.store.database_path)
        try:
            section = connection.execute("SELECT section FROM sections").fetchone()[0]
            connection.execute("UPDATE rows SET value_json='NaN' WHERE section=?", (section,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StewardError):
            self.store.read("current.json")

    def test_corrupt_empty_scalar_unordered_array_and_duplicate_object_reject(self):
        def fresh(value):
            directory = self.directory / f"corrupt-{len(list(self.directory.iterdir()))}"
            store = Store(directory, self.limits)
            store.initialize_database()
            store.write("current.json", value)
            return store

        scalar = fresh({"scalar": 1})
        connection = sqlite3.connect(scalar.database_path)
        try:
            connection.execute("DELETE FROM rows")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StewardError):
            scalar.read("current.json")

        array = fresh({"values": [1, 2]})
        connection = sqlite3.connect(array.database_path)
        try:
            connection.execute("UPDATE rows SET position=3 WHERE position=1")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StewardError):
            array.read("current.json")

        object_store = fresh({"value": {"a": 1, "b": 2}})
        connection = sqlite3.connect(object_store.database_path)
        try:
            section = connection.execute(
                "SELECT section FROM sections WHERE section='[\"value\"]'").fetchone()[0]
            connection.execute(
                "UPDATE rows SET item_key='a', position=1 WHERE section=? AND item_key='b'",
                (section,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StewardError):
            object_store.read("current.json")
        self.store.write("current.json", {"value": 1})
        connection = sqlite3.connect(self.store.database_path)
        try:
            section = connection.execute("SELECT section FROM sections").fetchone()[0]
            connection.execute("UPDATE rows SET value_json='{\"a\":1,\"a\":2}' WHERE section=?",
                               (section,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StewardError):
            self.store.read("current.json")

    def test_invalid_baseline_entries_are_rejected_without_loss(self):
        with self.assertRaises(StewardError):
            self.store.write("current.json", {
                "baselines": {"/first": None, "/second": {"complete": False}}
            })
        self.assertEqual(self.store.read("current.json", "empty"), "empty")
        with self.assertRaises(StewardError):
            self.store.write("current.json", {
                "baselines": {"/first": {"records": None}}
            })

    def test_database_path_with_uri_delimiters(self):
        directory = self.directory / "state #? space"
        store = Store(directory, self.limits)
        store.initialize_database()
        store.write("operations.json", [{"id": "a" * 32}])
        self.assertEqual(store.read("operations.json"), [{"id": "a" * 32}])

    def test_initialization_preserves_orphan_journal(self):
        store = Store(self.directory / "orphan", self.limits)
        journal = Path(str(store.database_path) + "-journal")
        journal.write_bytes(b"recovery evidence")
        with self.assertRaisesRegex(StewardError, "伴随文件已存在"):
            store.initialize_database()
        self.assertFalse(store.database_path.exists())
        self.assertEqual(journal.read_bytes(), b"recovery evidence")

    def test_corrupt_and_unsupported_database_are_rejected(self):
        original = self.store.database_path.read_bytes()
        self.store.database_path.write_bytes(b"not sqlite")
        with self.assertRaises(StewardError):
            self.store.check_database()
        self.assertEqual(self.store.database_path.read_bytes(), b"not sqlite")
        self.store.database_path.write_bytes(original)
        connection = sqlite3.connect(self.store.database_path)
        try:
            connection.execute("PRAGMA user_version=999")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StewardError):
            self.store.read("current.json", {})


if __name__ == "__main__":
    unittest.main()
