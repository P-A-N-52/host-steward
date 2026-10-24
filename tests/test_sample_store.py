import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

import sample_store
from database import Database, DatabaseError
from sample_store import SampleStore
from state import Store
import storage_tools


BASE = 1_700_000_000.0
V1_SCHEMA = """
CREATE TABLE datasets (
    dataset TEXT PRIMARY KEY,
    root_kind TEXT NOT NULL CHECK (root_kind IN ('object', 'array'))
) WITHOUT ROWID;
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE sections (
    dataset TEXT NOT NULL REFERENCES datasets(dataset) ON DELETE CASCADE,
    section TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('scalar', 'object', 'array')),
    ordinal INTEGER NOT NULL,
    PRIMARY KEY (dataset, section)
) WITHOUT ROWID;
CREATE TABLE rows (
    dataset TEXT NOT NULL,
    section TEXT NOT NULL,
    item_key TEXT NOT NULL,
    position INTEGER NOT NULL,
    value_json TEXT NOT NULL,
    PRIMARY KEY (dataset, section, position, item_key),
    FOREIGN KEY (dataset, section) REFERENCES sections(dataset, section)
        ON DELETE CASCADE
) WITHOUT ROWID;
PRAGMA user_version = 1;
"""


def create_v1(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(os.fspath(path))
    try:
        connection.executescript(V1_SCHEMA)
        connection.commit()
    finally:
        connection.close()


class SampleStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.limits = {"file_bytes": 65536, "total_bytes": 8 * 1024 * 1024,
                       "scan_seconds": 5}
        self.store = Store(self.base / "state", self.limits)
        self.store.initialize_database()
        self.samples = SampleStore(self.store)
        self.run_id = "11111111-1111-4111-8111-111111111111"
        self.policy = {"version": 2, "purpose": "资源历史测试",
                       "sampling": self.sampling()}
        self.evidence = {"policy_version": 2, "policy_digest": "a" * 64}
        self.boot = {"boot_id": "boot-a", "unix_time": BASE - 100}
        self.samples.start_run(self.run_id, self.policy, self.evidence,
                               started_at=BASE, boot=self.boot, pid=1234)

    def sampling(self, records=10, retention_hours=1, processes=4,
                 interval_seconds=15):
        return {"interval_seconds": interval_seconds,
                "cycle_seconds": min(5, interval_seconds),
                "process_interval_seconds": max(60, interval_seconds),
                "processes": processes, "records": records,
                "retention_hours": retention_hours}

    def append(self, offset, *, run_id=None, host=None, sources=None,
               processes=None, sampling=None):
        observed_at = BASE + offset
        if sources is None:
            sources = {"cpu": {"available": True, "attempted_at": observed_at,
                               "success_at": observed_at}}
        return self.samples.append_sample(
            run_id or self.run_id, observed_at=observed_at,
            monotonic_at=1000 + offset, boot=self.boot,
            host={"offset": offset, "nested": {"value": [offset]}} if host is None else host,
            sources=sources, processes=processes,
            sampling=sampling or self.sampling())

    def new_store(self, name, limits=None):
        store = Store(self.base / name, limits or self.limits)
        store.initialize_database()
        return store

    def count(self, table, where="", parameters=()):
        connection = sqlite3.connect(self.store.database_path)
        try:
            sql = f"SELECT COUNT(*) FROM {table}"
            if where:
                sql += " WHERE " + where
            return connection.execute(sql, parameters).fetchone()[0]
        finally:
            connection.close()

    def dataset_snapshot(self, store=None):
        store = store or self.store
        connection = sqlite3.connect(store.database_path)
        try:
            return {
                "datasets": connection.execute(
                    "SELECT dataset, root_kind FROM datasets ORDER BY dataset").fetchall(),
                "metadata": connection.execute(
                    "SELECT key, value_json FROM metadata ORDER BY key").fetchall(),
                "sections": connection.execute(
                    "SELECT dataset, section, kind, ordinal FROM sections "
                    "ORDER BY dataset, section, ordinal").fetchall(),
                "rows": connection.execute(
                    "SELECT dataset, section, item_key, position, value_json FROM rows "
                    "ORDER BY dataset, section, position, item_key").fetchall(),
            }
        finally:
            connection.close()

    def test_initialize_reports_schema_two_and_append_preserves_datasets(self):
        self.assertEqual(self.store.database_info()["schema_version"], 2)
        self.store.write("current.json", {"version": 1, "pending": [{"key": "keep"}]})
        self.store.write("inventory.json", {"resources": {"service": {"purpose": "keep"}}})
        self.store.write("operations.json", [{"id": "b" * 32, "status": "planned"}])
        before = self.dataset_snapshot()

        host = {"cpu": {"cores": 8}, "nested": [{"a": 1}], "available": True}
        sources = {
            "cpu": {"available": True, "attempted_at": BASE, "success_at": BASE},
            "disk_io": {"available": False, "attempted_at": BASE, "error_at": BASE,
                        "error": {"command": "iostat", "reason": "权限不足"}},
        }
        processes = [{"identity": "10:start-a:example", "pid": 10, "rss_bytes": 100},
                     {"identity": "11:start-b:example", "pid": 11, "rss_bytes": 200}]
        result = self.append(0, host=host, sources=sources, processes=processes,
                             sampling=self.sampling(records=5, processes=2))
        self.assertEqual(result["status"], "appended")
        self.assertTrue(result["process"]["observed"])
        self.assertEqual(result["process"]["count"], 2)
        self.assertEqual(result["retention"]["records"], 1)
        self.assertEqual(self.dataset_snapshot(), before)

        page = self.samples.query(BASE, BASE, limit=5)
        self.assertEqual(len(page["samples"]), 1)
        sample = page["samples"][0]
        self.assertEqual(sample["host"], host)
        self.assertEqual(sample["sources"], sources)
        self.assertEqual(sample["boot"], self.boot)
        self.assertEqual(sample["sampling"], self.sampling(records=5, processes=2))
        self.assertEqual(sample["run"]["run_id"], self.run_id)
        self.assertEqual(sample["run"]["policy"], self.policy)
        self.assertEqual(sample["run"]["evidence"], self.evidence)
        self.assertEqual(sample["run"]["pid"], 1234)
        self.assertTrue(sample["process_observed"])
        self.assertEqual(sample["process_count"], 2)
        self.assertIsNone(sample["process_meta"])

        filtered = self.samples.query(BASE, BASE, process="10:start-a:example")
        self.assertEqual(len(filtered["samples"]), 1)
        self.assertEqual(filtered["samples"][0]["processes"],
                         [{"position": 0, "identity": "10:start-a:example",
                           "payload": processes[0]}])
        latest = self.samples.latest_processes()
        self.assertTrue(latest["observed"])
        self.assertEqual([row["identity"] for row in latest["processes"]],
                         ["10:start-a:example", "11:start-b:example"])

        connection = sqlite3.connect(self.store.database_path)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("DELETE FROM resource_samples WHERE sample_id=?",
                               (result["sample_id"],))
            connection.commit()
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM process_samples").fetchone()[0], 0)
        finally:
            connection.close()
        self.assertEqual(self.dataset_snapshot(), before)

    def test_query_keyset_pagination_window_and_identity_filter(self):
        for offset in range(6):
            processes = [{"identity": f"p{offset % 2}", "rss_bytes": offset}]
            self.append(offset, processes=processes)
        first = self.samples.query(BASE, BASE + 3, limit=2)
        self.assertEqual([row["observed_at"] for row in first["samples"]],
                         [BASE + 3, BASE + 2])
        self.assertEqual(first["page"], {"limit": 2, "returned": 2, "truncated": True})
        self.assertEqual(first["next_before"], first["samples"][-1]["sample_id"])
        self.assertEqual(first["window"], {"since": BASE, "until": BASE + 3,
                                           "before": None, "process": None})
        second = self.samples.query(BASE, BASE + 3, limit=2,
                                    before=first["next_before"])
        self.assertEqual([row["observed_at"] for row in second["samples"]],
                         [BASE + 1, BASE])
        self.assertFalse(second["page"]["truncated"])
        self.assertIsNone(second["next_before"])
        self.assertEqual(second["window"], {"since": BASE, "until": BASE + 3,
                                            "before": first["next_before"],
                                            "process": None})

        filtered = self.samples.query(BASE, BASE + 5, process="p1")
        self.assertEqual([row["observed_at"] for row in filtered["samples"]],
                         [BASE + 5, BASE + 3, BASE + 1])
        for row in filtered["samples"]:
            self.assertEqual([item["identity"] for item in row["processes"]], ["p1"])
        paged = self.samples.query(BASE, BASE + 5, limit=2, process="p1")
        self.assertTrue(paged["page"]["truncated"])
        self.assertEqual(paged["next_before"], paged["samples"][-1]["sample_id"])
        continuation = self.samples.query(BASE, BASE + 5, limit=2,
                                          before=paged["next_before"], process="p1")
        self.assertEqual([row["observed_at"] for row in continuation["samples"]],
                         [BASE + 1])
        self.assertFalse(continuation["page"]["truncated"])

        connection = sqlite3.connect(self.store.database_path)
        try:
            indexes = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index'")}
        finally:
            connection.close()
        self.assertIn("process_samples_identity_idx", indexes)
        with self.assertRaises(DatabaseError):
            self.samples.query(BASE, BASE, limit=0)
        with self.assertRaises(DatabaseError):
            self.samples.query(BASE, BASE, limit=201)
        with self.assertRaises(DatabaseError):
            self.samples.query(BASE + 1, BASE)

    def test_latest_process_snapshot_is_not_empty_when_not_sampled(self):
        first = self.append(0, processes=[{"identity": "p1", "rss_bytes": 10}])
        second = self.append(1, processes=None)
        latest = self.samples.latest_processes()
        self.assertTrue(latest["observed"])
        self.assertEqual(latest["sample_id"], first["sample_id"])
        self.assertEqual(latest["observed_at"], BASE)
        self.assertEqual(latest["process_count"], 1)
        self.assertEqual(latest["processes"][0]["identity"], "p1")
        self.assertFalse(self.samples.latest_processes(until=BASE - 1)["observed"])

        page = self.samples.query(BASE, BASE + 1)
        self.assertEqual([row["sample_id"] for row in page["samples"]],
                         [second["sample_id"], first["sample_id"]])
        self.assertFalse(page["samples"][0]["process_observed"])
        self.assertEqual(page["samples"][0]["process_count"], 0)
        self.assertNotIn("processes", page["samples"][0])
        self.assertTrue(page["latest_processes"]["observed"])
        self.assertTrue(page["latest_processes"]["within_window"])
        status = self.samples.status(now=BASE + 2)
        self.assertEqual(status["last_process_sample"]["sample_id"], first["sample_id"])

        failed = self.append(2, processes={"available": False, "reason": "ps failed"})
        failed_latest = self.samples.latest_processes()
        self.assertTrue(failed_latest["observed"])
        self.assertEqual(failed_latest["sample_id"], failed["sample_id"])
        self.assertEqual(failed_latest["processes"], [])
        self.assertEqual(failed_latest["meta"]["reason"], "ps failed")
        failed_sample = self.samples.query(BASE + 2, BASE + 2)["samples"][0]
        self.assertTrue(failed_sample["process_observed"])
        self.assertEqual(failed_sample["process_meta"]["available"], False)

    def test_age_and_count_retention_keep_ids_monotonic(self):
        sampling = self.sampling(records=3, retention_hours=1, processes=2)
        results = [self.append(offset, processes=[{"identity": "p1", "rss_bytes": offset}],
                               sampling=sampling)
                   for offset in (0, 10, 20, 30)]
        self.assertEqual([result["retention"]["expired_by_age"] for result in results],
                         [0, 0, 0, 0])
        self.assertEqual(results[-1]["retention"]["evicted_by_count"], 1)
        self.assertEqual(results[-1]["retention"]["records"], 3)
        self.assertEqual(results[-1]["retention"]["oldest_observed_at"], BASE + 10)
        self.assertEqual(results[-1]["retention"]["newest_observed_at"], BASE + 30)
        self.assertEqual(results[-1]["retention"]["span_seconds"], 20.0)
        self.assertEqual(self.count("resource_samples"), 3)
        self.assertEqual([row["sample_id"] for row in
                          self.samples.query(BASE, BASE + 40)["samples"]],
                         [results[3]["sample_id"], results[2]["sample_id"],
                          results[1]["sample_id"]])

        aged = self.append(4000, processes=[{"identity": "p1", "rss_bytes": 1}],
                           sampling=sampling)
        self.assertEqual(aged["retention"]["expired_by_age"], 3)
        self.assertEqual(aged["retention"]["evicted_by_count"], 0)
        self.assertEqual(aged["retention"]["records"], 1)
        self.assertEqual(aged["retention"]["oldest_observed_at"], BASE + 4000)
        self.assertEqual(aged["retention"]["newest_observed_at"], BASE + 4000)
        self.assertEqual(aged["retention"]["span_seconds"], 0.0)
        self.assertGreater(aged["sample_id"], results[-1]["sample_id"])
        self.assertEqual(self.count("resource_samples"), 1)
        self.assertEqual(self.count("process_samples"), 1)

    def test_runs_are_bounded_but_sample_and_gap_evidence_is_retained(self):
        with patch.object(sample_store, "RUN_LIMIT", 4), \
                patch.object(sample_store, "RUN_RETENTION_HOURS", 1):
            for index in range(10):
                run_id = f"plain-{index:02d}"
                self.samples.start_run(run_id, self.policy, {"index": index},
                                       started_at=BASE + index * 10)
                self.samples.finish_run(run_id, stopped_at=BASE + index * 10 + 1)
            self.assertLessEqual(self.count("collector_runs"), 4)

            old_run = "run-with-sample"
            self.samples.start_run(old_run, self.policy, {"old": True},
                                   started_at=BASE + 100)
            self.append(100, run_id=old_run,
                        sampling=self.sampling(records=5, retention_hours=100))
            self.samples.finish_run(old_run, stopped_at=BASE + 101)
            for index in range(6):
                run_id = f"new-{index:02d}"
                self.samples.start_run(run_id, self.policy, {"index": index},
                                       started_at=BASE + 200 + index * 10)
                self.samples.finish_run(run_id, stopped_at=BASE + 201 + index * 10)
            self.assertEqual(self.count("collector_runs", "run_id=?", (old_run,)), 1)
            self.samples.start_run("future", self.policy, {"future": True},
                                   started_at=BASE + 10000)
            self.append(10000, run_id="future",
                        sampling=self.sampling(records=5, retention_hours=1))
            self.assertEqual(self.count("collector_runs", "run_id=?", (old_run,)), 0)

        with patch.object(sample_store, "RUN_LIMIT", 4), \
                patch.object(sample_store, "RUN_RETENTION_HOURS", 1), \
                patch.object(sample_store, "GAP_LIMIT", 10), \
                patch.object(sample_store, "GAP_RETENTION_HOURS", 1):
            gap_run = "run-with-gap"
            self.samples.start_run(gap_run, self.policy, {"gap": True},
                                   started_at=BASE + 20000)
            self.samples.finish_run(gap_run, stopped_at=BASE + 20001)
            self.samples.record_gap(BASE + 20000, None, "collector_restart",
                                    run_id=gap_run, detail={"error": "lost"})
            for index in range(4):
                run_id = f"gap-new-{index}"
                self.samples.start_run(run_id, self.policy, {"index": index},
                                       started_at=BASE + 20100 + index * 10)
                self.samples.finish_run(run_id, stopped_at=BASE + 20101 + index * 10)
            self.assertEqual(self.count("collector_runs", "run_id=?", (gap_run,)), 1)
            self.samples.record_gap(BASE + 20000, BASE + 20005,
                                    "collector_restart", run_id=gap_run)
            self.samples.start_run("later", self.policy, {"later": True},
                                   started_at=BASE + 30000)
            self.assertEqual(self.count("collector_gaps", "run_id=?", (gap_run,)), 0)
            self.assertEqual(self.count("collector_runs", "run_id=?", (gap_run,)), 0)

    def test_gaps_merge_and_auxiliary_counts_stay_bounded(self):
        with patch.object(sample_store, "GAP_LIMIT", 3), \
                patch.object(sample_store, "GAP_RETENTION_HOURS", 1000):
            for index in range(6):
                self.samples.record_gap(BASE + index * 10, BASE + index * 10 + 1,
                                        f"gap-{index}")
            self.assertLessEqual(self.count("collector_gaps"), 3)
            opened = self.samples.record_gap(BASE + 100, None, "open-gap",
                                             detail={"first": "lost"})
            self.assertEqual(opened["gap"]["end_at"], None)
            self.assertTrue(opened["gap"]["ongoing"])
            closed = self.samples.record_gap(BASE + 100, BASE + 120, "open-gap",
                                             detail={"later": "recovered"})
            self.assertEqual(closed["status"], "merged")
            self.assertEqual(closed["gap"]["start_at"], BASE + 100)
            self.assertEqual(closed["gap"]["end_at"], BASE + 120)
            self.assertEqual(closed["gap"]["detail"], {"first": "lost"})
            self.assertLessEqual(self.count("collector_gaps"), 3)

        with patch.object(sample_store, "SOURCE_LIMIT", 2):
            self.append(10, sources={"one": {"available": True},
                                     "two": {"available": True}})
            before = self.count("resource_samples")
            with self.assertRaises(DatabaseError):
                self.append(11, sources={"three": {"available": True}})
            self.assertEqual(self.count("resource_samples"), before)
            self.assertEqual(self.count("collector_sources"), 2)
        for index in range(10):
            self.samples.update_state(last_complete_at=BASE + 20 + index)
        self.assertEqual(self.count("collector_state"), 1)

    def test_single_entry_and_capacity_failures_preserve_previous_state(self):
        first = self.append(0, sampling=self.sampling(records=5))
        before = self.dataset_snapshot()
        before_count = self.count("resource_samples")
        with self.assertRaises(DatabaseError):
            self.append(1, host={"big": "x" * (self.limits["file_bytes"] + 1024)})
        self.assertEqual(self.count("resource_samples"), before_count)
        with self.assertRaises(DatabaseError):
            self.append(2, processes=[{"identity": "p1",
                                       "blob": "x" * (self.limits["file_bytes"] + 1024)}])
        self.assertEqual(self.count("resource_samples"), before_count)
        self.assertEqual(self.dataset_snapshot(), before)

        usage = self.store.usage()
        limited = Store(self.store.path, dict(self.limits, total_bytes=usage + 1))
        with self.assertRaises(DatabaseError) as caught:
            SampleStore(limited).append_sample(
                self.run_id, observed_at=BASE + 3, monotonic_at=1003,
                boot=self.boot, host={"x": 1}, sources={"cpu": {"available": True}},
                sampling=self.sampling(records=5))
        self.assertIn("容量", str(caught.exception))
        self.assertEqual(self.count("resource_samples"), before_count)
        self.assertEqual(self.dataset_snapshot(), before)
        self.assertEqual(first["sample_id"],
                         self.samples.query(BASE, BASE)["samples"][0]["sample_id"])

    def test_mid_transaction_failure_rolls_back_sample_process_sources_and_state(self):
        store = self.new_store("rollback")
        samples = SampleStore(store)
        run_id = "rollback-run"
        samples.start_run(run_id, self.policy, self.evidence, started_at=BASE,
                          boot=self.boot)
        before_status = samples.status(now=BASE + 2)
        connection = sqlite3.connect(store.database_path)
        try:
            connection.execute(
                "CREATE TRIGGER fail_process BEFORE INSERT ON process_samples "
                "BEGIN SELECT RAISE(ABORT, 'forced'); END")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DatabaseError) as caught:
            samples.append_sample(
                run_id, observed_at=BASE + 1, monotonic_at=1001, boot=self.boot,
                host={"x": 1}, sources={"cpu": {"available": True}},
                processes=[{"identity": "p1", "rss_bytes": 1}],
                sampling=self.sampling(records=5))
        self.assertIn("回滚", str(caught.exception))
        connection = sqlite3.connect(store.database_path)
        try:
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM resource_samples").fetchone()[0], 0)
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM process_samples").fetchone()[0], 0)
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM collector_sources").fetchone()[0], 0)
        finally:
            connection.close()
        after_status = samples.status(now=BASE + 2)
        self.assertEqual(after_status["run"], before_status["run"])
        self.assertEqual(after_status["heartbeat_at"], before_status["heartbeat_at"])
        self.assertEqual(after_status["last_sample"], before_status["last_sample"])
        self.assertEqual(after_status["sources"], before_status["sources"])

    def test_v1_datasets_remain_readable_and_upgrade_is_explicit(self):
        directory = self.base / "v1"
        create_v1(directory / "steward.sqlite3")
        store = Store(directory, self.limits)
        database = store._database()
        database.write("current.json", {"version": 1, "value": "old"})
        self.assertEqual(store.database_info()["schema_version"], 1)
        self.assertEqual(store.read("current.json"), {"version": 1, "value": "old"})
        store.write("current.json", {"version": 1, "value": "new"})
        self.assertEqual(store.read("current.json"), {"version": 1, "value": "new"})

        with self.assertRaises(DatabaseError) as caught:
            SampleStore(store).status(now=BASE)
        self.assertIn("upgrade_schema", str(caught.exception))
        preview = database.upgrade_schema()
        self.assertEqual(preview["from_version"], 1)
        self.assertFalse(preview["applied"])
        self.assertFalse(preview["already_current"])
        connection = sqlite3.connect(store.database_path)
        try:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        finally:
            connection.close()
        self.assertNotIn("resource_samples", tables)
        self.assertEqual(version, 1)

        applied = database.upgrade_schema(
            apply=True, total_bytes=self.limits["total_bytes"], outside_bytes=0)
        self.assertTrue(applied["applied"])
        self.assertEqual(applied["schema_version"], 2)
        self.assertEqual(store.database_info()["schema_version"], 2)
        self.assertEqual(store.read("current.json"), {"version": 1, "value": "new"})
        self.assertEqual(SampleStore(store).status(now=BASE)["status"], "not_started")

    def test_upgrade_capacity_and_partial_structure_fail_without_version_change(self):
        directory = self.base / "v1-capacity"
        create_v1(directory / "steward.sqlite3")
        database = Database(directory / "steward.sqlite3", self.limits["file_bytes"],
                            self.limits["total_bytes"])
        with self.assertRaises(DatabaseError):
            database.upgrade_schema(apply=True, total_bytes=1)
        connection = sqlite3.connect(directory / "steward.sqlite3")
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            connection.close()
        self.assertEqual(version, 1)
        self.assertNotIn("resource_samples", tables)

        conflict = self.base / "v1-conflict"
        create_v1(conflict / "steward.sqlite3")
        connection = sqlite3.connect(conflict / "steward.sqlite3")
        try:
            connection.execute("CREATE TABLE collector_runs (marker TEXT)")
            connection.commit()
        finally:
            connection.close()
        database = Database(conflict / "steward.sqlite3", self.limits["file_bytes"],
                            self.limits["total_bytes"])
        with self.assertRaises(DatabaseError) as caught:
            database.upgrade_schema(apply=True)
        self.assertIn("部分资源历史结构", str(caught.exception))
        connection = sqlite3.connect(conflict / "steward.sqlite3")
        try:
            self.assertEqual(connection.execute(
                "PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='resource_samples'"
            ).fetchone()[0], 0)
        finally:
            connection.close()

    def test_v2_missing_table_or_index_is_rejected(self):
        store = self.new_store("missing-table")
        connection = sqlite3.connect(store.database_path)
        try:
            connection.execute("DROP TABLE collector_state")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DatabaseError) as caught:
            store.database_info()
        self.assertIn("缺少表", str(caught.exception))

        store = self.new_store("missing-index")
        connection = sqlite3.connect(store.database_path)
        try:
            connection.execute("DROP INDEX process_samples_identity_idx")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DatabaseError) as caught:
            store.database_info()
        self.assertIn("索引", str(caught.exception))

    def test_status_lifecycle_sources_gaps_and_invalid_host_config(self):
        store = self.new_store("status")
        samples = SampleStore(store)
        initial = samples.status(now=BASE)
        self.assertEqual(initial["status"], "not_started")
        self.assertIsNone(initial["run"])
        self.assertIsNone(initial["heartbeat_at"])
        self.assertIsNone(initial["last_sample"])
        self.assertIsNone(initial["stopped_at"])

        run_id = "status-run"
        started = samples.start_run(run_id, self.policy, self.evidence,
                                    started_at=BASE, boot=self.boot)
        self.assertEqual(started["status"], "started")
        self.assertEqual(samples.status(now=BASE + 1)["status"], "running")
        sample = samples.append_sample(
            run_id, observed_at=BASE + 2, monotonic_at=1002, boot=self.boot,
            host={"x": 1}, sources={
                "cpu": {"available": True, "attempted_at": BASE + 2,
                        "success_at": BASE + 2},
                "disk_io": {"available": False, "attempted_at": BASE + 2,
                            "error_at": BASE + 2, "reason": "permission"},
            }, sampling=self.sampling(records=5))
        samples.update_state(last_complete_at=BASE + 3, detail={"cycle": 1})
        running = samples.status(now=BASE + 4)
        self.assertEqual(running["status"], "running")
        self.assertEqual(running["heartbeat_at"], BASE + 2)
        self.assertEqual(running["last_complete_at"], BASE + 3)
        self.assertEqual(running["last_sample"]["sample_id"], sample["sample_id"])
        self.assertEqual(running["sources"]["cpu"]["available"], True)
        self.assertEqual(running["sources"]["disk_io"]["available"], False)
        self.assertEqual(running["sources"]["disk_io"]["reason"], "permission")

        store.target("host.json").write_text("{broken json", encoding="utf-8")
        self.assertEqual(samples.status(now=BASE + 4)["status"], "running")
        self.assertEqual(len(samples.query(BASE, BASE + 4)["samples"]), 1)

        opened = samples.record_gap(BASE + 5, None, "collector_restart",
                                    detail={"error": "lost"})
        self.assertTrue(opened["gap"]["ongoing"])
        self.assertEqual(samples.status(now=BASE + 6)["open_gap_count"], 1)
        closed = samples.record_gap(BASE + 5, BASE + 8, "collector_restart")
        self.assertEqual(closed["gap"]["end_at"], BASE + 8)
        self.assertEqual(samples.status(now=BASE + 9)["open_gap_count"], 0)
        gap_page = samples.query(BASE + 4, BASE + 9)
        self.assertEqual(len(gap_page["gaps"]), 1)
        self.assertEqual(gap_page["gaps"][0]["detail"], {"error": "lost"})

        finished = samples.finish_run(run_id, stopped_at=BASE + 10, reason="signal")
        self.assertEqual(finished["status"], "stopped")
        stopped = samples.status(now=BASE + 11)
        self.assertEqual(stopped["status"], "stopped")
        self.assertEqual(stopped["stopped_at"], BASE + 10)
        self.assertIsNone(stopped["active_run"])
        self.assertEqual(samples.finish_run(run_id, stopped_at=BASE + 12)["status"],
                         "already_stopped")
        with self.assertRaises(DatabaseError):
            samples.append_sample(
                run_id, observed_at=BASE + 12, monotonic_at=1012, boot=self.boot,
                host={"x": 2}, sources={"cpu": {"available": True}},
                sampling=self.sampling(records=5))

        samples.start_run("second-run", self.policy, self.evidence,
                          started_at=BASE + 20)
        superseded = samples.start_run("third-run", self.policy, self.evidence,
                                       started_at=BASE + 30)
        self.assertEqual(superseded["closed_run"]["run_id"], "second-run")
        self.assertEqual(superseded["closed_run"]["stop_reason"], "superseded")
        running = samples.status(now=BASE + 31)
        self.assertEqual(running["status"], "running")
        self.assertEqual(running["active_run"]["run_id"], "third-run")
        self.assertEqual(running["run"]["run_id"], "third-run")
        with self.assertRaises(DatabaseError):
            samples.update_state(unknown=1)

    def test_backup_is_an_independent_consistent_sqlite_snapshot(self):
        self.store.write("current.json", {"version": 1, "keep": True})
        self.append(0, processes=[{"identity": "p1", "rss_bytes": 10}])
        destination = self.base / "backup.sqlite3"
        result = storage_tools.backup_database(self.store, str(destination))
        self.assertEqual(result["status"], "backed_up")
        self.assertTrue(result["verified"])
        self.assertTrue(destination.is_file())
        connection = sqlite3.connect(destination)
        try:
            self.assertEqual(connection.execute(
                "PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(connection.execute(
                "PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM resource_samples").fetchone()[0], 1)
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM process_samples").fetchone()[0], 1)
            self.assertGreater(connection.execute(
                "SELECT COUNT(*) FROM rows").fetchone()[0], 0)
        finally:
            connection.close()

    def test_source_history_keeps_last_success_error_and_unsampled_rounds(self):
        self.append(1, sources={"cpu": {
            "available": True, "attempted_at": BASE + 1, "success_at": BASE + 1}})
        self.append(16, sources={"cpu": {
            "available": False, "attempted_at": BASE + 16,
            "error_at": BASE + 16, "error": "source-failure"}})
        cpu = self.samples.status(now=BASE + 17)["sources"]["cpu"]
        self.assertFalse(cpu["available"])
        self.assertEqual(cpu["attempted_at"], BASE + 16)
        self.assertEqual(cpu["success_at"], BASE + 1)
        self.assertEqual(cpu["last_success_at"], BASE + 1)
        self.assertEqual(cpu["error"], "source-failure")
        self.assertEqual(cpu["error_at"], BASE + 16)
        self.assertEqual(cpu["last_error"], "source-failure")
        self.assertEqual(cpu["last_error_at"], BASE + 16)

        self.append(31, sources={"cpu": {
            "available": True, "attempted_at": BASE + 31, "success_at": BASE + 31}})
        cpu = self.samples.status(now=BASE + 32)["sources"]["cpu"]
        self.assertTrue(cpu["available"])
        self.assertEqual(cpu["success_at"], BASE + 31)
        self.assertEqual(cpu["attempted_at"], BASE + 31)
        self.assertEqual(cpu["error"], "source-failure")
        self.assertEqual(cpu["error_at"], BASE + 16)

        self.append(46, sources={"memory": {
            "available": True, "attempted_at": BASE + 46, "success_at": BASE + 46}})
        page = self.samples.query(BASE, BASE + 46, now=BASE + 47)
        cpu = page["sources"]["cpu"]
        self.assertTrue(cpu["available"])
        self.assertEqual(cpu["success_at"], BASE + 31)
        self.assertEqual(cpu["error"], "source-failure")
        self.assertEqual(cpu["updated_at"], BASE + 31)
        self.assertTrue(page["sources"]["memory"]["available"])

        with self.assertRaises(DatabaseError):
            self.append(47, sources={"cpu": {"available": "bad"}})

    def test_lifecycle_uses_run_sampling_heartbeat_and_query_summary(self):
        store = self.new_store("lifecycle")
        samples = SampleStore(store)
        initial = samples.status(now=BASE)
        self.assertEqual(initial["status"], "not_started")
        self.assertIsNone(initial["stale_after_seconds"])
        self.assertIsNone(initial["heartbeat_age_seconds"])

        samples.start_run("life", {"version": 2, "sampling": self.sampling()},
                          self.evidence, started_at=BASE)
        running = samples.status(now=BASE + 35)
        self.assertEqual(running["status"], "running")
        self.assertEqual(running["stale_after_seconds"], 35)
        self.assertEqual(running["heartbeat_age_seconds"], 35.0)
        stale = samples.status(now=BASE + 36)
        self.assertEqual(stale["status"], "stale")
        self.assertEqual(stale["heartbeat_age_seconds"], 36.0)

        samples.update_state(heartbeat_at=BASE + 16)
        query = samples.query(BASE, BASE + 16, now=BASE + 16)
        self.assertEqual(query["collector"]["status"], "running")
        self.assertEqual(query["collector"]["heartbeat_age_seconds"], 0.0)
        self.assertEqual(query["collector"]["stale_after_seconds"], 35)
        query_stale = samples.query(BASE, BASE + 16, now=BASE + 10000)
        self.assertEqual(query_stale["collector"]["status"], "stale")
        self.assertEqual(query_stale["collector"]["heartbeat_age_seconds"], 9984.0)

        samples.finish_run("life", stopped_at=BASE + 20)
        stopped = samples.status(now=BASE + 21)
        self.assertEqual(stopped["status"], "stopped")
        self.assertIsNone(stopped["active_run"])
        self.assertEqual(stopped["run"]["run_id"], "life")
        self.assertEqual(stopped["stale_after_seconds"], 35)

        samples.start_run("unknown-policy", {"version": 1}, self.evidence,
                          started_at=BASE + 30)
        unknown = samples.status(now=BASE + 31)
        self.assertEqual(unknown["status"], "unknown")
        self.assertIsNone(unknown["stale_after_seconds"])
        self.assertIn("sampling", unknown["status_reason"])
        self.assertEqual(
            samples.query(BASE + 30, BASE + 31, now=BASE + 31)["collector"]["status"],
            "unknown")

    def test_latest_run_uses_persistent_run_id_across_clock_jump(self):
        store = self.new_store("clock-jump")
        samples = SampleStore(store)
        samples.start_run("late", self.policy, self.evidence, started_at=BASE + 1000)
        samples.finish_run("late", stopped_at=BASE + 1001)
        samples.start_run("earlier", self.policy, self.evidence, started_at=BASE - 1000)
        samples.finish_run("earlier", stopped_at=BASE - 999)
        status = samples.status(now=BASE - 998)
        self.assertEqual(status["run"]["run_id"], "earlier")
        self.assertEqual(status["status"], "stopped")
        page = samples.query(None, None, now=BASE - 998)
        self.assertEqual(page["collector"]["run"]["run_id"], "earlier")
        self.assertEqual(page["collector"]["latest_run"]["run_id"], "earlier")

        samples.start_run("earlier-active", self.policy, self.evidence,
                          started_at=BASE - 2000)
        status = samples.status(now=BASE - 1999)
        self.assertEqual(status["run"]["run_id"], "earlier-active")
        self.assertEqual(status["active_run"]["run_id"], "earlier-active")
        self.assertEqual(status["status"], "running")
        page = samples.query(None, None, now=BASE - 1999)
        self.assertEqual(page["collector"]["run"]["run_id"], "earlier-active")

    def test_retention_summary_is_persisted_and_per_append(self):
        sampling = self.sampling(records=3, retention_hours=1, processes=2)
        results = [self.append(offset, sampling=sampling) for offset in (0, 10, 20, 30)]
        expected = results[-1]["retention"]
        self.assertEqual(expected["evicted_by_count"], 1)
        status = self.samples.status(now=BASE + 31)
        self.assertEqual(status["last_append"], expected)
        self.assertEqual(status["retention"]["last_append"], expected)
        page = self.samples.query(BASE, BASE + 40, now=BASE + 31)
        self.assertEqual(page["last_append"], expected)
        self.assertEqual(page["retention"]["last_append"], expected)

        self.samples.update_state(detail={"user": "detail"})
        self.assertEqual(self.samples.status(now=BASE + 31)["last_append"], expected)
        with self.assertRaises(DatabaseError):
            self.append(40, host={"big": "x" * (self.limits["file_bytes"] + 1024)},
                        sampling=sampling)
        self.assertEqual(self.samples.status(now=BASE + 31)["last_append"], expected)

        next_result = self.append(50, sampling=self.sampling(records=5,
                                                             retention_hours=1))
        self.assertEqual(next_result["retention"]["expired_by_age"], 0)
        self.assertEqual(next_result["retention"]["evicted_by_count"], 0)
        self.assertNotEqual(next_result["retention"]["sample_id"], expected["sample_id"])
        self.assertEqual(self.samples.status(now=BASE + 51)["last_append"],
                         next_result["retention"])

        connection = sqlite3.connect(self.store.database_path)
        try:
            connection.execute(
                "UPDATE collector_state SET detail_json=?",
                (json.dumps({"legacy": True}),))
            connection.commit()
        finally:
            connection.close()
        legacy = self.samples.status(now=BASE + 51)
        self.assertIsNone(legacy["last_append"])
        self.assertIsNone(legacy["retention"]["last_append"])
        legacy_page = self.samples.query(BASE, BASE + 40, now=BASE + 51)
        self.assertIsNone(legacy_page["last_append"])
        self.assertIsNone(legacy_page["retention"]["last_append"])
        state = self.samples.update_state()
        self.assertEqual(state["detail"], {"legacy": True})
        self.assertIsNone(state["retention"])

    def test_process_snapshot_uses_process_time_and_keeps_last_success(self):
        first = self.append(1, processes=[{"identity": "p1", "rss_bytes": 10}])
        second = self.append(16, processes={
            "available": False, "reason": "ps failed", "observed_at": BASE + 20})
        latest = self.samples.latest_processes()
        self.assertTrue(latest["observed"])
        self.assertTrue(latest["attempted"])
        self.assertFalse(latest["available"])
        self.assertFalse(latest["successful"])
        self.assertEqual(latest["sample_id"], second["sample_id"])
        self.assertEqual(latest["observed_at"], BASE + 20)
        self.assertEqual(latest["sample_observed_at"], BASE + 16)
        self.assertEqual(latest["processes"], [])
        self.assertEqual(latest["meta"]["reason"], "ps failed")

        before = self.samples.latest_processes(until=BASE + 19)
        self.assertEqual(before["sample_id"], first["sample_id"])
        self.assertEqual(before["observed_at"], BASE + 1)
        self.assertTrue(before["successful"])
        self.assertEqual(before["processes"][0]["identity"], "p1")
        successful = self.samples.latest_successful_processes()
        self.assertEqual(successful["sample_id"], first["sample_id"])

        status = self.samples.status(now=BASE + 21)["last_process_sample"]
        self.assertEqual(status["observed_at"], BASE + 20)
        self.assertEqual(status["sample_observed_at"], BASE + 16)
        self.assertFalse(status["available"])
        page = self.samples.query(BASE, BASE + 30, now=BASE + 21)
        self.assertEqual(page["samples"][0]["process_observed_at"], BASE + 20)
        self.assertEqual(page["latest_processes"]["observed_at"], BASE + 20)
        self.assertFalse(page["latest_processes"]["available"])
        self.assertTrue(page["latest_processes"]["within_window"])

    def test_overflow_timestamps_and_corrupt_or_oversized_history_are_rejected(self):
        huge = 10 ** 400
        with self.assertRaises(DatabaseError):
            self.samples.append_sample(
                self.run_id, observed_at=huge, monotonic_at=1, boot={}, host={},
                sources={}, sampling=self.sampling())
        with self.assertRaises(DatabaseError):
            self.samples.status(now=huge)
        with self.assertRaises(DatabaseError):
            self.samples.query(huge, BASE)
        with self.assertRaises(DatabaseError):
            self.samples.record_gap(huge, None, "bad-time")
        with self.assertRaises(DatabaseError):
            self.samples.update_state(heartbeat_at=huge)

        sample = self.append(0)
        connection = sqlite3.connect(self.store.database_path)
        try:
            connection.execute(
                "UPDATE resource_samples SET host_json=? WHERE sample_id=?",
                (json.dumps({"big": "x" * (self.limits["file_bytes"] + 1024)}),
                 sample["sample_id"]))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DatabaseError) as caught:
            self.samples.query(BASE, BASE)
        self.assertIn("读取上限", str(caught.exception))
        self.assertEqual(self.samples.status(now=BASE + 1)["status"], "running")

        connection = sqlite3.connect(self.store.database_path)
        try:
            connection.execute(
                "UPDATE resource_samples SET host_json='{broken' WHERE sample_id=?",
                (sample["sample_id"],))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DatabaseError) as caught:
            self.samples.query(BASE, BASE)
        self.assertIn("损坏", str(caught.exception))

    def test_query_window_respects_total_read_budget(self):
        for offset in range(3):
            self.append(offset, host={"blob": "x" * 3000})
        limited = Store(self.store.path, {
            "file_bytes": self.limits["file_bytes"],
            "total_bytes": 6000, "scan_seconds": 5})
        samples = SampleStore(limited)
        page = samples.query(BASE, BASE + 2, limit=1, now=BASE + 3)
        self.assertEqual(len(page["samples"]), 1)
        with self.assertRaises(DatabaseError) as caught:
            samples.query(BASE, BASE + 2, limit=2, now=BASE + 3)
        self.assertIn("总容量预算", str(caught.exception))

    def test_run_hard_limit_rejects_and_rolls_back_after_reference_cleanup(self):
        store = self.new_store("run-hard-limit")
        samples = SampleStore(store)
        policy = {"version": 2, "sampling": self.sampling(records=5,
                                                          retention_hours=100)}
        samples.start_run("A", policy, self.evidence, started_at=BASE)
        samples.append_sample(
            "A", observed_at=BASE, monotonic_at=1, boot=self.boot, host={"x": 1},
            sources={}, sampling=self.sampling(records=5, retention_hours=100))
        samples.finish_run("A", stopped_at=BASE + 1)
        samples.start_run("B", policy, self.evidence, started_at=BASE + 10)
        samples.record_gap(BASE + 10, None, "collector_restart", run_id="B")

        with patch.object(sample_store, "RUN_LIMIT", 2), \
                patch.object(sample_store, "RUN_RETENTION_HOURS", 1), \
                patch.object(sample_store, "GAP_RETENTION_HOURS", 100):
            with self.assertRaises(DatabaseError) as caught:
                samples.start_run("C", policy, self.evidence, started_at=BASE + 20)
            self.assertIn("硬上限", str(caught.exception))
            self.assertIn("引用", str(caught.exception))
            status = samples.status(now=BASE + 21)
            self.assertEqual(status["run"]["run_id"], "B")
            self.assertEqual(status["active_run"]["run_id"], "B")
            self.assertEqual(status["status"], "running")
            connection = sqlite3.connect(store.database_path)
            try:
                self.assertEqual({row[0] for row in connection.execute(
                    "SELECT run_id FROM collector_runs")}, {"A", "B"})
            finally:
                connection.close()

            samples.append_sample(
                "B", observed_at=BASE + 10000, monotonic_at=2, boot=self.boot,
                host={"x": 2}, sources={},
                sampling=self.sampling(records=5, retention_hours=1))
            samples.start_run("C", policy, self.evidence, started_at=BASE + 10001)
            connection = sqlite3.connect(store.database_path)
            try:
                runs = {row[0] for row in connection.execute(
                    "SELECT run_id FROM collector_runs")}
            finally:
                connection.close()
            self.assertEqual(runs, {"B", "C"})
            self.assertEqual(samples.status(now=BASE + 10002)["run"]["run_id"], "C")


if __name__ == "__main__":
    unittest.main()
