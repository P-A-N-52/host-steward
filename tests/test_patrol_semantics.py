import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
from state import StewardError
from state_schema import read_current
from steward import initialize, patrol


class PatrolSemanticsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.store, self.policy = initialize(self.base / "state", [self.root], "巡检语义回归")
        self.now = 1_800_000_000
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True},
                "gpu": {}, "model_usage": {}, "storage": [],
                "processes": {"available": True, "items": []}, "services": {"available": True, "items": []}}
        for mocker in [patch("steward.observe", return_value=host),
                       patch("steward.native_events", return_value={"available": False})]:
            mocker.start()
            self.addCleanup(mocker.stop)

    def run_patrol(self):
        with patch("steward.time.time", return_value=self.now):
            return patrol(self.store, self.policy)

    def status(self, *arguments):
        result = subprocess.run([sys.executable, str(PROJECT / "tools/steward.py"), "status",
                                 "--state", str(self.store.path), *arguments],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_atomic_file_replacement_is_a_change_with_complete_coverage(self):
        target = self.root / "skill.md"
        target.write_text("旧版本")
        self.run_patrol()
        old_id = read_current(self.store)["baselines"][str(self.root)]["records"][str(target)]["id"]
        replacement = self.base / "replacement"
        replacement.write_text("新版本及新增内容")
        os.replace(replacement, target)
        self.now += 3600
        report = self.run_patrol()
        self.assertTrue(report["last_run"]["coverage_complete"])
        self.assertEqual(report["gaps"], [])
        self.assertEqual(report["comparison_gaps"], [])
        change = next(row for row in report["changes"] if row["path"] == str(target))
        self.assertEqual(change["modified"], 1)
        self.assertTrue(change["continuity_gap"])
        self.assertIsNone(change["average_growth_bytes_per_second"])
        sample = change["samples"][0]
        self.assertTrue(sample["identity_changed"])
        self.assertEqual(sample["from"]["id"], old_id)
        self.assertNotEqual(sample["to"]["id"], old_id)
        current = read_current(self.store)
        self.assertEqual(current["coverage_gaps"], [])
        self.assertIn(change, current["changes"])

    def test_uncertain_move_keeps_reasons_without_a_scan_gap(self):
        source = self.root / "before"
        source.write_text("同一对象")
        with patch("files.birth", return_value=None):
            self.run_patrol()
            source.rename(self.root / "after")
            report = self.run_patrol()
            self.assertTrue(report["last_run"]["coverage_complete"])
            self.assertEqual(report["gaps"], [])
            reasons = report["comparison_gaps"][0]["reasons"]
            self.assertTrue(any("move uncertain" in reason for reason in reasons))
            self.assertEqual(sum(row["moved"] for row in report["changes"]), 0)
            self.assertEqual(self.status()["comparison_gaps"], report["comparison_gaps"])
            recovered = self.run_patrol()
            self.assertEqual(recovered["comparison_gaps"], [])
            self.assertTrue(recovered["observations_changed"])
            self.assertFalse(self.run_patrol()["observations_changed"])

    def test_scope_rebaseline_is_visible_even_without_file_changes(self):
        self.run_patrol()
        self.policy["roots"][0]["exclude_names"].append("new-filter")
        self.store.write("host.json", self.policy)
        report = self.run_patrol()
        self.assertEqual(report["changes"], [])
        self.assertEqual(report["gaps"], [])
        self.assertEqual(report["new_baselines"], [str(self.root)])
        self.assertTrue(report["comparison_gaps"])
        self.assertTrue(report["observations_changed"])
        current = read_current(self.store)
        self.assertEqual(current["comparison_gaps"], report["comparison_gaps"])
        self.assertEqual(self.status()["comparison_gaps"], report["comparison_gaps"])
        self.assertTrue(self.run_patrol()["observations_changed"])
        self.assertFalse(self.run_patrol()["observations_changed"])

    def test_retention_separates_age_and_count_eviction_across_runs(self):
        self.run_patrol()
        current = read_current(self.store)
        current["changes"] = [{"path": str(self.root), "observed_at": self.now - hours * 3600}
                              for hours in [49, 3, 2, 1]]
        self.store.write("current.json", current)
        self.policy["limits"].update(change_records=2, retention_hours=48)
        self.store.write("host.json", self.policy)
        report = self.run_patrol()
        retention = report["change_retention"]
        self.assertEqual(retention, {"retention_hours": 48, "record_limit": 2,
                                    "expired_by_age": 1, "evicted_by_count": 1,
                                    "oldest_observed_at": self.now - 7200,
                                    "newest_observed_at": self.now - 3600, "span_hours": 1})
        self.assertEqual(report["change_records_dropped"], 1)
        self.assertFalse(report["observations_changed"])
        self.assertEqual(read_current(self.store)["change_retention"], retention)
        self.assertEqual(self.status("--path", str(self.root / "unmatched"), "--limit", "1")["change_retention"],
                         retention)
        repeated = self.run_patrol()["change_retention"]
        self.assertEqual(repeated["expired_by_age"], 0)
        self.assertEqual(repeated["evicted_by_count"], 0)
        self.assertEqual(repeated["span_hours"], 1)
        self.now += 48 * 3600
        empty = self.run_patrol()["change_retention"]
        self.assertEqual(empty["expired_by_age"], 2)
        self.assertEqual(empty["evicted_by_count"], 0)
        for field in ["oldest_observed_at", "newest_observed_at", "span_hours"]:
            self.assertIsNone(empty[field])

    def test_retention_span_uses_timestamps_instead_of_record_order(self):
        self.run_patrol()
        for stamps in [[self.now], [self.now - 3600, self.now - 7200, self.now]]:
            with self.subTest(stamps=stamps):
                current = read_current(self.store)
                current["changes"] = [{"path": str(self.root), "observed_at": stamp} for stamp in stamps]
                self.store.write("current.json", current)
                retention = self.run_patrol()["change_retention"]
                self.assertEqual(retention["oldest_observed_at"], min(stamps))
                self.assertEqual(retention["newest_observed_at"], max(stamps))
                self.assertEqual(retention["span_hours"], 0 if len(stamps) == 1 else 2)

    def test_legacy_state_without_new_fields_remains_readable(self):
        self.store.write("current.json", {"version": 1, "change_records_dropped": 2,
                                          "extension": {"keep": True}})
        before = read_current(self.store)
        status = self.status()
        self.assertIsNone(status["change_retention"])
        self.assertEqual(status["comparison_gaps"], [])
        self.assertEqual(read_current(self.store), before)
        report = self.run_patrol()
        self.assertEqual(report["change_retention"]["evicted_by_count"], 0)
        self.assertEqual(read_current(self.store)["extension"], {"keep": True})

    def test_invalid_retention_metadata_is_blocked_before_observation(self):
        self.run_patrol()
        valid = read_current(self.store)
        for field, value in [("expired_by_age", -1), ("evicted_by_count", True),
                             ("oldest_observed_at", 10**400), ("newest_observed_at", "未知"),
                             ("span_hours", -1)]:
            with self.subTest(field=field):
                current = copy.deepcopy(valid)
                current["change_retention"][field] = value
                self.store.write("current.json", current)
                with patch("steward.observe") as observe, self.assertRaises(StewardError):
                    self.run_patrol()
                observe.assert_not_called()
                self.assertEqual(self.store.read("current.json"), current)


if __name__ == "__main__":
    unittest.main()
