import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
from files import identity
from state import StewardError
from state_schema import read_current
from steward import initialize, patrol, validate


class PolicyScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.store, self.policy = initialize(self.base / "state", [self.root], "隔离范围测试")
        self.host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True},
                     "gpu": {}, "model_usage": {}, "storage": [],
                     "processes": {"available": True, "items": []}, "services": {"available": True, "items": []}}

    def tearDown(self):
        self.temporary.cleanup()

    def run_patrol(self):
        with patch("steward.observe", return_value=self.host), \
             patch("steward.native_events", return_value={"available": True}):
            return patrol(self.store, self.policy)

    def cli(self, action, *arguments):
        return subprocess.run([sys.executable, str(PROJECT / "tools/steward.py"), action, "--state", str(self.store.path), *map(str, arguments)],
                              cwd="/", capture_output=True, text=True, timeout=5)

    def rule(self, path, kind="temporary"):
        return {"path": str(path), "purpose": "隔离规则", "kind": kind, "allow_quarantine": True,
                "retention_days": 0, "recycle_bytes": 1048576, "directory_id": identity(path.stat())}

    def test_agent_defined_directory_kind_does_not_authorize_quarantine(self):
        target = self.root / "original.txt"
        target.write_text("需要保留的原始资料")
        self.policy["directory_rules"] = [self.rule(self.root, "课程资料")]
        validate(self.policy)
        self.store.write("host.json", self.policy)
        result = self.cli("quarantine", "--path", target, "--apply")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(target.read_text(), "需要保留的原始资料")
        self.assertFalse((self.root / ".recycle").exists())

    def test_duplicate_rules_block_before_maintenance_in_both_orders(self):
        allow = self.rule(self.root)
        deny = dict(allow, allow_quarantine=False)
        target = self.root / "temporary"
        target.write_text("keep")
        for rules in ([allow, deny], [deny, allow], [allow, allow]):
            with self.subTest(rules=rules):
                policy = copy.deepcopy(self.policy)
                policy["directory_rules"] = rules
                with self.assertRaises(StewardError):
                    validate(policy)
                self.store.write("host.json", policy)
                before = self.store.target("host.json").read_bytes()
                result = self.cli("quarantine", "--path", target, "--apply")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(json.loads(result.stderr)["status"], "blocked")
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(target.read_text(), "keep")
                self.assertFalse(self.store.target("operations.json").exists())
                self.assertEqual(self.store.target("host.json").read_bytes(), before)

    def test_nested_distinct_rules_keep_longest_path_and_normal_recovery(self):
        child = self.root / "child"
        child.mkdir()
        target = child / "temporary"
        target.write_text("recover me")
        self.policy["directory_rules"] = [self.rule(self.root, "cold"), self.rule(child)]
        validate(self.policy)
        self.store.write("host.json", self.policy)
        moved = self.cli("quarantine", "--path", target, "--apply")
        self.assertEqual(moved.returncode, 0, moved.stderr)
        operation = json.loads(moved.stdout)["operation"]
        self.assertTrue(Path(operation["target"]).is_relative_to(child))
        restored = self.cli("restore", "--operation", operation["id"], "--apply")
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(target.read_text(), "recover me")

    def test_exclusion_names_are_valid_single_names(self):
        for value in (None, [], 1, "", ".", "..", "a/b", "bad\x00name"):
            with self.subTest(value=value):
                policy = copy.deepcopy(self.policy)
                policy["exclude_names"] = [value]
                with self.assertRaises(StewardError):
                    validate(policy)
        policy = copy.deepcopy(self.policy)
        policy["exclude_names"] += [".git", ".git"]
        validate(policy)

    def test_retired_roots_are_pruned_and_reentry_creates_fresh_baseline(self):
        other = self.base / "other"
        other.mkdir()
        self.store.write("current.json", {"version": 1, "pending": [{"key": "keep", "kind": "manual"}]})
        self.run_patrol()
        (self.root / "old-change").write_text("old")
        self.run_patrol()
        self.policy["roots"] = [str(other)]
        self.store.write("host.json", self.policy)
        report = self.run_patrol()
        self.assertEqual(report["new_baselines"], [str(other)])
        current = read_current(self.store)
        self.assertEqual(set(current["baselines"]), {str(other)})
        self.assertTrue(any(row["root"] == str(self.root) for row in current["changes"]))
        (self.root / "unobserved").write_text("new")
        self.policy["roots"] = [str(self.root)]
        self.store.write("host.json", self.policy)
        report = self.run_patrol()
        self.assertEqual(report["new_baselines"], [str(self.root)])
        self.assertEqual(report["changes"], [])
        self.assertEqual(set(read_current(self.store)["baselines"]), {str(self.root)})
        self.assertEqual([row["key"] for row in report["pending"]], ["keep"])
        result = self.cli("status", "--path", self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        status = json.loads(result.stdout)
        self.assertEqual(status["coverage_scope_count"], 1)
        self.assertEqual(set(status["coverage_scope"]), {str(self.root)})

    def test_exclude_change_rebaselines_without_deletion_and_stable_round_recovers(self):
        cache = self.root / "cache"
        cache.mkdir()
        target = cache / "keep"
        target.write_bytes(b"x" * 10)
        self.run_patrol()
        self.policy["exclude_names"].append("cache")
        self.store.write("host.json", self.policy)
        report = self.run_patrol()
        self.assertEqual(report["changes"], [])
        self.assertEqual(report["new_baselines"], [str(self.root)])
        self.assertTrue(report["last_run"]["coverage_complete"])
        self.assertTrue(any(reason.startswith("scope:") for row in report["gaps"] for reason in row["reasons"]))
        self.assertEqual(report["coverage_scope"][str(self.root)]["excluded"]["configured"], 1)
        self.assertTrue(target.is_file())
        self.assertFalse(any(row["kind"] == "directory_growth" for row in report["pending"]))
        self.assertEqual(self.run_patrol()["gaps"], [])
        self.assertFalse(self.run_patrol()["observations_changed"])

    def test_legacy_scope_is_upgraded_only_after_complete_snapshot(self):
        directory = self.root / "nested"
        directory.mkdir()
        (directory / "existing").write_text("keep")
        self.run_patrol()
        current = read_current(self.store)
        current["baselines"][str(self.root)].pop("scope")
        current.pop("coverage_scope")
        legacy = copy.deepcopy(current["baselines"][str(self.root)])
        self.store.write("current.json", current)
        self.policy["limits"]["scan_entries"] = 1
        self.store.write("host.json", self.policy)
        self.assertFalse(self.run_patrol()["last_run"]["coverage_complete"])
        self.assertEqual(read_current(self.store)["baselines"][str(self.root)], legacy)
        self.policy["limits"]["scan_entries"] = 5000
        self.store.write("host.json", self.policy)
        upgraded = self.run_patrol()
        self.assertEqual(upgraded["new_baselines"], [str(self.root)])
        self.assertEqual(upgraded["changes"], [])
        self.assertTrue(any(reason.startswith("scope:") for row in upgraded["gaps"] for reason in row["reasons"]))
        (directory / "new").write_text("new")
        self.assertTrue(self.run_patrol()["changes"])

    def test_non_scan_policy_changes_do_not_rebaseline(self):
        self.run_patrol()
        self.policy["purpose"] = "新的用途说明"
        self.policy["directory_rules"] = [self.rule(self.root)]
        self.policy["residents"] = [{"executable": "example", "reason": "只读保护"}]
        self.store.write("host.json", self.policy)
        report = self.run_patrol()
        self.assertEqual(report["new_baselines"], [])
        self.assertEqual(report["gaps"], [])
        self.assertEqual(report["changes"], [])

    def test_malformed_scope_and_coverage_metadata_fail_closed(self):
        self.run_patrol()
        original = read_current(self.store)
        payloads = []
        for field, value in (("device", True), ("exclude_names", ["x", "x"]), ("scan_depth", "bad")):
            current = copy.deepcopy(original)
            current["baselines"][str(self.root)]["scope"][field] = value
            payloads.append(current)
        current = copy.deepcopy(original)
        del current["baselines"][str(self.root)]["scope"]["state_path"]
        payloads.append(current)
        current = copy.deepcopy(original)
        current["baselines"][str(self.root)]["scope"]["other_volumes"]["count"] = 9
        payloads.append(current)
        for field, value in (("complete", 1), ("excluded", {"configured": True})):
            current = copy.deepcopy(original)
            current["coverage_scope"][str(self.root)][field] = value
            payloads.append(current)
        for index, current in enumerate(payloads):
            with self.subTest(case=index):
                self.store.write("current.json", current)
                before = self.store.target("current.json").read_bytes()
                with self.assertRaises(StewardError):
                    read_current(self.store)
                result = self.cli("status")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(self.store.target("current.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
