import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
from files import compare, identity, scan
from maintain import annotate, quarantine, restore
from observe import command, parse_processes
from state import Store, StewardError
from steward import initialize, memory_findings


class StewardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.store, self.policy = initialize(self.base / "state", [self.root], "测试样例")

    def tearDown(self):
        self.temporary.cleanup()

    def snapshot(self, limits=None):
        return scan([str(self.root)], limits or self.policy["limits"], state_path=str(self.store.path))

    def rule(self, directory, kind="temporary"):
        rule = {"path": str(directory), "purpose": "测试用途", "kind": kind, "allow_notes": True,
                "allow_quarantine": True, "retention_days": 0, "recycle_bytes": 1048576,
                "directory_id": identity(directory.stat())}
        self.policy["directory_rules"].append(rule)
        return rule

    def test_growth_without_file_count_change(self):
        logs = self.root / "logs"
        logs.mkdir()
        file = logs / "app.log"
        file.write_bytes(b"x")
        before = self.snapshot()
        file.write_bytes(b"x" * 10000)
        changes = compare(before, self.snapshot())["changes"]
        row = next(row for row in changes if row["path"] == str(logs))
        self.assertEqual(row["byte_delta"], 9999)
        self.assertEqual(row["modified"], 1)
        self.assertEqual(row["added"], 0)

    def test_new_tree_is_one_directory_event(self):
        before = self.snapshot()
        new = self.root / "new"
        new.mkdir()
        for i in range(150):
            (new / f"{i}.txt").write_text("x")
        changes = compare(before, self.snapshot())["changes"]
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["added"], 1)

    def test_directory_move_suppresses_children(self):
        from unittest.mock import patch
        source = self.root / "source"
        source.mkdir()
        (source / "item").write_text("value")
        with patch("files.birth", return_value=1):
            before = self.snapshot()
            source.rename(self.root / "target")
            changes = compare(before, self.snapshot())["changes"]
        self.assertEqual(sum(row["moved"] for row in changes), 1)
        self.assertEqual(sum(row["added"] + row["removed"] for row in changes), 0)

    def test_partial_scan_does_not_infer_deletion(self):
        for i in range(20):
            (self.root / str(i)).write_text("x")
        before = self.snapshot()
        partial = self.snapshot(dict(self.policy["limits"], scan_entries=2))
        delta = compare(before, partial)
        self.assertTrue(delta["gaps"])
        self.assertEqual(delta["changes"], [])

    def test_missing_root_is_gap(self):
        before = self.snapshot()
        self.root.rmdir()
        delta = compare(before, self.snapshot())
        self.assertTrue(delta["gaps"])
        self.assertFalse(delta["changes"])

    def test_hardlinks_do_not_double_count_bytes(self):
        file = self.root / "file"
        file.write_bytes(b"a" * 100)
        os.link(file, self.root / "alias")
        self.assertEqual(self.snapshot()[str(self.root)]["directories"][str(self.root)]["bytes"], 100)

    def test_symlink_tree_not_followed(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "large").write_bytes(b"x" * 10000)
        (self.root / "link").symlink_to(outside, target_is_directory=True)
        (outside / "AGENTS.md").write_text("外部说明")
        (self.root / "AGENTS.md").symlink_to(outside / "AGENTS.md")
        data = self.snapshot()[str(self.root)]
        self.assertEqual(data["directories"][str(self.root)]["bytes"], 0)
        self.assertIsNone(data["directories"][str(self.root)]["agents"])
        self.assertNotIn(str(outside / "large"), data["records"])

    def test_inode_reuse_not_inferred_as_move(self):
        path = self.root / "old"
        path.write_text("x")
        before = self.snapshot()
        after = copy.deepcopy(before)
        records = after[str(self.root)]["records"]
        entry = records.pop(str(path))
        entry.update(size=123, mtime=entry["mtime"] + 1, birth=(entry.get("birth") or 1) + 10)
        records[str(self.root / "new")] = entry
        self.assertEqual(sum(row["moved"] for row in compare(before, after)["changes"]), 0)

    def test_directory_replacement_is_visible_and_suppresses_children(self):
        directory = self.root / "replace"
        directory.mkdir()
        (directory / "old").write_text("x")
        before = self.snapshot()
        after = copy.deepcopy(before)
        root, path = str(self.root), str(directory)
        after[root]["records"][path]["id"] = "new:directory"
        after[root]["directories"][path]["id"] = "new:directory"
        record = after[root]["records"].pop(str(directory / "old"))
        record["id"] = "new:file"
        after[root]["records"][str(directory / "new")] = record
        delta = compare(before, after)
        self.assertEqual(len(delta["changes"]), 1)
        row = delta["changes"][0]
        self.assertEqual(row["path"], path)
        self.assertEqual(row["modified"], 1)
        self.assertEqual(row["added"] + row["removed"] + row["moved"], 0)
        self.assertTrue(row["continuity_gap"])
        self.assertTrue(row["samples"][0]["identity_changed"])
        self.assertTrue(any("identity:" in reason for reason in delta["gaps"][0]["reasons"]))

    def test_nested_directory_replacements_only_emit_outer_directory(self):
        parent = self.root / "parent"
        child = parent / "child"
        child.mkdir(parents=True)
        (child / "file").write_text("x")
        before = self.snapshot()
        after = copy.deepcopy(before)
        root = str(self.root)
        for path in [str(parent), str(child)]:
            after[root]["records"][path]["id"] = "new:" + path
            after[root]["directories"][path]["id"] = "new:" + path
        delta = compare(before, after)
        self.assertEqual(len(delta["changes"]), 1)
        self.assertEqual(delta["changes"][0]["path"], str(parent))
        self.assertEqual(delta["changes"][0]["modified"], 1)

    def test_reliable_move_is_not_directory_growth(self):
        from unittest.mock import patch
        from steward import patrol
        source, destination = self.root / "source", self.root / "destination"
        tree = source / "tree"
        tree.mkdir(parents=True)
        destination.mkdir()
        (tree / "file").write_bytes(b"x" * 100)
        rule = self.rule(destination, "active")
        rule["growth_warning_bytes"] = 1
        self.store.write("host.json", self.policy)
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        with patch("files.birth", return_value=1), patch("steward.observe", return_value=host), \
             patch("steward.native_events", return_value={"available": True}):
            patrol(self.store, self.policy)
            tree.rename(destination / "tree")
            report = patrol(self.store, self.policy)
        moved = [row for row in report["changes"] if row["moved"]]
        self.assertTrue(moved)
        self.assertTrue(all(row["average_growth_bytes_per_second"] is None for row in moved))
        self.assertFalse(any(row["kind"] == "directory_growth" and row["path"] == str(destination)
                             for row in report["pending"]))

    def test_nested_migration_ancestors_and_aggregated_real_growth(self):
        from steward import patrol
        self.rule(self.root, "active")["growth_warning_bytes"] = 1
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        with patch("files.birth", return_value=1), patch("steward.observe", return_value=host), \
             patch("steward.native_events", return_value={"available": True}):
            for limit in (96, 1):
                with self.subTest(groups=limit):
                    case = self.root / f"case-{limit}"
                    source, destination = case / "source", case / "destination"
                    tree = source / "tree"
                    tree.mkdir(parents=True)
                    nested = destination / "nested"
                    nested.mkdir(parents=True)
                    (source / "file").write_bytes(b"x" * 128)
                    (tree / "payload").write_bytes(b"x" * 256)
                    self.rule(destination, "active")["growth_warning_bytes"] = 1
                    self.policy["limits"]["change_records"] = limit
                    self.store.write("host.json", self.policy)
                    patrol(self.store, self.policy)
                    (source / "file").rename(nested / "file")
                    tree.rename(nested / "tree")
                    (self.root / f"log-{limit}").write_bytes(b"real")
                    report = patrol(self.store, self.policy)
                    by_path = {row["path"]: row for row in report["changes"]}
                    root_change = by_path[str(self.root)]
                    self.assertEqual(root_change["byte_delta"], 4)
                    self.assertFalse(root_change.get("migration_delta", False))
                    self.assertGreater(root_change["average_growth_bytes_per_second"], 0)
                    self.assertTrue(any(row["path"] == str(self.root) and row["growth_bytes"] == 4
                                        for row in report["pending"]))
                    if limit == 1:
                        self.assertEqual(len(by_path), 1)
                        self.assertGreater(root_change["moved"], 0)
                    else:
                        ancestor = by_path[str(destination)]
                        self.assertEqual(ancestor["byte_delta"], 384)
                        self.assertTrue(ancestor["migration_delta"])
                        self.assertIsNone(ancestor["average_growth_bytes_per_second"])
                        self.assertFalse(any(row["path"] == str(destination) for row in report["pending"]))

    def test_directory_to_file_is_one_replacement(self):
        directory = self.root / "replace"
        directory.mkdir()
        (directory / "old").write_text("x")
        before = self.snapshot()
        after = copy.deepcopy(before)
        root, path = str(self.root), str(directory)
        after[root]["records"][path].update(id="new:file", kind="file", size=1)
        del after[root]["records"][str(directory / "old")]
        del after[root]["directories"][path]
        delta = compare(before, after)
        self.assertEqual(len(delta["changes"]), 1)
        self.assertEqual(delta["changes"][0]["path"], path)
        self.assertEqual(delta["changes"][0]["modified"], 1)
        self.assertEqual(delta["changes"][0]["removed"], 0)
        self.assertTrue(delta["gaps"])

    def test_file_to_directory_is_one_replacement(self):
        path = self.root / "replace"
        path.write_text("x")
        before = self.snapshot()
        after = copy.deepcopy(before)
        root = str(self.root)
        after[root]["records"][str(path)].update(id="new:directory", kind="directory", size=0)
        after[root]["directories"][str(path)] = {"bytes": 1}
        after[root]["records"][str(path / "child")] = {"id": "new:child", "kind": "file", "size": 1,
                                                        "mtime": 1, "birth": 1}
        delta = compare(before, after)
        self.assertEqual(len(delta["changes"]), 1)
        row = delta["changes"][0]
        self.assertEqual(row["path"], str(path))
        self.assertEqual(row["modified"], 1)
        self.assertEqual(row["added"], 0)
        self.assertTrue(row["continuity_gap"])

    def test_file_swap_is_not_duplicate_modification_or_replacement(self):
        first, second = self.root / "a", self.root / "b"
        first.write_text("a")
        second.write_text("b")
        before = self.snapshot()
        root = str(self.root)
        before[root]["records"][str(first)]["birth"] = 1
        before[root]["records"][str(second)]["birth"] = 2
        after = copy.deepcopy(before)
        records = after[root]["records"]
        records[str(first)], records[str(second)] = records[str(second)], records[str(first)]
        delta = compare(before, after)
        self.assertEqual(sum(row["moved"] for row in delta["changes"]), 2)
        self.assertEqual(sum(row["modified"] for row in delta["changes"]), 0)
        self.assertEqual(delta["gaps"], [])

    def test_missing_birth_move_candidate_is_uncertain_not_moved(self):
        old = self.root / "old"
        old.write_text("x")
        before = self.snapshot()
        root = str(self.root)
        before[root]["records"][str(old)]["birth"] = None
        after = copy.deepcopy(before)
        record = after[root]["records"].pop(str(old))
        after[root]["records"][str(self.root / "new")] = record
        delta = compare(before, after)
        self.assertEqual(sum(row["moved"] for row in delta["changes"]), 0)
        self.assertEqual(sum(row["added"] for row in delta["changes"]), 1)
        self.assertEqual(sum(row["removed"] for row in delta["changes"]), 1)
        self.assertTrue(any("move uncertain" in reason for reason in delta["gaps"][0]["reasons"]))

    def test_replacement_byte_delta_is_not_growth_evidence(self):
        directory = self.root / "replace"
        directory.mkdir()
        file = directory / "file"
        file.write_text("x")
        before = self.snapshot()
        after = copy.deepcopy(before)
        root, path = str(self.root), str(directory)
        after[root]["records"][path]["id"] = "new:directory"
        after[root]["directories"][path]["id"] = "new:directory"
        after[root]["records"][str(file)]["size"] = 100
        after[root]["directories"][path]["bytes"] = 100
        after[root]["directories"][root]["bytes"] = 100
        delta = compare(before, after)
        self.assertTrue(delta["changes"])
        for row in delta["changes"]:
            self.assertTrue(row["continuity_gap"])
            self.assertIn("not growth evidence", row["size_scope"])

    def test_root_identity_change_rebases_with_identity_gap(self):
        before = self.snapshot()
        after = copy.deepcopy(before)
        root = str(self.root)
        after[root]["root_id"] = "new:root"
        after[root]["records"][root]["id"] = "new:root"
        delta = compare(before, after)
        self.assertEqual(delta["new_baselines"], [root])
        self.assertEqual(delta["changes"], [])
        self.assertTrue(any("identity: root changed" in reason for reason in delta["gaps"][0]["reasons"]))

    def test_state_quota_keeps_old_file_and_no_temp(self):
        self.store.write("current.json", {"original": True})
        before = self.store.target("current.json").read_bytes()
        small = Store(self.store.path, dict(self.policy["limits"], total_bytes=self.store.usage() + 1))
        with self.assertRaises(StewardError):
            small.write("current.json", {"replaced": True})
        self.assertEqual(self.store.target("current.json").read_bytes(), before)
        self.assertFalse(list(self.store.path.glob(".writing-*")))

    def test_corrupt_state_is_not_replaced(self):
        target = self.store.target("current.json")
        target.write_text("{bad")
        with self.assertRaises(StewardError):
            self.store.read("current.json")
        self.assertEqual(target.read_text(), "{bad")

    def test_wrong_current_schema_is_blocked_before_observation(self):
        from unittest.mock import patch
        from steward import patrol
        self.store.write("current.json", {"version": 1, "baselines": []})
        before = self.store.target("current.json").read_bytes()
        with patch("steward.native_events") as events:
            with self.assertRaises(StewardError):
                patrol(self.store, self.policy)
        events.assert_not_called()
        self.assertEqual(self.store.target("current.json").read_bytes(), before)

    def test_minimal_v1_and_unknown_top_level_are_preserved(self):
        from unittest.mock import patch
        from steward import patrol
        self.store.write("current.json", {"version": 1, "extension": {"keep": True}})
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": True}), \
             patch("steward.scan", return_value={}):
            patrol(self.store, self.policy)
        current = self.store.read("current.json")
        self.assertEqual(current["extension"], {"keep": True})
        self.assertEqual(current["pending_overflow"], [])
        self.assertEqual(current["pending_history"], [])

    def test_current_nested_schema_errors_are_steward_errors(self):
        from state_schema import read_current
        invalid = [
            ("events", []),
            ("pending", {}),
            ("changes", [{}]),
            ("samples", [{"time": 0, "processes": [{}]}]),
            ("directory_index", [{"root": "missing-path"}]),
        ]
        for key, value in invalid:
            with self.subTest(key=key):
                self.store.write("current.json", {"version": 1, key: value})
                before = self.store.target("current.json").read_bytes()
                with self.assertRaises(StewardError):
                    read_current(self.store)
                self.assertEqual(self.store.target("current.json").read_bytes(), before)
        self.store.write("current.json", {"version": 1, "pending": [{"key": "same"}, {"key": "same"}]})
        with self.assertRaises(StewardError):
            read_current(self.store)

    def test_store_rejects_duplicate_keys_and_nonfinite_numbers(self):
        target = self.store.target("current.json")
        for payload in ['{"version":1,"version":1}', '{"version":1,"value":1e309}', '{"version":1,"value":NaN}']:
            with self.subTest(payload=payload):
                target.write_text(payload)
                with self.assertRaises(StewardError):
                    self.store.read("current.json")
                self.assertEqual(target.read_text(), payload)

    def test_large_timestamp_is_blocked_before_observation_without_traceback(self):
        from state_schema import read_current
        from steward import patrol
        payloads = [
            {"changes": [{"path": str(self.root), "observed_at": 10**400}]},
            {"samples": [{"time": 10**400, "processes": []}]},
            {"baselines": {str(self.root): {"complete": False, "measured_at": 10**400}}},
            {"baselines": {str(self.root): {"complete": False, "measured_at": "bad"}}},
        ]
        for payload in payloads:
            with self.subTest(field=next(iter(payload))):
                self.store.write("current.json", dict(version=1, **payload))
                before = self.store.target("current.json").read_bytes()
                with self.assertRaises(StewardError):
                    read_current(self.store)
                with patch("steward.observe") as observation, self.assertRaises(StewardError):
                    patrol(self.store, self.policy)
                observation.assert_not_called()
                result = subprocess.run([str(PROJECT / "steward"), "patrol", "--state", str(self.store.path)],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(json.loads(result.stderr)["status"], "blocked")
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(self.store.target("current.json").read_bytes(), before)

    def test_timestamp_guard_does_not_restrict_integer_file_metadata(self):
        from state_schema import read_current
        baseline = {"complete": True, "root_id": "1:2", "measured_at": -10,
                    "records": {str(self.root / "old"): {"id": "1:3", "kind": "file",
                                 "size": 10**400, "mtime": -10**400, "birth": None}},
                    "directories": {str(self.root): {"bytes": 10**400}}}
        self.store.write("current.json", {"version": 1, "baselines": {str(self.root): baseline}})
        self.assertEqual(read_current(self.store)["baselines"][str(self.root)], baseline)

    def test_huge_byte_delta_keeps_exact_value_without_rate_overflow(self):
        from steward import patrol
        (self.root / "small").write_text("x")
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": True}):
            patrol(self.store, self.policy)
            original = self.store.read("current.json")
            for amount in (10**400, 10**308):
                with self.subTest(bytes=amount):
                    current = copy.deepcopy(original)
                    baseline = current["baselines"][str(self.root)]
                    baseline["directories"][str(self.root)]["bytes"] = amount
                    baseline["measured_at"] = 9.9
                    self.store.write("current.json", current)
                    with patch("steward.time.time", return_value=10.0):
                        report = patrol(self.store, self.policy)
                    change = next(row for row in report["changes"] if row["path"] == str(self.root))
                    self.assertEqual(change["byte_delta"], 1 - amount)
                    self.assertIsNone(change["average_growth_bytes_per_second"])
                    self.assertEqual(change["growth_rate_gap"], "numeric_range")
                    self.assertNotIn("Infinity", self.store.target("current.json").read_text())

    def test_host_rejects_duplicate_keys_and_boolean_version(self):
        from steward import load
        target = self.store.target("host.json")
        original = target.read_text()
        duplicate = original.replace('"version":1', '"version":1,"version":1', 1)
        self.assertNotEqual(duplicate, original)
        target.write_text(duplicate)
        with self.assertRaises(StewardError):
            load(self.store.path)
        policy = json.loads(original)
        policy["version"] = True
        self.store.write("host.json", policy)
        with self.assertRaises(StewardError):
            load(self.store.path)

    def test_quarantine_restore_supports_pre_epoch_mtime(self):
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("old but valid")
        os.utime(file, (-10, -10))
        moved = quarantine(self.store, self.policy, file, True)["operation"]
        self.assertLess(moved["identity"]["mtime"], 0)
        result = restore(self.store, self.policy, moved["id"], True)
        self.assertEqual(result["operation"]["status"], "restored")
        self.assertEqual(file.read_text(), "old but valid")

    def test_cli_wrong_schema_returns_blocked_json_not_traceback(self):
        self.store.write("current.json", {"version": 1, "baselines": []})
        result = subprocess.run([str(PROJECT / "steward"), "status", "--state", str(self.store.path)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["status"], "blocked")
        self.assertNotIn("Traceback", result.stderr)

    def test_patrol_lock_excludes_another_writer(self):
        other = Store(self.store.path, self.policy["limits"])
        with self.store.lock():
            with self.assertRaises(StewardError):
                with other.lock():
                    self.fail("重叠写入未被阻止")

    def test_patrol_refreshes_policy_and_store_limits_inside_lock(self):
        from unittest.mock import patch
        from steward import patrol
        fresh = copy.deepcopy(self.policy)
        fresh["limits"]["scan_entries"] = 1234
        self.store.write("host.json", fresh)
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": True}), \
             patch("steward.scan", return_value={}) as scanner:
            patrol(self.store, self.policy)
        self.assertEqual(scanner.call_args.args[1]["scan_entries"], 1234)
        self.assertEqual(self.store.limits["scan_entries"], 1234)

    def test_patrol_policy_change_before_commit_preserves_old_current(self):
        from unittest.mock import patch
        from steward import patrol
        self.store.write("current.json", {"version": 1})
        before = self.store.target("current.json").read_bytes()
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}

        def changing_scan(*args):
            changed = copy.deepcopy(self.policy)
            changed["purpose"] = "changed during scan"
            self.store.write("host.json", changed)
            return {}

        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": True}), \
             patch("steward.scan", side_effect=changing_scan):
            with self.assertRaises(StewardError):
                patrol(self.store, self.policy)
        self.assertEqual(self.store.target("current.json").read_bytes(), before)

    def test_main_uses_fresh_policy_for_quarantine(self):
        from unittest.mock import patch
        from steward import main
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("keep")
        fresh = copy.deepcopy(self.policy)
        fresh["directory_rules"] = []
        argv = ["steward", "quarantine", "--state", str(self.store.path), "--path", str(file), "--apply"]
        with patch("steward.read_policy", side_effect=[self.policy, fresh]), patch("steward.sys.argv", argv):
            with self.assertRaises(StewardError):
                main()
        self.assertEqual(file.read_text(), "keep")
        self.assertFalse((self.root / ".recycle").exists())

    def test_directory_rule_alias_is_rejected(self):
        from steward import validate
        real = self.root / "rule-directory"
        real.mkdir()
        alias = self.root / "rule-alias"
        alias.symlink_to(real, target_is_directory=True)
        policy = copy.deepcopy(self.policy)
        policy["directory_rules"] = [{"path": str(alias), "purpose": "alias", "kind": "cold"}]
        with self.assertRaises(StewardError):
            validate(policy)
        policy["directory_rules"][0]["path"] = str(real)
        validate(policy)

    def test_patrol_preserves_more_than_sixty_four_change_groups(self):
        from unittest.mock import patch
        from steward import patrol
        for index in range(65):
            (self.root / f"d{index}").mkdir()
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": True}):
            patrol(self.store, self.policy)
            for index in range(65):
                (self.root / f"d{index}" / "new.txt").write_text("x")
            report = patrol(self.store, self.policy)
        by_path = {row["path"]: row for row in report["changes"]}
        for index in range(65):
            row = by_path[str(self.root / f"d{index}")]
            self.assertEqual(row["added"], 1)
            self.assertEqual(row["byte_delta"], 1)
            self.assertNotIn("aggregation", row)

    def test_legacy_operation_alias_is_readable_but_restore_is_blocked(self):
        from maintain import fingerprint
        from state_schema import read_operations
        self.rule(self.root)
        alias = self.base / "operation-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        operation_id = "0" * 32
        target = self.root / ".recycle" / operation_id / "temporary"
        target.parent.mkdir(parents=True)
        target.write_text("recover me")
        operation = {"id": operation_id, "kind": "quarantine", "source": str(alias / "temporary"),
                     "target": str(target), "identity": fingerprint(target), "status": "quarantined"}
        self.store.write("operations.json", [operation])
        before = self.store.target("operations.json").read_bytes()
        self.assertEqual(len(read_operations(self.store)), 1)
        for apply in (False, True):
            with self.subTest(apply=apply), self.assertRaises(StewardError):
                restore(self.store, self.policy, operation_id, apply)
        self.assertEqual(target.read_text(), "recover me")
        self.assertEqual(self.store.target("operations.json").read_bytes(), before)

    def test_quarantine_policy_guard_preserves_source(self):
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("keep")

        def changed():
            raise StewardError("policy changed")

        with self.assertRaises(StewardError):
            quarantine(self.store, self.policy, file, True, changed)
        self.assertEqual(file.read_text(), "keep")
        self.assertEqual(self.store.read("operations.json")[0]["status"], "failed")

    def test_policy_change_does_not_rewrite_operation_with_stale_limits(self):
        from state import PolicyChangedError
        from steward import ensure_policy_locked
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("keep")
        changed = copy.deepcopy(self.policy)
        changed["limits"]["operation_records"] = 1

        def guard():
            self.store.write("host.json", changed)
            ensure_policy_locked(self.store, self.policy)

        with self.assertRaises(PolicyChangedError):
            quarantine(self.store, self.policy, file, True, guard)
        self.assertEqual(file.read_text(), "keep")
        self.assertEqual(self.store.read("operations.json")[0]["status"], "planned")

    def test_unreadable_policy_guard_preserves_planned_evidence(self):
        from state import PolicyChangedError
        from steward import ensure_policy_locked
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("keep")
        for action in (annotate, quarantine):
            for failure in ("corrupt", "missing", "io"):
                with self.subTest(action=action.__name__, failure=failure):
                    self.store.write("host.json", self.policy)

                    def guard():
                        if failure == "io":
                            with patch("steward.read_policy", side_effect=OSError("fixture I/O failure")):
                                ensure_policy_locked(self.store, self.policy)
                        else:
                            host = self.store.target("host.json")
                            if failure == "corrupt":
                                host.write_text("[]")
                            else:
                                host.unlink()
                            ensure_policy_locked(self.store, self.policy)

                    target = self.root if action is annotate else file
                    with self.assertRaises(PolicyChangedError):
                        action(self.store, self.policy, target, True, guard)
                    self.assertEqual(self.store.read("operations.json")[-1]["status"], "planned")
                    self.assertEqual(file.read_text(), "keep")
                    self.assertFalse((self.root / "AGENTS.md").exists())
                    self.assertFalse((self.root / ".recycle").exists())

    def test_unreadable_policy_during_restore_preserves_both_objects(self):
        from state import PolicyChangedError
        from steward import ensure_policy_locked
        self.rule(self.root)
        self.store.write("host.json", self.policy)
        file = self.root / "temporary"
        file.write_text("recover me")
        moved = quarantine(self.store, self.policy, file, True)["operation"]
        calls = []

        def guard():
            calls.append(1)
            if len(calls) == 2:
                self.store.target("host.json").write_text("[]")
            ensure_policy_locked(self.store, self.policy)

        with self.assertRaises(PolicyChangedError):
            restore(self.store, self.policy, moved["id"], True, guard)
        self.assertEqual(file.read_text(), "recover me")
        self.assertEqual(Path(moved["target"]).read_text(), "recover me")
        self.assertEqual(self.store.read("operations.json")[-1]["status"], "restoring")

    def test_restore_policy_guard_preserves_both_objects(self):
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("recover me")
        moved = quarantine(self.store, self.policy, file, True)["operation"]
        calls = []

        def changed():
            calls.append(1)
            if len(calls) == 2:
                raise StewardError("policy changed")

        with self.assertRaises(StewardError):
            restore(self.store, self.policy, moved["id"], True, changed)
        self.assertEqual(file.read_text(), "recover me")
        self.assertEqual(Path(moved["target"]).read_text(), "recover me")
        self.assertEqual(self.store.read("operations.json")[0]["status"], "restoring")

    def test_note_preserves_user_text_and_is_idempotent(self):
        self.rule(self.root, "cold")
        target = self.root / "AGENTS.md"
        original = "# 用户说明\n必须保留\n<!-- host-steward:managed -->\n旧说明\n<!-- host-steward:unknown -->\n"
        target.write_text(original)
        preview = annotate(self.store, self.policy, self.root)
        self.assertFalse(preview["applied"])
        self.assertEqual(target.read_text(), original)
        annotate(self.store, self.policy, self.root, True)
        text = target.read_text()
        self.assertTrue(text.startswith(original))
        self.assertEqual(text.count("<!-- host-steward:begin -->"), 1)
        self.assertEqual(text.count("<!-- host-steward:end -->"), 1)
        self.assertFalse(annotate(self.store, self.policy, self.root, True)["applied"])

    def test_cold_data_not_quarantined_even_if_old(self):
        self.rule(self.root, "cold")
        file = self.root / "original"
        file.write_text("important")
        os.utime(file, (1, 1))
        with self.assertRaises(StewardError):
            quarantine(self.store, self.policy, file, True)
        self.assertEqual(file.read_text(), "important")

    def test_quarantine_restore_and_occupied_destination(self):
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("recover me")
        moved = quarantine(self.store, self.policy, file, True)["operation"]
        self.assertEqual(moved["space_released_bytes"], 0)
        self.assertFalse(file.exists())
        file.write_text("new object")
        with self.assertRaises(StewardError):
            restore(self.store, self.policy, moved["id"], True)
        self.assertEqual(file.read_text(), "new object")
        file.unlink()
        restore(self.store, self.policy, moved["id"], True)
        self.assertEqual(file.read_text(), "recover me")

    def test_restore_allows_nonempty_operation_directory(self):
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("recover me")
        moved = quarantine(self.store, self.policy, file, True)["operation"]
        target = Path(moved["target"])
        extra = target.parent / "keep"
        extra.write_text("do not clean")
        result = restore(self.store, self.policy, moved["id"], True)
        self.assertEqual(result["operation"]["status"], "restored")
        self.assertFalse(result["cleanup"]["removed"])
        self.assertTrue(result["cleanup"]["reason"])
        self.assertEqual(file.read_text(), "recover me")
        self.assertFalse(target.exists())
        self.assertEqual(extra.read_text(), "do not clean")
        self.assertEqual(self.store.read("operations.json")[0]["status"], "restored")
        with self.assertRaises(StewardError):
            restore(self.store, self.policy, moved["id"], True)
        self.assertEqual(extra.read_text(), "do not clean")

    def test_restore_resumes_when_source_and_target_exist(self):
        from unittest.mock import patch
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("recover me")
        moved = quarantine(self.store, self.policy, file, True)["operation"]
        os.link(moved["target"], file)
        moved["status"] = "restoring"
        self.store.write("operations.json", [moved])
        with patch("maintain.os.link", side_effect=AssertionError("must not link twice")):
            result = restore(self.store, self.policy, moved["id"], True)
        self.assertEqual(result["operation"]["status"], "restored")
        self.assertEqual(file.read_text(), "recover me")
        self.assertFalse(Path(moved["target"]).exists())

    def test_restore_converges_record_after_target_was_removed(self):
        from unittest.mock import patch
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("recover me")
        moved = quarantine(self.store, self.policy, file, True)["operation"]
        os.link(moved["target"], file)
        Path(moved["target"]).unlink()
        moved["status"] = "restoring"
        self.store.write("operations.json", [moved])
        with patch("maintain.os.link", side_effect=AssertionError("must not link")):
            result = restore(self.store, self.policy, moved["id"], True)
        self.assertEqual(result["operation"]["status"], "restored")
        self.assertEqual(file.read_text(), "recover me")

    def test_restore_does_not_replay_planned_or_failed_quarantine(self):
        self.rule(self.root)
        for status in ["planned", "failed"]:
            with self.subTest(status=status):
                file = self.root / f"temporary-{status}"
                file.write_text("recover me")
                moved = quarantine(self.store, self.policy, file, True)["operation"]
                moved["status"] = status
                self.store.write("operations.json", [moved])
                with self.assertRaises(StewardError):
                    restore(self.store, self.policy, moved["id"], True)
                self.assertTrue(Path(moved["target"]).exists())
                self.assertEqual(self.store.read("operations.json")[0]["status"], status)

    def test_restore_rejects_operation_id_path_escape(self):
        from maintain import fingerprint
        self.rule(self.root)
        source = self.root / "temporary"
        operation_id = str(self.base / "outside-operation")
        target = Path(operation_id) / source.name
        target.parent.mkdir()
        target.write_text("outside")
        operation = {"id": operation_id, "kind": "quarantine", "source": str(source),
                     "target": str(target), "identity": fingerprint(target), "status": "quarantined"}
        self.store.write("operations.json", [operation])
        with self.assertRaises(StewardError):
            restore(self.store, self.policy, operation_id, True)
        self.assertEqual(target.read_text(), "outside")
        self.assertFalse(source.exists())

    def test_changed_directory_identity_blocks_maintenance(self):
        self.rule(self.root)
        self.policy["directory_rules"][0]["directory_id"] = "old:identity"
        with self.assertRaises(StewardError):
            annotate(self.store, self.policy, self.root, True)
        self.assertFalse((self.root / "AGENTS.md").exists())

    def test_recycle_budget_rejects_without_moving_file(self):
        rule = self.rule(self.root)
        rule["recycle_bytes"] = 1
        file = self.root / "temporary"
        file.write_text("too large")
        with self.assertRaises(StewardError):
            quarantine(self.store, self.policy, file, True)
        self.assertEqual(file.read_text(), "too large")

    def test_operation_limit_keeps_quarantine_recovery_evidence(self):
        self.rule(self.root)
        self.store.limits["operation_records"] = 1
        first = self.root / "first"
        second = self.root / "second"
        first.write_text("first")
        second.write_text("second")
        original = quarantine(self.store, self.policy, first, True)["operation"]
        with self.assertRaises(StewardError):
            quarantine(self.store, self.policy, second, True)
        self.assertEqual(second.read_text(), "second")
        self.assertEqual(self.store.read("operations.json")[0]["id"], original["id"])
        self.assertTrue(Path(original["target"]).exists())

    def test_malformed_operations_block_before_file_changes(self):
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("keep")
        for payload in [{}, [{}]]:
            with self.subTest(payload=payload):
                self.store.write("operations.json", payload)
                before = self.store.target("operations.json").read_bytes()
                with self.assertRaises(StewardError):
                    quarantine(self.store, self.policy, file, True)
                with self.assertRaises(StewardError):
                    restore(self.store, self.policy, "0" * 32, True)
                self.assertEqual(file.read_text(), "keep")
                self.assertEqual(self.store.target("operations.json").read_bytes(), before)

    def test_unknown_operation_kind_is_not_evicted(self):
        self.rule(self.root)
        self.store.limits["operation_records"] = 1
        opaque = {"id": "0" * 32, "kind": "future_operation", "status": "verified"}
        self.store.write("operations.json", [opaque])
        file = self.root / "temporary"
        file.write_text("keep")
        with self.assertRaises(StewardError):
            quarantine(self.store, self.policy, file, True)
        self.assertEqual(self.store.read("operations.json"), [opaque])
        self.assertEqual(file.read_text(), "keep")

    def test_restore_rejects_external_target_with_valid_operation_id(self):
        from maintain import fingerprint
        self.rule(self.root)
        source = self.root / "temporary"
        target = self.base / "outside"
        target.write_text("outside")
        operation = {"id": "0" * 32, "kind": "quarantine", "source": str(source),
                     "target": str(target), "identity": fingerprint(target), "status": "quarantined"}
        self.store.write("operations.json", [operation])
        with self.assertRaises(StewardError):
            restore(self.store, self.policy, operation["id"], True)
        self.assertEqual(target.read_text(), "outside")
        self.assertFalse(source.exists())

    def test_state_budget_blocks_maintenance_before_file_change(self):
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("keep")
        small = Store(self.store.path, dict(self.policy["limits"], total_bytes=self.store.usage() + 100))
        with self.assertRaises(StewardError):
            quarantine(small, self.policy, file, True)
        self.assertEqual(file.read_text(), "keep")
        self.assertFalse((self.root / ".recycle").exists())

    def test_macos_memory_failure_identifies_failed_source(self):
        from unittest.mock import patch
        from observe import observe
        success = {"ok": True, "reason": None, "text": ""}
        failure = {"ok": False, "reason": "command_failed", "text": ""}
        for failed in ["vm_stat", "sysctl"]:
            with self.subTest(source=failed):
                responses = {"vm_stat": dict(success, text="Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"),
                             "sysctl": dict(success, text="8589934592\n")}
                responses[failed] = failure
                with patch("observe.platform.system", return_value="Darwin"), \
                     patch("observe.command", side_effect=lambda arguments, *args: responses.get(arguments[0], success)):
                    result = observe(self.policy)
                self.assertFalse(result["memory"]["available"])
                self.assertIn(failed, result["memory"]["reason"])

    def test_macos_memory_does_not_accept_invalid_capacity_as_available(self):
        from unittest.mock import patch
        from observe import observe
        for value in ["", "unknown", "0"]:
            with self.subTest(capacity=value):
                def response(arguments, *args):
                    text = "page size of 16384 bytes" if arguments[0] == "vm_stat" else value if arguments[0] == "sysctl" else ""
                    return {"ok": True, "reason": None, "text": text}
                with patch("observe.platform.system", return_value="Darwin"), patch("observe.command", side_effect=response):
                    result = observe(self.policy)
                self.assertFalse(result["memory"]["available"])
                self.assertTrue(result["memory"]["reason"])

    def test_linux_memory_observation_uses_explicit_available_memory(self):
        from unittest.mock import patch
        from observe import observe
        with patch("observe.platform.system", return_value="Linux"), \
             patch("observe.Path.read_text", return_value="MemTotal: 1000 kB\nMemAvailable: 250 kB\n"), \
             patch("observe.command", return_value={"ok": True, "reason": None, "text": ""}):
            result = observe(self.policy)
        self.assertEqual(result["memory"]["total_bytes"], 1024000)
        self.assertEqual(result["memory"]["available_bytes"], 256000)

    def test_linux_event_reader_does_not_claim_persistent_history(self):
        from unittest.mock import patch
        from events import read_events
        with patch("events.sys.platform", "linux"):
            result = read_events([str(self.root)], 123)
        self.assertFalse(result["available"])
        self.assertEqual(result["source"], "metadata_snapshot")

    def test_event_flags_distinguish_rescan_from_history_loss(self):
        from events import apply_event_flag
        result = {"history_complete": False, "history_invalid": False, "rescan_required": False}
        apply_event_flag(result, 0x1)
        self.assertTrue(result["rescan_required"])
        self.assertFalse(result["history_invalid"])
        apply_event_flag(result, 0x10)
        self.assertTrue(result["history_complete"])
        apply_event_flag(result, 0x2)
        self.assertTrue(result["history_invalid"])

    def test_event_since_requires_a_reusable_cursor(self):
        from steward import event_since
        devices = {str(self.root): 1}
        previous = {"events": {"devices": devices, "cursor": 10, "history_invalid": False}}
        self.assertEqual(event_since(previous, devices), 10)
        self.assertIsNone(event_since(previous, {str(self.root): 2}))
        invalid = {"events": dict(previous["events"], history_invalid=True)}
        self.assertIsNone(event_since(invalid, devices))
        legacy = {"events": {"devices": devices, "cursor": 10, "history_complete": False, "rescan_required": True}}
        self.assertIsNone(event_since(legacy, devices))
        legacy["events"].update(history_complete=True, rescan_required=False)
        self.assertEqual(event_since(legacy, devices), 10)
        self.assertIsNone(event_since(previous, {str(self.root): None}))

    def test_event_cursor_commit_requires_complete_snapshots(self):
        from steward import event_since, finalize_events
        root = str(self.root)
        devices = {root: 1}
        previous = {"events": {"devices": devices, "cursor": 10, "history_invalid": False}}
        candidate = {"source": "macos_fsevents", "available": True, "cursor": 20,
                     "history_complete": True, "history_invalid": False, "rescan_required": True,
                     "baseline": False, "devices": devices}
        complete = {root: {"complete": True}}
        result = finalize_events(candidate, previous, complete, [root])
        self.assertEqual(result["cursor"], 20)
        self.assertFalse(result["cursor_pending"])
        result = finalize_events(candidate, previous, {root: {"complete": False}}, [root])
        self.assertEqual(result["cursor"], 10)
        self.assertTrue(result["cursor_pending"])
        baseline = dict(candidate, baseline=True, history_complete=False)
        self.assertEqual(finalize_events(baseline, previous, complete, [root])["cursor"], 20)
        invalid = dict(candidate, history_invalid=True)
        result = finalize_events(invalid, previous, complete, [root])
        self.assertTrue(result["history_invalid"])
        self.assertIsNone(event_since({"events": result}, devices))

    def test_event_retry_limit_forces_rebaseline(self):
        from steward import event_since, finalize_events
        root = str(self.root)
        devices = {root: 1}
        previous = {"events": {"devices": devices, "cursor": 10, "history_invalid": False, "retry_count": 2}}
        candidate = {"source": "macos_fsevents", "available": False, "baseline": False, "devices": devices}
        result = finalize_events(candidate, previous, {root: {"complete": True}}, [root])
        self.assertEqual(result["retry_count"], 3)
        self.assertTrue(result["history_invalid"])
        self.assertIsNone(result["cursor"])
        self.assertIsNone(event_since({"events": result}, devices))

    def test_native_events_rejects_non_object_json_and_malformed_previous(self):
        from unittest.mock import patch
        from steward import event_since, finalize_events, native_events
        root = str(self.root)
        devices = {root: os.stat(root).st_dev}
        self.assertIsNone(event_since({"events": []}, devices))
        previous = {"events": {"devices": devices, "cursor": 10, "history_invalid": False}}
        with patch("steward.sys.platform", "darwin"), \
             patch("steward.command", return_value={"ok": True, "reason": None, "text": "[]"}):
            candidate = native_events(self.policy, previous)
        self.assertFalse(candidate["available"])
        result = finalize_events(candidate, previous, {root: {"complete": True}}, [root])
        self.assertEqual(result["cursor"], 10)

    def test_macos_event_gap_is_reported_once_and_recovery_is_visible(self):
        from unittest.mock import patch
        from steward import patrol
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        unavailable = {"source": "macos_fsevents", "available": False}
        recovered = {"source": "macos_fsevents", "available": True, "baseline": True,
                     "history_complete": False, "history_invalid": False, "cursor": 20}
        with patch("steward.observe", return_value=host), \
             patch("steward.native_events", side_effect=[dict(unavailable), dict(unavailable), recovered]):
            first = patrol(self.store, self.policy)
            second = patrol(self.store, self.policy)
            third = patrol(self.store, self.policy)
        self.assertTrue(first["actionable"])
        self.assertFalse(second["actionable"])
        self.assertEqual(second["observation_gaps"], [{"kind": "events", "reason": "unavailable"}])
        self.assertTrue(third["actionable"])
        self.assertEqual(third["observation_gaps"], [])
        self.assertEqual(third["events"]["cursor"], 20)
        self.assertFalse(third["events"]["cursor_pending"])

    def test_linux_snapshot_mode_does_not_create_event_gap(self):
        from unittest.mock import patch
        from steward import patrol
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        events = {"source": "metadata_snapshot", "available": False}
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value=events):
            patrol(self.store, self.policy)
            report = patrol(self.store, self.policy)
        self.assertFalse(report["actionable"])
        self.assertEqual(report["observation_gaps"], [])
        self.assertTrue(report["last_run"]["coverage_complete"])
        self.assertEqual(report["events"]["source"], "metadata_snapshot")

    def test_restore_does_not_overwrite_file_created_after_plan(self):
        from unittest.mock import patch
        self.rule(self.root)
        file = self.root / "temporary"
        file.write_text("recover me")
        moved = quarantine(self.store, self.policy, file, True)["operation"]
        original_link = os.link
        def competing_link(source, destination):
            Path(destination).write_text("new object after plan")
            return original_link(source, destination)
        with patch("maintain.os.link", side_effect=competing_link):
            with self.assertRaises(FileExistsError):
                restore(self.store, self.policy, moved["id"], True)
        self.assertEqual(file.read_text(), "new object after plan")
        self.assertEqual(Path(moved["target"]).read_text(), "recover me")
        self.assertEqual(self.store.read("operations.json")[0]["status"], "restoring")
        file.unlink()
        result = restore(self.store, self.policy, moved["id"], True)
        self.assertEqual(result["operation"]["status"], "restored")
        self.assertEqual(file.read_text(), "recover me")
        self.assertFalse(Path(moved["target"]).exists())

    def test_symlink_maintenance_rejected(self):
        self.rule(self.root)
        (self.base / "outside").write_text("keep")
        (self.root / "alias").symlink_to(self.base / "outside")
        with self.assertRaises(StewardError):
            quarantine(self.store, self.policy, self.root / "alias", True)
        self.assertEqual((self.base / "outside").read_text(), "keep")

    def test_subprocess_output_and_time_are_bounded(self):
        result = command([sys.executable, "-c", "print('x'*100000)"], max_bytes=128)
        self.assertFalse(result["ok"])
        self.assertLessEqual(len(result["text"]), 128)
        result = command([sys.executable, "-c", "import time;time.sleep(10)"], timeout=0.1)
        self.assertEqual(result["reason"], "command_timeout")

    def test_process_identity_changes_after_restart(self):
        text = "10 1 Fri Oct 16 10:00:00 2026 2.0 100 /usr/bin/app\n10 1 Fri Oct 16 10:01:00 2026 2.0 100 /usr/bin/app\n"
        rows = parse_processes(text, [])
        self.assertNotEqual(rows[0]["identity"], rows[1]["identity"])
        self.assertIn("unknown", rows[0]["protection"])

    def test_memory_growth_is_only_suspicion_with_same_identity(self):
        samples = [{"time": i * 300, "processes": [{"identity": "same", "rss_bytes": (100 + i * 50) * 1024**2}]} for i in range(4)]
        self.assertEqual(memory_findings(samples)[0]["kind"], "suspected_memory_growth")
        for i, sample in enumerate(samples):
            sample["processes"][0]["identity"] = str(i)
        self.assertEqual(memory_findings(samples), [])

    def test_pending_overflow_preserves_patrol_progress(self):
        from unittest.mock import patch
        from steward import patrol
        rows = [{"key": f"old:{i}", "kind": "directory_growth", "observed_at": 1} for i in range(64)]
        self.store.write("current.json", {"version": 1, "baselines": {}, "changes": [], "samples": [], "pending": rows})
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        finding = {"key": "new", "kind": "directory_growth", "path": str(self.root)}
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": True}), \
             patch("steward.scan", return_value={}), patch("steward.memory_findings", return_value=[finding]):
            first = patrol(self.store, self.policy)
            current = self.store.read("current.json")
            self.assertEqual(len(current["pending"]), 64)
            self.assertEqual(current["pending_overflow"][0]["key"], "new")
            self.assertIsNotNone(current["last_run"])
            self.assertTrue(first["actionable"])
            first_seen = current["pending_overflow"][0]["first_observed_at"]
            second = patrol(self.store, self.policy)
        self.assertFalse(second["actionable"])
        self.assertEqual(len(second["pending_overflow"]), 1)
        self.assertEqual(second["pending_overflow"][0]["first_observed_at"], first_seen)

    def test_resolve_pending_promotes_overflow_and_allows_reopening(self):
        from unittest.mock import patch
        from steward import patrol, resolve_pending
        pending = [{"key": f"old:{i}", "kind": "directory_growth", "observed_at": i} for i in range(64)]
        overflow = [{"key": "queued", "kind": "directory_growth", "observed_at": 65},
                    {"key": "queued-two", "kind": "directory_growth", "observed_at": 66}]
        self.store.write("current.json", {"version": 1, "baselines": {}, "changes": [], "samples": [],
                                          "pending": pending, "pending_overflow": overflow})
        result = resolve_pending(self.store, "old:0", "已核对一次性格增长")
        self.assertEqual(result["promoted"], ["queued"])
        self.assertEqual(result["pending_count"], 64)
        self.assertEqual(result["pending_overflow_count"], 1)
        resolve_pending(self.store, "queued-two", "已核对溢出事项")
        current = self.store.read("current.json")
        self.assertEqual(len(current["pending_history"]), 2)
        self.assertFalse(current["pending_overflow"])
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        finding = {"key": "old:0", "kind": "directory_growth", "path": str(self.root)}
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": True}), \
             patch("steward.scan", return_value={}), patch("steward.memory_findings", return_value=[finding]):
            report = patrol(self.store, self.policy)
        self.assertTrue(report["actionable"])
        self.assertEqual(report["pending_overflow"][0]["key"], "old:0")

    def test_pending_overflow_limit_blocks_with_current_key(self):
        from unittest.mock import patch
        from steward import patrol
        pending = [{"key": f"old:{i}", "kind": "directory_growth"} for i in range(64)]
        overflow = [{"key": f"queued:{i}", "kind": "directory_growth"} for i in range(64)]
        self.store.write("current.json", {"version": 1, "baselines": {}, "changes": [], "samples": [],
                                          "pending": pending, "pending_overflow": overflow})
        before = self.store.target("current.json").read_bytes()
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        finding = {"key": "overflow-key", "kind": "directory_growth"}
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": True}), \
             patch("steward.scan", return_value={}), patch("steward.memory_findings", return_value=[finding]):
            with self.assertRaisesRegex(StewardError, "overflow-key"):
                patrol(self.store, self.policy)
        self.assertEqual(self.store.target("current.json").read_bytes(), before)

    def test_pending_capacity_precheck_reports_current_keys_and_key_limit(self):
        from unittest.mock import patch
        from steward import patrol
        pending = [{"key": f"old:{i}", "kind": "directory_growth"} for i in range(64)]
        overflow = [{"key": f"queued:{i}", "kind": "directory_growth"} for i in range(63)]
        self.store.write("current.json", {"version": 1, "baselines": {}, "changes": [], "samples": [],
                                          "pending": pending, "pending_overflow": overflow})
        before = self.store.target("current.json").read_bytes()
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        findings = [{"key": "first-key", "kind": "directory_growth"},
                    {"key": "second-key", "kind": "directory_growth"}]
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": True}), \
             patch("steward.scan", return_value={}), patch("steward.memory_findings", return_value=findings):
            with self.assertRaises(StewardError) as caught:
                patrol(self.store, self.policy)
        self.assertIn("first-key", str(caught.exception))
        self.assertIn("second-key", str(caught.exception))
        self.assertEqual(self.store.target("current.json").read_bytes(), before)
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": True}), \
             patch("steward.scan", return_value={}), patch("steward.memory_findings", return_value=[{"key": "x" * 513}]):
            with self.assertRaisesRegex(StewardError, "512"):
                patrol(self.store, self.policy)
        self.assertEqual(self.store.target("current.json").read_bytes(), before)

    def test_status_pages_pending_and_overflow(self):
        pending = [{"key": f"old:{i}", "kind": "directory_growth"} for i in range(25)]
        overflow = [{"key": f"queued:{i}", "kind": "directory_growth"} for i in range(3)]
        self.store.write("current.json", {"version": 1, "pending": pending, "pending_overflow": overflow})
        result = subprocess.run([str(PROJECT / "steward"), "status", "--state", str(self.store.path),
                                 "--limit", "2", "--offset", "1"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([row["key"] for row in report["pending"]], ["old:1", "old:2"])
        self.assertEqual(report["pending_count"], 25)
        self.assertEqual([row["key"] for row in report["pending_overflow"]], ["queued:1", "queued:2"])
        self.assertEqual(report["pending_overflow_count"], 3)

    def test_status_path_matches_legacy_alias_without_rewriting(self):
        alias = self.base / "old-index-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.store.write("current.json", {"version": 1,
                         "directory_index": [{"root": str(self.root), "path": str(alias)}],
                         "changes": [{"path": str(alias), "observed_at": time.time()}]})
        before = self.store.target("current.json").read_bytes()
        result = subprocess.run([str(PROJECT / "steward"), "status", "--state", str(self.store.path),
                                 "--path", str(self.root)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["directory_count"], 1)
        self.assertEqual(report["change_count"], 1)
        self.assertEqual(report["directory_index"][0]["path"], str(alias))
        self.assertEqual(self.store.target("current.json").read_bytes(), before)

    def test_pending_history_is_bounded(self):
        from steward import resolve_pending
        rows = [{"key": f"old:{i}", "kind": "directory_growth"} for i in range(33)]
        self.store.write("current.json", {"version": 1, "pending": rows})
        for row in rows:
            resolve_pending(self.store, row["key"], "已处理")
        current = self.store.read("current.json")
        self.assertEqual(len(current["pending_history"]), 32)
        self.assertEqual(current["pending_history_dropped"], 1)
        self.assertFalse(current["pending"])

    def test_partial_patrol_preserves_last_directory_index(self):
        from unittest.mock import patch
        from steward import patrol
        (self.root / "known").mkdir()
        fake_host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {}, "gpu": {},
                     "model_usage": {}, "storage": [], "processes": {"items": []}, "services": {"items": []}}
        with patch("steward.observe", return_value=fake_host), patch("steward.native_events", return_value={"available": False}):
            patrol(self.store, self.policy)
            self.policy["limits"]["scan_entries"] = 1
            self.store.write("host.json", self.policy)
            for i in range(5):
                (self.root / str(i)).write_text("x")
            patrol(self.store, self.policy)
        current = self.store.read("current.json")
        known = next(row for row in current["directory_index"] if row["path"] == str(self.root / "known"))
        self.assertTrue(known["stale"])
        self.assertFalse(known["complete"])
        self.assertTrue(current["coverage_gaps"])

    def test_loss_of_host_observation_is_reported_once(self):
        from unittest.mock import patch
        from steward import patrol
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True}, "gpu": {},
                "model_usage": {}, "storage": [], "processes": {"available": True, "items": []},
                "services": {"available": True, "items": []}}
        with patch("steward.observe", return_value=host), patch("steward.native_events", return_value={"available": False}):
            patrol(self.store, self.policy)
            host["processes"].update(available=False, reason="permission_denied")
            self.assertTrue(patrol(self.store, self.policy)["actionable"])
            self.assertFalse(patrol(self.store, self.policy)["actionable"])
        self.assertEqual(self.store.read("current.json")["observation_gaps"][0]["kind"], "processes")

    def test_shell_entry_works_in_bash_and_zsh(self):
        for shell in ["/bin/bash", "/bin/zsh"]:
            if Path(shell).exists():
                result = subprocess.run([shell, str(PROJECT / "steward"), "--help"], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_entry_handles_space_in_its_directory(self):
        directory = self.base / "skill with spaces"
        directory.mkdir()
        (directory / "steward").write_bytes((PROJECT / "steward").read_bytes())
        (directory / "tools").symlink_to(PROJECT / "tools", target_is_directory=True)
        for shell in ["/bin/bash", "/bin/zsh"]:
            if Path(shell).exists():
                result = subprocess.run([shell, str(directory / "steward"), "--help"], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
