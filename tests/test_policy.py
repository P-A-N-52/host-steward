import copy
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
from files import compare, scan, identity
from history_config import (DEFAULT_HISTORY, GAP_ABSOLUTE_LIMIT, HISTORY_FIELDS,
                            RETENTION_HOURS_ABSOLUTE_LIMIT, RUN_ABSOLUTE_LIMIT,
                            resolve_history, validate_history)
from inventory import query, register
from investigate import inspect_target
from maintain import quarantine, restore
from observe import observe
from policy import (DEFAULT_SAMPLING, convert_v1_policy, make_policy_evidence,
                    new_root, policy_digest, read_policy_with_evidence,
                    read_recorded_policy, root_rule, validate, excluded_by_rule)
from sample_store import SampleStore
from state import StewardError, decode
from state_schema import read_current, validate_scope
from steward import initialize, patrol, refresh_policy_locked


def legacy_limits(depth=2):
    return {
        "scan_entries": 5000, "scan_seconds": 3, "scan_depth": depth, "processes": 200,
        "command_bytes": 262144, "file_bytes": 1048576, "total_bytes": 4194304,
        "output_bytes": 32768, "change_records": 96, "sample_records": 48,
        "operation_records": 32, "retention_hours": 48,
    }


def legacy_policy(root, rules=()):
    return {
        "version": 1,
        "purpose": "v1 兼容测试",
        "roots": [str(root)],
        "exclude_names": [".git", "__pycache__"],
        "residents": [{"executable": "example", "reason": "只读保护"}],
        "directory_rules": list(rules),
        "limits": legacy_limits(),
        "host": {"system": platform.system(), "hostname": platform.node()},
        "未来扩展": {"keep": True},
    }


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "观察 目录"
        self.root.mkdir()
        self.store, self.policy = initialize(self.base / "state", [self.root], "配置专项测试")

    def host(self):
        return {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True},
                "gpu": {}, "model_usage": {}, "storage": [],
                "processes": {"available": True, "items": []}, "services": {"available": True, "items": []}}

    def patrol(self):
        with patch("steward.observe", return_value=self.host()), \
             patch("steward.native_events", return_value={"available": True}):
            return patrol(self.store, self.policy)

    def changed(self, change):
        policy = copy.deepcopy(self.policy)
        change(policy)
        return policy

    def status(self):
        result = subprocess.run([sys.executable, str(PROJECT / "tools/steward.py"), "status",
                                 "--state", str(self.store.path)],
                                cwd="/", capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_v2_requires_unique_root_rules_and_valid_sampling(self):
        self.assertEqual(self.policy["version"], 2)
        self.assertEqual(self.policy["roots"][0]["max_depth"], 32)
        self.assertEqual(self.policy["roots"][0]["exclude_paths"], [])
        self.assertEqual(self.policy["sampling"], DEFAULT_SAMPLING)
        self.assertGreaterEqual(DEFAULT_SAMPLING["records"] * DEFAULT_SAMPLING["interval_seconds"], 600)
        self.assertNotIn("scan_depth", self.policy["limits"])
        cases = [
            lambda p: p.update(exclude_names=[".git"]),
            lambda p: p["roots"][0].pop("exclude_paths"),
            lambda p: p["roots"][0].update(max_depth=-1),
            lambda p: p["roots"][0].update(max_depth=True),
            lambda p: p["roots"][0].update(exclude_names=["a/b"]),
            lambda p: p["roots"][0].update(exclude_paths=["/absolute"]),
            lambda p: p["roots"][0].update(exclude_paths=["."]),
            lambda p: p["roots"][0].update(exclude_paths=[".."]),
            lambda p: p["roots"][0].update(exclude_paths=["a/../b"]),
            lambda p: p["roots"][0].update(exclude_paths=["a//b"]),
            lambda p: p["limits"].update(scan_depth=1),
            lambda p: p["sampling"].pop("records"),
            lambda p: p["sampling"].update(extra=1),
            lambda p: p["sampling"].update(records=True),
            lambda p: p["sampling"].update(records=0),
            lambda p: p["sampling"].update(cycle_seconds=16),
            lambda p: p["sampling"].update(process_interval_seconds=10),
            lambda p: p.update(version=3),
            lambda p: p.update(version=True),
        ]
        for index, change in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(StewardError):
                validate(self.changed(change))
        missing = self.base / "尚未挂载"
        policy = self.changed(lambda p: p["roots"].append(new_root(str(missing))))
        validate(policy)
        self.assertTrue(policy["roots"][-1]["path"].endswith("尚未挂载"))

    def test_root_overlap_duplicate_and_samefile_alias(self):
        child = self.root / "child"
        child.mkdir()
        with self.assertRaisesRegex(StewardError, "包含"):
            validate(self.changed(lambda p: p["roots"].append(new_root(str(child)))))
        with self.assertRaisesRegex(StewardError, "不重叠"):
            validate(self.changed(lambda p: p["roots"].append(new_root(str(self.root)))))
        other = self.base / "other"
        other.mkdir()
        policy = self.changed(lambda p: p["roots"].append(new_root(str(other))))
        with patch("policy.os.path.samefile", return_value=True), \
             self.assertRaisesRegex(StewardError, "samefile"):
            validate(policy)

    def test_semantic_and_source_digests_are_separate(self):
        before, evidence = read_policy_with_evidence(self.store.path)
        self.assertEqual(before.policy_evidence, evidence)
        self.assertNotIn("policy_evidence", before)
        host = self.store.target("host.json")
        original = decode(host.read_bytes())
        reordered = {key: original[key] for key in reversed(list(original))}
        host.write_bytes((json.dumps(reordered, ensure_ascii=False, indent=2) + "\n").encode())
        after, changed_evidence = read_policy_with_evidence(self.store.path)
        self.assertEqual(policy_digest(before), policy_digest(after))
        self.assertEqual(evidence["policy_digest"], changed_evidence["policy_digest"])
        self.assertNotEqual(evidence["policy_source_digest"], changed_evidence["policy_source_digest"])
        modified = copy.deepcopy(dict(after))
        modified["purpose"] = "不同的用途"
        self.assertNotEqual(policy_digest(after), policy_digest(modified))

    def test_history_defaults_validation_and_ranges(self):
        self.assertEqual(set(DEFAULT_HISTORY), {"runs", "gaps"})
        self.assertEqual(set(DEFAULT_HISTORY["runs"]), HISTORY_FIELDS)
        self.assertEqual(self.policy["history"], DEFAULT_HISTORY)
        self.assertEqual(resolve_history(None), DEFAULT_HISTORY)
        resolved = resolve_history(None)
        resolved["runs"]["records"] = 8
        self.assertEqual(DEFAULT_HISTORY["runs"]["records"], 256)

        without = copy.deepcopy(self.policy)
        without.pop("history")
        validate(without)
        self.assertIsNone(without.get("history"))
        self.assertEqual(resolve_history(without.get("history")), DEFAULT_HISTORY)

        valid = [
            {"runs": {"records": 8, "retention_hours": 1},
             "gaps": {"records": 8, "retention_hours": 1}},
            {"runs": {"records": RUN_ABSOLUTE_LIMIT,
                      "retention_hours": RETENTION_HOURS_ABSOLUTE_LIMIT},
             "gaps": {"records": GAP_ABSOLUTE_LIMIT,
                      "retention_hours": RETENTION_HOURS_ABSOLUTE_LIMIT}},
            {"runs": {"records": 512, "retention_hours": 720},
             "gaps": {"records": 2048, "retention_hours": 24}},
        ]
        for history in valid:
            with self.subTest(history=history):
                policy = copy.deepcopy(self.policy)
                policy["history"] = history
                validate(policy)
                self.assertEqual(resolve_history(history), history)

    def test_history_rejects_incomplete_unknown_and_out_of_range_values(self):
        complete = copy.deepcopy(DEFAULT_HISTORY)
        missing_field = copy.deepcopy(complete)
        missing_field["gaps"].pop("retention_hours")
        invalid = [
            None, [], "default", 1, True,
            {"runs": complete["runs"]},
            {"gaps": complete["gaps"]},
            {"runs": complete["runs"], "gaps": complete["gaps"], "extra": {}},
            {"runs": list(complete["runs"].values()), "gaps": complete["gaps"]},
            missing_field,
        ]
        broken_field = copy.deepcopy(complete)
        broken_field["runs"].pop("records")
        invalid.append(broken_field)
        extra_field = copy.deepcopy(complete)
        extra_field["runs"]["extra"] = 1
        invalid.append(extra_field)
        for group, field, value in [
            ("runs", "records", "256"), ("runs", "records", 0), ("runs", "records", -1),
            ("runs", "records", True), ("runs", "records", 7), ("runs", "records", 256.0),
            ("runs", "records", RUN_ABSOLUTE_LIMIT + 1),
            ("gaps", "records", 7), ("gaps", "records", GAP_ABSOLUTE_LIMIT + 1),
            ("runs", "retention_hours", 0), ("runs", "retention_hours", True),
            ("runs", "retention_hours", RETENTION_HOURS_ABSOLUTE_LIMIT + 1),
            ("gaps", "retention_hours", -3), ("gaps", "retention_hours", "168"),
        ]:
            broken = copy.deepcopy(complete)
            broken[group][field] = value
            invalid.append(broken)
        for history in invalid:
            with self.subTest(history=history):
                with self.assertRaises(StewardError):
                    validate_history(history)
                policy = copy.deepcopy(self.policy)
                policy["history"] = history
                with self.assertRaises(StewardError):
                    validate(policy)

    def test_refresh_policy_locked_updates_store_history(self):
        changed = copy.deepcopy(self.policy)
        changed["history"]["gaps"]["records"] = 1024
        self.store.write("host.json", changed)
        refreshed = refresh_policy_locked(self.store)
        self.assertEqual(refreshed["history"], changed["history"])
        self.assertEqual(self.store.history, changed["history"])

    def test_policy_digest_includes_history(self):
        changed = copy.deepcopy(self.policy)
        changed["history"]["gaps"]["records"] = GAP_ABSOLUTE_LIMIT
        self.assertNotEqual(policy_digest(self.policy), policy_digest(changed))
        reordered = copy.deepcopy(self.policy)
        reordered["history"] = {group: {field: reordered["history"][group][field]
                                        for field in reversed(sorted(HISTORY_FIELDS))}
                                for group in reversed(sorted(reordered["history"]))}
        self.assertEqual(policy_digest(self.policy), policy_digest(reordered))

    def test_recorded_policy_reads_with_or_without_history(self):
        legacy = copy.deepcopy(self.policy)
        legacy.pop("history")
        SampleStore(self.store).start_run("run-without-history", legacy, make_policy_evidence(legacy))
        loaded, evidence, run_id = read_recorded_policy(self.store.path)
        self.assertEqual(run_id, "run-without-history")
        self.assertEqual(evidence["policy_digest"], policy_digest(legacy))
        self.assertIsNone(loaded.get("history"))
        self.assertEqual(resolve_history(loaded.get("history")), DEFAULT_HISTORY)

        archived = copy.deepcopy(self.policy)
        archived["history"]["runs"]["records"] = 512
        SampleStore(self.store).start_run("run-with-history", archived, make_policy_evidence(archived))
        loaded, _, run_id = read_recorded_policy(self.store.path)
        self.assertEqual(run_id, "run-with-history")
        self.assertEqual(loaded["history"]["runs"]["records"], 512)

        broken = copy.deepcopy(self.policy)
        broken["history"]["runs"]["records"] = 7
        SampleStore(self.store).start_run("run-broken-history", broken, make_policy_evidence(broken))
        with self.assertRaisesRegex(StewardError, "history.runs.records"):
            read_recorded_policy(self.store.path)

    def test_v1_compatibility_and_conversion_preserve_authorization_and_extensions(self):
        rule = {"path": str(self.root), "purpose": "临时资料", "kind": "temporary",
                "allow_quarantine": True, "retention_days": 0, "recycle_bytes": 1024}
        legacy = legacy_policy(self.root, [rule])
        validate(legacy)
        self.assertEqual(root_rule(legacy, str(self.root)),
                         {"path": str(self.root), "max_depth": 2,
                          "exclude_names": [".git", "__pycache__"], "exclude_paths": []})
        with self.assertRaises(StewardError):
            validate(dict(legacy, sampling=copy.deepcopy(DEFAULT_SAMPLING)))
        converted = convert_v1_policy(legacy)
        self.assertEqual(legacy["version"], 1)
        self.assertEqual(legacy["roots"], [str(self.root)])
        self.assertEqual(converted["version"], 2)
        self.assertEqual(converted["roots"], [{
            "path": str(self.root), "max_depth": 2,
            "exclude_names": [".git", "__pycache__"], "exclude_paths": []}])
        self.assertNotIn("scan_depth", converted["limits"])
        self.assertEqual(converted["limits"], {key: value for key, value in legacy_limits().items()
                                               if key != "scan_depth"})
        self.assertEqual(converted["sampling"], DEFAULT_SAMPLING)
        self.assertEqual(converted["history"], DEFAULT_HISTORY)
        self.assertEqual(converted["directory_rules"], [rule])
        self.assertEqual(converted["residents"], legacy["residents"])
        self.assertEqual(converted["未来扩展"], {"keep": True})
        self.assertNotIn("exclude_names", converted)
        with self.assertRaises(StewardError):
            convert_v1_policy(self.policy)
        with_history = copy.deepcopy(legacy)
        with_history["history"] = copy.deepcopy(DEFAULT_HISTORY)
        with self.assertRaisesRegex(StewardError, "v1 不能配置 history"):
            validate(with_history)
        with self.assertRaisesRegex(StewardError, "v1 不能配置 history"):
            convert_v1_policy(with_history)

    def test_v1_policy_supports_patrol_status_inventory_and_maintenance(self):
        rule = {"path": str(self.root), "purpose": "临时资料", "kind": "temporary",
                "allow_quarantine": True, "retention_days": 0, "recycle_bytes": 1024,
                "directory_id": identity(self.root.stat())}
        legacy = legacy_policy(self.root, [rule])
        self.store.write("host.json", legacy)
        report = self.patrol()
        self.assertEqual(report["policy_version"], 1)
        self.assertEqual(report["roots"], [str(self.root)])
        self.assertEqual(report["last_run"]["policy_evidence"]["policy_version"], 1)
        current = read_current(self.store)
        self.assertEqual(current["baselines"][str(self.root)]["scope"]["version"], 1)
        status = self.status()
        self.assertEqual(status["policy_version"], 1)
        self.assertEqual(status["coverage_scope"][str(self.root)]["scope"]["scan_depth"], 2)

        target = self.root / "原始 资料.txt"
        target.write_text("保留原文")
        definition = {"id": "v1.target", "kind": "file", "locator": str(target), "purpose": "原始资料",
                      "owner": "样例用户", "dependencies": [], "retention": "长期保留",
                      "maintenance": "原位观察", "basis": "observed", "source": "v1 兼容测试",
                      "evidence_at": 1, "review_after_hours": 24}
        register(self.store, definition)
        inspected = inspect_target(self.store, read_policy_with_evidence(self.store.path)[0], "v1.target")
        self.assertEqual(inspected["object"]["path"], str(target))
        self.assertTrue(query(self.store, legacy, "v1.target")["resources"])

        policy = read_policy_with_evidence(self.store.path)[0]
        moved = quarantine(self.store, policy, target, True)["operation"]
        self.assertTrue(Path(moved["target"]).is_file())
        restore(self.store, policy, moved["id"], True)
        self.assertEqual(target.read_text(), "保留原文")

    def test_v1_to_v2_scope_change_rebaselines_then_settles(self):
        legacy = legacy_policy(self.root)
        self.store.write("host.json", legacy)
        first = self.patrol()
        self.assertEqual(first["new_baselines"], [str(self.root)])
        converted = convert_v1_policy(legacy)
        self.store.write("host.json", converted)
        upgraded = self.patrol()
        self.assertEqual(upgraded["policy_version"], 2)
        self.assertEqual(upgraded["new_baselines"], [str(self.root)])
        self.assertEqual(upgraded["changes"], [])
        self.assertTrue(any(reason.startswith("scope:") for row in upgraded["comparison_gaps"]
                            for reason in row["reasons"]))
        self.assertEqual(read_current(self.store)["baselines"][str(self.root)]["scope"]["version"], 2)
        settled = self.patrol()
        self.assertEqual(settled["comparison_gaps"], [])
        self.assertEqual(settled["new_baselines"], [])

    def test_scan_depth_zero_and_multi_level_boundaries(self):
        (self.root / "top.txt").write_text("a")
        level1 = self.root / "一级"
        level1.mkdir()
        (level1 / "one.txt").write_text("bb")
        level2 = level1 / "二级"
        level2.mkdir()
        (level2 / "two.txt").write_text("ccc")
        level3 = level2 / "三级"
        level3.mkdir()
        (level3 / "three.txt").write_text("dddd")
        rule = copy.deepcopy(self.policy["roots"][0])
        limits = {"scan_entries": 1000, "scan_seconds": 10}
        for depth, expected in [(0, {"top.txt"}), (1, {"top.txt", "one.txt"}),
                                (2, {"top.txt", "one.txt", "two.txt"}),
                                (3, {"top.txt", "one.txt", "two.txt", "three.txt"})]:
            with self.subTest(depth=depth):
                rule["max_depth"] = depth
                snapshot = scan([rule], limits)[str(self.root)]
                self.assertTrue(snapshot["complete"])
                self.assertEqual(snapshot["gaps"], [])
                files = {Path(path).name for path, row in snapshot["records"].items() if row["kind"] == "file"}
                self.assertEqual(files, expected)
                self.assertEqual(snapshot["scope"]["version"], 2)
                self.assertEqual(snapshot["scope"]["max_depth"], depth)
        rule["max_depth"] = 0
        shallow = scan([rule], limits)[str(self.root)]
        self.assertEqual(shallow["directories"][str(self.root)]["bytes"], 1)
        self.assertGreaterEqual(shallow["excluded"]["depth_boundary"], 1)
        self.assertIn(str(level1), shallow["records"])
        self.assertTrue(shallow["directories"][str(level1)]["boundary"])
        self.assertNotIn(str(level1 / "one.txt"), shallow["records"])
        self.assertEqual(compare({str(self.root): shallow}, {str(self.root): shallow})["gaps"], [])

    def test_exclude_paths_use_root_relative_components_and_preserve_unicode(self):
        cache = self.root / "build" / "cache"
        cache.mkdir(parents=True)
        (cache / "drop 文件.txt").write_text("x" * 10)
        similar = self.root / "build" / "cache2"
        similar.mkdir()
        (similar / "keep.txt").write_text("y" * 20)
        other_cache = self.root / "other" / "cache"
        other_cache.mkdir(parents=True)
        (other_cache / "keep.txt").write_text("z" * 30)
        (self.root / "排除 名称.txt").write_text("name")
        rule = copy.deepcopy(self.policy["roots"][0])
        rule.update(max_depth=4, exclude_names=["排除 名称.txt"], exclude_paths=["build/cache"])
        snapshot = scan([rule], {"scan_entries": 1000, "scan_seconds": 10})[str(self.root)]
        self.assertTrue(snapshot["complete"])
        self.assertNotIn(str(cache / "drop 文件.txt"), snapshot["records"])
        self.assertIn(str(similar / "keep.txt"), snapshot["records"])
        self.assertIn(str(other_cache / "keep.txt"), snapshot["records"])
        self.assertNotIn(str(self.root / "排除 名称.txt"), snapshot["records"])
        self.assertEqual(snapshot["excluded"]["configured"], 2)
        self.assertIn("排除 名称.txt", snapshot["scope"]["exclude_names"])
        self.assertEqual(snapshot["scope"]["exclude_paths"], ["build/cache"])

    def test_excluded_by_rule_matches_path_components(self):
        rule = {"path": str(self.root), "exclude_names": ["cache"],
                "exclude_paths": ["build/output"]}
        self.assertTrue(excluded_by_rule(rule, str(self.root / "build" / "output")))
        self.assertTrue(excluded_by_rule(rule, str(self.root / "build" / "output" / "x")))
        self.assertFalse(excluded_by_rule(rule, str(self.root / "build" / "output2")))
        self.assertFalse(excluded_by_rule(rule, str(self.root / "build")))
        self.assertTrue(excluded_by_rule(rule, str(self.root / "cache" / "x")))
        self.assertFalse(excluded_by_rule(rule, str(self.root)))

    def test_missing_or_non_directory_root_is_gap_without_deletion(self):
        (self.root / "keep").write_text("keep")
        rule = self.policy["roots"][0]
        limits = {"scan_entries": 100, "scan_seconds": 10}
        baseline = scan([rule], limits)
        moved = self.base / "moved"
        os.rename(self.root, moved)
        missing = scan([rule], limits)
        self.assertFalse(missing[str(self.root)]["complete"])
        self.assertTrue(missing[str(self.root)]["gaps"])
        self.assertIsNone(missing[str(self.root)]["scope"]["device"])
        delta = compare(baseline, missing)
        self.assertEqual(delta["changes"], [])
        self.assertEqual(delta["new_baselines"], [])
        self.assertTrue(delta["gaps"])
        self.root.write_text("now a file")
        replaced = scan([rule], limits)
        self.assertFalse(replaced[str(self.root)]["complete"])
        self.assertIn("不是目录", replaced[str(self.root)]["gaps"][0])
        self.assertEqual(compare(baseline, replaced)["changes"], [])

    def test_missing_root_keeps_host_observation_and_marks_storage_uncovered(self):
        self.root.rename(self.base / "offline")
        responses = {
            ("ps", "-axo", "pid=,ppid=,lstart=,pcpu=,rss=,comm="):
                "42 1 Fri Oct 16 10:00:00 2026 0.0 100 /usr/bin/example\n",
            ("launchctl", "list"): "PID\tStatus\tLabel\n1\t0\tcom.example\n",
        }

        def response(arguments, *args):
            return responses[tuple(arguments)]

        utilization = {"available": True, "user_percent": 1.0, "system_percent": 2.0, "idle_percent": 97.0}
        network = {"available": True, "interfaces": {"available": True, "items": []},
                   "tcp_states": {"available": True, "states": {}}}
        with patch("observe.platform.system", return_value="Darwin"), \
             patch("observe.platform.machine", return_value="arm64"), \
             patch("observe.command", side_effect=response), \
             patch("observe.observe_boot", return_value={"available": True, "unix_time": 1, "reason": None}), \
             patch("observe.observe_darwin_memory", return_value={"available": True, "counters": {}}), \
             patch("observe.observe_iostat", return_value=(utilization, {"available": True, "disks": []})), \
             patch("observe.observe_gpu", return_value={"available": False, "reason": "test"}), \
             patch("observe.observe_network", return_value=network), \
             patch("observe.observe_power", return_value={"available": False, "reason": "test"}):
            result = observe(self.policy)
        self.assertTrue(result["processes"]["available"])
        self.assertTrue(result["cpu"]["utilization"]["available"])
        self.assertFalse(result["storage"][0]["available"])
        self.assertIn("暂不可见", result["storage"][0]["reason"])

    def test_incomplete_scan_preserves_previous_comparison_gaps(self):
        (self.root / "a").write_text("a")
        (self.root / "b").write_text("b")
        self.patrol()
        self.policy["roots"][0]["exclude_names"].append("new-filter")
        self.store.write("host.json", self.policy)
        rebased = self.patrol()
        self.assertEqual(rebased["new_baselines"], [str(self.root)])
        self.assertTrue(rebased["comparison_gaps"])
        self.policy["limits"]["scan_entries"] = 1
        self.store.write("host.json", self.policy)
        incomplete = self.patrol()
        self.assertFalse(incomplete["last_run"]["coverage_complete"])
        self.assertTrue(incomplete["gaps"])
        self.assertEqual(incomplete["changes"], [])
        self.assertTrue(any(reason.startswith("scope:")
                            for row in incomplete["comparison_gaps"] for reason in row["reasons"]))
        self.assertEqual(read_current(self.store)["baselines"][str(self.root)]["scope"]["max_depth"], 32)
        self.policy["limits"]["scan_entries"] = 5000
        self.store.write("host.json", self.policy)
        recovered = self.patrol()
        self.assertTrue(recovered["last_run"]["coverage_complete"])
        self.assertEqual(recovered["comparison_gaps"], [])
        self.assertEqual(recovered["changes"], [])

    def test_init_cli_resolves_absolute_targets_and_depth(self):
        state = self.base / "新 状态"
        alias = self.base / "别名"
        alias.symlink_to(self.root, target_is_directory=True)
        command = [sys.executable, str(PROJECT / "tools/steward.py"), "init", "--state", str(state),
                   "--root", str(alias), "--max-depth", "0", "--purpose", "初始化输出测试"]
        result = subprocess.run(command, cwd="/", capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["policy_version"], 2)
        self.assertEqual(output["roots"][0]["path"], str(self.root))
        self.assertEqual(output["roots"][0]["max_depth"], 0)
        self.assertEqual(output["root_resolution"], [{"input": str(alias), "path": str(self.root)}])
        self.assertEqual(output["policy_evidence"]["policy_version"], 2)
        read_back = decode((state / "host.json").read_bytes())
        validate(read_back)
        container = self.base / "状态包含根"
        nested = container / "root"
        nested.mkdir(parents=True)
        with self.assertRaisesRegex(StewardError, "状态目录不能包含观察根目录"):
            initialize(container, [nested], "非法嵌套")
        for arguments, message in [(["init", "--state", str(self.base / "relative-state"),
                                     "--root", "relative", "--purpose", "x"], "绝对路径"),
                                    (["init", "--state", "relative-state",
                                      "--root", str(self.root), "--purpose", "x"], "绝对路径"),
                                    (["init", "--state", str(self.base / "depth-state"),
                                      "--root", str(self.root), "--max-depth", "-1", "--purpose", "x"], "非负整数")]:
            with self.subTest(message=message):
                failed = subprocess.run([sys.executable, str(PROJECT / "tools/steward.py"), *arguments],
                                        cwd="/", capture_output=True, text=True, timeout=10)
                self.assertEqual(failed.returncode, 1, failed.stdout)
                self.assertIn(message, failed.stderr)

    def test_init_rejects_missing_non_directory_and_aliased_roots(self):
        missing = self.base / "missing-root"
        with self.assertRaisesRegex(StewardError, "无法访问"):
            initialize(self.base / "state-missing", [missing], "缺少 root")
        file = self.base / "file-root"
        file.write_text("x")
        with self.assertRaisesRegex(StewardError, "必须是目录"):
            initialize(self.base / "state-file", [file], "文件 root")
        alias = self.base / "alias-root"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(StewardError, "samefile"):
            initialize(self.base / "state-alias", [self.root, alias], "别名 root")

    def test_runtime_policy_cannot_observe_its_own_state_subtree(self):
        nested = self.store.path / "observed"
        nested.mkdir()
        policy = copy.deepcopy(self.policy)
        policy["roots"] = [new_root(str(nested))]
        self.store.write("host.json", policy)
        with self.assertRaisesRegex(StewardError, "状态目录不能包含观察根目录"):
            read_policy_with_evidence(self.store.path)
        allowed = copy.deepcopy(self.policy)
        self.store.write("host.json", allowed)
        read_policy_with_evidence(self.store.path)

    def test_case_unicode_and_exact_name_matching_are_preserved(self):
        root = self.base / "Case 目录"
        root.mkdir()
        payload = root / "Ä 资料.TXT"
        payload.write_text("大小写与 Unicode")
        store, policy = initialize(self.base / "case-state", [root], "大小写测试")
        rule = policy["roots"][0]
        snapshot = scan([rule], {"scan_entries": 10, "scan_seconds": 10})[str(root)]
        self.assertEqual(snapshot["scope"]["root"], str(root))
        self.assertIn(str(payload), snapshot["records"])
        self.assertEqual(Path(next(path for path in snapshot["records"] if path.endswith("Ä 资料.TXT"))).name,
                         "Ä 资料.TXT")
        rule["exclude_names"] = ["ä 资料.txt"]
        different_case = scan([rule], {"scan_entries": 10, "scan_seconds": 10})[str(root)]
        self.assertIn(str(payload), different_case["records"])
        rule["exclude_names"] = ["Ä 资料.TXT"]
        exact = scan([rule], {"scan_entries": 10, "scan_seconds": 10})[str(root)]
        self.assertNotIn(str(payload), exact["records"])
        self.assertEqual(exact["excluded"]["configured"], 1)

    def test_multiple_roots_share_the_same_entry_budget(self):
        second = self.base / "second"
        second.mkdir()
        (self.root / "one").write_text("1")
        (second / "a").write_text("a")
        (second / "b").write_text("b")
        rules = [self.policy["roots"][0], new_root(str(second))]
        snapshots = scan(rules, {"scan_entries": 2, "scan_seconds": 10})
        self.assertTrue(snapshots[str(self.root)]["complete"])
        self.assertFalse(snapshots[str(second)]["complete"])
        self.assertTrue(snapshots[str(second)]["gaps"])
        self.assertEqual(snapshots[str(second)]["scope"]["version"], 2)

    def test_state_schema_validates_scope_versions_separately(self):
        (self.root / "file").write_text("x")
        snapshot = scan(self.policy["roots"], {"scan_entries": 100, "scan_seconds": 10})[str(self.root)]
        validate_scope(snapshot["scope"], str(self.root), "test")
        legacy_scope = {key: value for key, value in snapshot["scope"].items()
                        if key not in {"max_depth", "exclude_paths"}}
        legacy_scope.update(version=1, scan_depth=snapshot["scope"]["max_depth"])
        validate_scope(legacy_scope, str(self.root), "test")
        malformed = []
        missing_depth = dict(snapshot["scope"])
        missing_depth.pop("max_depth")
        malformed.append(missing_depth)
        extra_v1 = dict(legacy_scope, max_depth=1)
        malformed.append(extra_v1)
        unsorted_paths = dict(snapshot["scope"], exclude_paths=["b", "a"])
        malformed.append(unsorted_paths)
        dot_path = dict(snapshot["scope"], exclude_paths=["."])
        malformed.append(dot_path)
        boolean_depth = dict(snapshot["scope"], max_depth=True)
        malformed.append(boolean_depth)
        for scope in malformed:
            with self.subTest(scope=scope):
                with self.assertRaises(StewardError):
                    validate_scope(scope, str(self.root), "test")

    def test_status_reports_current_config_without_a_collector_claim(self):
        self.patrol()
        status = self.status()
        self.assertEqual(status["policy_version"], 2)
        self.assertEqual(status["policy_evidence"]["policy_version"], 2)
        self.assertEqual(status["roots"], self.policy["roots"])
        self.assertEqual(status["policy"]["sampling"], self.policy["sampling"])
        self.assertTrue(status["policy_matches_last_run"])
        self.assertTrue(status["policy_source_matches_last_run"])
        self.assertEqual(status["coverage_policy_evidence"]["policy_digest"],
                         status["policy_evidence"]["policy_digest"])
        changed = copy.deepcopy(self.policy)
        changed["purpose"] = "巡检后修改的用途"
        self.store.write("host.json", changed)
        self.assertFalse(self.status()["policy_matches_last_run"])
        rendered = json.dumps(status, ensure_ascii=False)
        self.assertNotIn("常驻采集已", rendered)
        # collector 块只陈述事实：从未采集过的状态明确报 not_started，不冒充运行中。
        self.assertEqual(status["collector"]["status"], "not_started")
        self.assertEqual(status["collector"]["status_reason"], "没有运行记录")
        self.assertIsNone(status["collector"]["run"])


if __name__ == "__main__":
    unittest.main()
