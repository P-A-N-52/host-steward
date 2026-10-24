import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
import events
import recheck
from baseline import GAP_MTIME, GAP_RECHECK, resumable_scan
import files
from files import scan
from state import StewardError
from state_schema import read_current
from steward import initialize, native_events, patrol, status_report


class RecheckQueueTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()

    def state(self):
        state = recheck.empty()
        return state

    def test_same_path_events_keep_first_last_and_count(self):
        state = self.state()
        path = str(self.root / "data" / "file.txt")
        recheck.add(state, str(self.root), path, 10)
        recheck.add(state, str(self.root), path, 12)
        recheck.add(state, str(self.root), path, 11)
        self.assertEqual(len(state["items"]), 1)
        item = state["items"][0]
        self.assertEqual(item["path"], path)
        self.assertEqual(item["first_at"], 10)
        self.assertEqual(item["last_at"], 12)
        self.assertEqual(item["count"], 3)

    def test_stable_token_ignores_replayed_event(self):
        state = self.state()
        path = str(self.root / "data")
        recheck.add(state, str(self.root), path, 10, token=5)
        recheck.add(state, str(self.root), path, 20, token=5)
        item = state["items"][0]
        self.assertEqual((item["token"], item["count"], item["last_at"]), (5, 1, 10))
        recheck.add(state, str(self.root), path, 30, token=6)
        self.assertEqual((item["token"], item["count"], item["last_at"]), (6, 2, 30))

    def test_legacy_float_queue_token_is_treated_as_zero(self):
        path = str(self.root / "data")
        raw = {"version": 1, "limit": 64, "truncated": False, "aggregated": 0, "dropped": 0,
               "source_truncated": False, "degraded": None,
               "items": [{"root": str(self.root), "path": path, "first_at": 1, "last_at": 2,
                          "count": 1, "token": 1.8e9}]}
        state = recheck.restore(raw)
        self.assertEqual(recheck.targets(state)[str(self.root)][path], 0)
        recheck.add(state, str(self.root), path, 3, token=1000)
        self.assertEqual(state["items"][0]["token"], 1000)
        self.assertEqual(state["items"][0]["count"], 2)

    def test_child_and_parent_events_merge_into_one_item(self):
        state = self.state()
        child = str(self.root / "data" / "child.txt")
        parent = str(self.root / "data")
        recheck.add(state, str(self.root), child, 10)
        recheck.add(state, str(self.root), parent, 11)
        self.assertEqual(len(state["items"]), 1)
        self.assertEqual(state["items"][0]["path"], parent)
        self.assertEqual(state["items"][0]["count"], 2)
        self.assertEqual(state["items"][0]["first_at"], 10)
        self.assertEqual(state["items"][0]["last_at"], 11)
        recheck.add(state, str(self.root), str(self.root / "data" / "later.txt"), 12)
        self.assertEqual(len(state["items"]), 1)
        self.assertEqual(state["items"][0]["count"], 3)

    def test_queue_bound_aggregates_to_parent_and_marks_truncation(self):
        state = self.state()
        state["limit"] = 4
        for index in range(7):
            recheck.add(state, str(self.root), str(self.root / "data" / f"{index}.txt"), index)
        self.assertLessEqual(len(state["items"]), 4)
        self.assertTrue(state["truncated"])
        self.assertGreaterEqual(state["aggregated"], 1)
        self.assertIn(str(self.root / "data"), [item["path"] for item in state["items"]])
        self.assertEqual(sum(item["count"] for item in state["items"]), 7)

    def test_clear_and_consume_only_remove_targeted_subtrees(self):
        state = self.state()
        recheck.add(state, str(self.root), str(self.root / "a"), 1)
        recheck.add(state, str(self.root), str(self.root / "b"), 2)
        recheck.consume(state, {str(self.root): [str(self.root / "a")]})
        self.assertEqual([item["path"] for item in state["items"]], [str(self.root / "b")])
        recheck.consume(state, {str(self.root): [str(self.root)]})
        self.assertEqual(state["items"], [])
        self.assertFalse(state["truncated"])
        state = self.state()
        recheck.add(state, str(self.root), str(self.root / "a"), 1)
        recheck.clear(state, "history_invalid", 5)
        self.assertEqual(state["items"], [])
        self.assertEqual(state["degraded"], {"reason": "history_invalid", "since": 5})

    def test_clue_target_normalizes_files_depth_and_exclusions(self):
        parent = self.root / "parent"
        parent.mkdir()
        file = parent / "file.txt"
        file.write_text("x")
        rules = [{"path": str(self.root), "max_depth": 1, "exclude_names": [".git"],
                  "exclude_paths": ["skip"], "version": 2}]
        self.assertEqual(recheck.clue_target(str(file), rules), (str(self.root), str(parent)))
        (self.root / ".git").mkdir()
        self.assertIsNone(recheck.clue_target(str(self.root / ".git" / "config"), rules))
        (self.root / "skip" / "deep").mkdir(parents=True)
        self.assertIsNone(recheck.clue_target(str(self.root / "skip" / "deep" / "file"), rules))
        deep = self.root / "one" / "two" / "three"
        deep.mkdir(parents=True)
        self.assertEqual(recheck.clue_target(str(deep / "file"), rules),
                         (str(self.root), str(self.root / "one")))
        self.assertIsNone(recheck.clue_target(str(self.base / "outside"), rules))
        state_path = self.root / "state"
        state_path.mkdir()
        self.assertIsNone(recheck.clue_target(str(state_path / "file"), rules, str(state_path)))
        missing = parent / "gone.txt"
        self.assertEqual(recheck.clue_target(str(missing), rules), (str(self.root), str(parent)))

    def test_event_source_paths_are_bounded_and_marked_truncated(self):
        result = {"paths": [], "path_ids": [], "paths_truncated": False}
        seen, budget = {}, {"bytes": 0}
        for index in range(events.MAX_EVENT_PATHS + 20):
            events.collect_clue(result, seen, budget, f"/root/file-{index}.txt")
        self.assertLessEqual(len(result["paths"]), events.MAX_EVENT_PATHS)
        self.assertTrue(result["paths_truncated"])
        before = list(result["paths"])
        self.assertEqual(len(result["path_ids"]), len(result["paths"]))
        events.collect_clue(result, seen, budget, before[0], 42)
        self.assertEqual(result["paths"], before)
        self.assertEqual(result["path_ids"][0], 42)

    def test_degrade_keeps_queue_and_clear_resets_it(self):
        state = self.state()
        recheck.add(state, str(self.root), str(self.root / "data"), 1)
        recheck.degrade(state, "unavailable", 2)
        self.assertEqual(len(state["items"]), 1)
        self.assertEqual(state["degraded"]["reason"], "unavailable")
        recheck.degrade(state, "unavailable", 9)
        self.assertEqual(state["degraded"]["since"], 2)
        recheck.degrade(state, None, 10)
        self.assertIsNone(state["degraded"])


class PatrolRecheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.store, self.policy = initialize(self.base / "state", [self.root], "事件待复核回归")
        self.now = 1_800_000_000
        self.host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True},
                     "gpu": {}, "model_usage": {}, "storage": [],
                     "processes": {"available": True, "items": []},
                     "services": {"available": True, "items": []}}
        for mocker in [patch("steward.observe", return_value=self.host),
                       patch("steward.native_events", return_value=self.event([]))]:
            mocker.start()
            self.addCleanup(mocker.stop)

    def write(self, path, data=b"x"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def event(self, paths, **overrides):
        value = {"source": "macos_fsevents", "available": True, "baseline": False,
                 "history_complete": True, "history_invalid": False, "rescan_required": False,
                 "cursor": self.now, "devices": {str(self.root): os.stat(self.root).st_dev},
                 "paths": list(paths), "paths_truncated": False}
        value.update(overrides)
        return value

    def run_patrol(self, event_value=None, **options):
        self.now += 10
        with patch("steward.time.time", return_value=self.now), \
             patch("steward.native_events", return_value=event_value or self.event([])):
            return patrol(self.store, self.policy, **options)

    def set_budget(self, entries):
        self.policy["limits"]["scan_entries"] = entries
        self.store.write("host.json", self.policy)

    def queue(self):
        return read_current(self.store)["event_recheck"]

    def test_initial_baseline_is_not_reported_as_listener_rebuild(self):
        self.write(self.root / "data" / "file.txt")
        report = self.run_patrol()
        self.assertNotIn("event_recheck", report)
        self.assertIsNone(read_current(self.store)["event_recheck"]["degraded"])

    def test_replayed_event_with_budget_cut_completes_recheck(self):
        data = self.root / "data"
        for index in range(8):
            self.write(data / f"{index}.txt")
        self.run_patrol()
        self.set_budget(2)
        replay = self.event([str(data)], event_ids={str(data): 1000})
        reports = []
        for _ in range(15):
            report = self.run_patrol(replay)
            reports.append(report)
            if report["last_run"]["coverage_complete"]:
                break
            self.assertNotIn({"kind": "events", "reason": "history_invalid"}, report["observation_gaps"])
            for item in self.queue()["items"]:
                self.assertEqual(item["token"], 1000)
                self.assertEqual(item["count"], 1)
        self.assertTrue(reports[-1]["last_run"]["coverage_complete"])
        self.assertGreater(len(reports), 2)
        self.assertEqual(self.queue()["items"], [])
        records = read_current(self.store)["baselines"][str(self.root)]["records"]
        self.assertEqual(len([path for path in records if "/data/" in path]), 8)

    def test_event_during_active_recheck_does_not_mark_covered(self):
        data = self.root / "data"
        first = self.write(data / "00.txt", b"old zero")
        self.write(data / "01.txt", b"old one")
        self.run_patrol()
        self.set_budget(1)
        report = self.run_patrol(self.event([str(data)], event_ids={str(data): 1}))
        self.assertFalse(report["last_run"]["coverage_complete"])
        entry = read_current(self.store)["scan_progress"][str(self.root)]
        self.assertEqual(entry["recheck_active"][str(data)], 1)
        first.write_bytes(b"modified after being scanned")

        event = self.event([str(data)], event_ids={str(data): 2})
        report = self.run_patrol(event)
        self.assertFalse(report["last_run"]["coverage_complete"])
        scope = report["coverage_scope"][str(self.root)]["event_recheck"]
        self.assertEqual(scope["covered"], 0)
        self.assertEqual(len(self.queue()["items"]), 1)

        reports = [report]
        for _ in range(10):
            report = self.run_patrol(event)
            reports.append(report)
            if report["last_run"]["coverage_complete"]:
                break
        self.assertTrue(reports[-1]["last_run"]["coverage_complete"])
        self.assertTrue(any(row["modified"] for row in reports[-1]["changes"]))
        self.assertEqual(self.queue()["items"], [])

    def test_requeue_preserves_parent_and_sibling_gaps(self):
        target = str(self.root / "data" / "target")
        parent = str(self.root / "data")
        sibling = str(self.root / "data" / "sibling")
        for index in range(4):
            self.write(self.root / "data" / "target" / f"{index}.txt")
            self.write(self.root / "data" / "sibling" / f"{index}.txt")
        limits = {"scan_entries": 2, "scan_seconds": 10, "scan_depth": 8}
        snapshots, progress = resumable_scan(
            None, [str(self.root)], limits, recheck={str(self.root): {target: 1}})
        self.assertFalse(snapshots[str(self.root)]["complete"])
        own_gap = f"{GAP_MTIME}：{target}"
        parent_gap = f"{GAP_MTIME}：{parent}"
        sibling_gap = f"{GAP_MTIME}：{sibling}"
        progress[str(self.root)]["gaps"].extend([own_gap, parent_gap, sibling_gap])
        progress[str(self.root)]["queue"] = [item for item in progress[str(self.root)]["queue"]
                                             if item["path"] != target]
        snapshots, progress = resumable_scan(
            progress, [str(self.root)], limits, recheck={str(self.root): {target: 2}})
        gaps = snapshots[str(self.root)]["gaps"]
        self.assertNotIn(own_gap, gaps)
        self.assertIn(parent_gap, gaps)
        self.assertIn(sibling_gap, gaps)

    def test_new_event_each_round_with_budget_cut_completes_recheck(self):
        data = self.root / "data"
        for index in range(30):
            self.write(data / f"{index:02d}.txt")
        self.run_patrol()
        self.set_budget(4)
        reports, holding = [], False
        token = 1000
        for _ in range(40):
            report = self.run_patrol(self.event([str(data)], event_ids={str(data): token}))
            reports.append(report)
            if report["last_run"]["coverage_complete"]:
                break
            current = read_current(self.store)
            entry = current.get("scan_progress", {}).get(str(self.root), {})
            scope = report["coverage_scope"][str(self.root)]["event_recheck"]
            # 复核进行中每轮推进事件 id；一旦完成并留下 pending，就固定最后一次
            # 事件 id，让下一轮补齐复核。持续每轮新事件会让长子树保持 pending。
            if not entry and not scope["covered"] and scope["pending"]:
                holding = True
            if not holding:
                token += 1
        self.assertTrue(reports[-1]["last_run"]["coverage_complete"])
        self.assertLess(len(reports), 40)
        self.assertEqual(self.queue()["items"], [])
        records = read_current(self.store)["baselines"][str(self.root)]["records"]
        self.assertEqual(len([path for path in records if "/data/" in path]), 30)

    def test_new_event_token_rechecks_covered_subtree(self):
        data = self.root / "data"
        target = self.write(data / "file.txt")
        self.run_patrol()
        report = self.run_patrol(self.event([str(data)], event_ids={str(data): 100}))
        self.assertTrue(report["last_run"]["coverage_complete"])
        target.write_bytes(b"changed after covered")
        report = self.run_patrol(self.event([str(data)], event_ids={str(data): 200}))
        self.assertTrue(report["last_run"]["coverage_complete"])
        self.assertTrue(any(row["modified"] for row in report["changes"]))
        self.assertEqual(self.queue()["items"], [])

    def test_first_baseline_across_rounds_does_not_report_listener_rebuild(self):
        for index in range(6):
            self.write(self.root / "data" / f"{index}.txt")
        self.set_budget(2)
        baseline = self.event([], baseline=True, history_complete=False, cursor=None)
        reports = []
        for _ in range(10):
            report = self.run_patrol(baseline)
            reports.append(report)
            self.assertNotIn({"kind": "events", "reason": "baseline_rebuild"}, report["observation_gaps"])
            self.assertIsNone(self.queue()["degraded"])
            if report["last_run"]["coverage_complete"]:
                break
        self.assertFalse(reports[0]["last_run"]["coverage_complete"])
        self.assertIn({"kind": "events", "reason": "cursor_pending"}, reports[0]["observation_gaps"])
        self.assertTrue(reports[-1]["last_run"]["coverage_complete"])

    @unittest.skipUnless(sys.platform == "darwin", "FSEvents 子进程分支仅在 macOS 运行")
    def test_native_event_subprocess_failure_degrades_and_patrol_continues(self):
        self.write(self.root / "data" / "file.txt")
        with patch("steward.native_events", side_effect=lambda *args: native_events(*args)), \
             patch("steward.command", side_effect=TimeoutError("fixture events timeout")), \
             patch("steward.time.time", return_value=self.now + 10):
            result = native_events(self.policy, {})
            self.assertEqual(result["source"], "macos_fsevents")
            self.assertFalse(result["available"])
            self.assertIn("fixture events timeout", result["reason"])
            self.assertIn(str(self.root), result["devices"])
            report = patrol(self.store, self.policy)
        self.assertTrue(report["last_run"]["coverage_complete"])
        self.assertIn({"kind": "events", "reason": "unavailable"}, report["observation_gaps"])
        self.assertEqual(self.queue()["degraded"]["reason"], "unavailable")

    def test_events_do_not_create_changes_before_scan(self):
        target = self.write(self.root / "data" / "file.txt")
        self.write(self.root / "data" / "extra-1.txt")
        self.write(self.root / "data" / "extra-2.txt")
        self.run_patrol()
        target.write_bytes(b"changed content")
        self.set_budget(1)
        report = self.run_patrol(self.event([str(target)]))
        self.assertFalse(report["last_run"]["coverage_complete"])
        self.assertEqual(report["changes"], [])
        self.assertEqual(len(self.queue()["items"]), 1)
        self.assertEqual(self.queue()["items"][0]["path"], str(target.parent))

    def test_queue_persists_and_status_shows_pending_recheck(self):
        target = self.write(self.root / "data" / "file.txt")
        self.write(self.root / "data" / "extra-1.txt")
        self.write(self.root / "data" / "extra-2.txt")
        self.run_patrol()
        target.write_bytes(b"changed content")
        self.set_budget(1)
        self.run_patrol(self.event([str(target)]))
        current = read_current(self.store)
        self.assertEqual(current["event_recheck"], self.queue())
        self.assertEqual(len(current["event_recheck"]["items"]), 1)
        self.assertIn("event_recheck", current["coverage_scope"][str(self.root)])
        summary = status_report(self.store, self.policy)["event_recheck"]
        self.assertEqual(summary["pending"], 1)
        self.assertEqual(summary["items"][0]["path"], str(target.parent))
        self.set_budget(1000)
        report = self.run_patrol(self.event([]))
        self.assertTrue(report["last_run"]["coverage_complete"])
        self.assertEqual(self.queue()["items"], [])

    def test_four_change_kinds_are_confirmed_after_recheck(self):
        data = self.root / "data"
        replace = self.write(data / "replace.txt", b"old")
        move = self.write(data / "move.txt", b"move")
        delete = self.write(data / "delete.txt", b"delete")
        # 与 files.birth 相同口径探测当前平台/文件系统是否提供 birth time。
        has_birth = files.birth(os.lstat(replace)) is not None
        self.run_patrol()
        added = self.write(data / "added.txt", b"added")
        replacement = self.base / "replacement"
        replacement.write_bytes(b"new content")
        os.replace(replacement, replace)
        moved = data / "moved.txt"
        move.rename(moved)
        delete.unlink()
        report = self.run_patrol(self.event([str(data), str(added), str(replace),
                                             str(move), str(moved), str(delete)]))
        self.assertTrue(report["last_run"]["coverage_complete"])
        self.assertEqual(report["gaps"], [])
        totals = {key: sum(row[key] for row in report["changes"])
                  for key in ["added", "removed", "modified", "moved"]}
        if has_birth:
            self.assertEqual(totals, {"added": 1, "removed": 1, "modified": 1, "moved": 1})
        else:
            # 没有 birth time 时移动保守记为新增+删除，但必须给出 move uncertain 缺口。
            self.assertEqual(totals, {"added": 2, "removed": 2, "modified": 1, "moved": 0})
            reasons = [reason for row in report["comparison_gaps"] for reason in row.get("reasons", [])]
            self.assertTrue(any("move uncertain" in reason and str(move) in reason
                                and str(moved) in reason for reason in reasons), reasons)
        self.assertEqual(self.queue()["items"], [])
        scope = report["coverage_scope"][str(self.root)]["event_recheck"]
        self.assertEqual((scope["requested"], scope["covered"], scope["pending"]), (1, 1, 0))

    def test_history_invalid_clears_queue_and_avoids_unverified_deletion(self):
        data = self.root / "data"
        doomed = self.write(data / "doomed.txt")
        self.write(data / "extra-1.txt")
        self.write(data / "extra-2.txt")
        self.run_patrol()
        doomed.write_bytes(b"changed")
        self.set_budget(1)
        self.run_patrol(self.event([str(doomed)]))
        self.assertEqual(len(self.queue()["items"]), 1)
        doomed.unlink()
        report = self.run_patrol(self.event([str(doomed)], history_invalid=True,
                                            available=True, history_complete=False))
        self.assertEqual(self.queue()["items"], [])
        self.assertEqual(self.queue()["degraded"]["reason"], "history_invalid")
        self.assertIn({"kind": "events", "reason": "history_invalid"}, report["observation_gaps"])
        scope = report["coverage_scope"][str(self.root)]["event_recheck"]
        self.assertEqual(scope["degraded"], "history_invalid")
        self.assertFalse(any(row["removed"] for row in report["changes"]))

    def test_unavailable_events_keep_previous_queue_and_mark_degraded(self):
        target = self.write(self.root / "data" / "file.txt")
        self.write(self.root / "data" / "extra-1.txt")
        self.write(self.root / "data" / "extra-2.txt")
        self.run_patrol()
        target.write_bytes(b"changed")
        self.set_budget(1)
        self.run_patrol(self.event([str(target)]))
        self.assertEqual(len(self.queue()["items"]), 1)
        report = self.run_patrol(self.event([], available=False, cursor=None, history_complete=False))
        self.assertEqual(len(self.queue()["items"]), 1)
        self.assertEqual(self.queue()["degraded"]["reason"], "unavailable")
        self.assertIn({"kind": "events", "reason": "unavailable"}, report["observation_gaps"])

    def test_snapshot_only_source_clears_stale_queue(self):
        target = self.write(self.root / "data" / "file.txt")
        self.write(self.root / "data" / "extra-1.txt")
        self.write(self.root / "data" / "extra-2.txt")
        self.run_patrol()
        target.write_bytes(b"changed")
        self.set_budget(1)
        self.run_patrol(self.event([str(target)]))
        self.assertEqual(len(self.queue()["items"]), 1)
        report = self.run_patrol({"source": "metadata_snapshot", "available": False})
        self.assertEqual(self.queue()["items"], [])
        self.assertEqual(self.queue()["degraded"]["reason"], "snapshot_only")
        self.assertEqual(report["observation_gaps"], [])

    def test_listener_rebuild_reports_gap_and_clears_stale_queue(self):
        target = self.write(self.root / "data" / "file.txt")
        self.write(self.root / "data" / "extra-1.txt")
        self.write(self.root / "data" / "extra-2.txt")
        self.run_patrol()
        target.write_bytes(b"changed")
        self.set_budget(1)
        self.run_patrol(self.event([str(target)]))
        self.assertEqual(len(self.queue()["items"]), 1)
        report = self.run_patrol(self.event([], baseline=True, history_complete=False,
                                            cursor=self.now + 1000))
        self.assertEqual(self.queue()["items"], [])
        self.assertEqual(self.queue()["degraded"]["reason"], "baseline_rebuild")
        self.assertIn({"kind": "events", "reason": "baseline_rebuild"}, report["observation_gaps"])

    def test_corrupt_queue_blocks_patrol_and_reset_flag_clears_it(self):
        self.run_patrol()
        current = read_current(self.store)
        current["event_recheck"] = {
            "version": 1, "limit": 64, "items": [{}], "truncated": False,
            "aggregated": 0, "dropped": 0, "source_truncated": False, "degraded": None}
        self.store.write("current.json", current)
        with patch("steward.native_events") as native:
            with self.assertRaisesRegex(StewardError, "--discard-event-recheck"):
                self.run_patrol()
        native.assert_not_called()
        report = self.run_patrol(discard_event_recheck=True)
        self.assertTrue(report["event_recheck_discarded"])
        current = read_current(self.store)
        self.assertEqual(current["event_recheck"]["items"], [])

    def test_policy_change_clears_stale_path_clues(self):
        target = self.write(self.root / "data" / "file.txt")
        self.write(self.root / "data" / "extra-1.txt")
        self.write(self.root / "data" / "extra-2.txt")
        self.run_patrol()
        target.write_bytes(b"changed")
        self.set_budget(1)
        self.run_patrol(self.event([str(target)]))
        self.assertEqual(len(self.queue()["items"]), 1)
        self.policy["purpose"] = "范围调整后的用途"
        self.set_budget(1000)
        self.run_patrol(self.event([]))
        self.assertEqual(self.queue()["items"], [])


class BaselineRecheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()

    def limits(self, entries=1000):
        return {"scan_entries": entries, "scan_seconds": 10, "scan_depth": 8}

    def write(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
        return path

    def test_recheck_subtree_is_scanned_before_alphabetical_siblings(self):
        for name in ["aaa", "zzz"]:
            for index in range(4):
                self.write(self.root / name / f"{index}.txt")
        snapshots, progress = resumable_scan(
            None, [str(self.root)], self.limits(6),
            recheck={str(self.root): {str(self.root / "aaa"): 1}})
        snapshot = snapshots[str(self.root)]
        self.assertFalse(snapshot["complete"])
        self.assertIn(str(self.root / "aaa"), snapshot["recheck"]["targets"])
        paths = list(snapshot["records"])
        self.assertEqual(len([path for path in paths if "/aaa/" in path]), 4)
        self.assertFalse(any("/zzz/" in path for path in paths))
        self.assertIn(str(self.root / "zzz"), [item["path"]
                                               for item in progress[str(self.root)]["queue"]])

    def test_recheck_progress_survives_budget_cut_and_matches_full_scan(self):
        for index in range(10):
            self.write(self.root / "data" / f"{index}.txt")
        limits = self.limits(6)
        target = str(self.root / "data")
        snapshots, progress = resumable_scan(
            None, [str(self.root)], limits, recheck={str(self.root): {target: 1}})
        self.assertEqual(snapshots[str(self.root)]["recheck"]["pending"], [target])
        progress = json.loads(json.dumps(progress))
        rounds = 1
        while not snapshots[str(self.root)]["complete"]:
            snapshots, progress = resumable_scan(
                progress, [str(self.root)], limits, recheck={str(self.root): {target: 1}})
            rounds += 1
            self.assertLess(rounds, 20)
        self.assertEqual(snapshots[str(self.root)]["recheck"]["covered"], [target])
        self.assertEqual(progress, {})
        full = scan([str(self.root)], self.limits())[str(self.root)]
        self.assertEqual(snapshots[str(self.root)]["records"], full["records"])

    def test_recheck_accepts_flat_path_collection_and_mapping(self):
        target = str(self.write(self.root / "data" / "file.txt").parent)
        snapshots, progress = resumable_scan(
            None, [str(self.root)], self.limits(),
            recheck={str(self.root): {target + "/": 5}})
        self.assertEqual(snapshots[str(self.root)]["recheck"]["covered"], [target])
        rejected = [[target], {target: 5}, {str(self.root): [target]},
                    {str(self.root): 6}, target, (target, 5)]
        for value in rejected:
            with self.assertRaises(ValueError):
                resumable_scan(None, [str(self.root)], self.limits(), recheck=value)
        snapshots, progress = resumable_scan(
            None, [str(self.root)], {"scan_entries": 0, "scan_seconds": 10, "scan_depth": 8},
            recheck={str(self.root): {target: 1}})
        self.assertEqual(snapshots[str(self.root)]["recheck"]["pending"], [target])

    def test_requeued_recheck_clears_old_mtime_gap(self):
        target = str(self.root / "data")
        for index in range(6):
            self.write(self.root / "data" / f"{index}.txt")
        limits = self.limits(3)
        snapshots, progress = resumable_scan(
            None, [str(self.root)], limits, recheck={str(self.root): {target: 1}})
        self.assertFalse(snapshots[str(self.root)]["complete"])
        progress[str(self.root)]["gaps"].append(f"{GAP_MTIME}：{target}")
        progress[str(self.root)]["queue"] = [item for item in progress[str(self.root)]["queue"]
                                             if item["path"] != target]
        snapshots, progress = resumable_scan(
            progress, [str(self.root)], limits, recheck={str(self.root): {target: 2}})
        self.assertFalse(any(reason.startswith(GAP_MTIME) for reason in snapshots[str(self.root)]["gaps"]))
        rounds = 1
        while not snapshots[str(self.root)]["complete"]:
            snapshots, progress = resumable_scan(progress, [str(self.root)], self.limits())
            rounds += 1
            self.assertLess(rounds, 20)
        self.assertEqual(snapshots[str(self.root)]["gaps"], [])
        self.assertEqual(progress, {})

    def test_requeued_recheck_clears_old_recheck_gap(self):
        target = str(self.root / "data")
        for index in range(6):
            self.write(self.root / "data" / f"{index}.txt")
        limits = self.limits(3)
        snapshots, progress = resumable_scan(
            None, [str(self.root)], limits, recheck={str(self.root): {target: 1}})
        self.assertFalse(snapshots[str(self.root)]["complete"])
        progress[str(self.root)]["gaps"].append(f"{GAP_RECHECK}：{target}")
        progress[str(self.root)]["queue"] = [item for item in progress[str(self.root)]["queue"]
                                             if item["path"] != target]
        snapshots, progress = resumable_scan(
            progress, [str(self.root)], limits, recheck={str(self.root): {target: 2}})
        self.assertFalse(any(reason.startswith(GAP_RECHECK)
                             for reason in snapshots[str(self.root)]["gaps"]))
        while not snapshots[str(self.root)]["complete"]:
            snapshots, progress = resumable_scan(progress, [str(self.root)], self.limits())
        self.assertEqual(snapshots[str(self.root)]["gaps"], [])
        self.assertEqual(progress, {})

    def test_legacy_float_done_does_not_cover_new_event_id(self):
        target = str(self.root / "data")
        for index in range(6):
            self.write(self.root / "data" / f"{index}.txt")
        limits = self.limits(2)
        _, progress = resumable_scan(None, [str(self.root)], limits)
        self.assertIn(target, [item["path"] for item in progress[str(self.root)]["queue"]])
        progress[str(self.root)]["recheck_pending"][target] = 1.8e9
        _, normalized = resumable_scan(progress, [str(self.root)], limits)
        self.assertEqual(normalized[str(self.root)]["recheck_pending"].get(target, 0), 0)
        progress = normalized
        progress[str(self.root)]["recheck_done"][target] = 1.8e9
        progress[str(self.root)]["recheck_active"][target] = 1.8e9
        snapshots, progress = resumable_scan(
            progress, [str(self.root)], limits, recheck={str(self.root): {target: 1000}})
        info = snapshots[str(self.root)]["recheck"]
        self.assertEqual(info["covered"], [])
        self.assertIn(target, info["pending"])
        self.assertEqual(progress[str(self.root)]["recheck_done"][target], 0)
        while not snapshots[str(self.root)]["complete"]:
            snapshots, progress = resumable_scan(
                progress, [str(self.root)], self.limits(),
                recheck={str(self.root): {target: 1000}})
        self.assertEqual(snapshots[str(self.root)]["recheck"]["covered"], [target])

    def test_new_clue_token_rechecks_a_covered_subtree(self):
        target = self.write(self.root / "data" / "file.txt")
        self.write(self.root / "data" / "other.txt")
        target_dir = str(self.root / "data")
        snapshots, progress = resumable_scan(
            None, [str(self.root)], self.limits(),
            recheck={str(self.root): {target_dir: 1}})
        self.assertTrue(snapshots[str(self.root)]["complete"])
        self.assertEqual(progress, {})
        target.write_bytes(b"changed")
        snapshots, progress = resumable_scan(
            progress, [str(self.root)], self.limits(1),
            recheck={str(self.root): {target_dir: 2}})
        self.assertFalse(snapshots[str(self.root)]["complete"])
        self.assertEqual(snapshots[str(self.root)]["recheck"]["pending"], [target_dir])
        while not snapshots[str(self.root)]["complete"]:
            snapshots, progress = resumable_scan(
                progress, [str(self.root)], self.limits(),
                recheck={str(self.root): {target_dir: 2}})
        self.assertEqual(snapshots[str(self.root)]["recheck"]["covered"], [target_dir])

    def test_recheck_coexists_with_existing_scan_progress(self):
        for name, count in [("data", 8), ("other", 2)]:
            for index in range(count):
                self.write(self.root / name / f"{index}.txt")
        limits = self.limits(4)
        first, progress = resumable_scan(None, [str(self.root)], limits)
        self.assertFalse(first[str(self.root)]["complete"])
        self.assertIn(str(self.root), progress)
        target = str(self.root / "other")
        second, progress = resumable_scan(
            progress, [str(self.root)], limits, recheck={str(self.root): {target: 1}})
        self.assertEqual(second[str(self.root)]["recheck"]["covered"], [target])
        self.assertIn(str(self.root), progress)
        while not second[str(self.root)]["complete"]:
            second, progress = resumable_scan(progress, [str(self.root)], limits)
        self.assertEqual(progress, {})
        full = scan([str(self.root)], self.limits())[str(self.root)]
        self.assertEqual(second[str(self.root)]["records"], full["records"])


if __name__ == "__main__":
    unittest.main()
