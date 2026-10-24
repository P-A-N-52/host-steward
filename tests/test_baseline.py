import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
import baseline
import files
from baseline import (GAP_FAIR, GAP_MTIME, GAP_MTIME_PASS, GAP_RANGE, GAP_VANISHED,
                      resumable_scan)
from state_schema import read_current
from state import StewardError
from steward import initialize, patrol


class _EntryProxy:
    def __init__(self, entry, device):
        self.name = entry.name
        self.path = entry.path
        self.entry = entry
        self.device = device

    def stat(self, follow_symlinks=False):
        info = self.entry.stat(follow_symlinks=follow_symlinks)
        if self.device is None:
            return info
        values = list(info)
        values[2] = self.device
        return os.stat_result(values)


class _EntryCollection:
    def __init__(self, entries):
        self.entries = entries

    def __enter__(self):
        return iter(self.entries)

    def __exit__(self, exception_type, exception, traceback):
        return False


class BaselineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()

    def limits(self, entries=1000, seconds=10, depth=8):
        return {"scan_entries": entries, "scan_seconds": seconds, "scan_depth": depth}

    def write(self, path, size=1):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
        return path

    def full(self, roots, limits=None, exclude_names=(), state_path=None):
        return files.scan(roots, limits or self.limits(), exclude_names, state_path)

    def run_until_complete(self, progress, roots, limits, max_rounds=150, state_path=None):
        snapshots = None
        rounds = 0
        while True:
            snapshots, progress = resumable_scan(progress, roots, limits, state_path=state_path)
            rounds += 1
            self.assertLess(rounds, max_rounds, "续扫未在预期轮数内完成")
            if all(snapshot["complete"] for snapshot in snapshots.values()):
                return snapshots, progress, rounds

    def assert_complete_matches(self, snapshot, root, limits=None):
        full = self.full([root], limits)[str(root)]
        for key in ["root_id", "excluded", "records", "directories", "scope", "gaps"]:
            self.assertEqual(snapshot[key], full[key], key)
        self.assertNotIn("resumable", snapshot)

    def fake_devices(self, root, devices):
        real_scandir = os.scandir

        def scandir(path):
            if os.fspath(path) != str(root):
                return real_scandir(path)
            with real_scandir(path) as entries:
                values = list(entries)
            return _EntryCollection([_EntryProxy(value, devices.get(value.path)) for value in values])

        return patch("baseline.os.scandir", side_effect=scandir)

    def test_small_budget_matches_full_scan_and_progress_is_monotonic(self):
        for index in range(6):
            self.write(self.root / f"top-{index}.txt", index + 1)
            directory = self.root / f"dir-{index}"
            for inner in range(3):
                self.write(directory / f"file-{inner}.txt", index + inner + 1)
        limits = self.limits(entries=3)
        progress, previous_entries, rounds, snapshot = None, 0, 0, None
        while True:
            snapshots, progress = resumable_scan(progress, [self.root], limits)
            snapshot = snapshots[str(self.root)]
            rounds += 1
            self.assertLess(rounds, 150)
            if snapshot["complete"]:
                break
            self.assertEqual(set(snapshot["resumable"]),
                             {"pass_rounds", "entries_recorded", "queued_directories"})
            self.assertGreater(snapshot["resumable"]["entries_recorded"], previous_entries)
            previous_entries = snapshot["resumable"]["entries_recorded"]
            self.assertIn(str(self.root), progress)
            self.assertEqual(progress["next_index"], 0)
            for record in snapshot["records"].values():
                self.assertEqual(set(record), {"id", "kind", "size", "mtime", "birth"})
        self.assertGreater(rounds, 3)
        self.assertEqual(progress, {})
        self.assert_complete_matches(snapshot, self.root)

    def test_directory_resume_restarts_after_scanned_entries_change(self):
        data = self.root / "data"
        for index in range(10):
            self.write(data / f"a{index}.txt", index + 1)
        self.write(self.root / "z.txt")
        limits = self.limits(entries=3)
        snapshots, progress = resumable_scan(None, [self.root], limits)
        self.assertFalse(snapshots[str(self.root)]["complete"])
        item = progress[str(self.root)]["queue"][-1]
        self.assertEqual(item["path"], str(data))
        self.assertEqual(item["cursor"], "a0.txt")
        # 改动已扫部分：删除、改名，再加一个排在游标之后的新文件。
        (data / "a0.txt").unlink()
        (data / "a1.txt").rename(data / "a1-renamed.txt")
        self.write(data / "a05-new.txt")
        snapshots, progress = resumable_scan(progress, [self.root], limits)
        records = progress[str(self.root)]["records"]
        self.assertNotIn(str(data / "a0.txt"), records)
        self.assertIn(str(data / "a1-renamed.txt"), records)
        self.assertIn(str(data / "a05-new.txt"), records)
        self.assertEqual(progress[str(self.root)]["queue"][-1]["cursor"], "a2.txt")
        snapshots, progress, _ = self.run_until_complete(progress, [self.root], limits)
        snapshot = snapshots[str(self.root)]
        self.assertEqual(snapshot["directories"][str(self.root)]["bytes"],
                         self.full([self.root])[str(self.root)]["directories"][str(self.root)]["bytes"])
        self.assert_complete_matches(snapshot, self.root)

    def test_interrupted_round_resumes_from_last_committed_progress(self):
        for index in range(3):
            self.write(self.root / f"top-{index}.txt")
            for inner in range(4):
                self.write(self.root / f"sub-{index}" / f"file-{inner}.txt", inner + 1)
        limits = self.limits(entries=2)
        progress = None
        for _ in range(3):
            _, progress = resumable_scan(progress, [self.root], limits)
        committed = copy.deepcopy(progress)
        real_lstat = os.lstat
        root = str(self.root)

        def crashing_lstat(path):
            if os.fspath(path) == root:
                return real_lstat(path)
            raise OSError("模拟下一轮扫描中断")

        with patch("baseline.os.lstat", side_effect=crashing_lstat):
            with self.assertRaises(OSError):
                resumable_scan(progress, [self.root], self.limits(entries=1000))
        self.assertEqual(progress, committed)
        resumed, _, _ = self.run_until_complete(progress, [self.root], limits)
        restart, _, _ = self.run_until_complete(None, [self.root], limits)
        self.assertEqual(resumed[str(self.root)], restart[str(self.root)])
        self.assert_complete_matches(resumed[str(self.root)], self.root)

    def test_fair_rotation_completes_small_root_first(self):
        roots = []
        for name, count in [("big-a", 30), ("tiny-b", 1), ("big-c", 20)]:
            directory = self.base / name
            directory.mkdir()
            roots.append(str(directory))
            for index in range(count):
                self.write(directory / f"f{index:02}.txt")
        limits = self.limits(entries=4)
        snapshots, progress = resumable_scan(None, roots, limits)
        self.assertEqual(snapshots[roots[0]]["complete"], False)
        self.assertEqual(snapshots[roots[1]]["complete"], False)
        self.assertTrue(any(GAP_FAIR in reason for reason in snapshots[roots[1]]["gaps"]))
        self.assertNotIn(roots[1], progress)
        self.assertEqual(progress["next_index"], 1)
        completion = {}
        rounds = 1
        while progress:
            rounds += 1
            self.assertLess(rounds, 200)
            snapshots, progress = resumable_scan(progress, roots, limits)
            for root in roots:
                if snapshots[root]["complete"] and root not in completion:
                    completion[root] = rounds
        self.assertEqual(set(completion), set(roots))
        self.assertEqual(completion[roots[1]], 2)
        self.assertGreater(completion[roots[0]], completion[roots[1]])
        self.assertGreater(completion[roots[2]], completion[roots[1]])

    def test_scope_change_invalidates_progress_and_reports_reason(self):
        inner = self.root / "inner"
        for index in range(4):
            self.write(self.root / f"top-{index}.txt")
            self.write(inner / f"deep-{index}.txt")
        limits = self.limits(entries=3)
        _, progress = resumable_scan(None, [self.root], limits)
        self.assertFalse(any(path.startswith(str(inner) + os.sep) for path in progress[str(self.root)]["records"]))
        rule = {"path": str(self.root), "max_depth": 0, "exclude_names": [], "exclude_paths": []}
        snapshots, changed = resumable_scan(progress, [rule], limits)
        snapshot = snapshots[str(self.root)]
        self.assertFalse(snapshot["complete"])
        self.assertTrue(any(GAP_RANGE in reason for reason in snapshot["gaps"]))
        self.assertEqual(changed[str(self.root)]["scope"]["version"], 2)
        self.assertEqual(changed[str(self.root)]["scope"]["max_depth"], 0)
        self.assertFalse(any(path.startswith(str(inner) + os.sep)
                             for path in changed[str(self.root)]["records"]))
        snapshots, changed, _ = self.run_until_complete(changed, [rule], limits)
        full = files.scan([rule], self.limits())[str(self.root)]
        self.assertEqual(snapshots[str(self.root)]["records"], full["records"])
        self.assertEqual(snapshots[str(self.root)]["directories"], full["directories"])
        self.assertEqual(snapshots[str(self.root)]["excluded"], full["excluded"])
        self.assertEqual(snapshots[str(self.root)]["scope"], full["scope"])

    def test_root_replacement_invalidates_progress_with_reason(self):
        for index in range(8):
            self.write(self.root / f"old-{index}.txt")
        limits = self.limits(entries=3)
        _, progress = resumable_scan(None, [self.root], limits)
        moved = self.base / "old-root"
        self.root.rename(moved)
        self.root.mkdir()
        self.write(self.root / "fresh.txt", 5)
        for index in range(6):
            self.write(self.root / f"new-{index}.txt")
        snapshots, changed = resumable_scan(progress, [self.root], limits)
        snapshot = snapshots[str(self.root)]
        self.assertFalse(snapshot["complete"])
        self.assertTrue(any(GAP_RANGE in reason and "root_id" in reason for reason in snapshot["gaps"]))
        self.assertNotIn(str(moved / "old-0.txt"), changed[str(self.root)]["records"])
        snapshots, changed, _ = self.run_until_complete(changed, [self.root], limits)
        self.assertEqual(snapshots[str(self.root)]["records"], self.full([self.root])[str(self.root)]["records"])
        self.assertNotIn(str(moved / "old-0.txt"), snapshots[str(self.root)]["records"])

    def test_renamed_root_rebuilds_instead_of_resuming_old_path(self):
        for index in range(10):
            self.write(self.root / f"file-{index}.txt")
        limits = self.limits(entries=3)
        _, progress = resumable_scan(None, [self.root], limits)
        renamed = self.base / "renamed"
        self.root.rename(renamed)
        snapshots, changed = resumable_scan(progress, [renamed], limits)
        snapshot = snapshots[str(renamed)]
        self.assertFalse(snapshot["complete"])
        self.assertTrue(any(GAP_RANGE in reason and str(self.root) in reason for reason in snapshot["gaps"]))
        self.assertNotIn(str(self.root), changed)
        snapshots, changed, _ = self.run_until_complete(changed, [renamed], limits)
        self.assertEqual(snapshots[str(renamed)]["records"], self.full([renamed])[str(renamed)]["records"])

    def test_progress_for_removed_root_is_dropped_without_deletion_inference(self):
        first, second = self.base / "first", self.base / "second"
        for index in range(10):
            self.write(first / f"a-{index}.txt")
            self.write(second / f"b-{index}.txt")
        roots = [str(first), str(second)]
        limits = self.limits(entries=4)
        _, progress = resumable_scan(None, roots, limits)
        _, progress = resumable_scan(progress, roots, limits)
        self.assertIn(str(first), progress)
        self.assertIn(str(second), progress)
        snapshots, progress = resumable_scan(progress, [str(first)], limits)
        self.assertEqual(set(snapshots), {str(first)})
        self.assertEqual(set(progress), {str(first), "next_index"})
        self.assertNotIn(str(second), progress)

    def test_entry_budget_counts_every_scanned_entry(self):
        self.write(self.root / "excluded-me")
        for index in range(4):
            self.write(self.root / f"dir-{index}" / f"file-{index}.txt")
        rule = {"path": str(self.root), "max_depth": 8,
                "exclude_names": ["excluded-me"], "exclude_paths": []}
        full = files.scan([rule], self.limits())[str(self.root)]
        total = len(full["records"]) - 1 + sum(full["excluded"].values())
        snapshots, progress = resumable_scan(None, [rule], self.limits(entries=3))
        self.assertFalse(snapshots[str(self.root)]["complete"])
        self.assertEqual(snapshots[str(self.root)]["resumable"]["entries_recorded"], 3)
        self.assertEqual(progress[str(self.root)]["entries"], 3)
        snapshots, progress = resumable_scan(None, [rule], self.limits(entries=total - 1))
        self.assertFalse(snapshots[str(self.root)]["complete"])
        self.assertEqual(snapshots[str(self.root)]["resumable"]["entries_recorded"], total - 1)
        snapshots, progress = resumable_scan(progress, [rule], self.limits(entries=1))
        self.assertTrue(snapshots[str(self.root)]["complete"])
        self.assertEqual(progress, {})

    def test_time_budget_stops_before_entries_are_counted(self):
        for index in range(5):
            self.write(self.root / f"file-{index}.txt")
        clock = {"now": 0.0}
        real_scandir = os.scandir

        def delayed_scandir(path):
            scanned = real_scandir(path)
            clock["now"] = 100.0
            return scanned

        with patch("baseline.time.monotonic", side_effect=lambda: clock["now"]), \
                patch("baseline.os.scandir", side_effect=delayed_scandir):
            snapshots, progress = resumable_scan(
                None, [self.root], {"scan_entries": 100, "scan_seconds": 1, "scan_depth": 8})
        snapshot = snapshots[str(self.root)]
        self.assertFalse(snapshot["complete"])
        self.assertEqual(snapshot["resumable"]["entries_recorded"], 0)
        self.assertTrue(any("时间或条目预算" in reason for reason in snapshot["gaps"]))
        self.assertIn(str(self.root), progress)
        snapshots, _, _ = self.run_until_complete(progress, [self.root], self.limits())
        self.assert_complete_matches(snapshots[str(self.root)], self.root)

    def test_state_directory_and_depth_boundary_apply_during_resume(self):
        state_path = self.root / "state"
        self.write(state_path / "one.txt")
        self.write(state_path / "two.txt")
        self.write(self.root / "secret.txt")
        self.write(self.root / "AGENTS.md", 3)
        inner = self.root / "inner"
        self.write(inner / "visible.txt")
        deep = inner / "deep"
        self.write(deep / "hidden.txt")
        rule = {"path": str(self.root), "max_depth": 1,
                "exclude_names": ["secret.txt"], "exclude_paths": []}
        full = files.scan([rule], self.limits(), (), str(state_path))[str(self.root)]
        snapshots, progress, _ = self.run_until_complete(
            None, [rule], self.limits(entries=2), max_rounds=50, state_path=state_path)
        snapshot = snapshots[str(self.root)]
        for key in ["root_id", "excluded", "records", "directories", "scope", "gaps"]:
            self.assertEqual(snapshot[key], full[key], key)
        self.assertEqual(snapshot["excluded"], {"configured": 2, "depth_boundary": 1})
        self.assertTrue(snapshot["directories"][str(deep)]["boundary"])
        self.assertEqual(snapshot["directories"][str(deep)]["bytes"], 0)
        self.assertNotIn(str(deep / "hidden.txt"), snapshot["records"])
        self.assertNotIn(str(state_path / "one.txt"), snapshot["records"])
        self.assertEqual(snapshot["directories"][str(self.root)]["agents"], str(self.root / "AGENTS.md"))

    def test_hardlink_bytes_are_deduplicated_when_pass_completes(self):
        first = self.root / "first"
        second = self.root / "second"
        source = self.write(first / "original.bin", 4096)
        second.mkdir()
        os.link(source, second / "linked.bin")
        limits = self.limits(entries=2)
        snapshots, progress, _ = self.run_until_complete(None, [self.root], limits)
        snapshot = snapshots[str(self.root)]
        full = self.full([self.root])[str(self.root)]
        self.assertEqual(snapshot["records"], full["records"])
        self.assertEqual(snapshot["directories"][str(self.root)]["bytes"], 4096)
        self.assertEqual(snapshot["directories"][str(self.root)]["bytes"],
                         full["directories"][str(self.root)]["bytes"])
        self.assertEqual(snapshot["directories"][str(self.root)]["allocated_bytes"],
                         full["directories"][str(self.root)]["allocated_bytes"])

    def test_progress_survives_json_round_trip(self):
        for index in range(5):
            self.write(self.root / f"top-{index}.txt", index + 1)
            self.write(self.root / f"dir-{index}" / "inner.txt")
        limits = self.limits(entries=2)
        progress = None
        for _ in range(2):
            _, progress = resumable_scan(progress, [self.root], limits)
        encoded = json.dumps(progress, ensure_ascii=False)
        restored = json.loads(encoded)
        self.assertEqual(restored, progress)
        snapshots, progress, _ = self.run_until_complete(restored, [self.root], limits)
        self.assert_complete_matches(snapshots[str(self.root)], self.root)

    def test_other_volume_boundary_applies_across_rounds(self):
        mount = self.root / "mount"
        self.write(mount / "hidden.txt")
        self.write(self.root / "ordinary.txt", 3)
        root_device = os.lstat(self.root).st_dev
        fake_device = int(root_device) + 1000
        with self.fake_devices(self.root, {str(mount): fake_device}):
            full = self.full([self.root])[str(self.root)]
            snapshots, progress, _ = self.run_until_complete(
                None, [self.root], self.limits(entries=1))
        snapshot = snapshots[str(self.root)]
        self.assertEqual(snapshot["excluded"]["other_volume"], 1)
        self.assertEqual(snapshot["scope"]["other_volumes"]["count"], 1)
        self.assertEqual(snapshot["scope"]["other_volumes"]["samples"],
                         [{"path": str(mount), "device": fake_device}])
        self.assertNotIn(str(mount / "hidden.txt"), snapshot["records"])
        for key in ["root_id", "excluded", "records", "directories", "scope", "gaps"]:
            self.assertEqual(snapshot[key], full[key], key)

    def test_vanished_queued_directory_is_purged_and_pass_continues(self):
        for name in ["a-dir", "b-dir"]:
            for index in range(12):
                self.write(self.root / name / f"file-{index:02d}.txt")
        limits = self.limits(entries=4)
        snapshots, progress = resumable_scan(None, [self.root], limits)
        self.assertFalse(snapshots[str(self.root)]["complete"])
        queued = {item["path"] for item in progress[str(self.root)]["queue"]}
        self.assertEqual(queued, {str(self.root / "a-dir"), str(self.root / "b-dir")})
        victim = str(self.root / "b-dir")
        shutil.rmtree(victim)
        progress = json.loads(json.dumps(progress))
        snapshots, progress = resumable_scan(progress, [self.root], limits)
        snapshot = snapshots[str(self.root)]
        # 消失的排队目录不再抛错；本轮记为缺口，并清掉该子树候选。
        self.assertFalse(snapshot["complete"])
        self.assertTrue(any(GAP_VANISHED in reason and victim in reason for reason in snapshot["gaps"]))
        self.assertNotIn(victim, snapshot["records"])
        self.assertFalse(any(path.startswith(victim + os.sep) for path in snapshot["records"]))
        self.assertEqual(progress[str(self.root)]["vanished"], [victim])
        # pass 可继续：另一个目录仍在推进。
        self.assertTrue(any(path.startswith(str(self.root / "a-dir") + os.sep)
                            for path in progress[str(self.root)]["records"]))
        rounds = 0
        while progress:
            snapshots, progress = resumable_scan(progress, [self.root], limits)
            snapshot = snapshots[str(self.root)]
            rounds += 1
            self.assertLess(rounds, 50)
        # 队列耗尽但存在未核实范围：本轮不完成，清空进度，下一轮从头核对。
        self.assertFalse(snapshot["complete"])
        self.assertTrue(any(GAP_VANISHED in reason for reason in snapshot["gaps"]))
        self.assertEqual(progress, {})
        snapshots, progress, _ = self.run_until_complete(None, [self.root], limits)
        self.assert_complete_matches(snapshots[str(self.root)], self.root)

    def test_empty_queue_error_points_to_discard_entry(self):
        for index in range(5):
            self.write(self.root / f"file-{index}.txt")
        _, progress = resumable_scan(None, [self.root], self.limits(entries=2))
        progress[str(self.root)]["queue"] = []
        with self.assertRaisesRegex(ValueError, "discard-scan-progress"):
            resumable_scan(progress, [self.root], self.limits())

    def test_directory_mtime_churn_restarts_once_then_resumes_from_cursor(self):
        data = self.root / "data"
        for index in range(40):
            self.write(data / f"a{index:02d}.txt")
        limits = self.limits(entries=5)
        snapshots, progress = resumable_scan(None, [self.root], limits)
        item = progress[str(self.root)]["queue"][-1]
        self.assertEqual(item["path"], str(data))
        self.assertIsNotNone(item["cursor"])
        # 首次 mtime 变化仍从头重扫一次。
        self.write(data / "a00-new.txt")
        snapshots, progress = resumable_scan(progress, [self.root], limits)
        item = progress[str(self.root)]["queue"][-1]
        self.assertEqual(item["restarts"], 1)
        progress = json.loads(json.dumps(progress))
        # 之后持续变化：从游标续扫，不再重启，并记录覆盖缺口。
        entries = [snapshots[str(self.root)]["resumable"]["entries_recorded"]]
        first_cursor = item["cursor"]
        for round_index in range(6):
            self.write(data / f"churn-{round_index}.txt")
            snapshots, progress = resumable_scan(progress, [self.root], limits)
            snapshot = snapshots[str(self.root)]
            entries.append(snapshot["resumable"]["entries_recorded"])
            self.assertTrue(any(GAP_MTIME in reason for reason in snapshot["gaps"]))
        self.assertGreater(entries[-1], entries[0])
        self.assertEqual(entries, sorted(entries))
        item = progress[str(self.root)]["queue"][-1]
        self.assertEqual(item["restarts"], 1)
        self.assertGreater(item["cursor"], first_cursor)
        # 停止写入后，带缺口的 pass 仍不完整：不更新基线，清空进度，下一轮从头复核。
        rounds = 0
        while progress:
            snapshots, progress = resumable_scan(progress, [self.root], limits)
            rounds += 1
            self.assertLess(rounds, 60)
        snapshot = snapshots[str(self.root)]
        self.assertFalse(snapshot["complete"])
        self.assertTrue(any(GAP_MTIME in reason for reason in snapshot["gaps"]))
        self.assertTrue(any(GAP_MTIME_PASS in reason for reason in snapshot["gaps"]))
        self.assertEqual(progress, {})
        # 下一轮从头复核后完成，快照与 files.scan 一致且不带覆盖缺口。
        snapshots, progress, _ = self.run_until_complete(None, [self.root], limits)
        snapshot = snapshots[str(self.root)]
        self.assertNotIn("resumable", snapshot)
        self.assertEqual(progress, {})
        self.assert_complete_matches(snapshot, self.root)

    def test_restart_keeps_sibling_gap_and_reports_no_removals(self):
        data = self.root / "data"
        sibling = self.root / "data2"
        for index in range(12):
            self.write(data / f"a{index:02d}.txt", index + 1)
            self.write(sibling / f"a{index:02d}.txt", index + 1)
        baseline = self.full([self.root])[str(self.root)]
        limits = self.limits(entries=4)

        def gap_paths(reasons):
            return [reason.split("：", 1)[1] for reason in reasons
                    if reason.startswith(GAP_MTIME + "：")]

        snapshots, progress = resumable_scan(None, [self.root], limits)
        self.assertFalse(snapshots[str(self.root)]["complete"])
        # data2 在 data 之前扫描（同名前缀、栈序在后）；两次 mtime 变化制造缺口。
        self.write(sibling / "sibling-new.txt")
        snapshots, progress = resumable_scan(progress, [self.root], limits)
        self.write(sibling / "sibling-new2.txt")
        snapshots, progress = resumable_scan(progress, [self.root], limits)
        self.assertIn(str(sibling), gap_paths(progress[str(self.root)]["gaps"]))
        # 等 data 开始被扫描后，同样制造 data 自己的缺口。
        for _ in range(10):
            if any(path.startswith(str(data) + os.sep)
                   for path in progress[str(self.root)]["records"]):
                break
            snapshots, progress = resumable_scan(progress, [self.root], limits)
        else:
            self.fail("data 未在预期轮数内开始扫描")
        self.write(data / "data-new.txt")
        snapshots, progress = resumable_scan(progress, [self.root], limits)
        self.write(data / "data-new2.txt")
        snapshots, progress = resumable_scan(progress, [self.root], limits)
        paths = gap_paths(progress[str(self.root)]["gaps"])
        self.assertIn(str(data), paths)
        self.assertIn(str(sibling), paths)
        # 重启 data 身份：按路径边界清理 data 的旧缺口，data2 的缺口必须保留。
        data.rename(self.base / "old-data")
        data.mkdir()
        for index in range(12):
            self.write(data / f"b{index:02d}.txt", index + 1)
        snapshots, progress = resumable_scan(progress, [self.root], limits)
        paths = gap_paths(progress[str(self.root)]["gaps"])
        self.assertNotIn(str(data), paths)
        self.assertIn(str(sibling), paths)
        snapshot = snapshots[str(self.root)]
        self.assertFalse(snapshot["complete"])
        self.assertTrue(any(str(sibling) in reason for reason in snapshot["gaps"]))
        # 缺口 pass 的每一轮都不参与删除判断。
        self.assertEqual(files.compare({str(self.root): baseline}, snapshots)["changes"], [])
        rounds = 0
        while progress:
            snapshots, progress = resumable_scan(progress, [self.root], limits)
            rounds += 1
            self.assertLess(rounds, 60)
            self.assertEqual(files.compare({str(self.root): baseline}, snapshots)["changes"], [])
        # 带 data2 缺口的 pass 不完成、清空进度；data 的旧缺口没有额外造成重置。
        snapshot = snapshots[str(self.root)]
        self.assertFalse(snapshot["complete"])
        reset_paths = gap_paths(snapshot["gaps"])
        self.assertIn(str(sibling), reset_paths)
        self.assertNotIn(str(data), reset_paths)
        self.assertEqual(progress, {})
        # 下一轮完整复核：data2 未被误报删除，快照与 files.scan 一致。
        snapshots, progress, _ = self.run_until_complete(None, [self.root], limits)
        snapshot = snapshots[str(self.root)]
        self.assert_complete_matches(snapshot, self.root)
        delta = files.compare({str(self.root): baseline}, snapshots)
        self.assertFalse(any(str(sibling) in json.dumps(row, ensure_ascii=False)
                             for row in delta["changes"] if row.get("removed")), delta["changes"])

    def test_unavailable_root_preserves_progress_for_later_resume(self):
        for index in range(8):
            self.write(self.root / f"file-{index}.txt")
        limits = self.limits(entries=2)
        _, progress = resumable_scan(None, [self.root], limits)
        saved = copy.deepcopy(progress)
        moved = self.base / "temporarily-moved"
        self.root.rename(moved)
        snapshots, progress = resumable_scan(progress, [self.root], limits)
        snapshot = snapshots[str(self.root)]
        self.assertFalse(snapshot["complete"])
        self.assertIsNone(snapshot["scope"]["device"])
        self.assertTrue(any("观察根" in reason for reason in snapshot["gaps"]))
        self.assertEqual(progress, saved)
        moved.rename(self.root)
        snapshots, progress, _ = self.run_until_complete(progress, [self.root], limits)
        self.assert_complete_matches(snapshots[str(self.root)], self.root)


class PatrolBaselineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.store, self.policy = initialize(self.base / "state", [self.root], "续扫巡检回归")
        self.now = 1_800_000_000
        host = {"system": "test", "architecture": "test", "cpu": {}, "memory": {"available": True},
                "gpu": {}, "model_usage": {}, "storage": [],
                "processes": {"available": True, "items": []}, "services": {"available": True, "items": []}}
        for mocker in [patch("steward.observe", return_value=host),
                       patch("steward.native_events", return_value={"available": False})]:
            mocker.start()
            self.addCleanup(mocker.stop)

    def write(self, path, size=1):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
        return path

    def run_patrol(self, discard_scan_progress=False):
        self.now += 10
        with patch("steward.time.time", return_value=self.now):
            return patrol(self.store, self.policy, discard_scan_progress=discard_scan_progress)

    def mtime_gap_setup(self):
        data = self.root / "data"
        for index in range(12):
            self.write(data / f"a{index:02d}.txt", index + 1)
        self.policy["limits"]["scan_entries"] = 5000
        self.store.write("host.json", self.policy)
        self.assertTrue(self.run_patrol()["last_run"]["coverage_complete"])
        self.policy["limits"]["scan_entries"] = 4
        self.store.write("host.json", self.policy)
        self.assertFalse(self.run_patrol()["last_run"]["coverage_complete"])
        return data

    def test_mtime_gap_pass_withholds_baseline_and_suppresses_removals(self):
        data = self.mtime_gap_setup()
        root = str(self.root)
        (data / "a01.txt").unlink()
        # 首次 mtime 变化从头重扫，此时 a01 已消失；随后在游标之前重建同名文件，
        # 第二次变化改为从游标续扫，候选快照缺少 a01——不能据此报告删除。
        self.run_patrol()
        self.write(data / "a01.txt", 2)
        report = self.run_patrol()
        self.assertFalse(report["last_run"]["coverage_complete"])
        self.assertEqual(report["changes"], [])
        reasons = [reason for row in report["gaps"] for reason in row["reasons"]]
        self.assertTrue(any(GAP_MTIME in reason for reason in reasons), reasons)
        self.assertFalse(report["coverage_scope"][root]["complete"])
        # 正式 CLI status 同样能看到覆盖缺口与不完整范围。
        result = subprocess.run(
            [sys.executable, str(PROJECT / "tools/steward.py"), "status", "--state", str(self.store.path)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        status = json.loads(result.stdout)
        status_reasons = [reason for row in status["coverage_gaps"] for reason in row["reasons"]]
        self.assertTrue(any(GAP_MTIME in reason for reason in status_reasons), status_reasons)
        self.assertFalse(status["coverage_scope"][root]["complete"])
        # 队列耗尽：带缺口的 pass 不完成、不更新基线，进度清空等待下一轮复核。
        baseline = read_current(self.store)["baselines"][root]
        report = self.run_patrol()
        self.assertFalse(report["last_run"]["coverage_complete"])
        self.assertEqual(report["changes"], [])
        current = read_current(self.store)
        self.assertEqual(current["scan_progress"], {})
        self.assertEqual(current["baselines"][root], baseline)
        why = [reason for row in report["gaps"] for reason in row["reasons"]]
        self.assertTrue(any(GAP_MTIME_PASS in reason for reason in why), why)
        # 下一轮从头完整复核：重建的 a01 认作同路径替换，不报删除。
        self.policy["limits"]["scan_entries"] = 5000
        self.store.write("host.json", self.policy)
        report = self.run_patrol()
        self.assertTrue(report["last_run"]["coverage_complete"])
        self.assertEqual(sum(row.get("removed", 0) for row in report["changes"]), 0)
        self.assertIn(str(data / "a01.txt"), read_current(self.store)["baselines"][root]["records"])

    def test_directory_identity_replacement_clears_stale_gap(self):
        data = self.mtime_gap_setup()
        root = str(self.root)
        (data / "a01.txt").unlink()
        self.run_patrol()
        self.write(data / "a01.txt", 2)
        report = self.run_patrol()
        reasons = [reason for row in report["gaps"] for reason in row["reasons"]]
        self.assertTrue(any(GAP_MTIME in reason for reason in reasons), reasons)
        # 目录身份替换：旧目录移出 root，新目录从零重扫，旧 mtime 缺口当轮清理。
        data.rename(self.base / "old-data")
        data.mkdir()
        for index in range(12):
            self.write(data / f"b{index:02d}.txt", index + 1)
        report = self.run_patrol()
        self.assertFalse(report["last_run"]["coverage_complete"])
        self.assertEqual(report["changes"], [])
        progress = self.store.read("current.json", {})["scan_progress"][root]
        gap_paths = [reason.split("：", 1)[1] for reason in progress["gaps"]
                     if reason.startswith(GAP_MTIME + "：")]
        self.assertNotIn(str(data), gap_paths)
        # 旧缺口已清，剩余轮次无需额外重置即可完成。
        rounds = 0
        while True:
            report = self.run_patrol()
            rounds += 1
            self.assertLess(rounds, 30)
            if report["last_run"]["coverage_complete"]:
                break
            self.assertEqual(report["changes"], [])
            self.assertNotEqual(self.store.read("current.json", {}).get("scan_progress"), {})
        current = read_current(self.store)
        self.assertEqual(current["scan_progress"], {})
        self.assertFalse(any("mtime" in reason for reason in current["baselines"][root].get("gaps", [])))

    def test_capacity_failure_during_completion_keeps_progress_and_repeats(self):
        for index in range(300):
            directory = self.root / f"group{index // 100}" / f"dir-{index:04d}"
            self.write(directory / "file.txt", index + 1)
        self.policy["limits"].update(scan_entries=50, total_bytes=1_200_000)
        self.store.write("host.json", self.policy)
        failure = None
        for _ in range(40):
            try:
                report = self.run_patrol()
            except StewardError as exc:
                failure = str(exc)
                break
            self.assertFalse(report["last_run"]["coverage_complete"])
        self.assertIsNotNone(failure)
        self.assertIn("状态总容量不足", failure)
        root = str(self.root)
        current = read_current(self.store)
        progress = current["scan_progress"]
        self.assertIn(root, progress)
        self.assertFalse(current["coverage_scope"][root]["complete"])
        self.assertNotIn(root, current.get("baselines", {}))
        # 用相同预算与状态路径在内存中核对：失败的一轮本应完成基线。
        snapshots, remaining = resumable_scan(
            progress, self.policy["roots"], self.policy["limits"],
            self.policy.get("exclude_names", ()), str(self.store.path))
        self.assertTrue(snapshots[root]["complete"])
        self.assertEqual(remaining, {})
        # 下一轮基于同一份进度重试，报同一明确错误，进度不变。
        with self.assertRaises(StewardError) as raised:
            self.run_patrol()
        self.assertEqual(str(raised.exception), failure)
        self.assertEqual(read_current(self.store)["scan_progress"], progress)
        # 调高预算后从保留的进度完成并写入基线。
        self.policy["limits"]["total_bytes"] = 4 * 1024 * 1024
        self.store.write("host.json", self.policy)
        report = self.run_patrol()
        self.assertTrue(report["last_run"]["coverage_complete"])
        current = read_current(self.store)
        self.assertEqual(current["scan_progress"], {})
        self.assertIn(root, current["baselines"])

    def test_patrol_discard_scan_progress_rebuilds_without_touching_baselines(self):
        for index in range(12):
            self.write(self.root / f"file-{index:02d}.txt", index + 1)
        first = self.run_patrol()
        self.assertTrue(first["last_run"]["coverage_complete"])
        root = str(self.root)
        baseline = read_current(self.store)["baselines"][root]
        self.policy["limits"]["scan_entries"] = 2
        self.store.write("host.json", self.policy)
        self.run_patrol()
        current = self.store.read("current.json", {})
        self.assertIn(root, current["scan_progress"])
        current["scan_progress"][root]["queue"] = []
        self.store.write("current.json", current)
        # 损坏进度在常规巡检中阻断，并指向显式重置入口。
        with self.assertRaisesRegex(StewardError, "discard-scan-progress"):
            self.run_patrol()
        report = self.run_patrol(discard_scan_progress=True)
        self.assertTrue(report["scan_progress_discarded"])
        current = read_current(self.store)
        self.assertEqual(current["baselines"][root], baseline)
        self.assertIn(root, current["scan_progress"])
        self.assertTrue(current["scan_progress"][root]["queue"])
        # 重建的进度可以继续跨轮推进并完成。
        self.policy["limits"]["scan_entries"] = 5000
        self.store.write("host.json", self.policy)
        report = self.run_patrol()
        self.assertTrue(report["last_run"]["coverage_complete"])
        self.assertEqual(read_current(self.store)["scan_progress"], {})

    def test_patrol_defers_deletions_until_resumable_baseline_completes(self):
        keep = self.write(self.root / "a-keep.txt")
        modify = self.write(self.root / "b-modify.txt", 2)
        delete = self.write(self.root / "c-delete.txt", 3)
        first = self.run_patrol()
        self.assertTrue(first["last_run"]["coverage_complete"])
        baseline_measured = read_current(self.store)["baselines"][str(self.root)]["measured_at"]
        # 缩小单轮预算，让下一轮扫描必须跨轮推进。
        self.policy["limits"]["scan_entries"] = 2
        self.store.write("host.json", self.policy)
        for index in range(12):
            self.write(self.root / "bulk" / f"file-{index:02}.txt", index + 1)
        keep.unlink()
        incomplete_rounds = 0
        while True:
            report = self.run_patrol()
            incomplete_rounds += 1
            self.assertLess(incomplete_rounds, 80)
            current = read_current(self.store)
            self.assertIn("scan_progress", current)
            if report["last_run"]["coverage_complete"]:
                break
            coverage = report["coverage_scope"][str(self.root)]
            self.assertFalse(coverage["complete"])
            self.assertEqual(set(coverage["resumable"]),
                             {"pass_rounds", "entries_recorded", "queued_directories"})
            self.assertIn(str(self.root), current["scan_progress"])
            self.assertEqual(current["baselines"][str(self.root)]["measured_at"], baseline_measured)
            self.assertEqual(report["changes"], [])
        self.assertGreater(incomplete_rounds, 1)
        self.assertEqual(read_current(self.store)["scan_progress"], {})
        self.assertGreater(read_current(self.store)["baselines"][str(self.root)]["measured_at"], baseline_measured)
        self.assertNotIn(str(keep), read_current(self.store)["baselines"][str(self.root)]["records"])
        self.assertTrue(any(row["removed"] for row in report["changes"]))
        # 基线建立后，普通改动与删除恢复正常检出。
        self.policy["limits"]["scan_entries"] = 5000
        self.store.write("host.json", self.policy)
        modify.write_bytes(b"changed")
        delete.unlink()
        report = self.run_patrol()
        self.assertTrue(report["last_run"]["coverage_complete"])
        self.assertTrue(any(row["modified"] >= 1 and str(modify) in row["samples"]
                            for row in report["changes"]))
        self.assertTrue(any(row["removed"] >= 1 and str(delete) in row["samples"]
                            for row in report["changes"]))


if __name__ == "__main__":
    unittest.main()
