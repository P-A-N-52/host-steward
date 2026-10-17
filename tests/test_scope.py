import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
import files
from files import SCOPE_SAMPLE_LIMIT, compare, scan


class _EntryProxy:
    def __init__(self, entry, device):
        self.name = entry.name
        self.path = entry.path
        self._entry = entry
        self._device = device

    def stat(self, follow_symlinks=False):
        info = self._entry.stat(follow_symlinks=follow_symlinks)
        if self._device is None:
            return info
        values = list(info)
        values[2] = self._device
        return os.stat_result(values)


class _EntryCollection:
    def __init__(self, entries):
        self.entries = entries

    def __enter__(self):
        return iter(self.entries)

    def __exit__(self, exception_type, exception, traceback):
        return False


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def snapshot(self, roots=None, exclude_names=(), state_path=None, depth=8, entries=1000):
        roots = [self.root] if roots is None else roots
        limits = {"scan_entries": entries, "scan_seconds": 10, "scan_depth": depth}
        return scan([str(root) for root in roots], limits, exclude_names, state_path)

    def root_snapshot(self, **kwargs):
        return self.snapshot(**kwargs)[str(self.root)]

    def fake_devices(self, root, devices, reverse=False):
        real_scandir = files.os.scandir

        def scandir(path):
            if os.fspath(path) != str(root):
                return real_scandir(path)
            with real_scandir(path) as entries:
                entries = list(entries)
            if reverse:
                entries.reverse()
            return _EntryCollection([_EntryProxy(entry, devices.get(entry.path)) for entry in entries])

        return patch("files.os.scandir", side_effect=scandir)

    def assert_scope_shape(self, snapshot):
        scope = snapshot["scope"]
        self.assertEqual(set(scope), {"version", "root", "device", "exclude_names", "state_path",
                                     "scan_depth", "volume_policy", "other_volumes"})
        self.assertEqual(set(scope["other_volumes"]), {"count", "digest", "samples", "truncated"})
        self.assertRegex(scope["other_volumes"]["digest"], r"^[0-9a-f]{64}$")
        self.assertLessEqual(len(scope["other_volumes"]["samples"]), SCOPE_SAMPLE_LIMIT)

    def test_scope_contract_uses_stable_filters_without_authorization_or_budgets(self):
        state_path = self.base / "state"
        snapshot = self.root_snapshot(exclude_names=["cache", ".git", ".git"], state_path=state_path, depth=3)
        self.assert_scope_shape(snapshot)
        scope = snapshot["scope"]
        self.assertEqual(scope["version"], 1)
        self.assertEqual(scope["root"], str(self.root))
        self.assertIsInstance(scope["device"], int)
        self.assertEqual(scope["exclude_names"], [".git", "cache"])
        self.assertEqual(scope["state_path"], str(state_path.resolve()))
        self.assertEqual(scope["scan_depth"], 3)
        self.assertEqual(scope["volume_policy"], "root_device_only")
        self.assertEqual(scope["other_volumes"]["count"], 0)
        self.assertEqual(scope["other_volumes"]["samples"], [])
        self.assertFalse(scope["other_volumes"]["truncated"])
        self.assertNotIn("purpose", scope)
        self.assertNotIn("residents", scope)
        self.assertNotIn("roots", scope)
        self.assertNotIn("scan_entries", scope)
        self.assertNotIn("scan_seconds", scope)

    def test_failed_root_still_has_scope_but_is_not_comparable(self):
        missing = self.base / "missing"
        current = self.snapshot(roots=[missing])
        snapshot = current[str(missing)]
        self.assertFalse(snapshot["complete"])
        self.assert_scope_shape(snapshot)
        self.assertIsNone(snapshot["scope"]["device"])
        delta = compare({}, current)
        self.assertEqual(delta["changes"], [])
        self.assertEqual(delta["new_baselines"], [])
        self.assertTrue(delta["gaps"])
        self.assertFalse(any(reason.startswith("scope:") for row in delta["gaps"] for reason in row["reasons"]))

    def test_exclude_add_or_revoke_rebases_without_deletion(self):
        target = self.root / "keep.txt"
        target.write_text("keep")
        before = self.root_snapshot()
        excluded = self.root_snapshot(exclude_names=[target.name])
        for old, new in [(before, excluded), (excluded, before)]:
            with self.subTest(direction=(old["scope"]["exclude_names"], new["scope"]["exclude_names"])):
                delta = compare({str(self.root): old}, {str(self.root): new})
                self.assertEqual(delta["changes"], [])
                self.assertEqual(delta["new_baselines"], [str(self.root)])
                reasons = delta["gaps"][0]["reasons"]
                self.assertTrue(any(reason.startswith("scope:") and "exclude_names" in reason for reason in reasons))

    def test_filtered_git_addition_and_change_do_not_rebuild_or_report(self):
        before = self.root_snapshot(exclude_names=[".git"])
        git = self.root / ".git"
        git.mkdir()
        payload = git / "ignored"
        payload.write_text("one")
        after = self.root_snapshot(exclude_names=[".git"])
        self.assertEqual(before["scope"], after["scope"])
        delta = compare({str(self.root): before}, {str(self.root): after})
        self.assertEqual(delta["changes"], [])
        self.assertEqual(delta["gaps"], [])
        self.assertEqual(delta["new_baselines"], [])
        payload.write_text("two")
        changed = self.root_snapshot(exclude_names=[".git"])
        self.assertEqual(after["scope"], changed["scope"])
        self.assertEqual(compare({str(self.root): after}, {str(self.root): changed})["changes"], [])

    def test_visible_metadata_change_remains_comparable(self):
        payload = self.root / "visible"
        payload.write_bytes(b"a")
        before = self.root_snapshot()
        payload.write_bytes(b"abc")
        after = self.root_snapshot()
        delta = compare({str(self.root): before}, {str(self.root): after})
        self.assertEqual(delta["gaps"], [])
        self.assertEqual(delta["new_baselines"], [])
        self.assertTrue(any(row["path"] == str(payload.parent) and row["modified"] for row in delta["changes"]))
        self.assertEqual(sum(row["byte_delta"] for row in delta["changes"]), 2)

    def test_mount_and_unmount_boundary_rebase_without_deletion(self):
        mount = self.root / "mounted"
        mount.mkdir()
        (mount / "keep").write_text("keep")
        root_device = os.lstat(self.root).st_dev
        fake_device = int(root_device) + 1000
        before = self.root_snapshot()
        with self.fake_devices(self.root, {str(mount): fake_device}):
            mounted = self.root_snapshot()
        for old, new in [(before, mounted), (mounted, before)]:
            with self.subTest(old_count=old["scope"]["other_volumes"]["count"],
                              new_count=new["scope"]["other_volumes"]["count"]):
                delta = compare({str(self.root): old}, {str(self.root): new})
                self.assertEqual(delta["changes"], [])
                self.assertEqual(delta["new_baselines"], [str(self.root)])
                self.assertTrue(any(reason.startswith("scope:") and "other_volumes" in reason
                                    for reason in delta["gaps"][0]["reasons"]))
        self.assertEqual(mounted["excluded"]["other_volume"], 1)
        self.assertEqual(mounted["scope"]["other_volumes"]["count"], 1)
        self.assertEqual(mounted["scope"]["other_volumes"]["samples"],
                         [{"path": str(mount), "device": fake_device}])

    def test_boundary_digest_and_samples_are_stable_and_bounded(self):
        directories = []
        for index in range(SCOPE_SAMPLE_LIMIT + 2):
            directory = self.root / f"vol-{index}"
            directory.mkdir()
            directories.append(directory)
        devices = {str(directory): 2000 + index for index, directory in enumerate(directories)}
        with self.fake_devices(self.root, devices) as first:
            left = self.root_snapshot()
        with self.fake_devices(self.root, devices, reverse=True) as second:
            right = self.root_snapshot()
        first_scope = left["scope"]["other_volumes"]
        second_scope = right["scope"]["other_volumes"]
        self.assertEqual(first_scope, second_scope)
        self.assertEqual(first_scope["count"], SCOPE_SAMPLE_LIMIT + 2)
        self.assertTrue(first_scope["truncated"])
        self.assertEqual([row["path"] for row in first_scope["samples"]],
                         [str(directory) for directory in directories[:SCOPE_SAMPLE_LIMIT]])
        self.assertEqual(left["excluded"]["other_volume"], SCOPE_SAMPLE_LIMIT + 2)

    def test_scope_changes_are_isolated_per_root(self):
        other = self.base / "other"
        other.mkdir()
        roots = [self.root, other]
        before = self.snapshot(roots=roots)
        changed = other / "new"
        changed.write_text("new")
        mount = self.root / "mount"
        mount.mkdir()
        root_device = os.lstat(self.root).st_dev
        with self.fake_devices(self.root, {str(mount): int(root_device) + 77}):
            after = self.snapshot(roots=roots)
        delta = compare(before, after)
        self.assertEqual(delta["new_baselines"], [str(self.root)])
        self.assertFalse(any(row["root"] == str(self.root) and row["path"] == str(mount)
                             for row in delta["changes"]))
        other_changes = [row for row in delta["changes"] if row["root"] == str(other)]
        self.assertTrue(other_changes)
        self.assertTrue(any(row["path"] == str(other) and row["added"] for row in other_changes))

    def test_state_path_and_scan_depth_changes_rebase(self):
        baseline = self.root_snapshot(state_path=self.base / "state-a", depth=2)
        for kwargs, field in [({"state_path": self.base / "state-b", "depth": 2}, "state_path"),
                              ({"state_path": self.base / "state-a", "depth": 3}, "scan_depth")]:
            current = self.root_snapshot(**kwargs)
            delta = compare({str(self.root): baseline}, {str(self.root): current})
            self.assertEqual(delta["changes"], [])
            self.assertEqual(delta["new_baselines"], [str(self.root)])
            self.assertTrue(any(reason.startswith("scope:") and field in reason
                                for row in delta["gaps"] for reason in row["reasons"]))

    def test_partial_scan_keeps_old_baseline_and_does_not_rebase_scope(self):
        for index in range(8):
            (self.root / f"file-{index}").write_text("x")
        before = self.root_snapshot(entries=100)
        partial = self.root_snapshot(entries=2)
        self.assertFalse(partial["complete"])
        delta = compare({str(self.root): before}, {str(self.root): partial})
        self.assertEqual(delta["changes"], [])
        self.assertEqual(delta["new_baselines"], [])
        self.assertTrue(delta["gaps"])
        self.assertFalse(any(reason.startswith("scope:") for row in delta["gaps"] for reason in row["reasons"]))

    def test_legacy_scope_absence_is_only_a_one_time_rebaseline(self):
        (self.root / "file").write_text("x")
        scoped = self.root_snapshot()
        legacy_before = copy.deepcopy(scoped)
        legacy_before.pop("scope")
        delta = compare({str(self.root): legacy_before}, {str(self.root): scoped})
        self.assertEqual(delta["changes"], [])
        self.assertEqual(delta["new_baselines"], [str(self.root)])
        self.assertTrue(any(reason.startswith("scope:") for row in delta["gaps"] for reason in row["reasons"]))
        legacy_after = copy.deepcopy(scoped)
        legacy_after.pop("scope")
        self.assertEqual(compare({str(self.root): legacy_before}, {str(self.root): legacy_after}),
                         {"changes": [], "gaps": [], "new_baselines": []})


if __name__ == "__main__":
    unittest.main()
