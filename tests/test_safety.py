import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
from files import identity
from maintain import annotate, fingerprint, quarantine, restore
from state import Store, StewardError, encode, read_regular_bytes


def dataset_snapshot(store, name, default=None):
    return encode(store.read(name, default))


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def limits(self, **changes):
        result = {"file_bytes": 8192, "total_bytes": 1024 * 1024, "operation_records": 32}
        result.update(changes)
        return result

    def store(self, directory=None, **limits):
        store = Store(directory or self.base / "state", self.limits(**limits))
        store.initialize_database()
        return store

    def policy(self, root=None, extra_rules=()):
        root = root or self.root
        rule = {"path": str(root), "purpose": "测试用途", "kind": "temporary",
                "allow_notes": True, "allow_quarantine": True, "retention_days": 0,
                "recycle_bytes": 1024 * 1024, "directory_id": identity(root.stat())}
        return {"roots": [str(root)], "directory_rules": [rule, *extra_rules]}

    def test_read_missing_default_and_rejects_special_files_and_limit(self):
        store = self.store()
        self.assertEqual(store.read("missing.json", {"default": True}), {"default": True})

        fifo = self.base / "pipe"
        os.mkfifo(fifo)
        with self.assertRaises(StewardError):
            read_regular_bytes(fifo, 64)

        directory = self.base / "directory"
        directory.mkdir()
        with self.assertRaises(StewardError):
            read_regular_bytes(directory, 64)

        link_target = self.base / "link-target"
        link_target.write_bytes(b"target")
        link = self.base / "link"
        link.symlink_to(link_target)
        with self.assertRaises(OSError):
            read_regular_bytes(link, 64)
        store.target("link").symlink_to(link_target)
        with self.assertRaises(StewardError):
            store.read("link")

        oversized = self.base / "oversized"
        oversized.write_bytes(b"x" * 65)
        with self.assertRaises(StewardError):
            read_regular_bytes(oversized, 64)

    def test_read_rejects_metadata_change_during_read(self):
        path = self.base / "changing"
        path.write_bytes(b"before")
        original_fstat = os.fstat
        calls = 0

        def change_before_final_stat(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                path.write_bytes(b"after and changed")
            return original_fstat(fd)

        with patch("state_io.os.fstat", side_effect=change_before_final_stat):
            with self.assertRaises(StewardError):
                read_regular_bytes(path, 128)

    def test_lock_fifo_is_fast_and_does_not_leave_a_held_lock(self):
        store = self.store()
        fifo = store.target(".lock")
        os.mkfifo(fifo)
        started = time.monotonic()
        with self.assertRaises(StewardError):
            with store.lock():
                self.fail("FIFO lock unexpectedly acquired")
        self.assertLess(time.monotonic() - started, 1.0)
        fifo.unlink()
        with store.lock():
            pass

    def test_exclusive_write_never_replaces_external_file(self):
        store = self.store()
        target = store.target("external.json")
        target.write_bytes(b"external")
        created = {}
        with self.assertRaises(FileExistsError):
            store.write_bytes("external.json", b"new", exclusive=True, created=created)
        self.assertEqual(target.read_bytes(), b"external")
        self.assertEqual(created, {})
        self.assertEqual(list(store.path.glob(".writing-*")), [])

    def test_exclusive_write_records_published_identity_before_directory_fsync(self):
        store = self.store()
        payload = b"new state"
        created = {}
        original_fsync = os.fsync

        def fail_directory_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("directory fsync fixture failure")
            return original_fsync(fd)

        with patch("state.os.fsync", side_effect=fail_directory_fsync):
            with self.assertRaises(OSError):
                store.write_bytes("new.json", payload, exclusive=True, created=created)
        target = store.target("new.json")
        self.assertEqual(target.read_bytes(), payload)
        self.assertEqual(created["new.json"], (target.stat().st_dev, target.stat().st_ino,
                                                target.stat().st_size, target.stat().st_mtime_ns))
        self.assertEqual(list(store.path.glob(".writing-*")), [])

    def test_exclusive_capacity_accounts_for_temp_and_destination(self):
        payload = b"1234"
        store = self.store(total_bytes=len(payload) * 2 - 1)
        with self.assertRaises(StewardError):
            store.write_bytes("new.json", payload, exclusive=True)
        self.assertFalse(store.target("new.json").exists())
        self.assertEqual(list(store.path.glob(".writing-*")), [])

    def test_note_rejects_fifo_directory_and_link_without_operation(self):
        store = self.store()
        policy = self.policy()
        store.write("operations.json", [])
        cases = []

        fifo = self.root / "AGENTS.md"
        os.mkfifo(fifo)
        cases.append(fifo)
        for target in cases:
            for apply in (False, True):
                with self.subTest(kind="fifo", apply=apply):
                    before = dataset_snapshot(store, "operations.json")
                    with self.assertRaises(StewardError):
                        annotate(store, policy, self.root, apply)
                    self.assertEqual(dataset_snapshot(store, "operations.json"), before)
            target.unlink()

        directory = self.root / "AGENTS.md"
        directory.mkdir()
        for apply in (False, True):
            with self.subTest(kind="directory", apply=apply):
                before = dataset_snapshot(store, "operations.json")
                with self.assertRaises(StewardError):
                    annotate(store, policy, self.root, apply)
                self.assertEqual(dataset_snapshot(store, "operations.json"), before)
        directory.rmdir()

        outside = self.base / "outside-note"
        outside.write_text("outside")
        link = self.root / "AGENTS.md"
        link.symlink_to(outside)
        for apply in (False, True):
            with self.subTest(kind="link", apply=apply):
                before = dataset_snapshot(store, "operations.json")
                with self.assertRaises(StewardError):
                    annotate(store, policy, self.root, apply)
                self.assertEqual(dataset_snapshot(store, "operations.json"), before)
        link.unlink()

    def test_nested_state_is_not_a_maintainable_object_or_note_subtree(self):
        state_path = self.root / "nested-state"
        store = self.store(state_path)
        state_rule = {"path": str(state_path), "purpose": "错误授权 fixture", "kind": "temporary",
                      "allow_notes": True, "allow_quarantine": True, "retention_days": 0,
                      "recycle_bytes": 1024 * 1024, "directory_id": identity(state_path.stat())}
        policy = self.policy(extra_rules=[state_rule])
        names = ["host.json", "steward.sqlite3", ".lock"]
        store.target("host.json").write_bytes(b"{}\n")
        store.write("current.json", {})
        with store.lock():
            pass
        note_subtree = state_path / "notes"
        note_subtree.mkdir()
        before = {name: store.target(name).read_bytes() for name in names}
        operation_before = dataset_snapshot(store, "operations.json")

        for apply in (False, True):
            with self.subTest(action="note-state", apply=apply):
                with self.assertRaises(StewardError):
                    annotate(store, policy, state_path, apply)
            with self.subTest(action="note-subtree", apply=apply):
                with self.assertRaises(StewardError):
                    annotate(store, policy, note_subtree, apply)
            for name in names:
                with self.subTest(action="quarantine", name=name, apply=apply):
                    with self.assertRaises(StewardError):
                        quarantine(store, policy, store.target(name), apply)
        self.assertEqual({name: store.target(name).read_bytes() for name in names}, before)
        self.assertEqual(dataset_snapshot(store, "operations.json"), operation_before)
        self.assertFalse((state_path / ".recycle").exists())

    def test_restore_rejects_state_source_and_state_target_without_changes(self):
        operation_id = "a" * 32
        store = self.store()
        policy = self.policy()
        source = store.path / "source"
        source.write_bytes(b"state source")
        target = self.root / ".recycle" / operation_id / "source"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"recycled")
        operation = {"id": operation_id, "kind": "quarantine", "source": str(source),
                     "target": str(target), "identity": fingerprint(target), "status": "quarantined"}
        store.write("operations.json", [operation])
        before = dataset_snapshot(store, "operations.json")
        for apply in (False, True):
            with self.subTest(side="source", apply=apply), self.assertRaises(StewardError):
                restore(store, policy, operation_id, apply)
        self.assertTrue(source.exists())
        self.assertTrue(target.exists())
        self.assertEqual(dataset_snapshot(store, "operations.json"), before)

        state_path = self.root / ".recycle" / operation_id
        target_store = self.store(state_path)
        target_source = self.root / "target-source"
        target = state_path / target_source.name
        target.write_bytes(b"state target")
        target_operation = {"id": operation_id, "kind": "quarantine", "source": str(target_source),
                            "target": str(target), "identity": fingerprint(target), "status": "quarantined"}
        target_store.write("operations.json", [target_operation])
        target_before = dataset_snapshot(target_store, "operations.json")
        for apply in (False, True):
            with self.subTest(side="target", apply=apply), self.assertRaises(StewardError):
                restore(target_store, policy, operation_id, apply)
        self.assertFalse(target_source.exists())
        self.assertTrue(target.exists())
        self.assertEqual(dataset_snapshot(target_store, "operations.json"), target_before)

    def test_normal_quarantine_and_restore_still_work(self):
        store = self.store()
        policy = self.policy()
        source = self.root / "temporary"
        source.write_text("recover me")
        moved = quarantine(store, policy, source, True)["operation"]
        self.assertFalse(source.exists())
        self.assertTrue(Path(moved["target"]).exists())
        result = restore(store, policy, moved["id"], True)
        self.assertEqual(result["operation"]["status"], "restored")
        self.assertEqual(source.read_text(), "recover me")
        self.assertFalse(Path(moved["target"]).exists())


if __name__ == "__main__":
    unittest.main()
