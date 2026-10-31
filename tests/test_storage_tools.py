from collections import namedtuple
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

import steward
import storage_tools
from database import Database, SCHEMA_1_TABLE_STATEMENTS, SIDECAR_SUFFIXES
from policy import LEGACY_LIMIT_FIELDS, policy_digest, read_policy_with_evidence, validate
from sample_store import SampleStore
from state import Store, StewardError, decode, encode
from state_schema import read_current, read_operations
from storage_tools import (BUNDLE_FORMAT, BUNDLE_INCOMPLETE, BUNDLE_MANIFEST,
                           RESTORE_INCOMPLETE, backup_bundle, backup_database,
                           restore_bundle)


DiskUsage = namedtuple("DiskUsage", "total used free")


class BundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "观察 根目录"
        self.root.mkdir()
        (self.root / "资料 文件.txt").write_text("样例内容", encoding="utf-8")
        self.state = self.base / "本机 状态"
        self.store, self.policy = steward.initialize(self.state, [self.root], "完整备份测试")
        self.outside = self.base / "外部 备份"
        self.outside.mkdir()
        self.bundle = self.outside / "完整 备份"
        self.restored = self.base / "恢复 状态"
        self.populate()

    def populate(self):
        self.store.write("current.json", {"version": 1, "pending": [
            {"key": "待核验 事项", "reason": "保留事项", "observed_at": 1000.0}]})
        self.store.write("inventory.json", {"version": 1, "resources": {}})
        self.operations = []
        for index, status in enumerate(["planned", "quarantined", "restoring"]):
            self.operations.append({
                "id": f"{index + 1:032x}", "kind": "quarantine", "status": status,
                "source": os.path.normpath(str(self.base / f"旧 对象 {index}")),
                "target": os.path.normpath(str(self.base / f".recycle/对象 {index}")),
                "identity": {"id": f"dev:{index}", "size": 10 + index, "mtime": 1000 + index},
                "created_at": 1000.0 + index})
        self.store.write("operations.json", list(self.operations))
        samples = SampleStore(self.store)
        samples.start_run("run-1", dict(self.policy), steward.evidence_for(self.policy),
                          mode="once", started_at=1000.0)
        samples.append_sample(
            "run-1", observed_at=1000.0, monotonic_at=10.0, boot={"boot": 1},
            host={"system": "测试"}, sources={"cpu": {"available": True, "detail": {"value": 1}}},
            processes=[{"identity": "示例进程", "rss_bytes": 2048, "cpu_percent": 0.5}],
            sampling=dict(self.policy["sampling"]), last_complete_at=1000.0)
        samples.finish_run("run-1", stopped_at=1001.0, reason="once")
        self.original = self.store.export_data()
        self.current = read_current(self.store)
        self.operations_readback = read_operations(self.store)
        self.history = self.history_counts(self.store)

    @staticmethod
    def history_counts(store):
        connection = sqlite3.connect(store.database_path)
        try:
            return {table: connection.execute(
                f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in storage_tools.HISTORY_TABLES}
        finally:
            connection.close()

    def guarded_backup(self, destination=None, guard=None):
        destination = self.bundle if destination is None else Path(destination)
        with self.store.lock():
            policy = steward.refresh_policy_locked(self.store)
            self.policy = policy

            def policy_guard():
                steward.ensure_policy_locked(self.store, policy)

            return backup_bundle(self.store, policy, destination,
                                 guard if guard is not None else policy_guard)

    @staticmethod
    def tree_digest(root):
        result = []
        for path in sorted(Path(root).rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                result.append((relative, "symlink", os.readlink(path)))
            elif path.is_dir():
                result.append((relative, "dir"))
            else:
                result.append((relative, "file", hashlib.sha256(path.read_bytes()).hexdigest()))
        return result

    def manifest(self, root=None):
        root = self.bundle if root is None else Path(root)
        return json.loads((root / BUNDLE_MANIFEST).read_text(encoding="utf-8"))

    def rewrite_manifest(self, root, manifest):
        (Path(root) / BUNDLE_MANIFEST).write_text(
            json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

    def v1_store(self, name, schema=1):
        directory = self.base / name
        template = json.loads((PROJECT / "state/host.example.json").read_text(encoding="utf-8"))
        policy = dict(template, version=1, roots=[str(self.root)],
                      exclude_names=[".git", "cache"],
                      host={"system": platform.system(), "hostname": platform.node()})
        policy.pop("sampling", None)
        policy.pop("history", None)
        policy["limits"] = dict(template["limits"], scan_depth=7)
        self.assertEqual(set(policy["limits"]), LEGACY_LIMIT_FIELDS)
        validate(policy)
        store = Store(directory, policy["limits"])
        connection = sqlite3.connect(store.database_path)
        try:
            for statement in SCHEMA_1_TABLE_STATEMENTS:
                connection.execute(statement)
            connection.execute("PRAGMA user_version=1")
            connection.commit()
        finally:
            connection.close()
        store.write_bytes("host.json", encode(policy))
        store.write_bytes("adaptation.json", encode(
            {"source_version": "0.1.0", "removed_sections": [], "reason": "v1"}))
        guidance = directory / "guidance"
        guidance.mkdir()
        (guidance / "setup.md").write_text("v1 本机指导", encoding="utf-8")
        store.write("current.json", {"version": 1})
        store.write("inventory.json", {"version": 1, "resources": {}})
        store.write("operations.json", [])
        if schema == 2:
            database = store._database()
            database.upgrade_schema(apply=True, total_bytes=store.limits["total_bytes"],
                                    outside_bytes=store._database_outside(database))
        return store, policy

    def test_backup_bundle_creates_complete_directory_and_manifest(self):
        (self.state / "杂项 说明.txt").write_text("不纳入 bundle", encoding="utf-8")
        result = self.guarded_backup()

        self.assertEqual(result["status"], "bundle_created")
        self.assertFalse((self.bundle / BUNDLE_INCOMPLETE).exists())
        manifest = self.manifest()
        self.assertEqual(manifest["format"], BUNDLE_FORMAT)
        self.assertEqual(manifest["version"], 1)
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["tool_version"], steward.TOOL_VERSION)
        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["database"]["history"], self.history)
        self.assertEqual(manifest["database"]["export_sha256"],
                         hashlib.sha256(encode(self.original)).hexdigest())
        self.assertEqual(manifest["database"]["journal_mode"], "delete")
        self.assertEqual(manifest["database"]["integrity_check"], "ok")
        self.assertEqual(manifest["scope"]["other_entries"], ["杂项 说明.txt"])
        self.assertNotIn("杂项 说明.txt", [entry["path"] for entry in manifest["files"]])

        by_path = {entry["path"]: entry for entry in manifest["files"]}
        self.assertEqual(set(by_path) & {"steward.sqlite3", "host.json", "adaptation.json"},
                         {"steward.sqlite3", "host.json", "adaptation.json"})
        guidance = [path for path in by_path if path.startswith("guidance/")]
        self.assertEqual(len(guidance), manifest["scope"]["guidance_file_count"])
        self.assertGreaterEqual(len(guidance), 1)
        for relative, entry in by_path.items():
            payload = (self.bundle / relative).read_bytes()
            self.assertEqual(len(payload), entry["bytes"])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), entry["sha256"])
            self.assertEqual(entry["role"], {
                "steward.sqlite3": "database", "host.json": "configuration",
                "adaptation.json": "adaptation"}.get(relative, "guidance"))
        self.assertEqual((self.bundle / "host.json").read_bytes(),
                         (self.state / "host.json").read_bytes())
        self.assertEqual((self.bundle / "adaptation.json").read_bytes(),
                         (self.state / "adaptation.json").read_bytes())
        for suffix in SIDECAR_SUFFIXES:
            self.assertFalse((self.bundle / ("steward.sqlite3" + suffix)).exists())
        connection = sqlite3.connect(self.bundle / "steward.sqlite3")
        try:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        finally:
            connection.close()
        self.assertEqual(Database(self.bundle / "steward.sqlite3").export_data(), self.original)
        self.assertEqual(result["tool_version"], steward.TOOL_VERSION)

    def test_schema_one_and_v1_policy_bundle_round_trip(self):
        store, policy = self.v1_store("schema1 状态", schema=1)
        bundle = self.base / "schema1 备份"
        with store.lock():
            current = steward.refresh_policy_locked(store)
            result = backup_bundle(store, current, bundle,
                                   lambda: steward.ensure_policy_locked(store, current))
        self.assertEqual(result["schema_version"], 1)
        manifest = self.manifest(bundle)
        self.assertEqual(manifest["source"]["policy_version"], 1)
        self.assertEqual(manifest["database"]["history"], {})

        destination = self.base / "schema1 恢复"
        restored = restore_bundle(bundle, destination, apply=True)
        self.assertEqual(restored["status"], "restored")
        restored_store = Store(destination, current["limits"])
        self.assertEqual(restored_store.database_info()["schema_version"], 1)
        self.assertEqual(restored_store.export_data(), store.export_data())
        loaded, _ = read_policy_with_evidence(destination)
        self.assertEqual(dict(loaded), dict(current))
        self.assertEqual((destination / "host.json").read_bytes(),
                         (store.path / "host.json").read_bytes())

    def test_mixed_schema_two_with_v1_configuration_round_trip(self):
        store, _ = self.v1_store("混合 状态", schema=2)
        bundle = self.base / "混合 备份"
        with store.lock():
            current = steward.refresh_policy_locked(store)
            result = backup_bundle(store, current, bundle,
                                   lambda: steward.ensure_policy_locked(store, current))
        self.assertEqual(result["schema_version"], 2)
        destination = self.base / "混合 恢复"
        restore_bundle(bundle, destination, apply=True)
        restored_store = Store(destination, current["limits"])
        self.assertEqual(restored_store.database_info()["schema_version"], 2)
        loaded, _ = read_policy_with_evidence(destination)
        self.assertEqual(loaded["version"], 1)
        self.assertEqual(restored_store.export_data(), store.export_data())

    def test_operations_and_history_survive_bundle_and_restore(self):
        self.guarded_backup()
        result = restore_bundle(self.bundle, self.restored, apply=True)
        self.assertEqual(result["status"], "restored")
        store = Store(self.restored, self.policy["limits"])
        self.assertEqual(store.export_data(), self.original)
        self.assertEqual(read_current(store), self.current)
        self.assertEqual(read_operations(store), self.operations_readback)
        self.assertEqual([row["status"] for row in read_operations(store)],
                         ["planned", "quarantined", "restoring"])
        self.assertEqual(self.history_counts(store), self.history)
        history = SampleStore(store).query(0.0, 2000.0, process="示例进程")
        self.assertEqual(len(history["samples"]), 1)
        self.assertEqual(history["samples"][0]["processes"][0]["identity"], "示例进程")

    def test_backup_precheck_failures_leave_no_output(self):
        existing_file = self.outside / "已有 文件"
        existing_file.write_bytes("保留".encode("utf-8"))
        existing_dir = self.outside / "已有 空目录"
        existing_dir.mkdir()
        link = self.outside / "链接 备份"
        link.symlink_to(self.base / "不存在的目标")
        cases = [
            ("状态目录内", self.state / "内部 备份"),
            ("相对路径", Path("相对 备份")),
            ("父目录缺失", self.base / "不存在 的父目录" / "备份"),
            ("已有文件", existing_file),
            ("已有空目录", existing_dir),
            ("符号链接", link),
        ]
        for name, destination in cases:
            with self.subTest(name=name):
                with self.assertRaises(StewardError):
                    self.guarded_backup(destination)
        self.assertTrue(link.is_symlink())
        self.assertEqual(existing_file.read_bytes(), "保留".encode("utf-8"))
        self.assertEqual(list(existing_dir.iterdir()), [])
        self.assertEqual(set(path.name for path in self.outside.iterdir()),
                         {"链接 备份", "已有 文件", "已有 空目录"})
        self.assertFalse((PROJECT / "相对 备份").exists())

        missing_guidance = self.base / "无指导 状态"
        shutil.copytree(self.state, missing_guidance, symlinks=True,
                        ignore=shutil.ignore_patterns(".lock"))
        shutil.rmtree(missing_guidance / "guidance")
        store = Store(missing_guidance, self.policy["limits"])
        with self.assertRaisesRegex(StewardError, "guidance"):
            with store.lock():
                current = steward.refresh_policy_locked(store)
                backup_bundle(store, current, self.outside / "无指导 备份",
                              lambda: steward.ensure_policy_locked(store, current))
        self.assertFalse((self.outside / "无指导 备份").exists())

    def test_backup_requires_sqlite_database(self):
        store, _ = self.v1_store("无数据库 状态", schema=1)
        store.database_path.unlink()
        with self.assertRaisesRegex(StewardError, "SQLite 状态库不存在"):
            with store.lock():
                current = steward.refresh_policy_locked(store)
                backup_bundle(store, current, self.outside / "无数据库 备份",
                              lambda: steward.ensure_policy_locked(store, current))
        self.assertFalse((self.outside / "无数据库 备份").exists())

    def test_space_and_time_budget_before_output(self):
        with patch("storage_tools.shutil.disk_usage", return_value=DiskUsage(1, 1, 0)):
            with self.assertRaisesRegex(StewardError, "空间不足"):
                self.guarded_backup()
        self.assertFalse(self.bundle.exists())

        with patch("storage_tools.time.monotonic", side_effect=[0.0] + [100.0] * 30):
            with self.assertRaisesRegex(StewardError, "时间预算"):
                self.guarded_backup()
        self.assertFalse(self.bundle.exists())

    def test_time_budget_after_write_keeps_marker_without_manifest(self):
        offset = {"value": 0.0}
        real_monotonic = time.monotonic
        original = storage_tools.backup_database

        def fake_monotonic():
            return real_monotonic() + offset["value"]

        def delayed_backup(store, destination, *, deadline=None):
            result = original(store, destination, deadline=deadline)
            offset["value"] = 3600.0
            return result

        with patch("storage_tools.time.monotonic", side_effect=fake_monotonic), \
                patch("storage_tools.backup_database", side_effect=delayed_backup):
            with self.assertRaisesRegex(StewardError, "时间预算"):
                self.guarded_backup()
        self.assertTrue((self.bundle / BUNDLE_INCOMPLETE).is_file())
        self.assertFalse((self.bundle / BUNDLE_MANIFEST).exists())
        with self.assertRaisesRegex(StewardError, "未完成标记"):
            restore_bundle(self.bundle, self.restored)

    def test_interruptions_leave_marker_and_restore_rejects(self):
        original_write = storage_tools._write_output

        def fail_host(path, payload):
            if Path(path).name == "host.json":
                raise OSError("注入 host.json 写入失败")
            return original_write(path, payload)

        def source_change_guard():
            self.store.write_bytes("host.json", encode(dict(self.policy, purpose="备份期间改写")))

        scenarios = [
            ("host 写入失败", {"write": fail_host}, (OSError, StewardError)),
            ("数据库备份失败", {"backup": StewardError("注入数据库备份失败")}, StewardError),
            ("清单写入失败", {"manifest": OSError("注入清单写入失败")}, OSError),
            ("源配置变化", {"guard": source_change_guard}, StewardError),
        ]
        for name, setup, expected in scenarios:
            with self.subTest(name=name):
                destination = self.outside / ("不完整 " + name)
                patches = []
                if "write" in setup:
                    patches.append(patch("storage_tools._write_output", side_effect=setup["write"]))
                if "backup" in setup:
                    patches.append(patch("storage_tools.backup_database", side_effect=setup["backup"]))
                if "manifest" in setup:
                    patches.append(patch("storage_tools._write_manifest", side_effect=setup["manifest"]))
                try:
                    for item in patches:
                        item.start()
                    with self.assertRaises(expected):
                        self.guarded_backup(destination, setup.get("guard"))
                finally:
                    for item in reversed(patches):
                        item.stop()
                self.assertTrue((destination / BUNDLE_INCOMPLETE).is_file())
                self.assertFalse((destination / BUNDLE_MANIFEST).exists())
                target = self.base / ("拒绝恢复 " + name)
                with self.assertRaises(StewardError):
                    restore_bundle(destination, target)
                self.assertFalse(target.exists())

    def test_guidance_change_during_backup_keeps_marker(self):
        original = storage_tools.backup_database

        def changed_guidance(store, destination, *, deadline=None):
            result = original(store, destination, deadline=deadline)
            guidance = store.path / "guidance" / "setup.md"
            guidance.write_text(guidance.read_text(encoding="utf-8") + "变更",
                                encoding="utf-8")
            return result

        with patch("storage_tools.backup_database", side_effect=changed_guidance):
            with self.assertRaisesRegex(StewardError, "本机指导已变化"):
                self.guarded_backup()
        self.assertTrue((self.bundle / BUNDLE_INCOMPLETE).is_file())
        self.assertFalse((self.bundle / BUNDLE_MANIFEST).exists())

    def test_restore_preview_is_read_only_and_apply_reads_back(self):
        self.guarded_backup()
        bundle_before = self.tree_digest(self.bundle)
        base_before = sorted(path.name for path in self.base.iterdir())
        preview = restore_bundle(self.bundle, self.restored)
        self.assertEqual(preview["status"], "restore_plan")
        self.assertFalse(preview["applied"])
        self.assertTrue(preview["verified"])
        self.assertFalse(self.restored.exists())
        self.assertEqual(self.tree_digest(self.bundle), bundle_before)
        self.assertEqual(sorted(path.name for path in self.base.iterdir()), base_before)

        applied = restore_bundle(self.bundle, self.restored, apply=True)
        self.assertEqual(applied["status"], "restored")
        self.assertTrue(applied["applied"])
        self.assertFalse((self.restored / RESTORE_INCOMPLETE).exists())
        self.assertEqual(self.tree_digest(self.bundle), bundle_before)
        self.assertEqual(applied["readback"]["operations_count"], 3)

        store, policy = steward.load(self.restored)
        report = steward.status_report(store, policy)
        self.assertEqual(report["storage"]["schema_version"], 2)
        self.assertEqual(report["policy_version"], 2)
        self.assertEqual(report["pending"][0]["key"], "待核验 事项")
        self.assertEqual(report["operations"], self.operations_readback[-20:])
        history = SampleStore(store).query(0.0, 2000.0)
        self.assertEqual(len(history["samples"]), 1)
        self.assertEqual(history["samples"][0]["observed_at"], 1000.0)

    def test_unlisted_bundle_files_are_reported_not_restored(self):
        self.guarded_backup()
        extra = self.base / "额外 备份"
        shutil.copytree(self.bundle, extra)
        (extra / "未列出.txt").write_text("额外", encoding="utf-8")
        preview = restore_bundle(extra, self.restored)
        self.assertEqual(preview["unlisted_files"], ["未列出.txt"])
        restore_bundle(extra, self.restored, apply=True)
        self.assertFalse((self.restored / "未列出.txt").exists())

    def test_restore_rejects_tampered_bundles(self):
        self.guarded_backup()

        def copy(name):
            destination = self.base / ("篡改 " + name)
            shutil.copytree(self.bundle, destination)
            return destination

        def tamper_manifest(bundle, mutate):
            manifest = self.manifest(bundle)
            mutate(manifest)
            self.rewrite_manifest(bundle, manifest)

        def missing_manifest(bundle):
            (bundle / BUNDLE_MANIFEST).unlink()

        def missing_host(bundle):
            (bundle / "host.json").unlink()

        def digest_mismatch(bundle):
            target = bundle / "guidance" / "setup.md"
            payload = bytearray(target.read_bytes())
            payload[0] ^= 1
            target.write_bytes(bytes(payload))

        def version_two(bundle):
            tamper_manifest(bundle, lambda manifest: manifest.update(version=2))

        def schema_three(bundle):
            tamper_manifest(bundle, lambda manifest: manifest["database"].update(schema_version=3))

        def truncated_database(bundle):
            database = bundle / "steward.sqlite3"
            payload = database.read_bytes()[:100]
            database.write_bytes(payload)

            def mutate(manifest):
                for entry in manifest["files"]:
                    if entry["path"] == "steward.sqlite3":
                        entry["bytes"] = len(payload)
                        entry["sha256"] = hashlib.sha256(payload).hexdigest()
            tamper_manifest(bundle, mutate)

        def marker_present(bundle):
            (bundle / BUNDLE_INCOMPLETE).write_text("{}", encoding="utf-8")

        def escaping_path(bundle):
            tamper_manifest(bundle, lambda manifest: manifest["files"].append(
                {"path": "../逃逸", "role": "guidance", "bytes": 0, "sha256": "0" * 64}))

        def duplicate_path(bundle):
            tamper_manifest(bundle, lambda manifest: manifest["files"].append(
                dict(manifest["files"][1])))

        def symlink_parent(bundle):
            guidance = bundle / "guidance"
            real = bundle / "guidance-real"
            guidance.rename(real)
            guidance.symlink_to(real, target_is_directory=True)

        def sidecar(bundle):
            (bundle / ("steward.sqlite3-wal")).write_bytes(b"")

        cases = [
            ("清单缺失", missing_manifest),
            ("文件缺失", missing_host),
            ("摘要不符", digest_mismatch),
            ("清单版本", version_two),
            ("schema 版本", schema_three),
            ("数据库截断", truncated_database),
            ("未完成标记", marker_present),
            ("路径逃逸", escaping_path),
            ("路径重复", duplicate_path),
            ("符号链接父目录", symlink_parent),
            ("数据库伴随文件", sidecar),
        ]
        for name, mutate in cases:
            with self.subTest(name=name):
                bundle = copy(name)
                mutate(bundle)
                target = self.base / ("拒绝 " + name)
                with self.assertRaises(StewardError):
                    restore_bundle(bundle, target)
                self.assertFalse(target.exists())
                with self.assertRaises(StewardError):
                    restore_bundle(bundle, target, apply=True)
                self.assertFalse(target.exists())

        with self.assertRaises(StewardError):
            restore_bundle(Path("相对 备份"), self.base / "相对 bundle 目标")
        with self.assertRaises(StewardError):
            restore_bundle(self.base / "不存在的 bundle", self.base / "缺失 bundle 目标")
        outside_bundle = self.base / "非规范 bundle"
        shutil.copytree(self.bundle, outside_bundle)
        link = self.base / "bundle 链接"
        link.symlink_to(outside_bundle, target_is_directory=True)
        with self.assertRaises(StewardError):
            restore_bundle(link, self.base / "链接 bundle 目标")

    def test_restore_refuses_existing_targets_and_keeps_everything(self):
        self.guarded_backup()
        bundle_before = self.tree_digest(self.bundle)
        empty = self.base / "已有 空目录"
        empty.mkdir()
        existing_file = self.base / "已有 文件"
        existing_file.write_bytes("保留".encode("utf-8"))
        non_empty = self.base / "已有 非空目录"
        non_empty.mkdir()
        (non_empty / "内容.txt").write_text("保留", encoding="utf-8")
        for name, target, snapshot in (
                ("空目录", empty, self.tree_digest(empty)),
                ("文件", existing_file, existing_file.read_bytes()),
                ("非空目录", non_empty, self.tree_digest(non_empty))):
            with self.subTest(name=name):
                with self.assertRaisesRegex(StewardError, "尚不存在"):
                    restore_bundle(self.bundle, target, apply=True)
                if name == "文件":
                    self.assertEqual(target.read_bytes(), snapshot)
                else:
                    self.assertEqual(self.tree_digest(target), snapshot)
                self.assertEqual(self.tree_digest(self.bundle), bundle_before)
                with self.assertRaises(StewardError):
                    restore_bundle(self.bundle, target)
        inside_bundle = self.bundle / "恢复 目标"
        with self.assertRaisesRegex(StewardError, "bundle 目录内"):
            restore_bundle(self.bundle, inside_bundle)
        self.assertFalse(inside_bundle.exists())
        inside_source = self.state / "恢复 目标"
        with self.assertRaisesRegex(StewardError, "来源状态目录"):
            restore_bundle(self.bundle, inside_source)
        self.assertFalse(inside_source.exists())

    def test_restore_destination_cannot_contain_observation_root(self):
        outer = self.base / "外部 根"
        nested = outer / "内层 根目录"
        nested.mkdir(parents=True)
        store, policy = steward.initialize(self.base / "嵌套 状态", [nested], "嵌套测试")
        bundle = self.base / "嵌套 备份"
        with store.lock():
            current = steward.refresh_policy_locked(store)
            backup_bundle(store, current, bundle,
                          lambda: steward.ensure_policy_locked(store, current))
        shutil.rmtree(outer)
        with self.assertRaisesRegex(StewardError, "观察根目录"):
            restore_bundle(bundle, outer)

    def test_restore_space_and_time_checks_write_nothing(self):
        self.guarded_backup()
        with patch("storage_tools.shutil.disk_usage", return_value=DiskUsage(1, 1, 0)):
            with self.assertRaisesRegex(StewardError, "空间不足"):
                restore_bundle(self.bundle, self.restored, apply=True)
        self.assertFalse(self.restored.exists())
        with patch("storage_tools.time.monotonic", side_effect=[0.0] + [100.0] * 30):
            with self.assertRaisesRegex(StewardError, "时间预算"):
                restore_bundle(self.bundle, self.restored)
        self.assertFalse(self.restored.exists())

    def test_restore_copy_and_rename_failures_keep_staging(self):
        self.guarded_backup()

        original_copy = storage_tools._copy_verified

        def failing_copy(source, destination, expected_bytes, expected_sha256):
            if Path(source).name == "steward.sqlite3":
                raise OSError("注入复制失败")
            return original_copy(source, destination, expected_bytes, expected_sha256)

        for name, patcher, message in (
                ("复制失败", patch("storage_tools._copy_verified", side_effect=failing_copy), "复制失败"),
                ("发布失败", patch("storage_tools.os.rename", side_effect=OSError("注入发布失败")), "发布失败")):
            with self.subTest(name=name):
                target = self.base / ("未发布 " + name)
                with patcher:
                    with self.assertRaisesRegex(StewardError, message) as caught:
                        restore_bundle(self.bundle, target, apply=True)
                self.assertFalse(target.exists())
                staging = list(self.base.glob(f".{target.name}.restoring-*"))
                self.assertEqual(len(staging), 1)
                self.assertIn(str(staging[0]), str(caught.exception))
                marker = (staging[0] / RESTORE_INCOMPLETE).is_file()
                self.assertEqual(marker, name == "复制失败")
                shutil.rmtree(staging[0])

    def test_publish_readback_failure_diagnoses_and_keeps_target(self):
        self.guarded_backup()
        failure = OSError("注入发布后读回失败")
        stderr = io.StringIO()
        with patch("storage_tools.read_operations", side_effect=failure), \
                redirect_stderr(stderr):
            with self.assertRaises(OSError) as caught:
                restore_bundle(self.bundle, self.restored, apply=True)
        self.assertIs(caught.exception, failure)
        diagnostic = json.loads(stderr.getvalue())
        self.assertEqual(diagnostic["status"], "restore_incomplete")
        self.assertEqual(diagnostic["phase"], "datasets_readback")
        self.assertEqual(diagnostic["destination"], str(self.restored))
        self.assertTrue((self.restored / "steward.sqlite3").is_file())
        self.assertFalse((self.restored / RESTORE_INCOMPLETE).exists())

    def test_host_identity_and_allow_foreign_host(self):
        self.guarded_backup()
        bundle = self.base / "异主机 备份"
        shutil.copytree(self.bundle, bundle)
        host_path = bundle / "host.json"
        policy = json.loads(host_path.read_text(encoding="utf-8"))
        policy["host"] = {"system": policy["host"]["system"], "hostname": "另一台 主机"}
        payload = json.dumps(policy, ensure_ascii=False).encode("utf-8")
        host_path.write_bytes(payload)
        manifest = self.manifest(bundle)
        for entry in manifest["files"]:
            if entry["path"] == "host.json":
                entry["bytes"] = len(payload)
                entry["sha256"] = hashlib.sha256(payload).hexdigest()
        manifest["source"]["host"] = dict(policy["host"])
        manifest["source"]["policy_digest"] = policy_digest(policy)
        manifest["source"]["policy_source_digest"] = hashlib.sha256(payload).hexdigest()
        self.rewrite_manifest(bundle, manifest)

        with self.assertRaisesRegex(StewardError, "其他主机"):
            restore_bundle(bundle, self.restored)
        self.assertFalse(self.restored.exists())
        result = restore_bundle(bundle, self.restored, allow_foreign_host=True, apply=True)
        self.assertEqual(result["status"], "restored")
        self.assertFalse(result["host_identity_match"])
        self.assertEqual((self.restored / "host.json").read_bytes(), payload)

    def test_formal_cli_backup_bundle_and_restore_bundle(self):
        backup = self.cli("backup-bundle", "--state", str(self.state),
                          "--output", str(self.bundle))
        self.assertEqual(backup.returncode, 0, backup.stderr)
        self.assertEqual(json.loads(backup.stdout)["status"], "bundle_created")
        self.assertFalse((self.bundle / BUNDLE_INCOMPLETE).exists())

        preview = self.cli("restore-bundle", "--bundle", str(self.bundle),
                           "--state", str(self.restored))
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertEqual(json.loads(preview.stdout)["status"], "restore_plan")
        self.assertFalse(self.restored.exists())

        applied = self.cli("restore-bundle", "--bundle", str(self.bundle),
                           "--state", str(self.restored), "--apply")
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(json.loads(applied.stdout)["status"], "restored")

        status = self.cli("status", "--state", str(self.restored))
        self.assertEqual(status.returncode, 0, status.stderr)
        report = json.loads(status.stdout)
        self.assertEqual(report["policy_version"], 2)
        self.assertEqual(report["storage"]["schema_version"], 2)
        self.assertEqual(report["pending"][0]["key"], "待核验 事项")
        self.assertEqual(len(report["operations"]), 3)

        samples = self.cli("samples", "--state", str(self.restored),
                           "--since", "0", "--until", "2000")
        self.assertEqual(samples.returncode, 0, samples.stderr)
        self.assertEqual(len(json.loads(samples.stdout)["samples"]), 1)

        exported = self.cli("export", "--state", str(self.restored), "--dataset", "operations")
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertEqual(json.loads(exported.stdout)["data"], self.operations_readback)

        existing = self.base / "CLI 已有 目录"
        existing.mkdir()
        refused = self.cli("restore-bundle", "--bundle", str(self.bundle),
                           "--state", str(existing), "--apply")
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(list(existing.iterdir()), [])

    def cli(self, *arguments):
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run(
            [sys.executable, "-B", str(PROJECT / "tools/steward.py"), *arguments],
            cwd="/", capture_output=True, text=True, timeout=120, env=environment)

    def test_existing_backup_database_shape_and_scope_unchanged(self):
        destination = self.base / "旧式 SQLite 备份"
        with self.store.lock():
            result = backup_database(self.store, destination)
        self.assertEqual(set(result), {"status", "output", "bytes", "verified", "scope"})
        self.assertEqual(result["status"], "backed_up")
        self.assertTrue(result["verified"])
        self.assertEqual(result["scope"],
                         "SQLite 一致快照；host.json 与本机指导需分别保存")
        self.assertEqual(result["bytes"], destination.stat().st_size)
        self.assertEqual(Database(destination).export_data(), self.original)


if __name__ == "__main__":
    unittest.main()
