import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
import state
import steward
from state import Store, StewardError, decode, encode
from steward import initialize, load


class InitializationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def _snapshot(self, directory):
        result = {}
        for path in sorted(directory.rglob("*")):
            if path.is_file() and not path.is_symlink():
                result[str(path.relative_to(directory))] = path.read_bytes()
        return result

    def _guidance(self):
        source = PROJECT / "guidance"
        return {"guidance/" + str(path.relative_to(source)): path.read_bytes()
                for path in sorted(source.rglob("*.md"))}

    def _payloads(self, store, policy):
        payloads = {"steward.sqlite3": Store.empty_database_bytes()}
        payloads.update(self._guidance())
        payloads["adaptation.json"] = encode(
            {"source_version": "0.2.0", "removed_sections": [],
             "reason": "保留通用说明；具体能力和权限以观测结果、本机约定为准"})
        payloads["host.json"] = encode(policy)
        return payloads

    def _assert_payloads(self, store, policy):
        for name, payload in self._payloads(store, policy).items():
            if name == "steward.sqlite3":
                self.assertTrue(store.database_exists())
                store.check_database()
                self.assertEqual(store.database_info()["datasets"], {})
            else:
                self.assertEqual(store.target(name).read_bytes(), payload)

    def _assert_only_lock(self, directory):
        self.assertEqual(set(self._snapshot(directory)), {".lock"})

    def _template_limits(self, **changes):
        template_path = PROJECT / "state/host.example.json"
        template = decode(steward.read_regular_bytes(template_path, 32768))
        limits = dict(template["limits"])
        limits.update(changes)
        replacement = encode(dict(template, limits=limits))
        original = steward.read_regular_bytes

        def reader(path, limit):
            if Path(path) == template_path:
                return replacement
            return original(path, limit)

        return patch("steward.read_regular_bytes", side_effect=reader)

    def test_initialization_accepts_fresh_and_lock_only_directories(self):
        for label, lock_bytes in [("fresh", None), ("lock", b"lock sentinel")]:
            with self.subTest(directory=label):
                directory = self.base / label
                if lock_bytes is not None:
                    directory.mkdir()
                    (directory / ".lock").write_bytes(lock_bytes)
                store, policy = initialize(directory, [self.root], "初始化测试")
                self._assert_payloads(store, policy)
                loaded_store, loaded_policy = load(directory)
                self.assertEqual(loaded_store.path, store.path)
                self.assertEqual(loaded_policy, policy)
                if lock_bytes is not None:
                    self.assertEqual((directory / ".lock").read_bytes(), lock_bytes)

    def test_template_limits_keys_match_contract(self):
        template = decode(steward.read_regular_bytes(PROJECT / "state/host.example.json", 32768))
        self.assertEqual(set(template["limits"]), steward.LIMIT_FIELDS,
                         "模板 limits 键集与工具契约不一致，init 会拒绝自己生成的约定")

    def test_fresh_state_supports_immediate_status_and_inventory(self):
        directory = self.base / "first-run"
        initialize(directory, [self.root], "首跑衔接")
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        outputs = {}
        for action in ["status", "inventory"]:
            with self.subTest(action=action):
                result = subprocess.run([sys.executable, str(PROJECT / "tools/steward.py"), action, "--state", str(directory)],
                                        cwd="/", capture_output=True, text=True, timeout=5, env=environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                outputs[action] = json.loads(result.stdout)
        self.assertEqual(outputs["status"]["pending_count"], 0)
        self.assertEqual(outputs["status"]["directory_count"], 0)
        self.assertEqual(outputs["status"]["change_count"], 0)
        self.assertEqual(outputs["status"]["recent_changes"], [])
        self.assertEqual(outputs["status"]["operations"], [])
        self.assertEqual(outputs["inventory"]["status"], "not_registered")
        self.assertEqual(outputs["inventory"]["total"], 0)

    def test_missing_host_preserves_existing_state_byte_for_byte(self):
        directory = self.base / "existing"
        directory.mkdir()
        old = {
            ".lock": b"old lock",
            "steward.sqlite3": Store.empty_database_bytes(),
            "inventory.json": b"old inventory\x00",
            "current.json": b"old current",
            "operations.json": b"old operations",
            "arbitrary.bin": b"arbitrary bytes",
            "guidance/setup.md": "本机 guidance 原文".encode(),
        }
        for name, payload in old.items():
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        before = self._snapshot(directory)
        with self.assertRaisesRegex(StewardError, "不覆盖"):
            initialize(directory, [self.root], "不能重置")
        self.assertEqual(self._snapshot(directory), before)

    def test_public_cli_reinit_preserves_old_knowledge_and_reports_traceback(self):
        directory = self.base / "cli-state"
        store, _ = initialize(directory, [self.root], "第一次初始化")
        old = {
            "steward.sqlite3": Store.empty_database_bytes(),
            "guidance/setup.md": b"old local guidance",
        }
        for name, payload in old.items():
            target = store.target(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        store.target("host.json").unlink()
        before = self._snapshot(directory)
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        missing = subprocess.run([sys.executable, str(PROJECT / "tools/steward.py"), "status", "--state", str(directory)],
                                 cwd="/", capture_output=True, text=True, timeout=5, env=environment)
        self.assertEqual(missing.returncode, 1, missing.stderr)
        self.assertIn("Traceback", missing.stderr)
        self.assertIn("恢复", missing.stderr)
        self.assertNotIn("请先 init", missing.stderr)
        result = subprocess.run(
            [sys.executable, str(PROJECT / "tools/steward.py"), "init", "--state", str(directory),
             "--root", str(self.root), "--purpose", "不应覆盖"],
            cwd=str(PROJECT), capture_output=True, text=True, timeout=5, env=environment)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Traceback", result.stderr)
        self.assertIn("初始化仅接受空状态目录", result.stderr)
        self.assertIn("不覆盖", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self._snapshot(directory), before)

    def test_payload_prechecks_reject_single_file_and_total_capacity(self):
        file_bytes = max(8192, max(len(payload) for payload in self._guidance().values()))
        cases = [
            ("single", {"file_bytes": file_bytes}, "x" * (file_bytes + 1), "单文件预算"),
            ("total", {"total_bytes": 1}, "容量预检", "状态总容量不足"),
        ]
        for label, limits, purpose, message in cases:
            with self.subTest(kind=label):
                directory = self.base / ("preflight-" + label)
                with self._template_limits(**limits), self.assertRaisesRegex(StewardError, message):
                    initialize(directory, [self.root], purpose)
                self._assert_only_lock(directory)
                self.assertFalse(list(directory.rglob(".writing-*")))

    def test_guidance_write_failure_rolls_back_exactly_and_can_retry(self):
        directory = self.base / "retry-state"
        original = Store.write_bytes

        def fail_guidance(store, name, payload, **kwargs):
            if name == "guidance/setup.md":
                raise OSError("guidance write fixture failure")
            return original(store, name, payload, **kwargs)

        with patch.object(Store, "write_bytes", new=fail_guidance):
            with self.assertRaisesRegex(StewardError, "本次创建内容已回滚"):
                initialize(directory, [self.root], "可重试初始化")
        self._assert_only_lock(directory)
        self.assertFalse((directory / "guidance").exists())
        self.assertFalse(list(directory.rglob(".writing-*")))
        store, policy = initialize(directory, [self.root], "可重试初始化")
        self._assert_payloads(store, policy)

    def test_directory_fsync_failure_after_host_link_uses_created_metadata_for_rollback(self):
        directory = self.base / "fsync-state"
        original_fsync = state.os.fsync
        directory_fsyncs_after_host = []

        def fail_after_host(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode) and (directory / "host.json").exists():
                directory_fsyncs_after_host.append(fd)
                raise OSError("directory fsync fixture failure")
            return original_fsync(fd)

        with patch("state.os.fsync", side_effect=fail_after_host):
            with self.assertRaisesRegex(StewardError, "本次创建内容已回滚"):
                initialize(directory, [self.root], "目录同步失败")
        self.assertTrue(directory_fsyncs_after_host)
        self._assert_only_lock(directory)
        self.assertFalse((directory / "host.json").exists())
        with self.assertRaisesRegex(StewardError, "缺少本机约定"):
            load(directory)

    def test_foreign_same_name_is_never_overwritten_or_removed(self):
        for name in ("steward.sqlite3", "host.json"):
            with self.subTest(name=name):
                directory = self.base / ("foreign-" + name.split(".")[0])
                foreign = ("foreign " + name).encode()
                original = Store.write_bytes

                def publish_with_foreign(store, relative, payload, **kwargs):
                    if relative == name:
                        target = store.target(relative)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(foreign)
                    return original(store, relative, payload, **kwargs)

                with patch.object(Store, "write_bytes", new=publish_with_foreign):
                    with self.assertRaises(StewardError) as caught:
                        initialize(directory, [self.root], "外来文件竞争")
                self.assertEqual((directory / name).read_bytes(), foreign)
                self.assertFalse(list(directory.rglob(".writing-*")))
                if name == "steward.sqlite3":
                    self.assertEqual(set(self._snapshot(directory)), {".lock", name})
                else:
                    self.assertTrue((directory / "adaptation.json").exists())
                    self.assertTrue((directory / "steward.sqlite3").exists())
                    self.assertTrue((directory / "guidance").is_dir())
                    self.assertIn("残留", str(caught.exception))

    def test_external_rewrite_stops_rollback_and_preserves_uncleaned_files(self):
        directory = self.base / "rewrite-state"
        original = Store.write_bytes

        def rewrite_then_fail(store, name, payload, **kwargs):
            result = original(store, name, payload, **kwargs)
            if name == "guidance/inventory.md":
                store.target(name).write_bytes(b"external rewrite survives\n")
            if name == "guidance/patrol.md":
                raise OSError("later guidance write failure")
            return result

        with patch.object(Store, "write_bytes", new=rewrite_then_fail):
            with self.assertRaisesRegex(StewardError, "残留") as caught:
                initialize(directory, [self.root], "外部改写")
        self.assertIn("guidance/inventory.md", str(caught.exception))
        self.assertEqual((directory / "guidance/inventory.md").read_bytes(), b"external rewrite survives\n")
        self.assertTrue((directory / "steward.sqlite3").exists())
        self.assertFalse((directory / "guidance/patrol.md").exists())
        self.assertFalse((directory / "adaptation.json").exists())
        self.assertFalse((directory / "host.json").exists())
        self.assertTrue((directory / "guidance").is_dir())
        self.assertFalse(list(directory.rglob(".writing-*")))

    def test_host_cleanup_permission_error_keeps_other_complete_payloads_and_reports_residual(self):
        directory = self.base / "permission-state"
        original_fsync = state.os.fsync
        published = {}

        def fail_after_host(store, name, payload, **kwargs):
            result = original_write(store, name, payload, **kwargs)
            published[name] = payload
            return result

        original_write = Store.write_bytes

        def fail_directory_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode) and (directory / "host.json").exists():
                raise OSError("directory fsync fixture failure")
            return original_fsync(fd)

        original_unlink = state.Path.unlink

        def refuse_host_cleanup(path, *args, **kwargs):
            if path == directory / "host.json":
                raise PermissionError("host cleanup fixture denial")
            return original_unlink(path, *args, **kwargs)

        with patch.object(Store, "write_bytes", new=fail_after_host), \
             patch("state.os.fsync", side_effect=fail_directory_fsync), \
             patch("state.Path.unlink", new=refuse_host_cleanup):
            with self.assertRaisesRegex(StewardError, "残留") as caught:
                initialize(directory, [self.root], "清理权限失败")
        self.assertIn("host.json", str(caught.exception))
        for name, payload in published.items():
            self.assertEqual((directory / name).read_bytes(), payload)
        host = directory / "host.json"
        self.assertTrue(host.exists())
        self.assertEqual([row["path"] for row in decode(host.read_bytes())["roots"]], [str(self.root)])
        load(directory)
        self.assertFalse(list(directory.rglob(".writing-*")))

    def test_oversized_host_is_rejected_before_publication_and_load_has_no_invalid_host(self):
        directory = self.base / "oversized-host"
        with self.assertRaisesRegex(StewardError, "host.json"):
            initialize(directory, [self.root], "x" * 33000)
        self._assert_only_lock(directory)
        self.assertFalse((directory / "host.json").exists())
        with self.assertRaisesRegex(StewardError, "缺少本机约定"):
            load(directory)


if __name__ == "__main__":
    unittest.main()
