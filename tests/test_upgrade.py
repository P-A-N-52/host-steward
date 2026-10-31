from contextlib import redirect_stderr
import copy
import hashlib
import io
import json
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
from database import Database, SCHEMA_1_TABLE_STATEMENTS
from history_config import DEFAULT_HISTORY
from policy import LEGACY_LIMIT_FIELDS, convert_v1_policy, read_policy_with_evidence, validate
from state import StewardError, Store, encode
from storage_tools import upgrade_state


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "观察 根目录"
        self.root.mkdir()
        template = json.loads((PROJECT / "state/host.example.json").read_text(encoding="utf-8"))
        self.policy = dict(template, version=1, roots=[str(self.root)], exclude_names=[".git", "cache"],
                           host={"system": platform.system(), "hostname": platform.node()},
                           extension={"keep": [1, 2, 3]})
        self.policy.pop("sampling", None)
        self.policy.pop("history", None)
        self.policy["limits"] = dict(template["limits"], scan_depth=7)
        self.assertEqual(set(self.policy["limits"]), LEGACY_LIMIT_FIELDS)
        validate(self.policy)
        self.store = Store(self.base / "state", self.policy["limits"])
        connection = sqlite3.connect(self.store.database_path)
        try:
            for statement in SCHEMA_1_TABLE_STATEMENTS:
                connection.execute(statement)
            connection.execute("PRAGMA user_version=1")
            connection.commit()
        finally:
            connection.close()
        self.raw_host = json.dumps(self.policy, ensure_ascii=False, indent=2).encode("utf-8")
        self.store.write_bytes("host.json", self.raw_host)
        self.store.write("current.json", {"version": 1, "pending": [{"key": "keep", "reason": "保留事项"}]})
        self.store.write("inventory.json", {"version": 1, "resources": {}})
        self.store.write("operations.json", [])
        self.original = self.store.export_data()
        self.backup = self.base / "upgrade-backup"

    def schema(self):
        return self.store.database_info()["schema_version"]

    def digest(self):
        return hashlib.sha256(self.store.database_path.read_bytes()).hexdigest()

    def test_preview_does_not_change_state_or_create_backup(self):
        before = self.digest()
        result = upgrade_state(self.store, self.policy, str(self.backup))
        self.assertEqual(result["status"], "upgrade_plan")
        self.assertFalse(result["applied"])
        self.assertEqual(result["plan"]["database"]["from_version"], 1)
        self.assertEqual(result["plan"]["configuration"]["to_version"], 2)
        self.assertEqual(self.schema(), 1)
        self.assertEqual(self.digest(), before)
        self.assertFalse(self.backup.exists())
        self.assertEqual(self.store.target("host.json").read_bytes(), self.raw_host)

    def test_apply_requires_fresh_absolute_external_backup(self):
        for destination in [None, "relative", str(self.store.path / "backup")]:
            with self.subTest(destination=destination):
                with self.assertRaises(StewardError):
                    upgrade_state(self.store, self.policy, destination, apply=True)
                self.assertEqual(self.schema(), 1)
                self.assertEqual(self.store.target("host.json").read_bytes(), self.raw_host)
        self.backup.mkdir()
        marker = self.backup / "keep"
        marker.write_bytes(b"do not overwrite")
        with self.assertRaises(FileExistsError):
            upgrade_state(self.store, self.policy, str(self.backup), apply=True)
        self.assertEqual(marker.read_bytes(), b"do not overwrite")
        self.assertEqual(self.schema(), 1)

    def test_upgrade_preserves_source_backup_and_independent_dataset_readback(self):
        result = upgrade_state(self.store, self.policy, str(self.backup), apply=True)
        self.assertEqual(result["status"], "upgraded")
        self.assertEqual(self.schema(), 2)
        expected = convert_v1_policy(self.policy)
        loaded, evidence = read_policy_with_evidence(self.store.path)
        self.assertEqual(dict(loaded), expected)
        self.assertEqual(evidence["policy_version"], 2)
        self.assertEqual(loaded["extension"], self.policy["extension"])
        self.assertEqual(loaded["history"], DEFAULT_HISTORY)
        self.assertEqual(loaded["limits"]["total_bytes"], self.policy["limits"]["total_bytes"])
        self.assertEqual(loaded["roots"][0]["max_depth"], 7)
        self.assertEqual(self.store.export_data(), self.original)
        self.assertEqual((self.backup / "host.json").read_bytes(), self.raw_host)
        backed = Database(self.backup / "steward.sqlite3")
        self.assertEqual(backed.info()["schema_version"], 1)
        self.assertEqual(backed.export_data(), self.original)
        manifest = json.loads((self.backup / "upgrade.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["plan"]["configuration"]["source_sha256"], hashlib.sha256(self.raw_host).hexdigest())
        self.assertTrue(manifest["backup"]["database"]["verified"])
        repeat = upgrade_state(self.store, loaded, str(self.backup), apply=True)
        self.assertEqual(repeat["status"], "already_current")
        self.assertFalse(repeat["applied"])

    def test_guard_failure_before_backup_preserves_source(self):
        before = self.digest()
        def guard():
            raise StewardError("约定已经变化")
        with self.assertRaisesRegex(StewardError, "约定已经变化"):
            upgrade_state(self.store, self.policy, str(self.backup), apply=True, policy_guard=guard)
        self.assertEqual(self.digest(), before)
        self.assertEqual(self.schema(), 1)
        self.assertFalse(self.backup.exists())

    def test_source_change_during_backup_blocks_publication(self):
        calls = []
        def guard():
            calls.append(True)
            if len(calls) == 2:
                changed = copy.deepcopy(self.policy)
                changed["purpose"] = "外部改写后的新用途"
                self.store.write_bytes("host.json", encode(changed))
        with self.assertRaisesRegex(StewardError, "约定已变化"):
            upgrade_state(self.store, self.policy, str(self.backup), apply=True, policy_guard=guard)
        self.assertEqual(self.schema(), 1)
        self.assertEqual(self.store.export_data(), self.original)
        self.assertEqual((self.backup / "host.json").read_bytes(), self.raw_host)
        self.assertEqual(json.loads(self.store.target("host.json").read_text())["purpose"], "外部改写后的新用途")

    def test_configuration_publish_failure_leaves_readable_resumable_state(self):
        original_write = self.store.write_bytes
        def fail_host(name, payload, **kwargs):
            if name == "host.json":
                raise OSError("配置发布失败夹具")
            return original_write(name, payload, **kwargs)
        stderr = io.StringIO()
        with patch.object(self.store, "write_bytes", side_effect=fail_host), redirect_stderr(stderr):
            with self.assertRaisesRegex(OSError, "配置发布失败夹具"):
                upgrade_state(self.store, self.policy, str(self.backup), apply=True)
        diagnostic = json.loads(stderr.getvalue())
        self.assertEqual(diagnostic["status"], "upgrade_incomplete")
        self.assertTrue(diagnostic["schema_2_confirmed"])
        self.assertEqual(diagnostic["configuration_publication"], "unverified")
        self.assertEqual(diagnostic["backup"], str(self.backup))
        self.assertEqual(diagnostic["original_error_type"], "OSError")
        self.assertEqual(self.schema(), 2)
        self.assertEqual(self.store.target("host.json").read_bytes(), self.raw_host)
        self.assertEqual(self.store.export_data(), self.original)
        self.assertTrue((self.backup / "upgrade.json").is_file())
        retry_backup = self.base / "retry-backup"
        result = upgrade_state(self.store, self.policy, str(retry_backup), apply=True)
        self.assertEqual(result["status"], "upgraded")
        self.assertEqual(read_policy_with_evidence(self.store.path)[0]["version"], 2)
        self.assertEqual(Database(retry_backup / "steward.sqlite3").info()["schema_version"], 2)
        self.assertEqual(self.store.export_data(), self.original)

    def test_unchanged_v2_configuration_bytes_are_preserved_during_schema_upgrade(self):
        converted = convert_v1_policy(self.policy)
        raw_v2 = json.dumps(converted, ensure_ascii=False, indent=4).encode("utf-8")
        self.store.write_bytes("host.json", raw_v2)
        result = upgrade_state(self.store, converted, str(self.backup), apply=True)
        self.assertEqual(result["status"], "upgraded")
        self.assertEqual(self.schema(), 2)
        self.assertEqual(self.store.target("host.json").read_bytes(), raw_v2)
        self.assertEqual((self.backup / "host.json").read_bytes(), raw_v2)

    def test_capacity_refusal_keeps_schema_and_backup_readable(self):
        self.policy["limits"]["total_bytes"] = 150000
        self.raw_host = encode(self.policy)
        self.store.write_bytes("host.json", self.raw_host)
        before = self.digest()
        with self.assertRaisesRegex(StewardError, "容量"):
            upgrade_state(self.store, self.policy, str(self.backup), apply=True)
        self.assertEqual(self.schema(), 1)
        self.assertEqual(self.digest(), before)
        self.assertEqual(self.store.target("host.json").read_bytes(), self.raw_host)
        self.assertEqual(Database(self.backup / "steward.sqlite3").export_data(), self.original)
        self.assertTrue((self.backup / "upgrade.json").is_file())

    def test_path_object_backup_is_serializable(self):
        result = upgrade_state(self.store, self.policy, self.backup, apply=True)
        self.assertEqual(result["plan"]["backup"], str(self.backup))
        self.assertEqual(result["status"], "upgraded")
        self.assertTrue((self.backup / "upgrade.json").is_file())

    def test_foreign_host_and_state_containment_fail_before_backup_or_schema_change(self):
        for invalid in [dict(self.policy, host={"system": platform.system(), "hostname": "different-host"}),
                        dict(self.policy, roots=[str(self.store.path / "forbidden-root")])]:
            self.store.write_bytes("host.json", encode(invalid))
            before = self.digest()
            with self.assertRaises(StewardError):
                upgrade_state(self.store, invalid, str(self.backup), apply=True)
            self.assertEqual(self.schema(), 1)
            self.assertEqual(self.digest(), before)
            self.assertFalse(self.backup.exists())

    def test_final_readback_failure_diagnoses_partial_commit_without_changing_exception(self):
        original_read = read_policy_with_evidence
        calls = []
        failure = OSError("最终读回失败夹具")
        def reader(directory):
            calls.append(True)
            if len(calls) == 2:
                raise failure
            return original_read(directory)
        stderr = io.StringIO()
        with patch("policy.read_policy_with_evidence", side_effect=reader), redirect_stderr(stderr):
            with self.assertRaises(OSError) as caught:
                upgrade_state(self.store, self.policy, str(self.backup), apply=True)
        self.assertIs(caught.exception, failure)
        diagnostic = json.loads(stderr.getvalue())
        self.assertEqual(diagnostic["phase"], "configuration_readback")
        self.assertTrue(diagnostic["schema_2_confirmed"])
        self.assertEqual(self.schema(), 2)
        self.assertEqual(original_read(self.store.path)[0]["version"], 2)
        self.assertEqual((self.backup / "host.json").read_bytes(), self.raw_host)
        self.assertEqual(self.store.export_data(), self.original)

    def cli(self, *arguments):
        return subprocess.run([sys.executable, "-B", str(PROJECT / "tools/steward.py"),
                               *arguments, "--state", str(self.store.path)],
                              cwd="/", capture_output=True, text=True, timeout=30)

    def test_formal_upgrade_cli_preview_apply_and_readback(self):
        before = self.digest()
        preview = self.cli("upgrade")
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertEqual(json.loads(preview.stdout)["status"], "upgrade_plan")
        self.assertEqual(self.digest(), before)
        self.assertFalse(self.backup.exists())
        applied = self.cli("upgrade", "--apply", "--backup", str(self.backup))
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(json.loads(applied.stdout)["status"], "upgraded")
        status = self.cli("status")
        self.assertEqual(status.returncode, 0, status.stderr)
        report = json.loads(status.stdout)
        self.assertEqual(report["policy_version"], 2)
        self.assertEqual(report["pending"][0]["key"], "keep")
        self.assertEqual(report["storage"]["schema_version"], 2)
        self.assertEqual(self.store.export_data(), self.original)

    def test_formal_upgrade_cli_refuses_active_collector_lease(self):
        before = self.digest()
        with self.store.lock(".collector.lock"):
            result = self.cli("upgrade", "--apply", "--backup", str(self.backup))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("已有常驻采集运行", result.stderr)
        self.assertEqual(self.digest(), before)
        self.assertFalse(self.backup.exists())

    def test_formal_upgrade_cli_requires_backup_for_mutation(self):
        before = self.digest()
        result = self.cli("upgrade", "--apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--backup", result.stderr)
        self.assertEqual(self.digest(), before)
        self.assertEqual(self.schema(), 1)


if __name__ == "__main__":
    unittest.main()
