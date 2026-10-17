import copy
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
import demo
from demo import run_demo
from state import StewardError


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def cli(self, workspace):
        return subprocess.run([str(PROJECT / "steward"), "demo", "--workspace", str(workspace)],
                              cwd="/", capture_output=True, text=True, timeout=60)

    def assert_blocked(self, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(json.loads(result.stderr)["status"], "blocked")

    def test_cli_creates_verified_demo_and_reuses_history_without_writing(self):
        workspace = self.base / "demo"
        result = self.cli(workspace)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["status"], "demo_verified")
        self.assertTrue(summary["verified"])
        self.assertEqual(summary["demo_version"], 2)
        self.assertEqual(summary["workspace"], str(workspace))
        self.assertEqual(summary["platform"], platform.system())
        self.assertTrue(all(summary["file_coverage"].get(key) for key in ["baseline", "changes", "final"]))
        checks = summary["checks"]
        self.assertIsInstance(checks, dict)
        self.assertTrue(checks)
        self.assertTrue(all(type(value) is bool for value in checks.values()))
        self.assertTrue(all(checks.values()))
        self.assertTrue(checks["directory_changes_observed"])
        self.assertTrue(checks["log_growth_detected"])
        observations = summary["observations"]
        for kind in ["processes", "services"]:
            self.assertIn(kind, observations)
            self.assertTrue(all(field in observations[kind] for field in [
                "observed", "retained", "shown", "truncated", "scope"]))
        report = Path(summary["report"])
        self.assertEqual(report, workspace / "report.md")
        report_text = report.read_text()
        self.assertRegex(report_text, r"本轮时间：.+；平台：")
        self.assertIn("样例预算", report_text)
        self.assertIn("元数据快照覆盖", report_text)
        for label in ["进程", "服务"]:
            line = next(line for line in report_text.splitlines() if line.startswith(f"- {label}观测："))
            for field in ["observed", "retained", "shown", "truncated", "scope"]:
                self.assertIn(field, line)

        manifest_before = (workspace / "demo.json").read_bytes()
        report_before = report.read_bytes()
        reused = self.cli(workspace)
        self.assertEqual(reused.returncode, 0, reused.stderr)
        existing = json.loads(reused.stdout)
        self.assertEqual(existing["status"], "existing_demo")
        self.assertFalse(existing["verified"])
        self.assertEqual(existing["workspace"], str(workspace))
        self.assertEqual(existing["report"], str(report))
        self.assertEqual((workspace / "demo.json").read_bytes(), manifest_before)
        self.assertEqual(report.read_bytes(), report_before)

    def test_legacy_or_failed_historical_checks_are_not_fresh_verification(self):
        for index, fields in enumerate(({}, {"checks": {"historical": False}})):
            with self.subTest(fields=fields):
                workspace = self.base / f"legacy-{index}"
                workspace.mkdir()
                manifest = workspace / "demo.json"
                manifest.write_text(json.dumps(dict(status="demo_verified", workspace=str(workspace), **fields)))
                report = workspace / "report.md"
                report.write_text("旧版本报告，仅留存")
                before = manifest.read_bytes(), report.read_bytes()
                result = self.cli(workspace)
                self.assertEqual(result.returncode, 0, result.stderr)
                summary = json.loads(result.stdout)
                self.assertEqual(summary["status"], "existing_demo")
                self.assertFalse(summary["verified"])
                self.assertEqual((manifest.read_bytes(), report.read_bytes()), before)

    def test_cli_blocks_bad_manifests_as_blocked_without_traceback(self):
        cases = [
            ("bad-json", "{"),
            ("array", "[]"),
            ("null", "null"),
            ("duplicate-key", '{"status":"demo_verified","status":"demo_verified"}'),
            ("nan", '{"status":"demo_verified","workspace":"PLACEHOLDER","value":NaN}'),
            ("checks-list", {"status": "demo_verified", "workspace": "PLACEHOLDER", "checks": []}),
            ("checks-value", {"status": "demo_verified", "workspace": "PLACEHOLDER", "checks": {"ok": 1}}),
            ("version-value", {"status": "demo_verified", "workspace": "PLACEHOLDER", "demo_version": True}),
            ("verified-value", {"status": "demo_verified", "workspace": "PLACEHOLDER", "verified": 1}),
            ("changes-value", {"status": "demo_verified", "workspace": "PLACEHOLDER", "changes": {}}),
        ]
        for name, payload in cases:
            with self.subTest(case=name):
                workspace = self.base / name
                workspace.mkdir()
                manifest = workspace / "demo.json"
                report = workspace / "report.md"
                if isinstance(payload, str):
                    payload = payload.replace("PLACEHOLDER", str(workspace))
                    manifest.write_text(payload)
                else:
                    manifest.write_text(json.dumps({key: value if value != "PLACEHOLDER" else str(workspace)
                                                    for key, value in payload.items()}))
                report.write_text("历史报告")
                manifest_before = manifest.read_bytes()
                report_before = report.read_bytes()
                self.assert_blocked(self.cli(workspace))
                self.assertEqual(manifest.read_bytes(), manifest_before)
                self.assertEqual(report.read_bytes(), report_before)

    def test_cli_rejects_workspace_and_leaf_symlinks_without_writing_targets(self):
        target = self.base / "workspace-target"
        target.mkdir()
        workspace_link = self.base / "workspace-link"
        workspace_link.symlink_to(target, target_is_directory=True)
        self.assert_blocked(self.cli(workspace_link))
        self.assertTrue(workspace_link.is_symlink())
        self.assertEqual(list(target.iterdir()), [])

        manifest_workspace = self.base / "manifest-workspace"
        manifest_workspace.mkdir()
        manifest_target = self.base / "manifest-target.json"
        manifest_target.write_bytes(b"keep manifest")
        (manifest_workspace / "demo.json").symlink_to(manifest_target)
        (manifest_workspace / "report.md").write_text("历史报告")
        self.assert_blocked(self.cli(manifest_workspace))
        self.assertEqual(manifest_target.read_bytes(), b"keep manifest")

        report_workspace = self.base / "report-workspace"
        report_workspace.mkdir()
        report_target = self.base / "report-target.md"
        report_target.write_bytes(b"keep report")
        (report_workspace / "demo.json").write_text(json.dumps({
            "status": "demo_verified", "workspace": str(report_workspace), "checks": {"old": False}
        }))
        (report_workspace / "report.md").symlink_to(report_target)
        self.assert_blocked(self.cli(report_workspace))
        self.assertEqual(report_target.read_bytes(), b"keep report")

    def test_run_demo_verifies_when_birth_metadata_is_unavailable(self):
        workspace = self.base / "birth-none"
        with patch("files.birth", return_value=None):
            summary = run_demo(workspace)
        self.assertEqual(summary["status"], "demo_verified")
        self.assertTrue(summary["verified"])
        self.assertTrue(all(summary["checks"].values()))
        root = workspace / "sample-host"
        root_change = next(row for row in summary["changes"] if row["path"] == str(root))
        self.assertEqual((root_change["added"], root_change["removed"], root_change["moved"]), (2, 2, 0))
        self.assertLessEqual(len(root_change["samples"]), 3)
        self.assertTrue(any(any("move uncertain" in reason for reason in gap["reasons"])
                            for gap in summary["gaps"]))

    def run_with_second_patrol_mutation(self, workspace, mutation):
        real_patrol = demo.patrol
        calls = 0

        def patrol_with_mutation(store, policy):
            nonlocal calls
            result = real_patrol(store, policy)
            calls += 1
            if calls == 2:
                result = copy.deepcopy(result)
                mutation(result)
            return result

        with patch.object(demo, "patrol", side_effect=patrol_with_mutation):
            with self.assertRaises(StewardError):
                run_demo(workspace)

    def test_run_demo_does_not_accept_missing_second_round_changes(self):
        self.run_with_second_patrol_mutation(self.base / "missing-changes",
                                             lambda result: result.update(changes=[]))

    def test_run_demo_does_not_accept_wrong_log_growth_delta(self):
        def wrong_delta(result):
            log_row = next(row for row in result["changes"] if Path(row["path"]).name == "logs")
            log_row["byte_delta"] = 1

        self.run_with_second_patrol_mutation(self.base / "wrong-log-delta", wrong_delta)


if __name__ == "__main__":
    unittest.main()
