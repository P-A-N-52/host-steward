import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import time
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
from custom_checks import check_report
from policy import DEFAULT_SAMPLING, validate
from state import StewardError

LIMITS = {
    "scan_entries": 5000, "scan_seconds": 3, "processes": 200,
    "command_bytes": 262144, "file_bytes": 1048576, "total_bytes": 4194304,
    "output_bytes": 32768, "change_records": 96, "sample_records": 48,
    "operation_records": 32, "retention_hours": 48,
}


class CustomCheckTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.state = self.base / "state"
        self.state.mkdir()
        self.scripts = self.base / "scripts"
        self.scripts.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def script(self, name, body):
        path = self.scripts / f"{name}.py"
        path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
        path.chmod(0o755)
        return [sys.executable, str(path)]

    def policy(self, checks=None):
        return {
            "version": 2,
            "purpose": "自定义检查测试",
            "roots": [{"path": str(self.root), "max_depth": 1,
                       "exclude_names": [], "exclude_paths": []}],
            "sampling": dict(DEFAULT_SAMPLING),
            "residents": [],
            "directory_rules": [],
            "custom_checks": [] if checks is None else checks,
            "limits": dict(LIMITS),
            "host": {"system": platform.system(), "hostname": platform.node()},
        }

    def test_list_mode_reports_definitions_without_running(self):
        command = self.script("health", "print('should not run')\n")
        policy = self.policy([{"name": "health", "command": command, "purpose": "检查健康"}])
        report = check_report(policy, self.state, LIMITS)
        self.assertEqual(report["status"], "custom_checks")
        self.assertEqual(report["count"], 1)
        self.assertEqual(report["checks"][0]["name"], "health")
        self.assertEqual(report["checks"][0]["command"], command)
        self.assertTrue(report["checks"][0]["executable_available"])
        self.assertIn("未运行", report["note"])

    def test_run_json_check_receives_context_and_returns_data(self):
        command = self.script("health", (
            "import json, os\n"
            "print(json.dumps({'healthy': True, 'state': os.environ.get('HOST_STEWARD_STATE'),"
            " 'name': os.environ.get('HOST_STEWARD_CHECK_NAME')}))\n"))
        policy = self.policy([{"name": "health", "command": command, "purpose": "检查健康"}])
        report = check_report(policy, self.state, LIMITS, name="health")
        self.assertEqual(report["status"], "custom_check_results")
        self.assertTrue(report["complete"])
        result = report["checks"][0]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["format"], "json")
        self.assertEqual(result["data"], {"healthy": True, "state": str(self.state), "name": "health"})
        self.assertFalse(result["truncated"])

    def test_text_output_is_returned_verbatim(self):
        command = self.script("text", "print('hello')\n")
        policy = self.policy([{"name": "text", "command": command, "purpose": "文本输出"}])
        result = check_report(policy, self.state, LIMITS, name="text")["checks"][0]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["format"], "text")
        self.assertEqual(result["output"], "hello\n")

    def test_non_finite_json_falls_back_to_text(self):
        command = self.script("nan", "print('{\"value\": NaN}')\n")
        policy = self.policy([{"name": "nan", "command": command, "purpose": "非有限数字"}])
        result = check_report(policy, self.state, LIMITS, name="nan")["checks"][0]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["format"], "text")
        self.assertIn("NaN", result["output"])

    def test_nonzero_exit_is_reported_as_failed_with_output(self):
        command = self.script("fail", "import sys\nprint('needs attention')\nsys.exit(4)\n")
        policy = self.policy([{"name": "fail", "command": command, "purpose": "失败输出"}])
        report = check_report(policy, self.state, LIMITS, name="fail")
        self.assertFalse(report["complete"])
        self.assertEqual(report["failed"], 1)
        result = report["checks"][0]
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_code"], 4)
        self.assertIn("needs attention", result["output"])

    def test_timeout_is_reported_without_hanging(self):
        command = self.script("slow", "import time\ntime.sleep(5)\n")
        policy = self.policy([{"name": "slow", "command": command, "purpose": "超时"}])
        limits = dict(LIMITS, scan_seconds=1)
        started = time.monotonic()
        result = check_report(policy, self.state, limits, name="slow")["checks"][0]
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(result["status"], "timeout")
        self.assertIn("1", result["reason"])

    def test_output_limit_is_reported(self):
        command = self.script("loud", "print('x' * 2000)\n")
        policy = self.policy([{"name": "loud", "command": command, "purpose": "输出上限"}])
        limits = dict(LIMITS, command_bytes=512)
        result = check_report(policy, self.state, limits, name="loud")["checks"][0]
        self.assertEqual(result["status"], "output_limited")
        self.assertGreater(result["output_bytes"], 512)

    def test_all_skips_remaining_checks_when_total_budget_is_used(self):
        slow = self.script("slow", "import time\ntime.sleep(5)\n")
        quick = self.script("quick", "print('ok')\n")
        policy = self.policy([
            {"name": "slow", "command": slow, "purpose": "先用完预算"},
            {"name": "quick", "command": quick, "purpose": "应被跳过"},
        ])
        limits = dict(LIMITS, scan_seconds=1)
        report = check_report(policy, self.state, limits, run_all=True)
        self.assertEqual([row["status"] for row in report["checks"]], ["timeout", "skipped_budget"])
        self.assertEqual(report["skipped"], 1)
        self.assertFalse(report["complete"])

    def test_missing_name_is_an_error(self):
        policy = self.policy()
        with self.assertRaisesRegex(StewardError, "未配置自定义检查"):
            check_report(policy, self.state, LIMITS, name="missing")

    def test_empty_all_completes_without_running(self):
        report = check_report(self.policy(), self.state, LIMITS, run_all=True)
        self.assertEqual(report["status"], "custom_check_results")
        self.assertEqual(report["count"], 0)
        self.assertTrue(report["complete"])

    def test_policy_validation_accepts_custom_checks(self):
        command = self.script("health", "print('ok')\n")
        policy = self.policy([{"name": "health", "command": command, "purpose": "检查健康"}])
        self.assertEqual(validate(policy)["custom_checks"][0]["name"], "health")

    def test_policy_validation_rejects_invalid_custom_checks(self):
        command = self.script("health", "print('ok')\n")
        cases = [
            ("duplicate", [{"name": "health", "command": command, "purpose": "a"},
                           {"name": "health", "command": command, "purpose": "b"}]),
            ("relative", [{"name": "health", "command": ["python3", "x"], "purpose": "a"}]),
            ("name", [{"name": "bad name", "command": command, "purpose": "a"}]),
            ("purpose", [{"name": "health", "command": command, "purpose": " "}]),
            ("field", [{"name": "health", "command": command, "purpose": "a", "extra": 1}]),
            ("args", [{"name": "health", "command": [], "purpose": "a"}]),
        ]
        for label, checks in cases:
            with self.subTest(label=label):
                with self.assertRaises(StewardError):
                    validate(self.policy(checks))

    def test_missing_custom_checks_is_allowed(self):
        policy = self.policy()
        policy.pop("custom_checks")
        validate(policy)


if __name__ == "__main__":
    unittest.main()
