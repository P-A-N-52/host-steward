import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))
from custom_checks import check_report
from policy import DEFAULT_SAMPLING, validate
from state import PolicyChangedError, StewardError
from steward import initialize

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

    def marker_script(self, name, marker):
        return self.script(name, (
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('x', encoding='utf-8')\n"))

    def policy_script(self, name, marker, mutation):
        """先写 marker，再按 mutation 改写 host.json。"""
        return self.script(name, (
            "import json, os\n"
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('x', encoding='utf-8')\n"
            "path = Path(os.environ['HOST_STEWARD_STATE']) / 'host.json'\n"
            "policy = json.loads(path.read_text(encoding='utf-8'))\n"
            + mutation
            + "path.write_text(json.dumps(policy, ensure_ascii=False) + '\\n', encoding='utf-8')\n"))

    def corrupt_policy_script(self, name, marker, action):
        """先写 marker，再按 action 删除或写坏 host.json。"""
        return self.script(name, (
            "import os\n"
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('x', encoding='utf-8')\n"
            "path = Path(os.environ['HOST_STEWARD_STATE']) / 'host.json'\n"
            + action))

    def initialize_state(self, state=None, root=None):
        state = self.state if state is None else state
        root = self.root if root is None else root
        return initialize(str(state), [str(root)], "自定义检查策略核对测试")

    def write_checks(self, checks, state=None):
        path = (self.state if state is None else state) / "host.json"
        policy = json.loads(path.read_text(encoding="utf-8"))
        policy["custom_checks"] = checks
        path.write_text(json.dumps(policy, ensure_ascii=False) + "\n", encoding="utf-8")

    def run_cli_check(self, arguments, state=None):
        return subprocess.run(
            [sys.executable, str(PROJECT / "tools/steward.py"), "check",
             "--state", str(self.state if state is None else state), *arguments],
            capture_output=True, text=True, timeout=30)

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

    def test_lone_surrogate_json_falls_back_to_text_without_crashing(self):
        command = self.script("surrogate",
                              "print('{\"value\": \"\\\\ud800\"}')\n")
        policy = self.policy([{"name": "surrogate", "command": command,
                               "purpose": "孤立代理项"}])
        report = check_report(policy, self.state, LIMITS, name="surrogate")
        result = report["checks"][0]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["format"], "text")
        self.assertIn("\\ud800", result["output"])
        json.dumps(report, ensure_ascii=False).encode("utf-8")

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

    def test_wait_timeout_is_reported_as_timeout(self):
        command = self.script("closed-stdout",
                              "import os, time\nos.close(1)\ntime.sleep(5)\n")
        policy = self.policy([{"name": "closed-stdout", "command": command,
                               "purpose": "关闭 stdout 后挂起"}])
        limits = dict(LIMITS, scan_seconds=1)
        started = time.monotonic()
        result = check_report(policy, self.state, limits,
                              name="closed-stdout")["checks"][0]
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

    def test_policy_change_before_next_check_skips_remaining(self):
        first_marker = self.base / "first.marker"
        second_marker = self.base / "second.marker"
        policy = self.policy([
            {"name": "first", "command": self.marker_script("first", first_marker), "purpose": "第一项"},
            {"name": "second", "command": self.marker_script("second", second_marker), "purpose": "第二项"},
        ])
        calls = []

        def guard():
            calls.append(1)
            if len(calls) == 2:
                raise PolicyChangedError("本机约定在本轮执行期间变化，旧计划未提交；请重新运行")

        report = check_report(policy, self.state, LIMITS, run_all=True, policy_guard=guard)
        self.assertEqual([row["status"] for row in report["checks"]],
                         ["ok", "skipped_policy_changed"])
        self.assertTrue(first_marker.exists())
        self.assertFalse(second_marker.exists())
        self.assertEqual(report["executed"], 1)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["skipped"], 1)
        self.assertFalse(report["complete"])
        self.assertEqual(report["policy_changed"]["reason"],
                         "本机约定在检查运行期间变化或无法重新核对；后续脚本未启动，请重新运行")
        self.assertIn("执行期间变化", report["policy_changed"]["detail"])
        self.assertEqual(report["checks"][1]["reason"],
                         "本机约定在检查运行期间变化或无法重新核对；脚本未启动")
        self.assertNotIn("elapsed_seconds", report["checks"][1])
        self.assertEqual(len(calls), 2)

    def test_policy_change_before_named_check_does_not_run(self):
        marker = self.base / "only.marker"
        policy = self.policy([{"name": "only",
                               "command": self.marker_script("only", marker),
                               "purpose": "单项"}])
        calls = []

        def guard():
            calls.append(1)
            raise PolicyChangedError("执行前无法重新核对" + "x" * 600)

        report = check_report(policy, self.state, LIMITS, name="only", policy_guard=guard)
        self.assertEqual(report["checks"][0]["status"], "skipped_policy_changed")
        self.assertFalse(marker.exists())
        self.assertEqual(report["executed"], 0)
        self.assertEqual(report["skipped"], 1)
        self.assertFalse(report["complete"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(report["policy_changed"]["detail"]), 512)

    def test_policy_guard_called_once_per_launched_check(self):
        first = self.marker_script("first", self.base / "first.marker")
        second = self.marker_script("second", self.base / "second.marker")
        policy = self.policy([
            {"name": "first", "command": first, "purpose": "第一项"},
            {"name": "second", "command": second, "purpose": "第二项"},
        ])
        calls = []
        report = check_report(policy, self.state, LIMITS, run_all=True,
                              policy_guard=lambda: calls.append(1))
        self.assertTrue(report["complete"])
        self.assertEqual(report["executed"], 2)
        self.assertEqual(len(calls), 2)

    def test_policy_guard_not_called_for_budget_skipped_check(self):
        marker = self.base / "quick.marker"
        policy = self.policy([
            {"name": "slow", "command": self.script("slow", "import time\ntime.sleep(5)\n"),
             "purpose": "先用完预算"},
            {"name": "quick", "command": self.marker_script("quick", marker),
             "purpose": "应被跳过"},
        ])
        limits = dict(LIMITS, scan_seconds=1)
        calls = []
        report = check_report(policy, self.state, limits, run_all=True,
                              policy_guard=lambda: calls.append(1))
        self.assertEqual([row["status"] for row in report["checks"]],
                         ["timeout", "skipped_budget"])
        self.assertEqual(len(calls), 1)
        self.assertFalse(marker.exists())

    def test_list_mode_does_not_call_policy_guard(self):
        marker = self.base / "listed.marker"
        policy = self.policy([{"name": "health",
                               "command": self.marker_script("health", marker),
                               "purpose": "列表模式"}])
        calls = []
        report = check_report(policy, self.state, LIMITS, policy_guard=lambda: calls.append(1))
        self.assertEqual(report["status"], "custom_checks")
        self.assertEqual(calls, [])
        self.assertFalse(marker.exists())

    def test_skipped_policy_changed_is_not_counted_as_failed(self):
        marker = self.base / "skipped.marker"
        policy = self.policy([{"name": "only",
                               "command": self.marker_script("only", marker),
                               "purpose": "中止"}])

        def guard():
            raise PolicyChangedError("本机约定在本轮执行期间变化，旧计划未提交；请重新运行")

        report = check_report(policy, self.state, LIMITS, run_all=True, policy_guard=guard)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["skipped"], 1)
        self.assertEqual(report["executed"], 0)
        self.assertFalse(report["complete"])
        self.assertFalse(marker.exists())

    def test_missing_name_is_an_error(self):
        policy = self.policy()
        with self.assertRaisesRegex(StewardError, "未配置自定义检查"):
            check_report(policy, self.state, LIMITS, name="missing")

    def test_empty_all_completes_without_running(self):
        report = check_report(self.policy(), self.state, LIMITS, run_all=True)
        self.assertEqual(report["status"], "custom_check_results")
        self.assertEqual(report["count"], 0)
        self.assertTrue(report["complete"])

    def test_cli_all_stops_when_next_check_deleted(self):
        self.initialize_state()
        first_marker = self.base / "cli-first.marker"
        second_marker = self.base / "cli-second.marker"
        first = self.policy_script(
            "first", first_marker,
            "policy['custom_checks'] = [check for check in policy['custom_checks']"
            " if check['name'] != 'second']\n")
        second = self.marker_script("second", second_marker)
        self.write_checks([
            {"name": "first", "command": first, "purpose": "删除第二项"},
            {"name": "second", "command": second, "purpose": "不应启动"},
        ])
        result = self.run_cli_check(["--all"])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual([row["status"] for row in report["checks"]],
                         ["ok", "skipped_policy_changed"])
        self.assertTrue(first_marker.exists())
        self.assertFalse(second_marker.exists())
        self.assertEqual(report["executed"], 1)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["skipped"], 1)
        self.assertFalse(report["complete"])
        self.assertIn("policy_changed", report)

    def test_cli_all_stops_when_next_check_definition_changed(self):
        for field in ["command", "purpose"]:
            with self.subTest(field=field):
                state = self.base / f"state-{field}"
                root = self.base / f"root-{field}"
                root.mkdir()
                self.initialize_state(state=state, root=root)
                first_marker = self.base / f"first-{field}.marker"
                second_marker = self.base / f"second-{field}.marker"
                replacement_marker = self.base / f"replacement-{field}.marker"
                replacement = self.marker_script(f"replacement-{field}", replacement_marker)
                second = self.marker_script(f"second-{field}", second_marker)
                if field == "command":
                    mutation = ("policy['custom_checks'][1]['command'] = "
                                + json.dumps(replacement) + "\n")
                else:
                    mutation = "policy['custom_checks'][1]['purpose'] = '替换后的用途'\n"
                first = self.policy_script(f"first-{field}", first_marker, mutation)
                self.write_checks([
                    {"name": "first", "command": first, "purpose": "修改第二项"},
                    {"name": "second", "command": second, "purpose": "旧定义"},
                ], state=state)
                result = self.run_cli_check(["--all"], state=state)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stderr, "")
                report = json.loads(result.stdout)
                self.assertEqual([row["status"] for row in report["checks"]],
                                 ["ok", "skipped_policy_changed"])
                self.assertTrue(first_marker.exists())
                self.assertFalse(second_marker.exists())
                self.assertFalse(replacement_marker.exists())
                self.assertFalse(report["complete"])
                self.assertIn("policy_changed", report)

    def test_cli_all_reports_unreadable_policy(self):
        cases = {
            "deleted": "path.unlink()\n",
            "corrupt": "path.write_text('{broken', encoding='utf-8')\n",
        }
        for label, action in cases.items():
            with self.subTest(case=label):
                state = self.base / f"state-{label}"
                root = self.base / f"root-{label}"
                root.mkdir()
                self.initialize_state(state=state, root=root)
                first_marker = self.base / f"first-{label}.marker"
                second_marker = self.base / f"second-{label}.marker"
                first = self.corrupt_policy_script(f"first-{label}", first_marker, action)
                second = self.marker_script(f"second-{label}", second_marker)
                self.write_checks([
                    {"name": "first", "command": first, "purpose": "破坏配置"},
                    {"name": "second", "command": second, "purpose": "不应启动"},
                ], state=state)
                result = self.run_cli_check(["--all"], state=state)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stderr, "")
                report = json.loads(result.stdout)
                self.assertEqual([row["status"] for row in report["checks"]],
                                 ["ok", "skipped_policy_changed"])
                self.assertIn("无法重新核对", report["policy_changed"]["detail"])
                self.assertFalse(second_marker.exists())
                self.assertFalse(report["complete"])

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
