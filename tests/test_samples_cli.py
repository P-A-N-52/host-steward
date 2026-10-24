"""collect/samples 正式 CLI 集成：无锁查询、坏配置只读回退与分页约束。"""

import fcntl
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))


class SamplesCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "观察 根目录"
        self.root.mkdir()
        self.state = self.base / "状态 目录"
        result = self.cli("init", "--state", str(self.state), "--root", str(self.root),
                          "--purpose", "samples CLI 集成测试")
        self.assertEqual(result.returncode, 0, result.stderr)

    def cli(self, *arguments):
        started = time.monotonic()
        result = subprocess.run([sys.executable, str(PROJECT / "tools/steward.py"), *map(str, arguments)],
                                cwd="/", capture_output=True, text=True, timeout=120)
        result.elapsed = time.monotonic() - started
        return result

    def collect_once(self):
        result = self.cli("collect", "--once", "--state", str(self.state))
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def hold_patrol_lock(self):
        handle = open(self.state / ".lock", "a+b")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(lambda: (fcntl.flock(handle.fileno(), fcntl.LOCK_UN), handle.close()))
        return handle

    def test_collect_once_then_samples_and_status_are_queryable(self):
        collected = self.collect_once()
        self.assertEqual(collected["status"], "ok")
        self.assertEqual(collected["samples"], 1)
        samples = self.cli("samples", "--state", str(self.state))
        self.assertEqual(samples.returncode, 0, samples.stderr)
        report = json.loads(samples.stdout)
        self.assertEqual(report["status"], "resource_history")
        self.assertEqual(len(report["samples"]), 1)
        self.assertEqual(report["policy_source"], "current_host_json")
        self.assertTrue(report["current_policy_valid"])
        self.assertIn("latest_processes", report)
        status = self.cli("status", "--state", str(self.state))
        self.assertEqual(status.returncode, 0, status.stderr)
        summary = json.loads(status.stdout)
        self.assertEqual(summary["collector"]["status"], "stopped")
        self.assertEqual(summary["collector"]["run"]["mode"], "once")

    def test_status_and_samples_do_not_wait_for_patrol_lock(self):
        self.collect_once()
        self.hold_patrol_lock()
        for action in ("status", "samples"):
            result = self.cli(action, "--state", str(self.state))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLess(result.elapsed, 30, f"{action} 不应等待巡检锁")
            self.assertIn("policy_evidence", result.stdout)
        refused = self.cli("collect", "--once", "--state", str(self.state))
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("持锁", refused.stderr)

    def test_invalid_current_policy_still_reads_history_with_archived_budget(self):
        self.collect_once()
        host = self.state / "host.json"
        original = host.read_bytes()
        host.write_text("{broken", encoding="utf-8")
        try:
            samples = self.cli("samples", "--state", str(self.state))
            self.assertEqual(samples.returncode, 0, samples.stderr)
            report = json.loads(samples.stdout)
            self.assertEqual(report["status"], "resource_history")
            self.assertEqual(len(report["samples"]), 1)
            self.assertEqual(report["policy_source"], "last_valid_collector_run")
            self.assertFalse(report["current_policy_valid"])
            self.assertEqual(report["current_policy_adopted"], False)
            self.assertIn("current_policy_error", report)
            status = self.cli("status", "--state", str(self.state))
            self.assertEqual(status.returncode, 0, status.stderr)
            summary = json.loads(status.stdout)
            self.assertEqual(summary["policy_source"], "last_valid_collector_run")
            self.assertEqual(summary["collector"]["status"], "stopped")
            for action, extra in (("collect", ["--once"]), ("patrol", []),
                                  ("upgrade", []), ("inventory", [])):
                denied = self.cli(action, "--state", str(self.state), *extra)
                self.assertNotEqual(denied.returncode, 0,
                                    f"{action} 不得在配置无效时静默使用归档预算")
        finally:
            host.write_bytes(original)
        recovered = self.collect_once()
        self.assertEqual(recovered["status"], "ok")

    def test_samples_paging_requires_fixed_window_and_export_is_exclusive(self):
        self.collect_once()
        rejected = self.cli("samples", "--state", str(self.state), "--before", "1")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("--since", rejected.stderr)
        output = self.base / "历史导出.json"
        exported = self.cli("samples", "--state", str(self.state), "--raw", "--output", str(output))
        self.assertEqual(exported.returncode, 0, exported.stderr)
        receipt = json.loads(exported.stdout)
        self.assertEqual(receipt["status"], "resource_history_exported")
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "resource_history")
        self.assertEqual(payload["raw_count"], 1)
        again = self.cli("samples", "--state", str(self.state), "--output", str(output))
        self.assertNotEqual(again.returncode, 0)

    def test_output_budget_collapse_exits_nonzero_and_never_claims_success(self):
        self.collect_once()

        def set_output_bytes(value):
            host = self.state / "host.json"
            policy = json.loads(host.read_text(encoding="utf-8"))
            policy["limits"]["output_bytes"] = value
            host.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")

        for budget in (6000, 4096):
            with self.subTest(budget=budget):
                set_output_bytes(budget)
                result = self.cli("samples", "--state", str(self.state))
                self.assertEqual(result.returncode, 2, result.stdout)
                report = json.loads(result.stdout)
                self.assertTrue(report.get("pagination_blocked_by_output")
                                or report.get("status") == "output_limited")
                if report.get("samples"):
                    self.assertIsNotNone(report.get("next_before"))
        set_output_bytes(256)
        status = self.cli("status", "--state", str(self.state))
        self.assertEqual(status.returncode, 2, status.stdout)
        self.assertEqual(json.loads(status.stdout)["status"], "output_limited")

    def test_collect_once_budget_failure_exits_nonzero_without_fake_sample(self):
        host = self.state / "host.json"
        policy = json.loads(host.read_text(encoding="utf-8"))
        policy["sampling"].update(interval_seconds=1, cycle_seconds=1,
                                  process_interval_seconds=1)
        host.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
        result = self.cli("collect", "--once", "--state", str(self.state))
        self.assertEqual(result.returncode, 2, result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["samples"], 0)
        samples = self.cli("samples", "--state", str(self.state), "--minutes", "5")
        self.assertEqual(samples.returncode, 0, samples.stderr)
        self.assertEqual(json.loads(samples.stdout)["page"]["returned"], 0)


if __name__ == "__main__":
    unittest.main()
