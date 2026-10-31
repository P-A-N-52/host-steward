"""changes 正式 CLI 集成：区间/两点、预算退出码、导出与巡检锁下读取。"""

import fcntl
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from sample_store import SampleStore
from steward import load

BASE = 1_700_000_000.0
_UNSET = object()


class ChangesCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "观察 根目录"
        self.root.mkdir()
        self.state = self.base / "状态 目录"
        result = self.cli("init", "--state", str(self.state), "--root", str(self.root),
                          "--purpose", "changes CLI 集成测试")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.store, self.policy = load(self.state)
        self.history = SampleStore(self.store)
        self.sampling = self.policy["sampling"]
        self.run_id = "cli-run"
        self.history.start_run(
            self.run_id, {"version": 2, "sampling": self.sampling},
            {"policy_version": 2, "policy_digest": "d" * 64},
            started_at=BASE, boot={"boot_id": "boot-a"})

    def cli(self, *arguments):
        started = time.monotonic()
        result = subprocess.run(
            [sys.executable, str(PROJECT / "tools/steward.py"),
             *map(str, arguments)],
            cwd="/", capture_output=True, text=True, timeout=120)
        result.elapsed = time.monotonic() - started
        return result

    def host(self, *, memory=800, read=100, ticks=100, interfaces=None):
        return {
            "cpu": {"available": True, "hz": 100,
                    "counters": {"user": ticks, "nice": 0, "system": ticks,
                                 "idle": ticks * 5, "iowait": 0, "irq": 0,
                                 "softirq": 0, "steal": 0}},
            "memory": {"available": True, "total_bytes": 1000,
                       "available_bytes": memory,
                       "swap": {"available": True, "used_bytes": 10}},
            "diskio": {"available": True, "disks": [
                {"name": "nvme0n1", "identity": "dev-a", "major": 259,
                 "minor": 0, "read_bytes": read, "write_bytes": read * 2}]},
            "network": {"available": True, "interfaces": {
                "available": True,
                "items": interfaces if interfaces is not None else [
                    {"name": "eth0", "ifindex": 2, "ibytes": read,
                     "obytes": read * 2, "ipackets": 0, "opackets": 0,
                     "ierrs": 0, "oerrs": 0}]}},
        }

    def append(self, index, *, run_id=None, boot="boot-a", host=None,
               sources=None, processes=_UNSET):
        at = BASE + index * 15
        if host is None:
            host = self.host(memory=800 - index * 50,
                             read=100 + index * 50,
                             ticks=100 + index * 50)
        if sources is None:
            sources = {
                "cpu": {"available": True, "attempted_at": at, "success_at": at},
                "network": {"available": True, "attempted_at": at,
                            "success_at": at}}
        if processes is _UNSET:
            processes = {"available": True, "observed_at": at, "items": [
                {"identity": "p1", "pid": 42, "rss_bytes": 1000 + index * 100,
                 "cpu_ticks": 100 + index * 100, "hz": 100}]}
        return self.history.append_sample(
            run_id or self.run_id, observed_at=at, monotonic_at=1000 + index * 15,
            boot={"boot_id": boot}, host=host, sources=sources,
            processes=processes, sampling=self.sampling)

    def db_sample(self, sample_id):
        connection = sqlite3.connect(self.state / "steward.sqlite3")
        try:
            return connection.execute(
                "SELECT sample_id, observed_at FROM resource_samples "
                "WHERE sample_id=?", (sample_id,)).fetchone()
        finally:
            connection.close()

    def hold_patrol_lock(self):
        handle = open(self.state / ".lock", "a+b")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(lambda: (fcntl.flock(handle.fileno(), fcntl.LOCK_UN),
                                 handle.close()))
        return handle

    def test_range_and_pair_changes_are_queryable_and_match_database(self):
        ids = [self.append(index)["sample_id"] for index in range(3)]
        range_result = self.cli("changes", "--state", str(self.state),
                                "--since", BASE, "--until", BASE + 40)
        self.assertEqual(range_result.returncode, 0, range_result.stderr)
        report = json.loads(range_result.stdout)
        self.assertEqual(report["status"], "resource_changes")
        self.assertEqual(report["contract"],
                         {"name": "host-steward.resource_changes", "version": 1})
        self.assertEqual(report["mode"], "range")
        self.assertEqual(report["evaluated_samples"], 3)
        self.assertEqual(report["evaluated_pairs"], 2)
        disk = [row for row in report["changes"]
                if row["path"] == "diskio.disks.nvme0n1.read_bytes"]
        self.assertEqual(len(disk), 1)
        episode = disk[0]
        self.assertEqual((episode["before"], episode["after"],
                          episode["delta"], episode["pairs"]),
                         (100, 200, 100, 2))
        self.assertEqual(episode["first_sample_id"], ids[1])
        self.assertEqual(episode["last_sample_id"], ids[2])
        self.assertEqual(self.db_sample(episode["first_sample_id"])[1],
                         episode["first_observed_at"])
        self.assertEqual(self.db_sample(episode["last_sample_id"])[1],
                         episode["last_observed_at"])

        pair_result = self.cli("changes", "--state", str(self.state),
                               "--from-sample", ids[0], "--to-sample", ids[1])
        self.assertEqual(pair_result.returncode, 0, pair_result.stderr)
        pair = json.loads(pair_result.stdout)
        self.assertEqual(pair["mode"], "pair")
        self.assertEqual(pair["baseline"]["sample_id"], ids[0])
        self.assertEqual(pair["target"]["sample_id"], ids[1])
        memory = [row for row in pair["changes"]
                  if row["path"] == "memory.available_bytes"]
        self.assertEqual(len(memory), 1)
        self.assertEqual((memory[0]["before"], memory[0]["after"],
                          memory[0]["delta"]), (800, 750, -50))
        self.assertEqual(memory[0]["first_sample_id"], ids[1])
        self.assertNotIn("pairs", memory[0])

    def test_pair_mode_argument_errors_are_explicit(self):
        first = self.append(0)["sample_id"]
        second = self.append(1)["sample_id"]
        only_from = self.cli("changes", "--state", str(self.state),
                            "--from-sample", first)
        self.assertNotEqual(only_from.returncode, 0)
        self.assertIn("两点模式", only_from.stderr)
        mixed = self.cli("changes", "--state", str(self.state),
                        "--from-sample", first, "--to-sample", second,
                        "--minutes", 5)
        self.assertNotEqual(mixed.returncode, 0)
        unordered = self.cli("changes", "--state", str(self.state),
                            "--from-sample", second, "--to-sample", first)
        self.assertNotEqual(unordered.returncode, 0)
        self.assertIn("from_sample", unordered.stderr)
        missing = self.cli("changes", "--state", str(self.state),
                          "--from-sample", first, "--to-sample", 999999)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("样本不存在", missing.stderr)
        rejected = self.cli("changes", "--state", str(self.state), "--before", 1)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("--since", rejected.stderr)
        invalid = self.cli("changes", "--state", str(self.state),
                          "--since", BASE, "--until", BASE + 20,
                          "--resource", "bogus")
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("--resource", invalid.stderr)

    def test_process_filter_and_not_loaded_marker(self):
        self.append(0)
        second = self.append(1)
        plain = self.cli("changes", "--state", str(self.state),
                        "--since", BASE, "--until", BASE + 20)
        self.assertEqual(plain.returncode, 0, plain.stderr)
        report = json.loads(plain.stdout)
        self.assertTrue(report["summary"]["process_changes_not_loaded"])
        self.assertFalse(any(row["resource"] == "processes"
                             for row in report["changes"]))
        process = self.cli("changes", "--state", str(self.state),
                          "--since", BASE, "--until", BASE + 20,
                          "--process", "p1")
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        rows = {row["path"]: row for row in report["changes"]
                if row["resource"] == "processes"}
        self.assertEqual(rows["processes.p1.rss_bytes"]["delta"], 100)
        self.assertEqual(rows["processes.p1.rss_bytes"]["last_sample_id"],
                         second["sample_id"])
        self.assertTrue(report["summary"]["process_changes_loaded"])

    def test_resource_filter_max_changes_and_fixed_window_paging(self):
        ids = [self.append(index)["sample_id"] for index in range(4)]
        filtered = self.cli("changes", "--state", str(self.state),
                           "--since", BASE, "--until", BASE + 60,
                           "--resource", "memory")
        self.assertEqual(filtered.returncode, 0, filtered.stderr)
        report = json.loads(filtered.stdout)
        self.assertEqual({row["resource"] for row in report["changes"]},
                         {"memory"})
        self.assertEqual(len(report["changes"]), 1)
        self.assertEqual(report["changes"][0]["delta"], -150)

        limited = self.cli("changes", "--state", str(self.state),
                          "--since", BASE, "--until", BASE + 60,
                          "--max-changes", 1)
        self.assertEqual(limited.returncode, 0, limited.stderr)
        report = json.loads(limited.stdout)
        self.assertEqual(len(report["changes"]), 1)
        self.assertGreater(report["changes_omitted"], 0)
        self.assertTrue(report["truncated"])

        first_page = self.cli("changes", "--state", str(self.state),
                             "--since", BASE, "--until", BASE + 60, "--limit", 2)
        self.assertEqual(first_page.returncode, 0, first_page.stderr)
        report = json.loads(first_page.stdout)
        self.assertEqual(report["evaluated_samples"], 2)
        self.assertEqual(report["evaluated_pairs"], 1)
        self.assertEqual(report["next_before"], ids[2])
        self.assertEqual(report["boundary"]["predecessor_sample_id"], ids[1])
        older = self.cli("changes", "--state", str(self.state),
                        "--since", BASE, "--until", BASE + 60,
                        "--before", report["next_before"], "--limit", 2)
        self.assertEqual(older.returncode, 0, older.stderr)
        report = json.loads(older.stdout)
        self.assertEqual(report["evaluated_samples"], 2)
        self.assertEqual(report["changes"][0]["first_sample_id"], ids[1])

    def test_output_budget_exits_two_and_export_is_exclusive_and_complete(self):
        for index in range(3):
            self.append(index)
        host = self.state / "host.json"
        policy = json.loads(host.read_text(encoding="utf-8"))
        policy["limits"]["output_bytes"] = 800
        host.write_text(json.dumps(policy, ensure_ascii=False, indent=2),
                        encoding="utf-8")
        bounded = self.cli("changes", "--state", str(self.state),
                          "--since", BASE, "--until", BASE + 40)
        self.assertEqual(bounded.returncode, 2, bounded.stdout)
        self.assertLessEqual(len(bounded.stdout.encode()), 800)
        report = json.loads(bounded.stdout)
        self.assertTrue(report.get("pagination_blocked_by_output")
                        or report.get("output_limited")
                        or report.get("status") == "output_limited")
        output = self.base / "changes 导出.json"
        exported = self.cli("changes", "--state", str(self.state),
                           "--since", BASE, "--until", BASE + 40,
                           "--raw", "--output", str(output))
        self.assertEqual(exported.returncode, 0, exported.stderr)
        receipt = json.loads(exported.stdout)
        self.assertEqual(receipt["status"], "resource_changes_exported")
        self.assertEqual(receipt["mode"], "range")
        self.assertGreater(receipt["changes"], 0)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "resource_changes")
        self.assertEqual(len(payload["pairs"]), 2)
        self.assertTrue(payload["raw"])
        again = self.cli("changes", "--state", str(self.state),
                        "--since", BASE, "--until", BASE + 40,
                        "--output", str(output))
        self.assertNotEqual(again.returncode, 0)

    def test_changes_do_not_wait_for_patrol_lock(self):
        first = self.append(0)["sample_id"]
        second = self.append(1)["sample_id"]
        self.hold_patrol_lock()
        for arguments in (
                ("changes", "--state", str(self.state),
                 "--since", BASE, "--until", BASE + 20),
                ("changes", "--state", str(self.state),
                 "--from-sample", first, "--to-sample", second)):
            result = self.cli(*arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLess(result.elapsed, 30, "changes 不应等待巡检锁")
            self.assertIn("policy_evidence", result.stdout)
        refused = self.cli("collect", "--once", "--state", str(self.state))
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("持锁", refused.stderr)


if __name__ == "__main__":
    unittest.main()
