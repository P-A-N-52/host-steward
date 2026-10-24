import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

import linux_observe as linux
import observe
from policy import make_policy_evidence
from resource_sampler import (
    DarwinBudgetExceeded,
    DarwinBudgetRunner,
    sample_resources,
)
from sample_store import SampleStore
from state import Store
from state_io import StewardError


BOOT_ID = "11111111-2222-3333-4444-555555555555"
BTIME = 1_700_000_000
CPU_STAT = """cpu  100 2 30 400 10 5 6 7 8 9
cpu0 50 1 15 200 5 2 3 3 4 4
cpu1 50 1 15 200 5 3 3 4 4 5
btime 1700000000
"""
MEMINFO = """MemTotal:       1000 kB
MemFree:         100 kB
MemAvailable:    400 kB
Buffers:          10 kB
Cached:          200 kB
SwapTotal:       500 kB
SwapFree:        300 kB
HugePages_Total:   4
"""
DISKSTATS = "8 0 sda 100 2 2000 3 400 5 8000 7 0 9 10\n"
NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
"""


def pid_stat(pid, comm="worker", state="S", ppid=1, utime=10, stime=20,
             start_ticks=100, rss_pages=3, threads=1):
    fields = [
        state, str(ppid), "0", "0", "0", "0", "0",
        "0", "0", "0", "0",
        str(utime), str(stime), "0", "0",
        "20", "0", str(threads), "0", str(start_ticks),
        "1000", str(rss_pages),
    ]
    return f"{pid} ({comm}) " + " ".join(fields) + "\n"


def policy(root, *, sampling=None, limits=None):
    return {
        "version": 2,
        "purpose": "资源采样测试",
        "roots": [str(root)],
        "sampling": sampling or {
            "interval_seconds": 15,
            "cycle_seconds": 5,
            "process_interval_seconds": 60,
            "processes": 4,
            "records": 10,
            "retention_hours": 1,
        },
        "residents": [],
        "limits": limits or {
            "command_bytes": 262144,
            "file_bytes": 65536,
            "total_bytes": 8 * 1024 * 1024,
        },
    }


class LinuxFixture:
    def __init__(self, base):
        self.base = Path(base).resolve()
        self.proc = self.base / "proc"
        self.sys = self.base / "sys"
        self.root = self.base / "观察根"
        self.root.mkdir(parents=True)
        self.proc.mkdir()
        self.sys.mkdir()
        self.write_proc("stat", CPU_STAT)
        self.write_proc("sys/kernel/random/boot_id", BOOT_ID + "\n")
        self.write_proc("meminfo", MEMINFO)
        self.write_proc("diskstats", DISKSTATS)
        self.write_proc("net/dev", NET_DEV)
        self.write_proc("1/stat", pid_stat(1, comm="init"))
        self.write_proc("2/stat", pid_stat(2, comm="worker", rss_pages=5))
        os.symlink("/sbin/init", self.proc / "1" / "exe")
        self.write_sys("class/net/eth0/ifindex", "2\n")
        self.sysconf_values = {"SC_CLK_TCK": 100, "SC_PAGE_SIZE": 4096}

    def write_proc(self, relative, text):
        path = self.proc / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def write_sys(self, relative, text):
        path = self.sys / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def source(self, **overrides):
        options = {
            "proc_root": self.proc,
            "sys_root": self.sys,
            "sysconf": lambda name: self.sysconf_values[name],
            "loadavg": lambda: (0.5, 0.25, 0.1),
        }
        options.update(overrides)
        return linux.LinuxSource(**options)

    def policy(self, sampling=None):
        return policy(self.root, sampling=sampling)

    def sample(self, **kwargs):
        kwargs.setdefault("system", "Linux")
        kwargs.setdefault("linux_source", self.source())
        kwargs.setdefault("roots", [self.root])
        return sample_resources(self.policy(), **kwargs)


class FakeCommands:
    def __init__(self, clock=None):
        self.calls = []
        self.clock = clock

    def __call__(self, arguments, *, max_bytes, timeout, metadata=None):
        self.calls.append((list(arguments), max_bytes, timeout))
        text = self._response(arguments)
        if metadata is not None:
            metadata["output_bytes"] = len(text.encode("utf-8"))
        return text

    def _response(self, arguments):
        if arguments[0] == "sysctl":
            target = arguments[-1]
            if target == "kern.boottime":
                return "sec = 1700000000\n"
            if target == "hw.memsize":
                return "17179869184\n"
            if target == "vm.swapusage":
                return "total = 2.00G  used = 0.50G  free = 1.50G\n"
        if arguments[0] == "vm_stat":
            return ("Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
                    "Pages free: 1000.\nPages active: 2000.\n")
        if arguments[0] == "iostat":
            return ("disk0 cpu load average\n"
                    "0.5 10 0.2 5.0 10.0 50.0 1.0 2.0 3.0\n")
        if arguments[0] == "netstat":
            return ("Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n"
                    "lo0 16384 <Link#1> 100 0 2000 100 0 2000 0\n"
                    "en9 1500 <Link#2> 10 1 300 20 2 400 0\n")
        if arguments[0] == "ps":
            return ("1 0 Thu Oct 24 10:00:00 2026 0.0 1024 /sbin/launchd\n"
                    "2 1 Thu Oct 24 10:00:01 2026 1.5 2048 /usr/bin/worker\n")
        raise AssertionError(f"未预期的命令：{arguments}")


class ResourceSamplerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = LinuxFixture(temporary.name)

    def test_linux_batch_reads_all_resource_sources_without_duplicate_arrays(self):
        result = self.fixture.sample(process_due=True)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["complete"])
        self.assertTrue(result["usable"])
        self.assertEqual(result["platform"], "Linux")
        self.assertGreaterEqual(result["elapsed_seconds"], 0.0)
        self.assertEqual(set(result["host"]),
                         {"boot", "cpu", "memory", "diskio", "network", "storage"})
        self.assertEqual(result["boot"]["boot_id"], BOOT_ID)
        self.assertEqual(result["boot"]["unix_time"], BTIME)
        self.assertEqual(result["host"]["cpu"]["cores"], 2)
        self.assertEqual(result["host"]["memory"]["total_bytes"], 1024 * 1000)
        self.assertIn("disks", result["host"]["diskio"])
        self.assertNotIn("devices", result["host"]["diskio"])
        self.assertEqual(result["host"]["diskio"]["array_field"], "disks")
        interface = result["host"]["network"]["interfaces"]["items"][0]
        self.assertEqual(interface["identity"], "ifindex:2")
        self.assertEqual(result["host"]["storage"]["roots"][0]["path"],
                         str(self.fixture.root))
        self.assertEqual(result["sources"]["cpu"]["available"], True)
        self.assertIn("success_at", result["sources"]["cpu"])
        self.assertEqual(len(result["processes"]["items"]), 2)
        self.assertEqual(result["processes"]["items"][0]["rss_bytes"], 5 * 4096)
        self.assertIn("gpu", result["not_observed"])
        self.assertIn("tcp_states", result["not_observed"])

    def test_source_failure_is_isolated_and_keeps_traceback(self):
        with patch.object(linux, "observe_memory",
                          side_effect=PermissionError("meminfo denied")):
            result = self.fixture.sample(process_due=True)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["complete"])
        self.assertTrue(result["usable"])
        self.assertEqual(result["host"]["memory"]["available"], False)
        status = result["sources"]["memory"]
        self.assertEqual(status["available"], False)
        self.assertEqual(status["error"]["type"], "PermissionError")
        self.assertIn("meminfo denied", status["error"]["message"])
        self.assertIn("Traceback", status["error"]["traceback"])
        self.assertIn("attempted_at", status)
        self.assertIn("error_at", status)
        self.assertNotIn("success_at", status)
        self.assertEqual(result["sources"]["cpu"]["available"], True)
        self.assertIn("memory", result["failed_sources"])

    def test_memory_success_failure_success_does_not_advance_last_success(self):
        policy_document = self.fixture.policy()
        evidence = make_policy_evidence(policy_document)
        store = Store(self.fixture.base / "state-history",
                      policy_document["limits"])
        store.initialize_database()
        samples = SampleStore(store)
        clock = {"wall": 1_700_000_000.0, "mono": 1000.0}

        def wall():
            clock["wall"] += 0.1
            return clock["wall"]

        def monotonic():
            clock["mono"] += 0.01
            return clock["mono"]

        def sample():
            return sample_resources(
                policy_document, system="Linux", process_due=False,
                linux_source=self.fixture.source(), wall_clock=wall,
                monotonic=monotonic)

        first = sample()
        with patch.object(linux, "observe_memory",
                          side_effect=PermissionError("meminfo denied")):
            second = sample()
        third = sample()
        self.assertTrue(first["host"]["memory"]["available"])
        self.assertFalse(second["host"]["memory"]["available"])
        self.assertTrue(third["host"]["memory"]["available"])
        self.assertIn("success_at", first["sources"]["memory"])
        self.assertNotIn("success_at", second["sources"]["memory"])
        self.assertIn("error_at", second["sources"]["memory"])
        self.assertIn("success_at", third["sources"]["memory"])

        samples.start_run(
            "source-history-run", policy_document, evidence,
            started_at=first["started_at"], boot=first["boot"], pid=123)
        for result in (first, second, third):
            samples.append_sample(
                "source-history-run", observed_at=result["observed_at"],
                monotonic_at=result["monotonic_at"], boot=result["boot"],
                host=result["host"], sources=result["sources"],
                processes=result["processes"],
                sampling=policy_document["sampling"])
        page = samples.query(None, None, limit=10)
        newest, middle, oldest = page["samples"]
        self.assertIn("success_at", newest["sources"]["memory"])
        self.assertNotIn("success_at", middle["sources"]["memory"])
        self.assertIn("error_at", middle["sources"]["memory"])
        self.assertEqual(middle["sources"]["memory"]["error"]["type"],
                         "PermissionError")
        self.assertIn("success_at", oldest["sources"]["memory"])
        memory = samples.status()["sources"]["memory"]
        self.assertTrue(memory["available"])
        self.assertEqual(memory["success_at"],
                         newest["sources"]["memory"]["success_at"])
        self.assertEqual(memory["last_success_at"],
                         newest["sources"]["memory"]["success_at"])
        self.assertEqual(memory["error_at"],
                         middle["sources"]["memory"]["error_at"])
        self.assertEqual(memory["last_error_at"],
                         middle["sources"]["memory"]["error_at"])
        self.assertEqual(memory["last_error"]["type"], "PermissionError")

    def test_budget_exhaustion_marks_following_sources_not_attempted(self):
        failure = linux.LinuxBudgetExceededError(
            "time", "/proc/meminfo", limit=5, observed=5)
        with patch.object(linux, "observe_memory", side_effect=failure):
            result = self.fixture.sample(process_due=True)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["budget_exhausted"])
        self.assertEqual(result["host"]["memory"]["budget_exhausted"], True)
        self.assertIn("budget_kind", result["sources"]["memory"])
        self.assertEqual(result["sources"]["memory"]["error"]["type"],
                         "LinuxBudgetExceededError")
        self.assertNotIn("success_at", result["sources"]["memory"])
        self.assertIn("error_at", result["sources"]["memory"])
        self.assertTrue(result["sources"]["diskio"]["budget_not_attempted"])
        self.assertTrue(result["sources"]["network"]["budget_not_attempted"])
        self.assertTrue(result["sources"]["storage"]["budget_not_attempted"])
        self.assertIsNone(result["processes"])
        self.assertIn("processes", result["not_attempted_sources"])
        self.assertIn("budget_not_attempted", result["host"]["diskio"]["reason"])
        self.assertNotIn("attempted_at", result["sources"]["diskio"])

    def test_all_core_failures_do_not_create_a_usable_sample(self):
        errors = [
            patch.object(linux, "observe_boot", side_effect=PermissionError("boot")),
            patch.object(linux, "observe_cpu", side_effect=PermissionError("cpu")),
            patch.object(linux, "observe_memory", side_effect=PermissionError("memory")),
            patch.object(linux, "observe_diskio", side_effect=PermissionError("diskio")),
            patch.object(linux, "observe_network", side_effect=PermissionError("network")),
            patch.object(linux, "observe_processes", side_effect=PermissionError("processes")),
        ]
        for item in errors:
            item.start()
            self.addCleanup(item.stop)
        result = sample_resources(
            self.fixture.policy(), system="Linux",
            linux_source=self.fixture.source(), roots=[])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["usable"])
        self.assertFalse(result["complete"])
        for name in ("boot", "cpu", "memory", "diskio", "network", "storage"):
            self.assertEqual(result["host"][name]["available"], False)
        self.assertEqual(result["sources"]["cpu"]["error"]["type"], "PermissionError")
        self.assertIn("Traceback", result["sources"]["cpu"]["error"]["traceback"])
        self.assertEqual(result["host"]["storage"]["available"], False)
        self.assertEqual(result["sources"]["storage"]["available"], False)

    def test_darwin_uses_one_iostat_for_cpu_and_disk_and_marks_rates(self):
        commands = FakeCommands()
        ifindex = lambda name: 1 if name == "lo0" else (_ for _ in ()).throw(
            OSError("ifindex unavailable"))
        result = sample_resources(
            self.fixture.policy(), system="Darwin", command_runner=commands,
            if_nametoindex=ifindex, roots=[self.fixture.root])
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["complete"])
        self.assertEqual(result["host"]["cpu"]["rate"], True)
        self.assertIsNone(result["host"]["cpu"]["counters"])
        self.assertEqual(result["host"]["diskio"]["rate"], True)
        self.assertIn("disks", result["host"]["diskio"])
        self.assertEqual(result["host"]["memory"]["page_size"], 16384)
        self.assertEqual(result["host"]["memory"]["swap"]["used_bytes"],
                         512 * 1024 * 1024)
        self.assertIn("当前", result["host"]["memory"]["swap"]["semantics"])
        self.assertNotIn("累计高水位", result["host"]["memory"]["swap"]["semantics"])
        items = result["host"]["network"]["interfaces"]["items"]
        self.assertEqual(items[0]["ifindex"], 1)
        self.assertEqual(items[0]["identity"], "ifindex:1")
        self.assertIsNone(items[1]["ifindex"])
        self.assertIsNone(items[1]["identity"])
        self.assertIn("ifindex unavailable", items[1]["identity_reason"])
        self.assertEqual(result["host"]["network"]["tcp_states"]["available"], False)
        iostat_calls = [call for call in commands.calls if call[0][0] == "iostat"]
        self.assertEqual(len(iostat_calls), 1)
        # 每条命令共用剩余 deadline，而不是每条重置为 5 秒。
        timeouts = [call[2] for call in commands.calls]
        self.assertTrue(all(value <= 5.0 for value in timeouts))
        self.assertEqual(timeouts, sorted(timeouts, reverse=True))
        self.assertEqual(len(result["processes"]["items"]), 2)

    def test_darwin_shared_deadline_blocks_later_sources(self):
        class AdvancingClock:
            def __init__(self):
                self.value = 1000.0

            def __call__(self):
                return self.value

        clock = AdvancingClock()

        def command(arguments, *, max_bytes, timeout, metadata=None):
            if arguments[0] == "sysctl":
                clock.value += 2.0
                text = "sec = 1700000000\n"
                if metadata is not None:
                    metadata["output_bytes"] = len(text.encode("utf-8"))
                return text
            raise AssertionError(f"预算耗尽后不应执行：{arguments}")

        result = sample_resources(
            self.fixture.policy(sampling={
                "interval_seconds": 15, "cycle_seconds": 1,
                "process_interval_seconds": 60, "processes": 4,
                "records": 10, "retention_hours": 1}),
            system="Darwin", command_runner=command,
            monotonic=clock, roots=[self.fixture.root])
        self.assertEqual(result["host"]["boot"]["available"], True)
        self.assertTrue(result["sources"]["cpu"]["budget_exhausted"])
        self.assertEqual(result["sources"]["cpu"]["error"]["type"],
                         "DarwinBudgetExceeded")
        self.assertTrue(result["sources"]["memory"]["budget_not_attempted"])
        self.assertTrue(result["sources"]["network"]["budget_not_attempted"])
        self.assertTrue(result["sources"]["storage"]["budget_not_attempted"])
        self.assertIsNone(result["processes"])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["usable"])

    def test_linux_shared_byte_budget_blocks_following_sources(self):
        budget = linux.LinuxBudget(32, 5)
        result = sample_resources(
            self.fixture.policy(), system="Linux",
            linux_source=self.fixture.source(), budget=budget, roots=[])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["usable"])
        self.assertTrue(result["budget_exhausted"])
        boot = result["sources"]["boot"]
        self.assertTrue(boot["budget_exhausted"])
        self.assertEqual(boot["error"]["type"], "LinuxBudgetExceededError")
        self.assertTrue(result["sources"]["cpu"]["budget_not_attempted"])
        self.assertTrue(result["sources"]["memory"]["budget_not_attempted"])
        self.assertTrue(result["sources"]["storage"]["budget_not_attempted"])
        self.assertIsNone(result["processes"])
        self.assertGreater(budget.used_bytes, 0)

    @unittest.skipUnless(platform.system() == "Darwin", "仅在本机 macOS 跑真实命令")
    def test_real_darwin_sample_records_actual_elapsed(self):
        result = sample_resources(self.fixture.policy(), process_due=False)
        self.assertIn(result["status"], {"ok", "partial"})
        self.assertEqual(result["platform"], "Darwin")
        self.assertTrue(result["host"]["cpu"]["available"])
        self.assertTrue(result["host"]["memory"]["available"])
        self.assertTrue(result["host"]["diskio"]["available"])
        self.assertTrue(result["host"]["network"]["available"])
        self.assertTrue(result["host"]["storage"]["available"])
        self.assertGreaterEqual(result["elapsed_seconds"], 0.0)
        print(f"\n[real macOS sample] elapsed={result['elapsed_seconds']:.3f}s "
              f"status={result['status']} sources="
              f"{sorted(result['sources'])}")


class ObserveCommandTests(unittest.TestCase):
    def test_command_metadata_covers_success_and_failure_paths(self):
        metadata = {}
        text = observe.command(
            [sys.executable, "-c",
             "import sys; sys.stdout.buffer.write('你好'.encode('utf-8'))"],
            max_bytes=1024, timeout=5, metadata=metadata)
        self.assertEqual(text, "你好")
        self.assertEqual(metadata["output_bytes"], len("你好".encode("utf-8")))

        self.assertEqual(metadata["output_bytes"], 6)
        with self.assertRaises(StewardError) as overflow:
            observe.command(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"],
                max_bytes=64, timeout=5, metadata=metadata)
        self.assertIn("输出超过", str(overflow.exception))
        self.assertGreater(overflow.exception.output_bytes, 64)
        self.assertEqual(metadata["output_bytes"], overflow.exception.output_bytes)

        with self.assertRaises(observe.CommandFailedError) as failed:
            observe.command(
                [sys.executable, "-c", "import sys; sys.stdout.write('err'); sys.exit(3)"],
                max_bytes=1024, timeout=5, metadata=metadata)
        self.assertEqual(failed.exception.returncode, 3)
        self.assertEqual(failed.exception.output_bytes, 3)
        self.assertEqual(metadata["output_bytes"], 3)

        with self.assertRaises(UnicodeDecodeError) as decode:
            observe.command(
                [sys.executable, "-c",
                 "import sys; sys.stdout.buffer.write(b'\\xff')"],
                max_bytes=1024, timeout=5, metadata=metadata)
        self.assertEqual(decode.exception.output_bytes, 1)
        self.assertEqual(metadata["output_bytes"], 1)

        with self.assertRaises(TimeoutError) as timeout:
            observe.command(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                max_bytes=1024, timeout=0.1, metadata=metadata)
        self.assertEqual(getattr(timeout.exception, "output_bytes", None), 0)
        self.assertEqual(metadata["output_bytes"], 0)

    def test_real_output_overflow_exhausts_runner_budget(self):
        runner = DarwinBudgetRunner(64, 5)
        with self.assertRaises(StewardError) as caught:
            runner.run([sys.executable, "-c",
                        "import sys; sys.stdout.write('x' * 100000)"],
                       source="overflow")
        self.assertIn("输出超过", str(caught.exception))
        self.assertGreaterEqual(caught.exception.output_bytes, 65)
        self.assertGreaterEqual(runner.used_bytes, 65)
        with self.assertRaises(DarwinBudgetExceeded) as blocked:
            runner.run([sys.executable, "-c", "raise SystemExit(0)"])
        self.assertEqual(blocked.exception.kind, "command_bytes")

    def test_runner_uses_reported_bytes_not_reencoded_text(self):
        def command(arguments, *, max_bytes, timeout, metadata=None):
            metadata["output_bytes"] = 9
            return "x"

        runner = DarwinBudgetRunner(10, 5, command=command)
        self.assertEqual(runner.run(["first"]), "x")
        self.assertEqual(runner.used_bytes, 9)
        # 若按返回文本重新编码只会计 1 字节；这里应剩 1 字节而不是 9 字节。
        self.assertEqual(runner.remaining_bytes, 1)

    def test_runner_supports_legacy_command_without_metadata(self):
        def command(arguments, *, max_bytes, timeout):
            return "abc"

        runner = DarwinBudgetRunner(3, 5, command=command)
        self.assertEqual(runner.run(["legacy"]), "abc")
        self.assertEqual(runner.used_bytes, 3)
        with self.assertRaises(DarwinBudgetExceeded):
            runner.run(["next"])


class DarwinRunnerTests(unittest.TestCase):
    def test_runner_never_resets_the_shared_deadline(self):
        class Clock:
            def __init__(self):
                self.value = 10.0

            def __call__(self):
                return self.value

        clock = Clock()
        calls = []

        def command(arguments, *, max_bytes, timeout, metadata=None):
            calls.append((arguments, max_bytes, timeout))
            clock.value += 0.5
            if metadata is not None:
                metadata["output_bytes"] = 2
            return "ok"

        runner = DarwinBudgetRunner(100, 1.0, clock=clock, command=command)
        self.assertEqual(runner.run(["first"]), "ok")
        self.assertEqual(runner.run(["second"]), "ok")
        with self.assertRaises(Exception):
            runner.run(["third"])
        self.assertEqual(len(calls), 2)
        self.assertLess(calls[1][2], calls[0][2])


if __name__ == "__main__":
    unittest.main()
