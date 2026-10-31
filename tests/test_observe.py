import platform
import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from observe import CommandFailedError, observe_gpu, parse_gpu_statistics
from steward import initialize, patrol


LIMITS = {"command_bytes": 262144}
UNKNOWN_METRICS = ('"PerformanceStatistics" = {"recoveryCount"=0,"lastRecoveryTime"=0,'
                   '"TiledSceneBytes"=819200}')
KNOWN_METRICS = ('"PerformanceStatistics" = {"Device Utilization %"=62,"Renderer Utilization %"=62,'
                 '"Tiler Utilization %"=62,"Alloc system memory"=1671708672,'
                 '"In use system memory"=649166848}')


def gpu_result(text, machine="x86_64"):
    with patch("observe.platform.machine", return_value=machine), \
         patch("observe.command", return_value=text):
        return observe_gpu(LIMITS)


class GpuCapabilityTests(unittest.TestCase):
    def test_parser_keeps_malformed_structure_as_error(self):
        with self.assertRaisesRegex(ValueError, "结构无法解析"):
            parse_gpu_statistics('"PerformanceStatistics" = {"Device Utilization %"=62')

    def test_missing_statistics_reports_unavailable(self):
        for text in ["", "+-o IOAccelerator  <class IOAccelerator>\n      {\n"]:
            with self.subTest(text=text):
                self.assertEqual(gpu_result(text), {
                    "available": False,
                    "reason": "IOAccelerator 没有 PerformanceStatistics 属性",
                })

    def test_empty_or_unknown_metrics_report_unavailable(self):
        for text in ['"PerformanceStatistics" = { }', UNKNOWN_METRICS]:
            with self.subTest(text=text):
                result = gpu_result(text)
                self.assertFalse(result["available"])
                self.assertEqual(result["reason"], "IOAccelerator 的 PerformanceStatistics 不含已知 GPU 指标")
                self.assertNotIn("device_utilization_percent", result)

    def test_known_metrics_stay_available(self):
        result = gpu_result(KNOWN_METRICS, machine="arm64")
        self.assertTrue(result["available"])
        self.assertEqual(result["device_utilization_percent"], 62)
        self.assertEqual(result["allocated_bytes"], 1671708672)
        self.assertEqual(result["source_class"], "IOGPU")

    def test_command_failure_is_not_capability_absence(self):
        failure = CommandFailedError(1, "ioreg -r -d 1 -w 0 -c IOAccelerator", "ioreg: error\n")
        with patch("observe.platform.machine", return_value="x86_64"), \
             patch("observe.command", side_effect=failure), \
             self.assertRaises(CommandFailedError):
            observe_gpu(LIMITS)


class PatrolGpuCapabilityTests(unittest.TestCase):
    def test_patrol_reports_gpu_unavailable_instead_of_crashing(self):
        responses = {
            ("ps", "-axo", "pid=,ppid=,lstart=,pcpu=,rss=,comm="):
                "42 1 Fri Oct 16 10:00:00 2026 0.0 100 /usr/bin/example\n",
            ("sysctl", "-n", "kern.boottime"):
                "{ sec = 1791379437, usec = 417 } Wed Oct  7 21:23:57 2026\n",
            ("vm_stat",):
                "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
                "Pages free: 1000.\n"
                "Pages active: 2000.\n",
            ("sysctl", "-n", "hw.memsize"): "8589934592\n",
            ("sysctl", "-n", "vm.swapusage"):
                "total = 2048.00M  used = 0.00M  free = 2048.00M  (encrypted)\n",
            ("launchctl", "list"): "PID\tStatus\tLabel\n1\t0\tcom.example\n",
            ("iostat", "-c", "2"):
                "              disk0       cpu    load average\n"
                "    KB/t  tps  MB/s  us sy id   1m   5m   15m\n"
                "   28.79   60  1.68   8  5 87  1.71 2.34 2.71\n"
                "   12.22  159  1.90   7  5 88  1.57 2.30 2.70\n",
            ("ioreg", "-r", "-d", "1", "-w", "0", "-c", "IOAccelerator"):
                "+-o IOAccelerator  <class IOAccelerator>\n"
                "  {\n    " + UNKNOWN_METRICS + "\n  }\n",
            ("netstat", "-ib"):
                "Name  Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n"
                "en0 1500 <Link#4> a4:83:e7:12:34:56 123456 7 987654 654321 2 456789 0\n",
            ("netstat", "-an"): "tcp4 0 0 *.5000 *.* LISTEN\n",
            ("pmset", "-g", "batt"): "Now drawing from 'AC Power'\n",
            ("pmset", "-g", "therm"): "Note: No thermal warning level has been recorded\n",
        }

        def response(arguments, *args, **kwargs):
            return responses[tuple(arguments)]

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "root"
            root.mkdir()
            store, policy = initialize(base / "state", [root], "GPU 能力缺失巡检")
            # 只替换 observe 模块引用的 platform：host.json 与主机标识核对仍使用真实 platform。
            darwin = SimpleNamespace(system=lambda: "Darwin", machine=lambda: "x86_64",
                                     node=platform.node)
            with patch("observe.platform", darwin), \
                 patch("observe.command", side_effect=response):
                report = patrol(store, policy)
        self.assertEqual(report["status"], "observed")
        self.assertEqual(report["host"]["gpu"], {
            "available": False,
            "reason": "IOAccelerator 的 PerformanceStatistics 不含已知 GPU 指标",
        })


if __name__ == "__main__":
    unittest.main()
