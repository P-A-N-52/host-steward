import errno
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

import linux_observe as linux
import observe
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
HugePages_Free:    2
HugePages_Rsvd:    1
HugePages_Surp:    0
Hugepagesize:   2048 kB
Odd:               7 MB
"""

# K6 真机 60 字段样式；带括号字段、无单位 HugePages 计数与未知单位各一处。
MEMINFO_REALISTIC = """MemTotal:       32784628 kB
MemFree:          5234567 kB
MemAvailable:   23456789 kB
Buffers:           654321 kB
Cached:           9876543 kB
SwapCached:             0 kB
Active:          12345678 kB
Inactive:         5678901 kB
Active(anon):     3456789 kB
Inactive(anon):    456789 kB
Active(file):     8888889 kB
Inactive(file):   5222112 kB
Unevictable:          32 kB
Mlocked:              32 kB
SwapTotal:       8388604 kB
SwapFree:        7340032 kB
Zswap:                 0 kB
Zswapped:              0 kB
Dirty:              4321 kB
Writeback:             0 kB
AnonPages:        4567890 kB
Mapped:           1234567 kB
Shmem:             345678 kB
KReclaimable:      456789 kB
Slab:              567890 kB
SReclaimable:      456789 kB
SUnreclaim:        111101 kB
KernelStack:        12345 kB
PageTables:         23456 kB
SecPageTables:          0 kB
NFS_Unstable:           0 kB
Bounce:                 0 kB
WritebackTmp:           0 kB
CommitLimit:     24575918 kB
Committed_AS:     6789012 kB
VmallocTotal:   34359738367 kB
VmallocUsed:        12345 kB
VmallocChunk:           0 kB
Percpu:              4567 kB
HardwareCorrupted:      0 kB
AnonHugePages:      123456 kB
ShmemHugePages:          0 kB
ShmemPmdMapped:          0 kB
FileHugePages:           0 kB
FilePmdMapped:           0 kB
CmaTotal:                0 kB
CmaFree:                 0 kB
Unaccepted:              0 kB
Balloon:                 0 kB
GPUActive:               0 kB
HugePages_Total:         4
HugePages_Free:          2
HugePages_Rsvd:          1
HugePages_Surp:          0
Hugepagesize:         2048 kB
Hugetlb:                 0 kB
DirectMap4k:        678901 kB
DirectMap2M:       8910112 kB
DirectMap1G:      16777216 kB
Odd:                     7 MB
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


class LinuxObserveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.proc = self.base / "proc"
        self.sys = self.base / "sys"
        self.proc.mkdir()
        self.sys.mkdir()
        self.write_proc("stat", CPU_STAT)
        self.write_proc("sys/kernel/random/boot_id", BOOT_ID + "\n")
        self.sysconf_values = {"SC_CLK_TCK": 100, "SC_PAGE_SIZE": 4096}

    def write_proc(self, relative, text):
        path = self.proc / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write_sys(self, relative, text):
        path = self.sys / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def source(self, **overrides):
        options = {
            "proc_root": self.proc,
            "sys_root": self.sys,
            "sysconf": lambda name: self.sysconf_values[name],
            "loadavg": lambda: (0.5, 0.25, 0.1),
        }
        options.update(overrides)
        return linux.LinuxSource(**options)

    def budget(self, command_bytes=1024 * 1024, seconds=5):
        return linux.LinuxBudget(command_bytes, seconds)

    def add_process(self, pid, **kwargs):
        self.write_proc(f"{pid}/stat", pid_stat(pid, **kwargs))

    def add_exe(self, pid, target="/usr/bin/bash"):
        os.symlink(target, self.proc / str(pid) / "exe")

    def write_ifindex(self, name, value):
        return self.write_sys(f"class/net/{name}/ifindex", f"{value}\n")

    def write_net_dev(self, *names):
        rows = [
            "Inter-|   Receive                                                |  Transmit",
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
        ]
        for index, name in enumerate(names, 1):
            counters = [index, 1, 0, 0, 0, 0, 0, 0, index, 1, 0, 0, 0, 0, 0, 0]
            rows.append(f"{name}: " + " ".join(str(value) for value in counters))
        self.write_proc("net/dev", "\n".join(rows) + "\n")

    def test_cpu_aggregate_ignores_nested_guest_and_reports_hz_cores_load(self):
        result = linux.observe_cpu(self.budget(), source=self.source())
        self.assertTrue(result["available"])
        self.assertEqual(result["counters"], {
            "user": 100, "nice": 2, "system": 30, "idle": 400,
            "iowait": 10, "irq": 5, "softirq": 6, "steal": 7,
        })
        self.assertEqual(result["hz"], 100)
        self.assertEqual(result["cores"], 2)
        self.assertEqual(result["load_average"], [0.5, 0.25, 0.1])
        self.assertNotIn("guest", result["counters"])
        self.assertIn("guest", result["counters_semantics"])

    def test_boot_uses_boot_id_and_keeps_btime(self):
        result = linux.observe_boot(self.budget(), proc_root=self.proc)
        self.assertTrue(result["available"])
        self.assertEqual(result["boot_id"], BOOT_ID)
        self.assertEqual(result["btime"], BTIME)
        self.assertEqual(result["unix_time"], BTIME)
        self.assertEqual(result["identity"], BOOT_ID)
        self.assertEqual(result["identity_kind"], "boot_id")
        self.assertIsNone(result["fallback"])
        self.assertIsNone(result["reason"])

    def test_boot_falls_back_to_btime_only_when_boot_id_is_missing(self):
        (self.proc / "sys/kernel/random/boot_id").unlink()
        result = linux.observe_boot(self.budget(), source=self.source())
        self.assertTrue(result["available"])
        self.assertIsNone(result["boot_id"])
        self.assertEqual(result["btime"], BTIME)
        self.assertEqual(result["fallback"], "btime")
        self.assertEqual(result["identity"], f"btime:{BTIME}")
        self.assertEqual(result["identity_kind"], "btime")
        self.assertIn("boot_id 不存在", result["reason"])

    def test_boot_other_failure_raises_instead_of_falling_back(self):
        boot_path = self.proc / "sys/kernel/random/boot_id"
        boot_path.unlink()
        boot_path.mkdir()
        with self.assertRaises(OSError):
            linux.observe_boot(self.budget(), source=self.source())

        boot_path.rmdir()
        boot_path.write_text("two tokens\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            linux.observe_boot(self.budget(), source=self.source())

        boot_path.write_text(BOOT_ID + "\n", encoding="utf-8")
        self.write_proc("stat", "cpu  1 2 3 4 5 6 7 8\ncpu0 1 2 3 4 5 6 7 8\n")
        with self.assertRaises(ValueError):
            linux.observe_boot(self.budget(), source=self.source())

    def test_meminfo_preserves_units_and_unitless_counts(self):
        self.write_proc("meminfo", MEMINFO)
        result = linux.observe_memory(self.budget(), source=self.source())
        self.assertEqual(result["total_bytes"], 1000 * 1024)
        self.assertEqual(result["available_bytes"], 400 * 1024)
        self.assertEqual(result["counters"]["MemTotal"], 1000 * 1024)
        self.assertEqual(result["counters"]["HugePages_Total"], 4)
        self.assertEqual(result["counters"]["HugePages_Free"], 2)
        self.assertEqual(result["counters"]["HugePages_Rsvd"], 1)
        self.assertEqual(result["counters"]["HugePages_Surp"], 0)
        self.assertEqual(result["counters"]["Hugepagesize"], 2048 * 1024)
        self.assertEqual(result["units"]["HugePages_Total"], "count")
        self.assertIsNone(result["source_units"]["HugePages_Total"])
        self.assertEqual(result["units"]["MemTotal"], "bytes")
        self.assertEqual(result["units"]["Odd"], "MB")
        self.assertEqual(result["counters"]["Odd"], 7)
        self.assertEqual(result["swap"]["total_bytes"], 500 * 1024)
        self.assertEqual(result["swap"]["free_bytes"], 300 * 1024)
        self.assertEqual(result["swap"]["used_bytes"], 200 * 1024)
        self.assertIn("不保证是历史高水位", result["swap"]["semantics"])

    def test_old_kernel_without_memavailable_is_a_platform_gap(self):
        self.write_proc("meminfo", "\n".join(
            line for line in MEMINFO.splitlines() if not line.startswith("MemAvailable:")) + "\n")
        result = linux.observe_memory(self.budget(), source=self.source())
        self.assertIsNone(result["available_bytes"])
        self.assertNotIn("MemAvailable", result["counters"])
        self.assertEqual(result["platform_gaps"][0]["field"], "MemAvailable")
        self.assertIn("不伪造", result["available_reason"])

    def test_memory_section_parses_full_meminfo_and_classifies_units(self):
        section = linux.memory_section(MEMINFO_REALISTIC)
        self.assertTrue(section["available"])
        self.assertIsNone(section["reason"])
        self.assertEqual(section["source"], "/proc/meminfo")
        self.assertEqual(len(section["counters"]), 60)
        self.assertEqual(section["total_bytes"], 32784628 * 1024)
        self.assertEqual(section["available_bytes"], 23456789 * 1024)
        self.assertEqual(section["counters"]["Active(anon)"], 3456789 * 1024)
        self.assertEqual(section["counters"]["Inactive(file)"], 5222112 * 1024)
        self.assertEqual(section["units"]["Active(anon)"], "bytes")
        self.assertEqual(section["counters"]["HugePages_Total"], 4)
        self.assertEqual(section["counters"]["HugePages_Free"], 2)
        self.assertEqual(section["counters"]["HugePages_Rsvd"], 1)
        self.assertEqual(section["counters"]["HugePages_Surp"], 0)
        self.assertEqual(section["units"]["HugePages_Total"], "count")
        self.assertIsNone(section["source_units"]["HugePages_Total"])
        self.assertEqual(section["counters"]["Hugepagesize"], 2048 * 1024)
        self.assertEqual(section["units"]["Hugepagesize"], "bytes")
        self.assertEqual(section["counters"]["Odd"], 7)
        self.assertEqual(section["units"]["Odd"], "MB")
        self.assertEqual(section["source_units"]["Odd"], "MB")
        self.assertEqual(section["platform_gaps"], [])
        self.assertIsNone(section["available_reason"])
        self.assertEqual(section["swap"]["total_bytes"], 8388604 * 1024)
        self.assertEqual(section["swap"]["free_bytes"], 7340032 * 1024)
        self.assertEqual(section["swap"]["used_bytes"], (8388604 - 7340032) * 1024)
        self.assertIn("units=count", section["units_semantics"])

    def test_memory_section_missing_memavailable_is_a_platform_gap(self):
        text = "\n".join(line for line in MEMINFO_REALISTIC.splitlines()
                         if not line.startswith("MemAvailable:")) + "\n"
        section = linux.memory_section(text)
        self.assertIsNone(section["available_bytes"])
        self.assertNotIn("MemAvailable", section["counters"])
        self.assertEqual(section["platform_gaps"], [{
            "field": "MemAvailable",
            "reason": "旧内核 /proc/meminfo 未提供 MemAvailable；不伪造推导值"}])
        self.assertEqual(section["available_reason"], section["platform_gaps"][0]["reason"])
        adapted = observe.observe_linux_memory(
            {"command_bytes": 262144},
            source=self.source(read_bytes=lambda path, limit: text.encode("utf-8")))
        self.assertEqual(adapted["platform_gaps"], section["platform_gaps"])
        self.assertIsNone(adapted["available_bytes"])

    def test_memory_section_rejects_inconsistent_or_malformed_fields(self):
        base = MEMINFO_REALISTIC.splitlines()
        cases = {
            "duplicate field": base + ["MemFree: 1 kB"],
            "swap free above total": [
                line.replace("SwapFree:        7340032 kB", "SwapFree:        9340032 kB")
                for line in base],
            "available above total": [
                line.replace("MemAvailable:   23456789 kB", "MemAvailable:   93456789 kB")
                for line in base],
            "MemTotal zero": [
                line.replace("MemTotal:       32784628 kB", "MemTotal:              0 kB")
                for line in base],
            "wrong MemTotal unit": [
                line.replace("MemTotal:       32784628 kB", "MemTotal:       32784628 MB")
                for line in base],
            "wrong SwapTotal unit": [
                line.replace("SwapTotal:       8388604 kB", "SwapTotal:       8388604 MB")
                for line in base],
            "wrong MemAvailable unit": [
                line.replace("MemAvailable:   23456789 kB", "MemAvailable:   23456789 MB")
                for line in base],
            "malformed line": base + ["not a meminfo line"],
        }
        for label, lines in cases.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                linux.memory_section("\n".join(lines) + "\n")

    def test_memory_section_matches_observe_memory_and_patrol_adapter(self):
        expected = linux.memory_section(MEMINFO_REALISTIC)
        source = self.source(read_bytes=lambda path, limit: MEMINFO_REALISTIC.encode("utf-8"))
        self.assertEqual(linux.observe_memory(self.budget(), source=source), expected)
        adapted = observe.observe_linux_memory({"command_bytes": 262144}, source=source)
        self.assertEqual(adapted, dict(expected, semantics=expected["units_semantics"]))
        self.assertEqual(adapted["semantics"], adapted["units_semantics"])
        self.assertEqual(set(adapted), set(expected) | {"semantics"})

    def test_observe_linux_memory_uses_command_byte_budget(self):
        source = self.source(read_bytes=lambda path, limit: MEMINFO_REALISTIC.encode("utf-8"))
        with self.assertRaises(linux.LinuxBudgetExceededError) as raised:
            observe.observe_linux_memory({"command_bytes": 64}, source=source)
        self.assertEqual(raised.exception.kind, "command_bytes")

    def test_meminfo_required_and_inconsistent_fields_raise(self):
        base = MEMINFO.splitlines()
        cases = {
            "missing MemTotal": [line for line in base if not line.startswith("MemTotal:")],
            "missing SwapTotal": [line for line in base if not line.startswith("SwapTotal:")],
            "missing SwapFree": [line for line in base if not line.startswith("SwapFree:")],
            "swap free above total": [line.replace("SwapFree:        300 kB", "SwapFree:        600 kB")
                                      for line in base],
            "available above total": [line.replace("MemAvailable:    400 kB", "MemAvailable:   1200 kB")
                                      for line in base],
            "wrong MemTotal unit": [line.replace("MemTotal:       1000 kB", "MemTotal:       1000 MB")
                                    for line in base],
            "wrong MemAvailable unit": [line.replace("MemAvailable:    400 kB", "MemAvailable:    400 MB")
                                        for line in base],
            "malformed line": base + ["not a meminfo line"],
        }
        for label, lines in cases.items():
            with self.subTest(label=label):
                self.write_proc("meminfo", "\n".join(lines) + "\n")
                with self.assertRaises(ValueError):
                    linux.observe_memory(self.budget(), source=self.source())

    def test_diskstats_uses_512_byte_sectors_and_marks_non_additive_devices(self):
        self.write_proc("diskstats", "\n".join([
            "   8       0 sda 10 2 100 5 20 3 200 7 1 8 9",
            "   8       1 sda1 8 0 80 4 16 0 160 6 0 7 8",
            " 253       0 dm-0 4 1 40 2 8 1 80 3 2 4 5 6 7 20 8 9 10 11",
        ]) + "\n")
        self.write_sys("dev/block/8:0/device/wwid", "naa.6000000000000001\n")
        (self.sys / "dev/block/8:1").mkdir(parents=True)
        self.write_sys("dev/block/8:1/partition", "1\n")
        (self.sys / "dev/block/253:0/dm").mkdir(parents=True)
        self.write_sys("dev/block/253:0/device/serial", "DM-SERIAL-1\n")

        result = linux.observe_diskio(self.budget(), source=self.source())
        self.assertTrue(result["available"])
        self.assertTrue(result["non_additive"])
        self.assertEqual(result["aggregation"], "non_additive")
        self.assertEqual(result["sector_bytes"], 512)
        self.assertNotIn("total_bytes", result)
        self.assertIs(result["devices"], result["disks"])
        by_name = {row["name"]: row for row in result["devices"]}
        self.assertEqual(by_name["sda"]["read_bytes"], 100 * 512)
        self.assertEqual(by_name["sda"]["write_bytes"], 200 * 512)
        self.assertEqual(by_name["sda"]["sectors_read"], 100)
        self.assertEqual(by_name["sda"]["reads_completed"], 10)
        self.assertEqual(by_name["sda"]["io_time_ms"], 8)
        self.assertEqual(by_name["sda"]["weighted_io_time_ms"], 9)
        self.assertFalse(by_name["sda"]["partition"])
        self.assertEqual(by_name["sda"]["device_type"], "whole")
        self.assertEqual(by_name["sda"]["identity"], "naa.6000000000000001")
        self.assertTrue(by_name["sda1"]["partition"])
        self.assertEqual(by_name["sda1"]["partition_index"], 1)
        self.assertEqual(by_name["sda1"]["device_type"], "partition")
        self.assertEqual(by_name["dm-0"]["device_type"], "virtual:dm")
        self.assertEqual(by_name["dm-0"]["identity"], "DM-SERIAL-1")
        self.assertEqual(by_name["dm-0"]["discards_completed"], 6)
        self.assertEqual(by_name["dm-0"]["flushes_completed"], 9)
        self.assertFalse(any(row["additive"] for row in result["devices"]))
        self.assertEqual([gap["device"] for gap in result["comparison_gaps"]], ["sda1"])
        self.assertEqual(result["lifecycle_evidence"], {"stable_identity": 2, "without_identity": 1})

    def test_diskstats_empty_is_capability_and_bad_line_raises(self):
        self.write_proc("diskstats", "")
        result = linux.observe_diskio(self.budget(), source=self.source())
        self.assertFalse(result["available"])
        self.assertEqual(result["devices"], [])
        self.assertIn("没有块设备", result["reason"])

        self.write_proc("diskstats", "8 0 sda 1 2\n")
        with self.assertRaises(ValueError):
            linux.observe_diskio(self.budget(), source=self.source())

    def test_diskstats_without_sysfs_returns_identity_gaps(self):
        self.write_proc("diskstats", "8 0 sda 1 0 1 0 1 0 1 0 0 0 0\n")
        result = linux.observe_diskio(self.budget(), source=self.source())
        row = result["devices"][0]
        self.assertIsNone(row["partition"])
        self.assertIsNone(row["identity"])
        self.assertEqual(row["device_type"], "unknown")
        self.assertEqual(result["comparison_gaps"][0]["device"], "sda")

    def test_network_parses_fixed_fields_and_bounds_interfaces(self):
        self.write_proc("net/dev", """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0
  eth0: 5000 50 0 0 0 0 0 0 6000 60 1 2 0 0 0 0
 wlan0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0
""")
        self.write_ifindex("eth0", 7)
        result = linux.observe_network(self.budget(), source=self.source(), limit=1)
        self.assertTrue(result["available"])
        interfaces = result["interfaces"]
        self.assertEqual(interfaces["observed"], 3)
        self.assertEqual(interfaces["returned"], 1)
        self.assertEqual(interfaces["omitted"], 2)
        self.assertTrue(interfaces["truncated"])
        row = interfaces["items"][0]
        self.assertEqual(row["name"], "eth0")
        self.assertEqual(row["ibytes"], 5000)
        self.assertEqual(row["ipackets"], 50)
        self.assertEqual(row["ierrs"], 0)
        self.assertEqual(row["idrop"], 0)
        self.assertEqual(row["obytes"], 6000)
        self.assertEqual(row["opackets"], 60)
        self.assertEqual(row["oerrs"], 1)
        self.assertEqual(row["odrop"], 2)
        self.assertEqual(row["ifindex"], 7)
        self.assertEqual(row["identity"], "ifindex:7")
        self.assertEqual(row["identity_source"], "sysfs:class/net/eth0/ifindex")
        self.assertIsNone(row["identity_reason"])
        self.assertEqual(result["comparison_gaps"], [])
        self.assertFalse(result["tcp_states"]["available"])

    def test_network_empty_and_bad_line(self):
        self.write_proc("net/dev", "")
        result = linux.observe_network(self.budget(), source=self.source())
        self.assertFalse(result["available"])
        self.assertFalse(result["interfaces"]["available"])
        self.assertEqual(result["interfaces"]["observed"], 0)

        self.write_proc("net/dev", "eth0: 1 2 3\n")
        with self.assertRaises(ValueError):
            linux.observe_network(self.budget(), source=self.source())

    def test_network_ifindex_identity_changes_and_tracks_add_remove(self):
        self.write_net_dev("eth0")
        self.write_ifindex("eth0", 3)
        first = linux.observe_network(self.budget(), source=self.source())
        first_row = first["interfaces"]["items"][0]
        self.assertEqual(first_row["ifindex"], 3)
        self.assertEqual(first_row["identity"], "ifindex:3")
        self.assertEqual(first["comparison_gaps"], [])

        self.write_ifindex("eth0", 4)
        second = linux.observe_network(self.budget(), source=self.source())
        second_row = second["interfaces"]["items"][0]
        self.assertEqual(second_row["ifindex"], 4)
        self.assertNotEqual(second_row["identity"], first_row["identity"])

        self.write_ifindex("wlan0", 5)
        self.write_net_dev("eth0", "wlan0")
        added = linux.observe_network(self.budget(), source=self.source())
        self.assertEqual([row["name"] for row in added["interfaces"]["items"]], ["eth0", "wlan0"])
        self.assertEqual(added["interfaces"]["observed"], 2)
        added_by_name = {row["name"]: row for row in added["interfaces"]["items"]}
        self.assertEqual(added_by_name["eth0"]["identity"], "ifindex:4")
        self.assertEqual(added_by_name["wlan0"]["identity"], "ifindex:5")

        self.write_net_dev("wlan0")
        removed = linux.observe_network(self.budget(), source=self.source())
        self.assertEqual([row["name"] for row in removed["interfaces"]["items"]], ["wlan0"])
        self.assertEqual(removed["interfaces"]["observed"], 1)
        self.assertEqual(removed["interfaces"]["items"][0]["identity"], "ifindex:5")

    def test_network_ifindex_gap_and_non_capability_errors(self):
        self.write_net_dev("eth0")
        result = linux.observe_network(self.budget(), source=self.source())
        row = result["interfaces"]["items"][0]
        self.assertIsNone(row["ifindex"])
        self.assertIsNone(row["identity"])
        self.assertIn("ifindex", row["identity_reason"])
        self.assertEqual(result["comparison_gaps"],
                         [{"interface": "eth0", "reason": row["identity_reason"]}])

        self.write_ifindex("eth0", "0")
        with self.assertRaises(ValueError):
            linux.observe_network(self.budget(), source=self.source())

        self.write_ifindex("eth0", "3")

        def denied_ifindex(path, limit):
            if path.endswith("/ifindex"):
                raise PermissionError(errno.EACCES, "denied", path)
            return Path(path).read_bytes()

        with self.assertRaises(PermissionError):
            linux.observe_network(self.budget(), source=self.source(read_bytes=denied_ifindex))

    def test_process_complex_comm_ticks_rss_and_pid_lifecycle(self):
        pid = 1234
        self.add_process(pid, comm="name ) with ( paren", ppid=42, utime=12, stime=34,
                         start_ticks=250, rss_pages=3, threads=2)
        self.add_exe(pid, "/usr/bin/bash")
        result = linux.observe_processes(
            self.budget(), residents=[{"executable": "bash", "reason": "shell"}], source=self.source())
        self.assertTrue(result["complete"])
        self.assertFalse(result["partial"])
        self.assertEqual(result["observed"], 1)
        row = result["items"][0]
        self.assertEqual(row["pid"], pid)
        self.assertEqual(row["comm"], "name ) with ( paren")
        self.assertEqual(row["parent_pid"], 42)
        self.assertEqual(row["ppid"], 42)
        self.assertEqual(row["start_ticks"], 250)
        self.assertEqual(row["boot_id"], BOOT_ID)
        self.assertEqual(row["identity"], f"{pid}:{BOOT_ID}:250")
        self.assertAlmostEqual(row["started"], BTIME + 2.5)
        self.assertEqual(row["cpu_ticks"], {"user": 12, "system": 34, "total": 46})
        self.assertEqual(row["hz"], 100)
        self.assertAlmostEqual(row["cpu_seconds"]["total"], 0.46)
        self.assertEqual(row["rss_pages"], 3)
        self.assertEqual(row["rss_bytes"], 3 * 4096)
        self.assertEqual(row["page_size"], 4096)
        self.assertEqual(row["executable"], "/usr/bin/bash")
        self.assertEqual(row["executable_status"], "available")
        self.assertTrue(row["resident"])
        self.assertEqual(row["protection"], "shell")
        self.assertNotIn("cpu_percent", row)

        self.add_process(pid, comm="name ) with ( paren", ppid=42, utime=12, stime=34,
                         start_ticks=300, rss_pages=3, threads=2)
        changed = linux.observe_processes(self.budget(), source=self.source())["items"][0]
        self.assertEqual(changed["start_ticks"], 300)
        self.assertNotEqual(changed["identity"], row["identity"])
        self.assertAlmostEqual(changed["started"], BTIME + 3.0)

    def test_process_exit_race_is_counted_and_partial(self):
        (self.proc / "200").mkdir()
        result = linux.observe_processes(self.budget(), source=self.source())
        self.assertEqual(result["observed"], 0)
        self.assertEqual(result["exit_races"], 1)
        self.assertTrue(result["partial"])
        self.assertFalse(result["truncated"])
        self.assertFalse(result["complete"])
        self.assertEqual(result["omitted"]["exit_races"], 1)
        self.assertIn("exit race", result["partial_reason"])

    def test_process_identity_change_during_exe_read_is_discarded(self):
        pid = 321
        self.add_process(pid, start_ticks=100)
        self.add_exe(pid)

        def replace_stat(path):
            if path.endswith(f"/{pid}/exe"):
                self.add_process(pid, start_ticks=200)
            return os.readlink(path)

        result = linux.observe_processes(
            self.budget(), source=self.source(readlink=replace_stat))
        self.assertEqual(result["items"], [])
        self.assertEqual(result["observed"], 0)
        self.assertEqual(result["identity_races"], 1)
        self.assertEqual(result["exit_races"], 0)
        self.assertTrue(result["partial"])
        self.assertFalse(result["complete"])
        self.assertEqual(result["omitted"]["identity_races"], 1)
        self.assertIn("identity race", result["partial_reason"])

    def test_process_disappearance_during_exe_read_is_exit_race(self):
        pid = 322
        self.add_process(pid)
        self.add_exe(pid)

        def remove_stat(path):
            if path.endswith(f"/{pid}/exe"):
                (self.proc / str(pid) / "stat").unlink()
            return os.readlink(path)

        result = linux.observe_processes(
            self.budget(), source=self.source(readlink=remove_stat))
        self.assertEqual(result["items"], [])
        self.assertEqual(result["observed"], 0)
        self.assertEqual(result["exit_races"], 1)
        self.assertEqual(result["identity_races"], 0)
        self.assertTrue(result["partial"])
        self.assertEqual(result["omitted"]["exit_races"], 1)
        self.assertIn("exit race", result["partial_reason"])

    def test_process_second_stat_permission_raises(self):
        pid = 323
        self.add_process(pid)
        self.add_exe(pid)
        reads = {"count": 0}

        def read_bytes(path, limit):
            if path.endswith(f"/{pid}/stat"):
                reads["count"] += 1
                if reads["count"] == 2:
                    raise PermissionError(errno.EACCES, "denied", path)
            return Path(path).read_bytes()

        with self.assertRaises(PermissionError):
            linux.observe_processes(self.budget(), source=self.source(read_bytes=read_bytes))
        self.assertEqual(reads["count"], 2)

    def test_process_entries_limit_is_bounded_and_marks_unknown_omission(self):
        for pid in [100, 101, 102, 103, 104]:
            self.add_process(pid)
        source = self.source(listdir=lambda path: ["100", "101", "102", "103", "104", "not-a-pid"])
        result = linux.observe_processes(
            self.budget(), limit=20, entries_limit=3, source=source)
        self.assertEqual(result["entries_examined"], 3)
        self.assertEqual(result["observed"], 3)
        self.assertTrue(result["entries_truncated"])
        self.assertTrue(result["partial"])
        self.assertTrue(result["truncated"])
        self.assertFalse(result["complete"])
        self.assertIsNone(result["omitted"]["not_examined"])
        self.assertFalse(result["omitted"]["not_examined_known"])
        self.assertEqual(result["omitted"]["not_returned"], 0)
        self.assertIn("entries_limit=3", result["partial_reason"])

    def test_process_top_rss_keeps_resident_rule_priority(self):
        self.add_process(1, rss_pages=1)
        self.add_process(2, rss_pages=2)
        self.add_process(3, rss_pages=3)
        self.add_process(4, rss_pages=4)
        for pid in [1, 2, 3, 4]:
            self.add_exe(pid, "/usr/bin/bash" if pid == 1 else "/usr/bin/python3")
        result = linux.observe_processes(
            self.budget(), residents=[{"executable": "bash", "reason": "protected"}],
            limit=2, source=self.source())
        self.assertEqual(result["observed"], 4)
        self.assertEqual(result["returned"], 2)
        self.assertEqual([row["pid"] for row in result["items"]], [1, 4])
        self.assertEqual(result["items"][0]["protection"], "protected")
        self.assertEqual(result["omitted"]["not_returned"], 2)
        self.assertTrue(result["truncated"])
        self.assertFalse(result["partial"])

    def test_process_kernel_thread_without_exe_is_not_an_exit(self):
        self.add_process(7, comm="kworker/0:1", state="I")
        result = linux.observe_processes(self.budget(), source=self.source())
        self.assertEqual(result["returned"], 1)
        self.assertEqual(result["exit_races"], 0)
        self.assertFalse(result["partial"])
        self.assertEqual(result["executable_unavailable"], 1)
        row = result["items"][0]
        self.assertIsNone(row["executable"])
        self.assertEqual(row["executable_status"], "no_exe")
        self.assertEqual(row["executable_error"]["errno"], errno.ENOENT)
        self.assertIn("内核线程", row["executable_error"]["reason"])

    def test_process_exe_permission_is_a_field_gap_but_stat_permission_raises(self):
        pid = 8
        self.add_process(pid)
        self.add_exe(pid)

        def denied_readlink(path):
            if path.endswith(f"/{pid}/exe"):
                raise PermissionError(errno.EACCES, "denied", path)
            return os.readlink(path)

        result = linux.observe_processes(
            self.budget(), source=self.source(readlink=denied_readlink))
        row = result["items"][0]
        self.assertIsNone(row["executable"])
        self.assertEqual(row["executable_status"], "permission_denied")
        self.assertEqual(row["executable_error"]["errno"], errno.EACCES)
        self.assertEqual(result["executable_unavailable"], 1)
        self.assertEqual(result["observed"], 1)

        other = 9
        self.add_process(other)

        def denied_stat(path, limit):
            if path.endswith(f"/{other}/stat"):
                raise PermissionError(errno.EACCES, "denied", path)
            return Path(path).read_bytes()

        with self.assertRaises(PermissionError):
            linux.observe_processes(
                self.budget(), entries_limit=1,
                source=self.source(listdir=lambda path: [str(other)], read_bytes=denied_stat))

    def test_zero_size_stat_files_still_read_nonempty_proc_content(self):
        self.write_proc("meminfo", MEMINFO)
        self.write_proc("diskstats", "8 0 sda 1 0 2 0 3 0 4 0 0 0 0\n")
        self.write_net_dev("eth0")
        self.write_ifindex("eth0", 4)
        self.add_process(555, start_ticks=42)
        self.add_exe(555)
        real_fstat = os.fstat

        def zero_size(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_size=0)

        with patch.object(linux.os, "fstat", side_effect=zero_size):
            boot = linux.observe_boot(self.budget(), source=self.source())
            cpu = linux.observe_cpu(self.budget(), source=self.source())
            memory = linux.observe_memory(self.budget(), source=self.source())
            diskio = linux.observe_diskio(self.budget(), source=self.source())
            network = linux.observe_network(self.budget(), source=self.source())
            processes = linux.observe_processes(self.budget(), source=self.source())

        self.assertEqual(boot["boot_id"], BOOT_ID)
        self.assertEqual(boot["btime"], BTIME)
        self.assertEqual(cpu["counters"]["user"], 100)
        self.assertEqual(memory["total_bytes"], 1000 * 1024)
        self.assertTrue(diskio["available"])
        self.assertEqual(diskio["devices"][0]["name"], "sda")
        self.assertEqual(network["interfaces"]["items"][0]["ifindex"], 4)
        self.assertEqual(processes["observed"], 1)
        self.assertEqual(processes["items"][0]["pid"], 555)
        self.assertEqual(processes["items"][0]["start_ticks"], 42)

    def test_truly_empty_file_returns_eof(self):
        empty = self.write_proc("empty", "")
        budget = self.budget()
        self.assertEqual(self.source().read_bytes(empty, budget), b"")
        self.assertEqual(budget.used_bytes, 0)
        self.assertEqual(budget.reads, 1)

    def test_zero_size_source_byte_and_time_limits(self):
        path = self.write_proc("large", "x" * 200_000)
        real_fstat = os.fstat

        def zero_size(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_size=0)

        with patch.object(linux.os, "fstat", side_effect=zero_size):
            with self.assertRaises(linux.LinuxBudgetExceededError) as byte_error:
                self.source().read_bytes(path, linux.LinuxBudget(100, 5), max_bytes=1000)
            self.assertEqual(byte_error.exception.kind, "command_bytes")

            ticks = {"count": 0}

            def clock():
                ticks["count"] += 1
                return 0.0 if ticks["count"] <= 3 else 2.0

            reads = []
            real_read = os.read

            def counting_read(fd, size):
                reads.append(size)
                return real_read(fd, size)

            with patch.object(linux.os, "read", side_effect=counting_read):
                with self.assertRaises(linux.LinuxBudgetExceededError) as time_error:
                    self.source().read_bytes(
                        path, linux.LinuxBudget(1_000_000, 1.0, clock=clock),
                        max_bytes=1_000_000)
            self.assertEqual(time_error.exception.kind, "time")
            self.assertEqual(len(reads), 1)

    def test_injected_read_not_called_with_zero_budget(self):
        calls = []

        def read_hook(path, limit):
            calls.append((path, limit))
            return b"x"

        source = self.source(read_bytes=read_hook)
        with self.assertRaises(linux.LinuxBudgetExceededError) as byte_error:
            source.read_bytes(self.proc / "stat", linux.LinuxBudget(0, 5))
        self.assertEqual(byte_error.exception.kind, "command_bytes")

        with self.assertRaises(linux.LinuxBudgetExceededError) as time_error:
            source.read_bytes(self.proc / "stat", linux.LinuxBudget(100, 0, clock=lambda: 0.0))
        self.assertEqual(time_error.exception.kind, "time")
        self.assertEqual(calls, [])

    def test_budget_and_read_limit_errors_are_not_execution_failures(self):
        self.write_proc("meminfo", MEMINFO)
        with self.assertRaises(linux.LinuxBudgetExceededError) as byte_error:
            linux.observe_memory(linux.LinuxBudget(64, 5), source=self.source())
        self.assertEqual(byte_error.exception.kind, "command_bytes")
        self.assertIsInstance(byte_error.exception, StewardError)
        self.assertNotIsInstance(byte_error.exception, OSError)

        ticks = [0.0]

        def clock():
            value = ticks[0]
            ticks[0] += 0.6
            return value

        with self.assertRaises(linux.LinuxBudgetExceededError) as time_error:
            linux.observe_cpu(linux.LinuxBudget(1_000_000, 1.0, clock=clock), source=self.source())
        self.assertEqual(time_error.exception.kind, "time")
        self.assertNotIsInstance(time_error.exception, OSError)

        with self.assertRaises(linux.LinuxReadLimitError) as limit_error:
            self.source().read_bytes(self.proc / "meminfo", linux.LinuxBudget(1_000_000, 5),
                                     max_bytes=16)
        self.assertIsInstance(limit_error.exception, StewardError)
        self.assertNotIsInstance(limit_error.exception, OSError)

    def test_failed_reads_keep_byte_cost_and_do_not_reset_shared_budget(self):
        path = self.write_proc("oversized", "x" * 64)
        budget = linux.LinuxBudget(16, 5)
        with self.assertRaises(linux.LinuxBudgetExceededError):
            self.source().read_bytes(path, budget, max_bytes=64)
        self.assertEqual(budget.used_bytes, 17)
        self.assertEqual(budget.remaining_bytes, 0)
        with patch.object(linux.os, "read") as reader:
            with self.assertRaises(linux.LinuxBudgetExceededError):
                self.source().read_bytes(self.proc / "stat", budget)
            reader.assert_not_called()
        file_budget = linux.LinuxBudget(100, 5)
        with self.assertRaises(linux.LinuxReadLimitError):
            self.source().read_bytes(path, file_budget, max_bytes=16)
        self.assertEqual(file_budget.used_bytes, 17)
        self.assertEqual(file_budget.remaining_bytes, 83)

    def test_read_crossing_deadline_still_records_consumed_bytes(self):
        path = self.write_proc("slow", "payload")
        ticks = [0.0]
        budget = linux.LinuxBudget(100, 1, clock=lambda: ticks[0])
        original_read = os.read
        def slow_read(fd, count):
            data = original_read(fd, count)
            ticks[0] = 2.0
            return data
        with patch.object(linux.os, "read", side_effect=slow_read):
            with self.assertRaises(linux.LinuxBudgetExceededError) as error:
                self.source().read_bytes(path, budget)
        self.assertEqual(error.exception.kind, "time")
        self.assertEqual(budget.used_bytes, 7)

    def test_injected_over_budget_read_is_accounted(self):
        budget = linux.LinuxBudget(10, 5)
        source = self.source(read_bytes=lambda path, limit: b"x" * 20)
        with self.assertRaises(linux.LinuxBudgetExceededError):
            source.read_bytes(self.proc / "stat", budget)
        self.assertEqual(budget.used_bytes, 20)
        self.assertEqual(budget.remaining_bytes, 0)

    def test_process_stat_read_is_bounded_before_parse(self):
        pid = 999
        self.add_process(pid)
        stat_path = self.proc / str(pid) / "stat"
        stat_path.write_text(stat_path.read_text(encoding="utf-8") + " " + "0" * linux.PID_STAT_BYTES,
                             encoding="utf-8")
        with self.assertRaises(linux.LinuxReadLimitError) as raised:
            linux.observe_processes(self.budget(), source=self.source())
        self.assertEqual(raised.exception.limit, linux.PID_STAT_BYTES)


if __name__ == "__main__":
    unittest.main()
