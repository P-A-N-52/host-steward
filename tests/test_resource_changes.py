import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from resource_changes import resource_changes


class ResourceChangesTests(unittest.TestCase):
    def sample(self, at, multiplier=1):
        return {
            "run_id": "run-a", "boot": {"boot_id": "boot-a"},
            "observed_at": at, "monotonic_at": at - 900,
            "host": {
                "cpu": {"available": True, "hz": 100,
                        "counters": {"user": multiplier * 10, "nice": 0, "system": multiplier * 10,
                                     "idle": multiplier * 70, "iowait": multiplier * 10,
                                     "irq": 0, "softirq": 0, "steal": 0}},
                "memory": {"available": True, "total_bytes": 1000, "available_bytes": 800 - multiplier * 10,
                           "swap": {"available": True, "used_bytes": multiplier * 20}},
                "network": {"available": True, "interfaces": {"available": True, "items": [
                    {"name": "eth0", "ifindex": 2, "ibytes": multiplier * 100,
                     "obytes": multiplier * 200, "ipackets": multiplier * 10,
                     "opackets": multiplier * 20, "ierrs": 0, "oerrs": 0}]}},
                "diskio": {"available": True, "disks": [
                    {"name": "nvme0n1", "identity": "device-a", "major": 259, "minor": 0,
                     "read_bytes": multiplier * 1024, "write_bytes": multiplier * 2048}]},
            },
            "processes": {"items": [{"identity": "boot-a:42:123", "pid": 42, "rss_bytes": multiplier * 1000,
                                      "cpu_ticks": multiplier * 100, "hz": 100}]},
        }

    def pair(self):
        return self.sample(1000), self.sample(1010, 2)

    def process_item(self, identity, pid, rss=1000, ticks=100, hz=100):
        return {"identity": identity, "pid": pid, "rss_bytes": rss,
                "cpu_ticks": ticks, "hz": hz}

    def interface(self, name, ifindex, multiplier=1):
        return {"name": name, "ifindex": ifindex, "ibytes": multiplier * 100,
                "obytes": multiplier * 200, "ipackets": multiplier * 10,
                "opackets": multiplier * 20, "ierrs": 0, "oerrs": 0}

    def test_counter_rates_and_gauge_differences_use_actual_interval(self):
        before, after = self.pair()
        result = resource_changes(before, after)
        self.assertTrue(result["continuity"]["comparable"])
        self.assertEqual(result["cpu"]["busy_percent"], 20)
        self.assertEqual(result["cpu"]["percent"]["iowait"], 10)
        self.assertEqual(result["network"]["items"][0]["per_second"]["ibytes"], 10)
        self.assertEqual(result["diskio"]["items"][0]["per_second"]["read_bytes"], 102.4)
        self.assertEqual(result["memory"]["gauge_delta"]["available_bytes"], -10)
        self.assertEqual(result["memory"]["gauge_delta"]["swap_used_bytes"], 20)
        self.assertEqual(result["processes"]["items"][0]["rss_bytes_delta"], 1000)
        self.assertEqual(result["processes"]["items"][0]["interval_cpu_percent"], 10)

    def test_run_and_boot_changes_do_not_produce_rates(self):
        for field, value, reason in [("run_id", "run-b", "run_changed"),
                                     ("boot", {"boot_id": "boot-b"}, "host_reboot"),
                                     ("boot", None, "boot_identity_missing")]:
            before, after = self.pair()
            after[field] = value
            result = resource_changes(before, after)
            self.assertIn(reason, result["continuity"]["reasons"])
            self.assertNotIn("cpu", result)

    def test_missing_run_is_not_continuous(self):
        before, after = self.pair()
        before.pop("run_id")
        after.pop("run_id")
        self.assertIn("run_changed", resource_changes(before, after)["continuity"]["reasons"])

    def test_open_and_closed_gaps_block_only_overlapping_interval(self):
        before, after = self.pair()
        for gap in [{"start_at": 1005, "end_at": None}, {"start_at": 990, "end_at": 1001}]:
            self.assertIn("collection_gap", resource_changes(before, after, [gap])["continuity"]["reasons"])
        for gap in [{"start_at": 990, "end_at": 1000}, {"start_at": 1010, "end_at": None}]:
            self.assertTrue(resource_changes(before, after, [gap])["continuity"]["comparable"])

    def test_gap_history_before_complete_since_blocks_rates(self):
        before, after = self.pair()
        result = resource_changes(before, after, (),
                                  {"complete_since": 1005})
        self.assertIn("gap_history_incomplete", result["continuity"]["reasons"])
        self.assertNotIn("cpu", result)
        late = resource_changes(before, after, (),
                                {"complete_since": 990})
        self.assertTrue(late["continuity"]["comparable"])

    def test_clock_jump_and_nonincreasing_time_do_not_produce_rates(self):
        before, after = self.pair()
        after["observed_at"] += 60
        self.assertIn("clock_jump", resource_changes(before, after)["continuity"]["reasons"])
        after["monotonic_at"] = before["monotonic_at"]
        self.assertIn("time_not_increasing", resource_changes(before, after)["continuity"]["reasons"])

    def test_missing_and_boolean_timestamps_are_not_numbers(self):
        for value in [None, True, float("inf"), float("nan"), 10**400]:
            before, after = self.pair()
            after["monotonic_at"] = value
            self.assertIn("timestamp_missing", resource_changes(before, after)["continuity"]["reasons"])

    def test_failed_boot_source_is_not_identity_evidence(self):
        before, after = self.pair()
        after["boot"] = {"available": False, "boot_id": "boot-a"}
        self.assertIn("boot_identity_missing", resource_changes(before, after)["continuity"]["reasons"])

    def test_counter_reset_is_local_and_never_negative_rate(self):
        before, after = self.pair()
        after["host"]["network"]["interfaces"]["items"][0]["ibytes"] = 1
        after["host"]["cpu"]["counters"]["user"] = 1
        result = resource_changes(before, after)
        self.assertEqual(result["network"]["items"][0]["reason"], "counter_reset")
        self.assertEqual(result["cpu"]["reason"], "counter_reset")
        self.assertTrue(result["diskio"]["items"][0]["comparable"])

    def test_device_identity_changes_do_not_reuse_name(self):
        before, after = self.pair()
        after["host"]["network"]["interfaces"]["items"][0]["ifindex"] = 3
        after["host"]["diskio"]["disks"][0]["identity"] = "device-b"
        result = resource_changes(before, after)
        for kind in ["network", "diskio"]:
            self.assertEqual(result[kind]["items"][0]["reason"], "object_identity_changed")

    def test_added_and_disappeared_devices_are_not_zero_measurements(self):
        before, after = self.pair()
        after["host"]["network"]["interfaces"]["items"][0]["name"] = "eth1"
        result = resource_changes(before, after)
        reasons = {row["name"]: row["reason"] for row in result["network"]["items"]}
        self.assertEqual(reasons, {"eth0": "object_not_observed", "eth1": "object_added"})

    def test_mac_instantaneous_cpu_and_disk_rates_are_not_differenced(self):
        before, after = self.pair()
        for sample in [before, after]:
            sample["host"]["cpu"] = {"utilization": {"available": True, "idle_percent": 90}}
            sample["host"]["diskio"] = {"available": True, "disks": [{"name": "disk0", "mb_per_second": 3}]}
        result = resource_changes(before, after)
        self.assertEqual(result["cpu"]["reason"], "instantaneous_measurement")
        self.assertEqual(result["diskio"]["items"][0]["reason"], "instantaneous_measurement")

    def test_source_unavailable_is_not_zero(self):
        before, after = self.pair()
        after["host"]["network"] = {"available": False, "reason": "采集错误"}
        after["host"]["memory"] = {"available": False, "reason": "采集错误"}
        result = resource_changes(before, after)
        self.assertFalse(result["network"]["comparable"])
        self.assertFalse(result["memory"]["comparable"])
        self.assertEqual(result["network"]["items"], [])

    def test_pid_reuse_does_not_continue_process_series(self):
        before, after = self.pair()
        after["processes"]["items"][0]["identity"] = "boot-a:42:456"
        result = resource_changes(before, after)["processes"]["items"]
        self.assertEqual({row["reason"] for row in result}, {"process_added", "process_not_observed"})
        self.assertTrue(all("interval_cpu_percent" not in row for row in result))

    def test_ps_lifetime_cpu_is_not_interval_cpu(self):
        before, after = self.pair()
        for sample in [before, after]:
            row = sample["processes"]["items"][0]
            row.pop("cpu_ticks")
            row["cpu_percent"] = 70
        result = resource_changes(before, after)["processes"]["items"][0]
        self.assertIsNone(result["interval_cpu_percent"])
        self.assertEqual(result["cpu_gap"], "counter_missing")

    def test_absent_process_sample_is_not_empty_process_list(self):
        before, after = self.pair()
        after["processes"] = None
        result = resource_changes(before, after)["processes"]
        self.assertFalse(result["comparable"])
        self.assertEqual(result["reason"], "process_snapshot_not_observed")

    def test_unidentified_devices_do_not_claim_identity_continuity(self):
        before, after = self.pair()
        for sample in [before, after]:
            sample["host"]["network"]["interfaces"]["items"][0].pop("ifindex")
            sample["host"]["diskio"]["disks"][0].pop("identity")
        result = resource_changes(before, after)
        for kind in ["network", "diskio"]:
            self.assertEqual(result[kind]["items"][0]["reason"], "object_identity_missing")

    def test_process_rate_uses_process_snapshot_interval(self):
        before, after = self.pair()
        before["processes"]["observed_at"] = 950
        after["processes"]["observed_at"] = 1010
        result = resource_changes(before, after)["processes"]
        self.assertEqual(result["interval_seconds"], 60)
        self.assertEqual(result["items"][0]["interval_cpu_percent"], 1.6667)

    def test_reused_process_snapshot_is_not_new_measurement(self):
        before, after = self.pair()
        for sample in [before, after]:
            sample["processes"]["observed_at"] = 950
        result = resource_changes(before, after)["processes"]
        self.assertFalse(result["comparable"])
        self.assertEqual(result["reason"], "process_snapshot_not_advanced")

    def test_linux_process_cpu_tick_structure_uses_total_once(self):
        before, after = self.pair()
        before["processes"]["items"][0]["cpu_ticks"] = {"user": 70, "system": 30, "total": 100}
        after["processes"]["items"][0]["cpu_ticks"] = {"user": 140, "system": 60, "total": 200}
        result = resource_changes(before, after)["processes"]["items"][0]
        self.assertEqual(result["interval_cpu_percent"], 10)

    def test_failed_process_snapshot_is_not_empty(self):
        before, after = self.pair()
        after["processes"] = {"available": False, "items": []}
        result = resource_changes(before, after)["processes"]
        self.assertFalse(result["comparable"])
        self.assertEqual(result["reason"], "source_unavailable")

    def test_inputs_are_not_modified(self):
        before, after = self.pair()
        original = copy.deepcopy((before, after))
        resource_changes(before, after)
        self.assertEqual((before, after), original)

    def test_truncated_process_topn_does_not_claim_start_or_exit(self):
        before, after = self.pair()
        before["processes"] = {
            "available": True, "observed_at": 1000, "observed": 5,
            "returned": 2, "limit": 2, "truncated": True,
            "items": [self.process_item("p1", 1),
                      self.process_item("p2", 2)]}
        after["processes"] = {
            "available": True, "observed_at": 1010, "observed": 5,
            "returned": 2, "limit": 2, "truncated": True,
            "items": [self.process_item("p1", 1, rss=1500, ticks=200),
                      self.process_item("p3", 3)]}
        result = resource_changes(before, after)["processes"]
        self.assertFalse(result["complete"])
        self.assertTrue(result["truncated"])
        reasons = {row["identity"]: row.get("reason") for row in result["items"]}
        self.assertEqual(reasons["p2"], "left_bounded_snapshot")
        self.assertEqual(reasons["p3"], "entered_bounded_snapshot")
        common = next(row for row in result["items"] if row["identity"] == "p1")
        self.assertEqual(common["rss_bytes_delta"], 500)
        self.assertEqual(common["interval_cpu_percent"], 10)
        self.assertFalse(common["coverage_complete"])

    def test_partial_process_snapshot_uses_conservative_lifecycle_reasons(self):
        before, after = self.pair()
        before["processes"] = {
            "available": True, "observed_at": 1000, "partial": True,
            "complete": False, "items": [self.process_item("p2", 2)]}
        after["processes"] = {
            "available": True, "observed_at": 1010, "complete": True,
            "items": [self.process_item("p3", 3)]}
        result = resource_changes(before, after)["processes"]
        self.assertFalse(result["complete"])
        self.assertTrue(result["partial"])
        reasons = {row["identity"]: row.get("reason") for row in result["items"]}
        self.assertEqual(reasons, {"p2": "left_bounded_snapshot",
                                   "p3": "entered_bounded_snapshot"})

    def test_truncated_network_topn_is_not_interface_disappearance(self):
        before, after = self.pair()
        before["host"]["network"]["interfaces"] = {
            "available": True, "observed": 2, "returned": 1, "limit": 1,
            "truncated": True, "items": [self.interface("eth0", 2)]}
        after["host"]["network"]["interfaces"] = {
            "available": True, "observed": 2, "returned": 1, "limit": 1,
            "truncated": True, "items": [self.interface("eth1", 3)]}
        result = resource_changes(before, after)["network"]
        self.assertFalse(result["complete"])
        self.assertTrue(result["truncated"])
        reasons = {row["name"]: row.get("reason") for row in result["items"]}
        self.assertEqual(reasons, {"eth0": "left_bounded_snapshot",
                                   "eth1": "entered_bounded_snapshot"})

    def test_truncated_disk_view_is_not_device_disappearance(self):
        before, after = self.pair()
        before["host"]["diskio"] = {
            "available": True, "observed": 2, "truncated": True,
            "disks": [{"name": "disk0", "identity": "disk-a",
                       "read_bytes": 100, "write_bytes": 200}]}
        after["host"]["diskio"] = {
            "available": True, "observed": 2, "truncated": True,
            "disks": [{"name": "disk1", "identity": "disk-b",
                       "read_bytes": 100, "write_bytes": 200}]}
        result = resource_changes(before, after)["diskio"]
        self.assertFalse(result["complete"])
        reasons = {row["name"]: row.get("reason") for row in result["items"]}
        self.assertEqual(reasons, {"disk0": "left_bounded_snapshot",
                                   "disk1": "entered_bounded_snapshot"})

    def test_null_host_sections_are_unavailable_not_empty_statistics(self):
        before, after = self.pair()
        for name in ("cpu", "memory", "diskio", "network"):
            before["host"][name] = None
        result = resource_changes(before, after)
        for name in ("cpu", "memory", "diskio", "network"):
            self.assertFalse(result[name]["comparable"])
            self.assertEqual(result[name]["reason"], "source_unavailable")
        before["host"] = None
        result = resource_changes(before, after)
        for name in ("cpu", "memory", "diskio", "network"):
            self.assertFalse(result[name]["comparable"])
            self.assertEqual(result[name]["reason"], "source_unavailable")

    def test_not_loaded_process_rows_are_not_absent_snapshot(self):
        before, after = self.pair()
        before["processes"] = {"loaded": False}
        after["processes"] = {"loaded": False}
        result = resource_changes(before, after)["processes"]
        self.assertFalse(result["comparable"])
        self.assertEqual(result["reason"], "process_changes_not_loaded")
        self.assertFalse(result["loaded"])
        self.assertEqual(result["items"], [])


if __name__ == "__main__":
    unittest.main()
