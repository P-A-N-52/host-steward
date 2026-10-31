import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from database import DatabaseError
from resource_changes import resource_changes
from resource_query import changes_report, fit_changes_output
from sample_store import SampleStore
from state import Store
from state_io import StewardError, encode


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


BASE = 1_700_000_000.0
_UNSET = object()


class ChangesReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.store = Store(self.base / "state", {
            "file_bytes": 65536, "total_bytes": 8 * 1024 * 1024,
            "scan_seconds": 5})
        self.store.initialize_database()
        self.sampling = {"interval_seconds": 15, "cycle_seconds": 5,
                         "process_interval_seconds": 60, "processes": 20,
                         "records": 120, "retention_hours": 1}
        self.history = SampleStore(self.store)
        self.run_id = "run-a"
        self.history.start_run(
            self.run_id, {"version": 2, "sampling": self.sampling},
            {"policy_version": 2, "policy_digest": "a" * 64},
            started_at=BASE, boot={"boot_id": "boot-a"})

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
                {"name": "nvme0n1", "identity": "dev-a", "major": 259, "minor": 0,
                 "read_bytes": read, "write_bytes": read * 2}]},
            "network": {"available": True, "interfaces": {
                "available": True,
                "items": interfaces if interfaces is not None else [
                    {"name": "eth0", "ifindex": 2, "ibytes": read,
                     "obytes": read * 2, "ipackets": 0, "opackets": 0,
                     "ierrs": 0, "oerrs": 0}]}},
        }

    def append(self, index, *, run_id=None, boot="boot-a", host=None,
               sources=None, processes=_UNSET, monotonic=None, at=None):
        at = BASE + index * 15 if at is None else at
        if host is None:
            host = self.host(memory=800 - index * 100, read=100 + index * 100,
                             ticks=100 + index * 100)
        if sources is None:
            sources = {
                "cpu": {"available": True, "attempted_at": at, "success_at": at},
                "network": {"available": True, "attempted_at": at,
                            "success_at": at}}
        if processes is _UNSET:
            processes = {"available": True, "observed_at": at, "items": [
                {"identity": "p1", "pid": 42, "rss_bytes": 1000 + index * 100,
                 "cpu_ticks": 100 + index * 100, "hz": 100}]}
        monotonic_at = 1000 + (at - BASE) if monotonic is None else monotonic
        return self.history.append_sample(
            run_id or self.run_id, observed_at=at, monotonic_at=monotonic_at,
            boot={"boot_id": boot}, host=host, sources=sources,
            processes=processes, sampling=self.sampling)

    def switch_run(self, run_id="run-b", started_at=None):
        return self.history.start_run(
            run_id, {"version": 2, "sampling": self.sampling},
            {"policy_version": 2, "policy_digest": "b" * 64},
            started_at=BASE + 30 if started_at is None else started_at,
            boot={"boot_id": "boot-a"})

    @staticmethod
    def path_changes(report, path):
        return [row for row in report["changes"] if row["path"] == path]

    def test_two_point_mode_returns_field_level_diff_with_db_times(self):
        first = self.append(0)
        second = self.append(1)
        report = changes_report(self.store, from_sample=first["sample_id"],
                                to_sample=second["sample_id"])
        self.assertEqual(report["status"], "resource_changes")
        self.assertEqual(report["contract"],
                         {"name": "host-steward.resource_changes", "version": 1})
        self.assertEqual(report["mode"], "pair")
        self.assertEqual(report["evaluated_samples"], 2)
        self.assertEqual(report["evaluated_pairs"], 1)
        self.assertEqual(report["baseline"]["sample_id"], first["sample_id"])
        self.assertEqual(report["target"]["sample_id"], second["sample_id"])
        self.assertEqual(report["baseline"]["observed_at"], BASE)
        self.assertEqual(report["target"]["observed_at"], BASE + 15)
        memory = self.path_changes(report, "memory.available_bytes")
        self.assertEqual(len(memory), 1)
        change = memory[0]
        self.assertEqual((change["kind"], change["unit"]),
                         ("value_change", "bytes"))
        self.assertEqual((change["before"], change["after"], change["delta"]),
                         (800, 700, -100))
        self.assertEqual(change["first_sample_id"], second["sample_id"])
        self.assertEqual(change["last_sample_id"], second["sample_id"])
        self.assertEqual(change["first_observed_at"], second["observed_at"])
        self.assertEqual(change["baseline_sample_id"], first["sample_id"])
        self.assertEqual(change["continuity"],
                         {"comparable": True, "reasons": []})
        self.assertNotIn("pairs", change)
        self.assertFalse(any(row["resource"] == "processes"
                             for row in report["changes"]))
        self.assertTrue(report["summary"]["process_changes_not_loaded"])

    def test_range_mode_merges_episodes_and_breaks_on_stable_value(self):
        ids = [self.append(index, host=self.host(
            memory=memory, read=100 + index * 100, ticks=100 + index * 100)
        )["sample_id"] for index, memory in enumerate([800, 700, 700, 600])]
        report = changes_report(self.store, since=BASE, until=BASE + 60)
        memory = self.path_changes(report, "memory.available_bytes")
        self.assertEqual(len(memory), 2)
        first, second = memory
        self.assertEqual((first["before"], first["after"], first["delta"]),
                         (800, 700, -100))
        self.assertEqual((first["pairs"], first["direction"]), (1, "decrease"))
        self.assertEqual(first["first_sample_id"], ids[1])
        self.assertEqual(first["last_sample_id"], ids[1])
        self.assertEqual([point["sample_id"] for point in first["samples"]],
                         [ids[0], ids[1]])
        self.assertEqual([point["value"] for point in first["samples"]],
                         [800, 700])
        self.assertEqual((second["before"], second["after"], second["delta"]),
                         (700, 600, -100))
        self.assertEqual(second["first_sample_id"], ids[3])
        self.assertEqual(second["last_sample_id"], ids[3])
        disk = self.path_changes(report, "diskio.disks.nvme0n1.read_bytes")
        self.assertEqual(len(disk), 1)
        self.assertEqual((disk[0]["before"], disk[0]["after"], disk[0]["delta"]),
                         (100, 400, 300))
        self.assertEqual((disk[0]["pairs"], disk[0]["direction"]),
                         (3, "increase"))
        self.assertEqual(disk[0]["first_sample_id"], ids[1])
        self.assertEqual(disk[0]["last_sample_id"], ids[3])
        self.assertEqual([point["sample_id"] for point in disk[0]["samples"]],
                         ids)
        self.assertGreaterEqual(report["summary"]["episodes"], 1)

    def test_range_mode_reversal_starts_new_episode(self):
        ids = [self.append(index, host=self.host(memory=memory))["sample_id"]
               for index, memory in enumerate([800, 700, 800])]
        report = changes_report(self.store, since=BASE, until=BASE + 45)
        memory = self.path_changes(report, "memory.available_bytes")
        self.assertEqual(len(memory), 2)
        self.assertEqual((memory[0]["before"], memory[0]["after"]),
                         (800, 700))
        self.assertEqual(memory[0]["direction"], "decrease")
        self.assertEqual((memory[1]["before"], memory[1]["after"]),
                         (700, 800))
        self.assertEqual(memory[1]["direction"], "increase")
        self.assertEqual(memory[1]["first_sample_id"], ids[2])
        self.assertEqual(memory[1]["baseline_sample_id"], ids[1])

    def test_counter_reset_is_not_merged_into_episode(self):
        for index, read in enumerate([100, 200, 50, 60, 70]):
            self.append(index, host=self.host(memory=800, read=read,
                                              ticks=100 + index * 10))
        report = changes_report(self.store, since=BASE, until=BASE + 75)
        disk = self.path_changes(report, "diskio.disks.nvme0n1.read_bytes")
        reset = [row for row in disk if row.get("reason") == "counter_reset"]
        self.assertEqual(len(reset), 1)
        self.assertEqual((reset[0]["before"], reset[0]["after"],
                          reset[0]["delta"]), (200, 50, None))
        merged = [row for row in disk if row.get("pairs") == 2]
        self.assertEqual(len(merged), 1)
        self.assertEqual((merged[0]["before"], merged[0]["after"],
                          merged[0]["delta"]), (50, 70, 20))

    def test_run_change_ends_episode_and_records_discontinuity(self):
        first = self.append(0)
        second = self.append(1)
        self.switch_run()
        self.append(2, run_id="run-b")
        report = changes_report(self.store, since=BASE, until=BASE + 60)
        self.assertEqual([row["reasons"] for row in report["discontinuities"]],
                         [["run_changed"]])
        memory = self.path_changes(report, "memory.available_bytes")
        self.assertEqual(len(memory), 1)
        self.assertEqual((memory[0]["before"], memory[0]["after"]), (800, 700))
        self.assertEqual(memory[0]["last_sample_id"], second["sample_id"])
        self.assertEqual(first["sample_id"] + 1, second["sample_id"])

    def test_boot_change_ends_episode_and_records_discontinuity(self):
        self.append(0)
        second = self.append(1)
        self.append(2, boot="boot-b")
        report = changes_report(self.store, since=BASE, until=BASE + 60)
        self.assertEqual([row["reasons"] for row in report["discontinuities"]],
                         [["host_reboot"]])
        memory = self.path_changes(report, "memory.available_bytes")
        self.assertEqual(len(memory), 1)
        self.assertEqual(memory[0]["last_sample_id"], second["sample_id"])

    def test_clock_jump_ends_episode(self):
        self.append(0)
        self.append(1, monotonic=1005)
        report = changes_report(self.store, since=BASE, until=BASE + 30)
        self.assertEqual([row["reasons"] for row in report["discontinuities"]],
                         [["clock_jump"]])
        self.assertEqual(report["changes"], [])

    def test_collection_gap_ends_episode_and_stays_separate_from_changes(self):
        self.append(0)
        self.append(1)
        self.history.record_gap(BASE + 5, BASE + 10, "source_failed")
        report = changes_report(self.store, since=BASE, until=BASE + 30)
        self.assertEqual([row["reasons"] for row in report["discontinuities"]],
                         [["collection_gap"]])
        self.assertEqual(report["changes"], [])
        self.assertEqual(report["summary"]["gap_count"], 1)
        self.assertEqual(len(report["gaps"]), 1)

    def test_pruned_gap_history_blocks_episode_merge(self):
        history = {"runs": {"records": 256, "retention_hours": 168},
                   "gaps": {"records": 256, "retention_hours": 1}}
        self.store.history = history
        self.history.start_run(
            "run-history", {"version": 2, "sampling": self.sampling,
                            "history": history},
            {"policy_version": 2, "policy_digest": "c" * 64},
            started_at=BASE, boot={"boot_id": "boot-a"})
        self.append(0, run_id="run-history")
        self.append(1, run_id="run-history")
        self.history.record_gap(BASE + 40, BASE + 50, "source_failed")
        self.history.record_gap(BASE + 4000, BASE + 4001, "later_gap")
        report = changes_report(self.store, since=BASE, until=BASE + 30)
        self.assertGreater(report["gap_history"]["complete_since"], BASE + 30)
        self.assertEqual(report["changes"], [])
        self.assertEqual(len(report["discontinuities"]), 1)
        self.assertIn("gap_history_incomplete",
                      report["discontinuities"][0]["reasons"])

    def test_process_changes_require_explicit_identity(self):
        first = self.append(0, processes={
            "available": True, "observed_at": BASE, "items": [
                {"identity": "p1", "pid": 42, "rss_bytes": 1000,
                 "cpu_ticks": 100, "hz": 100}]})
        second = self.append(1, processes={
            "available": True, "observed_at": BASE + 15, "items": [
                {"identity": "p1", "pid": 42, "rss_bytes": 1500,
                 "cpu_ticks": 200, "hz": 100}]})
        plain = changes_report(self.store, since=BASE, until=BASE + 20)
        self.assertTrue(plain["summary"]["process_changes_not_loaded"])
        self.assertFalse(any(row["resource"] == "processes"
                             for row in plain["changes"]))
        report = changes_report(self.store, since=BASE, until=BASE + 20,
                                process="p1")
        rows = {row["path"]: row for row in report["changes"]
                if row["resource"] == "processes"}
        self.assertEqual(rows["processes.p1.rss_bytes"]["delta"], 500)
        self.assertEqual(rows["processes.p1.cpu_ticks"]["delta"], 100)
        self.assertEqual(rows["processes.p1.rss_bytes"]["first_sample_id"],
                         second["sample_id"])
        self.assertEqual(rows["processes.p1.rss_bytes"]["baseline_sample_id"],
                         first["sample_id"])

    def test_sources_availability_changes_and_resource_filter(self):
        self.append(0, sources={
            "cpu": {"available": True, "attempted_at": BASE,
                    "success_at": BASE},
            "network": {"available": True, "attempted_at": BASE,
                        "success_at": BASE}})
        self.append(1, sources={
            "cpu": {"available": True, "attempted_at": BASE + 15,
                    "success_at": BASE + 15},
            "network": {"available": False, "attempted_at": BASE + 15,
                        "error_at": BASE + 15}})
        report = changes_report(self.store, since=BASE, until=BASE + 20)
        sources = [row for row in report["changes"]
                   if row["resource"] == "sources"]
        self.assertEqual(len(sources), 1)
        self.assertEqual(
            (sources[0]["path"], sources[0]["kind"], sources[0]["before"],
             sources[0]["after"]),
            ("sources.network.available", "availability_change", True, False))
        filtered = changes_report(self.store, since=BASE, until=BASE + 20,
                                  resources=["memory"])
        self.assertTrue(filtered["changes"])
        self.assertEqual({row["resource"] for row in filtered["changes"]},
                         {"memory"})
        comma = changes_report(self.store, since=BASE, until=BASE + 20,
                               resources=["cpu,memory"])
        self.assertTrue(comma["changes"])
        self.assertLessEqual({row["resource"] for row in comma["changes"]},
                             {"cpu", "memory"})
        with self.assertRaises(StewardError):
            changes_report(self.store, since=BASE, until=BASE + 20,
                           resources=["bogus"])

    def test_max_changes_bounds_entries_and_reports_omitted(self):
        interfaces = [
            {"name": f"eth{index}", "ifindex": index + 2,
             "ibytes": 100, "obytes": 200, "ipackets": 10, "opackets": 20,
             "ierrs": 0, "oerrs": 0} for index in range(5)]
        self.append(0, host=self.host(interfaces=interfaces))
        changed = [dict(row, ibytes=row["ibytes"] + 50,
                        obytes=row["obytes"] + 50,
                        ipackets=row["ipackets"] + 5,
                        opackets=row["opackets"] + 5)
                   for row in interfaces]
        self.append(1, host=self.host(interfaces=changed))
        full = changes_report(self.store, since=BASE, until=BASE + 20)
        self.assertGreater(full["summary"]["changes_evaluated"], 2)
        limited = changes_report(self.store, since=BASE, until=BASE + 20,
                                 max_changes=2)
        self.assertEqual(len(limited["changes"]), 2)
        self.assertTrue(limited["truncated"])
        self.assertEqual(limited["changes_omitted"],
                         full["summary"]["changes_evaluated"] - 2)
        self.assertEqual(limited["summary"]["changes_returned"], 2)

    def test_output_budget_bounds_changes_and_never_claims_success(self):
        for index in range(2):
            interfaces = [
                {"name": f"eth{item}", "ifindex": item + 2,
                 "ibytes": (index + 1) * (item + 1) * 100,
                 "obytes": (index + 1) * (item + 1) * 200,
                 "ipackets": (index + 1) * (item + 1) * 10,
                 "opackets": (index + 1) * (item + 1) * 20,
                 "ierrs": 0, "oerrs": 0} for item in range(5)]
            self.append(index, host=self.host(interfaces=interfaces))
        report = changes_report(self.store, since=BASE, until=BASE + 20)
        original = copy.deepcopy(report)
        bounded = fit_changes_output(report, 4000)
        self.assertLessEqual(len(encode(bounded)), 4000)
        self.assertTrue(bounded.get("output_trimmed"))
        self.assertEqual(report, original)
        tiny = fit_changes_output(report, 300)
        self.assertLessEqual(len(encode(tiny)), 300)
        self.assertTrue(tiny.get("output_limited")
                        or tiny.get("status") == "output_limited")
        empty = fit_changes_output(report, 1500)
        self.assertLessEqual(len(encode(empty)), 1500)
        if not empty.get("changes"):
            self.assertTrue(empty.get("pagination_blocked_by_output")
                            or empty.get("output_limited")
                            or empty.get("status") == "output_limited")

    def test_episode_trace_is_bounded_and_fit_keeps_original_total(self):
        for index in range(20):
            self.append(index, host=self.host(memory=800, read=100 + index * 10,
                                              ticks=100))
        report = changes_report(self.store, since=BASE, until=BASE + 300)
        disk = self.path_changes(report, "diskio.disks.nvme0n1.read_bytes")
        self.assertEqual(len(disk), 1)
        episode = disk[0]
        self.assertEqual(episode["pairs"], 19)
        self.assertEqual(len(episode["samples"]), 16)
        self.assertEqual(episode["samples_omitted"], 4)
        bounded = fit_changes_output(report, 6000)
        kept = [row for row in bounded.get("changes") or []
                if row["path"] == "diskio.disks.nvme0n1.read_bytes"]
        if kept:
            self.assertGreaterEqual(kept[0]["samples_omitted"], 4)
            self.assertEqual(len(kept[0]["samples"])
                             + kept[0]["samples_omitted"], 20)

    def test_page_seam_is_reported_by_boundary_not_merged(self):
        ids = [self.append(index)["sample_id"] for index in range(3)]
        report = changes_report(self.store, since=BASE, until=BASE + 40,
                                limit=2)
        self.assertEqual(report["evaluated_samples"], 2)
        self.assertEqual(report["evaluated_pairs"], 1)
        self.assertEqual(report["page"]["truncated"], True)
        self.assertEqual(report["next_before"], ids[1])
        boundary = report["boundary"]
        self.assertEqual(boundary["status"], "computed")
        self.assertEqual(boundary["page_oldest_sample_id"], ids[1])
        self.assertEqual(boundary["predecessor_sample_id"], ids[0])
        self.assertTrue(boundary["in_window"])
        self.assertTrue(boundary["comparable"])
        self.assertFalse(boundary["included_in_changes"])
        memory = self.path_changes(report, "memory.available_bytes")
        self.assertEqual(len(memory), 1)
        self.assertEqual((memory[0]["before"], memory[0]["after"]), (700, 600))

    def test_two_point_mode_rejects_range_arguments_and_missing_ids(self):
        first = self.append(0)
        second = self.append(1)
        with self.assertRaises(StewardError):
            changes_report(self.store, from_sample=first["sample_id"])
        with self.assertRaises(StewardError):
            changes_report(self.store, from_sample=first["sample_id"],
                           to_sample=second["sample_id"], minutes=5)
        with self.assertRaises(StewardError):
            changes_report(self.store, since=BASE, before=1)
        with self.assertRaises(StewardError):
            changes_report(self.store, max_changes=0)
        with self.assertRaises(DatabaseError) as caught:
            changes_report(self.store, from_sample=second["sample_id"],
                           to_sample=first["sample_id"])
        self.assertIn("from_sample", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
