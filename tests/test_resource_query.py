import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from resource_query import fit_history_output, history_report
from sample_store import SampleStore
from state import Store
from state_io import StewardError, encode

BASE = 1700000000
_UNSET = object()


class ResourceQueryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.store = Store(self.base / "state", {"file_bytes": 65536, "total_bytes": 4194304, "scan_seconds": 5})
        self.store.initialize_database()
        self.store.write("current.json", {"version": 1, "pending": [{"key": "keep"}]})
        self.sampling = {"interval_seconds": 15, "cycle_seconds": 5, "process_interval_seconds": 60,
                         "processes": 20, "records": 120, "retention_hours": 1}
        self.history = SampleStore(self.store)
        self.history.start_run("run-a", {"version": 2, "sampling": self.sampling},
                               {"policy_version": 2, "policy_digest": "a" * 64}, started_at=BASE)

    def append(self, index, run_id="run-a", boot="boot-a", sources=None,
               at=None, host=None, processes=_UNSET):
        at = BASE + index * 15 if at is None else at
        if host is None:
            host = {
                "cpu": {"available": True, "cores": 8, "hz": 100, "load_average": [1.0, 1.2, 1.3],
                        "counters": {"user": index * 2 + 1, "nice": 0, "system": index + 1,
                                     "idle": index * 7 + 1, "iowait": 0, "irq": 0, "softirq": 0, "steal": 0}},
                "memory": {"available": True, "total_bytes": 20000, "available_bytes": 10000 - index * 100,
                           "swap": {"available": True, "used_bytes": index * 20}},
                "network": {"available": True, "interfaces": {"available": True, "items": [
                    {"name": "eth0", "ifindex": 2, "ibytes": index * 100, "obytes": index * 200,
                     "ipackets": index * 2, "opackets": index * 4, "ierrs": 0, "oerrs": 0}]}},
                "diskio": {"available": True, "disks": [{"name": "disk", "identity": "disk-a",
                                                         "read_bytes": index * 512, "write_bytes": index * 1024}]},
                "raw_detail": "x" * 1200,
            }
        if processes is _UNSET:
            processes = {"available": True, "observed_at": at,
                         "items": [{"identity": "p1", "pid": 42, "rss_bytes": index * 100,
                                    "cpu_ticks": index * 100, "hz": 100, "executable": "/usr/bin/example"}]} if index % 4 == 0 else None
        return self.history.append_sample(run_id, observed_at=at, monotonic_at=1000 + (at - BASE),
                                          boot={"boot_id": boot}, host=host,
                                          sources=sources or {"cpu": {"available": True, "attempted_at": at, "success_at": at}},
                                          processes=processes, sampling=self.sampling)

    def switch_run(self, run_id, started_at):
        self.history.start_run(run_id, {"version": 2, "sampling": self.sampling},
                               {"policy_version": 2, "policy_digest": "b" * 64},
                               started_at=started_at)

    def test_recent_ten_minute_summary_and_current_processes_are_readable(self):
        for index in range(41):
            self.append(index)
        report = history_report(self.store, until=BASE + 600, limit=100)
        self.assertEqual(report["status"], "resource_history")
        self.assertEqual(report["window"]["since"], BASE)
        self.assertEqual(report["summary"]["evaluated_samples"], 41)
        self.assertEqual(report["summary"]["observed_from"], BASE)
        self.assertEqual(report["summary"]["observed_to"], BASE + 600)
        self.assertEqual(report["summary"]["cpu_busy_percent"]["minimum"], 30)
        self.assertEqual(report["summary"]["available_memory_bytes"]["latest"], 6000)
        self.assertEqual(report["summary"]["swap_used_bytes"]["latest"], 800)
        self.assertEqual(report["latest_processes"]["observed_at"], BASE + 600)
        self.assertEqual(report["latest_processes"]["processes"][0]["identity"], "p1")
        self.assertNotIn("raw_detail", report["samples"][0]["host"])
        self.assertEqual(report["samples"][0]["policy_evidence"]["policy_version"], 2)

    def test_discontinuity_and_partial_sources_do_not_become_zero_rates(self):
        self.append(0)
        self.append(1)
        self.history.record_gap(BASE + 20, BASE + 25, "source_failed", detail={"type": "PermissionError", "message": "权限不足"})
        self.append(2)
        report = history_report(self.store, until=BASE + 30)
        self.assertEqual(report["summary"]["overlapping_gap_count"], 1)
        self.assertEqual(report["summary"]["discontinuity_count"], 1)
        self.assertIn("collection_gap", report["samples"][0]["change_from_previous"]["continuity"]["reasons"])
        self.assertNotIn("cpu", report["samples"][0]["change_from_previous"])
        self.assertEqual(report["gaps"][0]["detail"]["message"], "权限不足")

    def test_process_identity_query_uses_its_real_sampling_interval(self):
        for index in range(9):
            self.append(index)
        report = history_report(self.store, until=BASE + 120, process="p1")
        self.assertEqual(len(report["samples"]), 3)
        result = report["samples"][0]["change_from_previous"]["processes"]
        self.assertEqual(result["interval_seconds"], 60)
        self.assertEqual(result["items"][0]["interval_cpu_percent"], 6.6667)

    def test_raw_output_keeps_original_source_detail_and_configuration(self):
        self.append(0, sources={"cpu": {"available": False, "attempted_at": BASE,
                                       "error": {"type": "ValueError", "message": "坏格式", "traceback": "trace" * 100}}})
        raw = history_report(self.store, until=BASE, raw=True)
        self.assertIn("raw_detail", raw["samples"][0]["host"])
        self.assertEqual(raw["samples"][0]["run"]["policy"]["version"], 2)
        self.assertIn("traceback", raw["sources"]["cpu"]["error"])
        summary = history_report(self.store, until=BASE)
        self.assertTrue(summary["sources"]["cpu"]["error"]["detail_omitted"])
        self.assertNotIn("traceback", summary["sources"]["cpu"]["error"])

    def test_output_budget_reports_trim_and_keeps_stable_continuation(self):
        for index in range(41):
            self.append(index)
        report = history_report(self.store, until=BASE + 600, limit=100)
        original = copy.deepcopy(report)
        # 固定契约元数据约 4.3KB；6000 字节预算仍须保留至少一个样本。
        bounded = fit_history_output(report, 6000)
        self.assertLessEqual(len(encode(bounded)), 6000)
        self.assertTrue(bounded["output_trimmed"])
        self.assertGreater(bounded["output_sample_omitted"], 0)
        self.assertTrue(bounded["samples"])
        self.assertEqual(bounded["next_before"], bounded["samples"][-1]["sample_id"])
        self.assertEqual(bounded["raw_count"], len(bounded["samples"]))
        self.assertLess(bounded["raw_count"], bounded["summary"]["evaluated_samples"])
        continuation = history_report(self.store, since=bounded["window"]["since"], until=bounded["window"]["until"],
                                      before=bounded["next_before"], limit=100)
        self.assertEqual(continuation["samples"][0]["sample_id"], bounded["next_before"] - 1)
        self.assertEqual(report, original)
        self.assertEqual(bounded["summary"]["evaluated_samples"], 41)

    def test_tiny_output_budget_does_not_claim_empty_success(self):
        self.append(0)
        result = fit_history_output(history_report(self.store, until=BASE), 256)
        self.assertLessEqual(len(encode(result)), 256)
        self.assertTrue(result.get("output_limited") or result.get("status") == "output_limited")
        self.assertNotEqual(result.get("status"), "resource_history")

    def test_invalid_host_configuration_does_not_block_saved_history(self):
        self.append(0)
        self.store.target("host.json").write_text("{broken", encoding="utf-8")
        report = history_report(self.store, until=BASE)
        self.assertEqual(len(report["samples"]), 1)
        self.assertEqual(report["samples"][0]["policy_evidence"]["policy_digest"], "a" * 64)

    def test_query_is_read_only_and_does_not_rewrite_agent_state(self):
        self.append(0)
        before = self.store.database_path.read_bytes()
        history_report(self.store, until=BASE)
        self.assertEqual(self.store.database_path.read_bytes(), before)
        self.assertEqual(self.store.read("current.json")["pending"], [{"key": "keep"}])

    def test_invalid_minutes_are_rejected(self):
        for minutes in [True, 0, -1, float("inf"), float("nan"), "10"]:
            with self.subTest(minutes=minutes), self.assertRaises(StewardError):
                history_report(self.store, minutes=minutes, until=BASE)

    def test_default_limit_covers_the_closed_ten_minute_interval(self):
        for index in range(41):
            self.append(index)
        report = history_report(self.store, until=BASE + 600)
        self.assertEqual(report["summary"]["evaluated_samples"], 41)
        self.assertEqual(len(report["samples"]), 41)
        self.assertEqual(report["window"]["since"], BASE)
        self.assertEqual(report["window"]["until"], BASE + 600)
        self.assertFalse(report["truncated"])

    def test_boundary_predecessor_reports_run_change_across_page_seam(self):
        for index in range(4):
            self.append(index)
        self.switch_run("run-b", BASE + 60)
        for index in (4, 5, 6):
            self.append(index, run_id="run-b", at=BASE + index * 15)
        report = history_report(self.store, until=BASE + 90, limit=3)
        self.assertEqual([row["sample_id"] for row in report["samples"]], [7, 6, 5])
        boundary = report["boundary"]
        self.assertEqual(boundary["status"], "computed")
        self.assertTrue(boundary["in_window"])
        self.assertEqual(boundary["predecessor_sample_id"], 4)
        self.assertNotIn(4, [row["sample_id"] for row in report["samples"]])
        self.assertIn("run_changed", boundary["change"]["continuity"]["reasons"])
        self.assertTrue(report["summary"]["boundary_discontinuity"])
        self.assertEqual(report["summary"]["evaluated_samples"], 3)
        self.assertEqual(report["next_before"], 5)
        for key in ("included_in_samples", "included_in_cursor", "included_in_summary"):
            self.assertFalse(boundary[key])

    def test_boundary_without_predecessor_does_not_use_out_of_window_change(self):
        for index in range(4):
            self.append(index)
        report = history_report(self.store, since=BASE + 30, until=BASE + 45, limit=2)
        self.assertEqual([row["sample_id"] for row in report["samples"]], [4, 3])
        self.assertEqual(report["boundary"]["status"], "first_observation")
        self.assertFalse(report["boundary"]["in_window"])
        self.assertIsNone(report["boundary"]["change"])
        self.assertFalse(report["summary"]["boundary_change_evaluated"])
        continuation = history_report(self.store, since=BASE + 30, until=BASE + 45,
                                      before=4, limit=2)
        self.assertEqual([row["sample_id"] for row in continuation["samples"]], [3])
        self.assertEqual(continuation["boundary"]["status"], "predecessor_not_available")
        self.assertIsNone(continuation["boundary"]["change"])

    def test_gap_detail_keeps_sources_and_recovery_context_within_budget(self):
        self.append(0)
        self.append(1)
        detail = {
            "failed_sources": ["cpu", "memory"],
            "not_attempted_sources": ["network"],
            "source_errors": [{"source": "cpu", "type": "PermissionError",
                               "message": "权限不足", "traceback": "T" * 50000}],
            "dropped_intervals": 3,
            "previous_boot": {"boot_id": "boot-old"},
            "closed_by": "collector_start",
            "recovered": True,
        }
        self.history.record_gap(BASE + 20, BASE + 25, "sample_unavailable", detail=detail)
        report = history_report(self.store, until=BASE + 30)
        gap = report["gaps"][0]
        self.assertEqual(gap["reason"], "sample_unavailable")
        kept = gap["detail"]
        self.assertEqual(kept["failed_sources"], ["cpu", "memory"])
        self.assertEqual(kept["not_attempted_sources"], ["network"])
        self.assertEqual(kept["dropped_intervals"], 3)
        self.assertEqual(kept["previous_boot"]["boot_id"], "boot-old")
        self.assertEqual(kept["closed_by"], "collector_start")
        self.assertTrue(kept["recovered"])
        self.assertEqual(kept["source_errors"][0]["source"], "cpu")
        self.assertEqual(kept["source_errors"][0]["message"], "权限不足")
        self.assertIn("省略", kept["source_errors"][0]["traceback"])
        self.assertTrue(kept["context_truncated"])
        self.assertLessEqual(len(encode(kept)), 1024)

    def test_recovered_source_keeps_history_but_not_current_failure(self):
        failed = {"cpu": {"available": False, "attempted_at": BASE, "error_at": BASE,
                          "error": {"type": "PermissionError", "message": "denied",
                                    "traceback": "t" * 1000}}}
        self.append(0, sources=failed)
        self.append(1)
        report = history_report(self.store, until=BASE + 15)
        source = report["sources"]["cpu"]
        self.assertTrue(source["current_available"])
        self.assertIsNone(source["current_error"])
        self.assertIsNone(source["error"])
        self.assertTrue(source["recovered"])
        self.assertEqual(source["status"], "recovered")
        self.assertEqual(source["last_error"]["message"], "denied")
        self.assertEqual(source["last_success_at"], BASE + 15)
        self.assertEqual(source["updated_at"], BASE + 15)
        scope = report["source_status_scope"]
        self.assertEqual(scope["scope"], "global_latest")
        self.assertTrue(scope["window_independent"])

    def test_large_collector_source_errors_are_bounded_and_samples_survive(self):
        self.append(0)
        self.append(1)
        self.history.update_state(detail={
            "phase": "sampling",
            "failed_sources": ["cpu"],
            "source_errors": [{"source": "cpu", "traceback": "X" * 51200}],
            "last_success_at": BASE,
        })
        report = history_report(self.store, until=BASE + 15)
        detail = report["collector"]["state"]["detail"]
        self.assertTrue(detail["context_truncated"])
        self.assertLessEqual(len(encode(detail)), 4096)
        self.assertIn("省略", detail["source_errors"][0]["traceback"])
        self.assertEqual(len(report["samples"]), 2)
        bounded = fit_history_output(report, len(encode(report)) * 2 // 3)
        self.assertNotEqual(bounded.get("status"), "output_limited")
        self.assertFalse(bounded.get("output_limited"))
        self.assertTrue(bounded["samples"])
        self.assertTrue(bounded.get("output_detail_trimmed"))
        self.assertTrue(bounded["collector"]["state"]["detail_truncated"])

    def test_large_latest_process_meta_is_bounded(self):
        self.append(0, processes={
            "available": True, "observed_at": BASE, "reason": "R" * 50000,
            "items": [{"identity": "p1", "pid": 42, "rss_bytes": 100,
                       "cpu_ticks": 0, "hz": 100}]})
        report = history_report(self.store, until=BASE)
        meta = report["latest_processes"]["meta"]
        self.assertTrue(meta["context_truncated"])
        self.assertLessEqual(len(encode(meta)), 1024)
        self.assertIn("省略", meta["reason"])
        self.assertEqual(len(report["latest_processes"]["processes"]), 1)

    def test_default_process_changes_are_not_loaded_not_not_observed(self):
        for index in range(5):
            self.append(index)
        report = history_report(self.store, until=BASE + 60)
        change = report["samples"][0]["change_from_previous"]
        self.assertEqual(change["processes"]["reason"], "process_changes_not_loaded")
        self.assertNotEqual(change["processes"]["reason"], "process_snapshot_not_observed")
        self.assertFalse(change["processes"]["comparable"])
        self.assertEqual(change["processes"]["items"], [])
        latest = report["latest_processes"]
        self.assertFalse(latest["page_scoped"])
        self.assertEqual(latest["scope"], "global_latest_at_or_before_until")
        self.assertEqual(latest["as_of"], BASE + 60)
        self.assertEqual(latest["sample_id"], 5)
        older = history_report(self.store, until=BASE + 60, before=5, limit=2)
        self.assertEqual([row["sample_id"] for row in older["samples"]], [4, 3])
        self.assertEqual(older["latest_processes"]["sample_id"], 5)
        self.assertFalse(older["latest_processes"]["page_scoped"])

    def test_process_drilldown_still_loads_filtered_process_changes(self):
        for index in range(5):
            self.append(index)
        report = history_report(self.store, until=BASE + 60, process="p1")
        self.assertEqual([row["sample_id"] for row in report["samples"]], [5, 1])
        change = report["samples"][0]["change_from_previous"]["processes"]
        self.assertEqual(change["interval_seconds"], 60)
        self.assertEqual(change["items"][0]["identity"], "p1")
        self.assertEqual(change["items"][0]["interval_cpu_percent"], 6.6667)
        self.assertTrue(change["filtered"])
        self.assertEqual(report["boundary"]["status"], "first_observation")
        seam = history_report(self.store, until=BASE + 60, process="p1", limit=1)
        self.assertEqual([row["sample_id"] for row in seam["samples"]], [5])
        self.assertEqual(seam["boundary"]["predecessor_sample_id"], 1)
        self.assertEqual(seam["boundary"]["status"], "computed")

    def test_output_budget_that_removes_all_samples_clears_cursor(self):
        for index in range(6):
            self.append(index)
        report = history_report(self.store, until=BASE + 75, before=6, limit=5)
        self.assertEqual(report["window"]["before"], 6)
        self.assertEqual(len(report["samples"]), 5)
        # 4500 字节可容纳空页固定元数据，但容不下一个完整样本。
        bounded = fit_history_output(report, 4500)
        self.assertNotEqual(bounded.get("status"), "output_limited")
        self.assertEqual(bounded["samples"], [])
        self.assertIsNone(bounded["next_before"])
        self.assertTrue(bounded["pagination_blocked_by_output"])
        self.assertEqual(bounded["window"]["before"], 6)
        self.assertEqual(bounded["raw_count"], 0)
        self.assertEqual(bounded["evaluated_sample_count"], 5)
        self.assertEqual(bounded["summary"]["evaluated_samples"], 5)
        self.assertEqual(bounded["summary"]["output_samples"], 0)

    def test_null_and_missing_host_sections_do_not_break_summary(self):
        null_host = {"cpu": None, "memory": None, "diskio": None, "network": None}
        self.append(0, host=null_host)
        self.append(1)
        self.append(2, host={})
        report = history_report(self.store, until=BASE + 30)
        by_id = {row["sample_id"]: row for row in report["samples"]}
        null_host = by_id[1]["host"]
        missing_host = by_id[3]["host"]
        for name in ("cpu", "memory", "diskio", "network"):
            self.assertIsNone(null_host[name]["available"])
            self.assertEqual(null_host[name]["reason"], "host_section_null")
            self.assertIsNone(missing_host[name]["available"])
            self.assertEqual(missing_host[name]["reason"], "host_section_missing")
        self.assertIsNone(null_host["diskio"]["disks"])
        self.assertIsNone(null_host["network"]["interfaces"]["items"])
        change = by_id[2]["change_from_previous"]
        for name in ("cpu", "memory", "diskio", "network"):
            self.assertFalse(change[name]["comparable"])
            self.assertEqual(change[name]["reason"], "source_unavailable")
        self.assertIsNone(report["summary"]["cpu_busy_percent"])
        self.assertEqual(report["summary"]["available_memory_bytes"]["latest"], 9900)
        self.assertEqual(report["summary"]["swap_used_bytes"]["latest"], 20)

    def test_contract_and_retention_history_survive_output_trimming(self):
        effective = {"runs": {"records": 8, "retention_hours": 100},
                     "gaps": {"records": 9, "retention_hours": 50}}
        declared = {"runs": {"records": 12, "retention_hours": 200},
                    "gaps": {"records": 20, "retention_hours": 60}}
        self.store.history = declared
        self.history.start_run("run-h", {"version": 2, "sampling": self.sampling,
                                         "history": effective},
                               {"policy_version": 2, "policy_digest": "c" * 64},
                               started_at=BASE)
        for index in range(41):
            self.append(index, run_id="run-h")
        report = history_report(self.store, until=BASE + 600, limit=100)
        contract = {"name": "host-steward.resource_history", "version": 1}
        self.assertEqual(report["contract"], contract)
        retention = report["retention"]["history"]
        self.assertEqual(retention["retention_source"], "latest_run_policy")
        self.assertEqual(retention["effective"], effective)
        self.assertEqual(retention["declared"], declared)
        self.assertFalse(retention["over_target"]["runs"])
        self.assertFalse(retention["over_target"]["gaps"])
        gap_history = report["gap_history"]
        self.assertEqual(gap_history["retention_source"], "latest_run_policy")
        self.assertEqual(gap_history["retention_hours"], 50)
        self.assertEqual(gap_history["count_limit"], 9)
        self.assertEqual(gap_history["declared_retention_hours"], 60)
        self.assertEqual(gap_history["declared_count_limit"], 20)
        self.assertIsNone(gap_history["pruned_through"])
        self.assertFalse(gap_history["over_target"])

        for raw in (False, True):
            with self.subTest(raw=raw):
                trimmed = fit_history_output(
                    history_report(self.store, until=BASE + 600, limit=100, raw=raw), 6000)
                self.assertLessEqual(len(encode(trimmed)), 6000)
                self.assertEqual(trimmed["contract"], contract)
                history = trimmed["retention"]["history"]
                self.assertEqual(history["retention_source"], "latest_run_policy")
                self.assertEqual(history["effective"], effective)
                self.assertEqual(history["declared"], declared)
                self.assertFalse(history["over_target"]["runs"])
                self.assertFalse(history["over_target"]["gaps"])
                self.assertIn("counts", history)
                self.assertIn("hard_limits", history)
                gap = trimmed["gap_history"]
                self.assertEqual(gap["retention_source"], "latest_run_policy")
                self.assertIsNone(gap["pruned_through"])
                self.assertEqual(gap["declared_retention_hours"], 60)
                self.assertEqual(gap["declared_count_limit"], 20)
                self.assertIn("hard_count_limit", gap)
                self.assertIn("gap_history_degraded", gap)
                self.assertFalse(gap["over_target"])

    def test_memory_summary_projects_non_byte_units_and_platform_gaps(self):
        counters = {"MemTotal": 20000, "MemFree": 1000, "Cached": 500, "AnonPages": 300,
                    "HugePages_Total": 4, "HugePages_Free": 2, "HugePages_Rsvd": 1,
                    "HugePages_Surp": 0, "Odd": 7}
        units = {"MemTotal": "bytes", "MemFree": "bytes", "Cached": "bytes",
                 "AnonPages": "bytes", "HugePages_Total": "count",
                 "HugePages_Free": "count", "HugePages_Rsvd": "count",
                 "HugePages_Surp": "count", "Odd": "MB"}
        source_units = {"MemTotal": "kB", "MemFree": "kB", "Cached": "kB",
                        "AnonPages": "kB", "HugePages_Total": None,
                        "HugePages_Free": None, "HugePages_Rsvd": None,
                        "HugePages_Surp": None, "Odd": "MB"}
        reason = "旧内核 /proc/meminfo 未提供 MemAvailable；不伪造推导值"
        self.append(0, host={"memory": {
            "available": True, "reason": None, "source": "/proc/meminfo",
            "total_bytes": 20000, "available_bytes": None, "available_reason": reason,
            "counters": counters, "units": units, "source_units": source_units,
            "platform_gaps": [{"field": "MemAvailable", "reason": reason}],
            "swap": {"available": True, "total_bytes": 0, "free_bytes": 0, "used_bytes": 0}}})
        memory = history_report(self.store, until=BASE + 15)["samples"][0]["host"]["memory"]
        self.assertIn("Cached", memory["components"])
        self.assertEqual(memory["component_units"],
                         "components 均为已换算的 bytes 口径；其余 counters 的单位见 non_byte_units，"
                         "HugePages_* 为无单位计数")
        self.assertEqual(memory["non_byte_units"]["HugePages_Total"],
                         {"units": "count", "source_units": None})
        self.assertEqual(memory["non_byte_units"]["Odd"],
                         {"units": "MB", "source_units": "MB"})
        self.assertNotIn("Cached", memory["non_byte_units"])
        self.assertEqual(memory["non_byte_counters"]["HugePages_Total"], 4)
        self.assertEqual(memory["non_byte_counters"]["Odd"], 7)
        self.assertEqual(memory["available_reason"], reason)
        self.assertEqual(memory["platform_gaps"], [{"field": "MemAvailable",
                                                    "reason": reason}])
        self.assertNotIn("non_byte_units_omitted", memory)
        self.assertNotIn("platform_gaps_omitted", memory)

    def test_memory_summary_stays_quiet_without_linux_unit_fields(self):
        self.append(0, host={"memory": {
            "available": True, "reason": None, "total_bytes": 20000, "page_size": 4096,
            "counters": {"Pages free": 10, "Pages active": 20},
            "swap": {"available": True, "used_bytes": 20}}})
        memory = history_report(self.store, until=BASE + 15)["samples"][0]["host"]["memory"]
        self.assertEqual(memory["component_units"], "vm_stat 保留页数；不混合相加")
        for key in ("non_byte_units", "non_byte_counters", "non_byte_units_omitted",
                    "non_byte_counters_omitted", "available_reason",
                    "platform_gaps", "platform_gaps_omitted"):
            self.assertNotIn(key, memory)

    def test_memory_projection_bounds_items_with_omitted_markers(self):
        keys = [f"Counter{index:02d}" for index in range(18)]
        counters = {key: index for index, key in enumerate(keys)}
        units = {key: "MB" for key in keys}
        reason = "R" * 600
        gaps = [{"field": f"field-{index}", "reason": reason} for index in range(9)]
        self.append(0, host={"memory": {
            "available": True, "total_bytes": 20000, "available_bytes": 1000,
            "counters": counters, "units": units,
            "source_units": dict(units), "platform_gaps": gaps}})
        memory = history_report(self.store, until=BASE + 15)["samples"][0]["host"]["memory"]
        self.assertEqual(len(memory["non_byte_units"]), 16)
        self.assertEqual(memory["non_byte_units_omitted"], 2)
        self.assertEqual(len(memory["non_byte_counters"]), 16)
        self.assertEqual(memory["non_byte_counters_omitted"], 2)
        self.assertEqual(len(memory["platform_gaps"]), 8)
        self.assertEqual(memory["platform_gaps_omitted"], 1)
        self.assertIn("省略", memory["platform_gaps"][0]["reason"])
        self.assertLess(len(memory["platform_gaps"][0]["reason"].encode("utf-8")), 600)

    def test_history_limit_defaults_and_maximum_are_explicit(self):
        self.append(0)
        self.assertEqual(history_report(self.store, until=BASE)["page"]["limit"], 41)
        self.assertEqual(
            history_report(self.store, until=BASE, limit=200)["page"]["limit"], 200)
        for limit in (0, -1, 201, True, "10", 2.5):
            with self.subTest(limit=limit), self.assertRaises(StewardError) as caught:
                history_report(self.store, until=BASE, limit=limit)
            self.assertIn("200", str(caught.exception))
            self.assertIn("41", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
