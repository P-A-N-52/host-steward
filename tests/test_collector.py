import fcntl
import json
import os
from pathlib import Path
import platform
import signal
import sqlite3
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from collector import (
    Collector,
    CollectorBusyError,
    CollectorConfigError,
    CollectorError,
    collector_lease,
)
from policy import make_policy_evidence, policy_digest
from sample_store import SampleStore
from state import Store
from state_io import DatabaseError, StewardError


LIMITS = {"file_bytes": 65536, "total_bytes": 8 * 1024 * 1024}
BASE_WALL = 1_700_000_000.0
BASE_MONO = 1000.0


def sampling(*, interval=1, cycle=1, process_interval=3, processes=2,
             records=20, retention_hours=1):
    return {
        "interval_seconds": interval,
        "cycle_seconds": cycle,
        "process_interval_seconds": process_interval,
        "processes": processes,
        "records": records,
        "retention_hours": retention_hours,
    }


def make_policy(*, purpose="collector 测试", config_sampling=None,
                roots=None, limits=None):
    return {
        "version": 2,
        "purpose": purpose,
        "roots": roots or ["/tmp"],
        "sampling": config_sampling or sampling(),
        "residents": [],
        "limits": limits or dict(LIMITS),
    }


class Clock:
    def __init__(self):
        self.mono = BASE_MONO
        self.wall = BASE_WALL

    def monotonic(self):
        return self.mono

    def time(self):
        return self.wall

    def advance(self, seconds):
        self.mono += seconds
        self.wall += seconds

    def jump_wall(self, seconds):
        self.wall += seconds


def make_store(base):
    store = Store(Path(base).resolve() / "state", dict(LIMITS))
    store.initialize_database()
    return store


def boot(value="boot-a", unix_time=1_699_999_000):
    return {"available": True, "boot_id": value, "unix_time": unix_time}


def build_result(clock, *, process_due=True, complete=True, usable=True,
                 process_failure=False, all_failed=False, source_error=False,
                 boot_value=None, failed_status=None):
    observed_at = clock.time()
    boot_value = boot_value or boot()
    host = {
        "boot": dict(boot_value),
        "cpu": {"available": True, "source": "fake", "counters": {}, "hz": 100},
        "memory": {"available": True, "source": "fake", "total_bytes": 1000,
                   "available_bytes": 500},
        "diskio": {"available": True, "source": "fake", "disks": []},
        "network": {"available": True, "source": "fake",
                    "interfaces": {"available": True, "items": []}},
        "storage": {"available": True, "source": "fake", "available_count": 1,
                    "roots": [{"path": "/tmp", "available": True}]},
    }
    sources = {}
    for name in ("boot", "cpu", "memory", "diskio", "network", "storage"):
        sources[name] = {
            "available": True,
            "attempted_at": observed_at,
            "success_at": observed_at,
            "source": "fake",
        }
    if source_error:
        host["memory"] = {"available": False, "reason": "memory failed",
                          "source": "fake"}
        sources["memory"] = {
            "available": False,
            "attempted_at": observed_at,
            "error_at": observed_at,
            "reason": "memory failed",
            "error": {"type": "RuntimeError", "message": "memory failed",
                      "traceback": "Traceback (most recent call last):\n"
                                   "  File \"fake.py\", line 1\n"
                                   "RuntimeError: memory failed",
                      "source": "memory"},
        }
        complete = False
    if all_failed:
        for name in ("boot", "cpu", "memory", "diskio", "network"):
            host[name] = {"available": False, "reason": f"{name} failed",
                          "source": "fake"}
            sources[name] = {
                "available": False,
                "attempted_at": observed_at,
                "error_at": observed_at,
                "reason": f"{name} failed",
                "error": {"type": "PermissionError", "message": f"{name} failed",
                          "traceback": "Traceback (most recent call last):\n"
                                       f"PermissionError: {name} failed",
                          "source": name},
            }
        host["storage"] = {"available": False, "reason": "no roots",
                           "available_count": 0, "roots": []}
        sources["storage"] = {"available": False, "attempted_at": observed_at,
                              "error_at": observed_at, "reason": "no roots"}
        complete, usable = False, False
    processes = None
    if process_due:
        if all_failed or process_failure:
            processes = {
                "available": False,
                "reason": "ps failed",
                "attempted_at": observed_at,
                "error": {"type": "RuntimeError", "message": "ps failed"},
                "items": [],
            }
            sources["processes"] = {
                "available": False,
                "attempted_at": observed_at,
                "error_at": observed_at,
                "reason": "ps failed",
                "error": {"type": "RuntimeError", "message": "ps failed",
                          "traceback": "Traceback (most recent call last):\n"
                                       "RuntimeError: ps failed",
                          "source": "processes"},
            }
            if not all_failed:
                complete = False
        else:
            processes = {
                "available": True,
                "observed": 1,
                "returned": 1,
                "truncated": False,
                "limit": 2,
                "items": [{"identity": "pid:boot:1", "pid": 1,
                           "rss_bytes": 100}],
            }
            sources["processes"] = {
                "available": True,
                "attempted_at": observed_at,
                "success_at": observed_at,
                "source": "fake ps",
            }
    status = failed_status or ("ok" if complete else "partial")
    if all_failed:
        status = "failed"
    return {
        "host": host,
        "boot": boot_value,
        "sources": sources,
        "processes": processes,
        "process_due": process_due,
        "observed_at": observed_at,
        "monotonic_at": clock.monotonic(),
        "elapsed_seconds": 0.01,
        "complete": complete and (processes is None or processes.get("available") is True),
        "usable": usable,
        "status": status,
        "failed_sources": sorted(
            name for name, value in sources.items()
            if value.get("available") is False),
        "not_attempted_sources": [],
        "budget_exhausted": False,
        "not_observed": ["gpu", "services", "power"],
    }


class FakeSampler:
    def __init__(self, clock, *, factory=None,
                 process_failure=False, all_failed=False, source_error=False,
                 complete=True, boot_value=None):
        self.clock = clock
        self.factory = factory
        self.process_failure = process_failure
        self.all_failed = all_failed
        self.source_error = source_error
        self.complete = complete
        self.boot_value = boot_value
        self.calls = []
        self.collector = None
        self.on_call = None

    def __call__(self, policy, *, process_due=True):
        self.calls.append(process_due)
        if self.on_call is not None:
            self.on_call(self, process_due)
        if self.factory is not None:
            return self.factory(self, process_due)
        return build_result(
            self.clock, process_due=process_due,
            process_failure=self.process_failure,
            all_failed=self.all_failed,
            source_error=self.source_error,
            complete=self.complete,
            boot_value=self.boot_value)


class ScriptedReader:
    def __init__(self, sequence):
        self.sequence = list(sequence)
        self.calls = 0

    def __call__(self, directory):
        self.calls += 1
        if len(self.sequence) > 1:
            item = self.sequence.pop(0)
        else:
            item = self.sequence[0]
        if isinstance(item, BaseException):
            raise item
        return item, make_policy_evidence(item)


def advancing_wait(clock, *, on_wait=None, extra=0.0):
    def wait(timeout):
        clock.advance(timeout + extra)
        if on_wait is not None:
            on_wait()
        return False
    return wait


def stop_on_sampler_call(collector_ref, count):
    def callback(sampler, process_due):
        if len(sampler.calls) >= count:
            collector_ref["collector"].request_stop()
    return callback


def make_collector(store, clock, sampler, *, policy=None, reader=None,
                   boot_sampler=None, wait=None, stop_lock_timeout=0.0,
                   wait_slice_seconds=60.0, run_id_counter=None):
    counter = run_id_counter or {"value": 0}

    def run_id():
        counter["value"] += 1
        return f"run-{counter['value']}"

    options = {
        "sampler": sampler,
        "boot_sampler": boot_sampler or (lambda policy: boot()),
        "clock": clock.monotonic,
        "wall_clock": clock.time,
        "wait": wait or advancing_wait(clock),
        "wait_slice_seconds": wait_slice_seconds,
        "stop_lock_timeout": stop_lock_timeout,
        "pid": 4321,
        "run_id_factory": run_id,
    }
    if reader is not None:
        collector = Collector(store, policy_reader=reader, **options)
    else:
        collector = Collector(store, policy=policy, **options)
    sampler.collector = collector
    return collector


def run_rows(store):
    connection = sqlite3.connect(store.database_path)
    try:
        return connection.execute(
            "SELECT run_id, stop_reason, policy_json, evidence_json "
            "FROM collector_runs ORDER BY started_at, run_id").fetchall()
    finally:
        connection.close()


def state_detail(store):
    connection = sqlite3.connect(store.database_path)
    try:
        row = connection.execute(
            "SELECT detail_json FROM collector_state WHERE singleton=1").fetchone()
        return json.loads(row[0])["detail"]
    finally:
        connection.close()


class CollectorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.store = make_store(self.base)
        self.clock = Clock()
        self.policy = make_policy()
        self.sampler = FakeSampler(self.clock)

    def test_collector_lock_is_regular_file_and_releases_after_error(self):
        with collector_lease(self.store):
            lock = self.store.target(".collector.lock")
            self.assertTrue(lock.is_file())
            self.assertTrue(stat.S_ISREG(lock.stat().st_mode))
            with self.assertRaises(CollectorBusyError):
                with collector_lease(self.store):
                    pass
        with self.assertRaises(RuntimeError):
            with collector_lease(self.store):
                raise RuntimeError("boom")
        with collector_lease(self.store):
            pass

    def test_fifo_and_symlink_lock_targets_are_rejected(self):
        lock = self.store.target(".collector.lock")
        os.mkfifo(lock)
        with self.assertRaises(CollectorError):
            with collector_lease(self.store):
                pass
        lock.unlink()
        target = self.store.path / "regular.lock"
        target.write_text("", encoding="utf-8")
        lock.symlink_to(target)
        with self.assertRaises(CollectorError):
            with collector_lease(self.store):
                pass

    def test_once_does_not_hold_patrol_lock_and_commits_one_sample(self):
        checks = []

        def on_call(sampler, process_due):
            with self.store.lock():
                checks.append(process_due)

        self.sampler.on_call = on_call
        collector = make_collector(self.store, self.clock, self.sampler,
                                   policy=self.policy)
        summary = collector.run(once=True)
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["cycles"], 1)
        self.assertEqual(summary["samples"], 1)
        self.assertEqual(summary["stop_reason"], "once")
        self.assertTrue(checks)
        self.assertTrue(all(checks))
        status = collector.samples.status()
        self.assertEqual(status["status"], "stopped")
        self.assertEqual(status["retention"]["records"], 1)
        self.assertEqual(status["open_gap_count"], 0)
        page = collector.samples.query(None, None)
        self.assertEqual(len(page["samples"]), 1)
        self.assertEqual(page["samples"][0]["run"]["run_id"], "run-1")
        self.assertEqual(page["samples"][0]["host"]["cpu"]["available"], True)

    def test_start_lock_busy_is_rejected_before_run_creation(self):
        collector = make_collector(self.store, self.clock, self.sampler,
                                   policy=self.policy)
        with self.store.lock():
            with self.assertRaises(CollectorBusyError):
                collector.run(once=True)
        self.assertEqual(self.sampler.calls, [])
        self.assertEqual(collector.samples.status()["status"], "not_started")
        with collector_lease(self.store):
            pass

    def test_sigterm_stops_at_batch_boundary_and_restores_handler(self):
        def sentinel(signum, frame):
            pass

        original = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, sentinel)
        self.addCleanup(signal.signal, signal.SIGTERM, original)

        def on_call(sampler, process_due):
            os.kill(os.getpid(), signal.SIGTERM)

        self.sampler.on_call = on_call
        collector = make_collector(self.store, self.clock, self.sampler,
                                   policy=self.policy)
        summary = collector.run()
        self.assertIs(signal.getsignal(signal.SIGTERM), sentinel)
        self.assertEqual(summary["stop_reason"], "signal")
        self.assertEqual(summary["signal"], signal.SIGTERM)
        self.assertEqual(summary["samples"], 1)
        status = collector.samples.status()
        self.assertEqual(status["status"], "stopped")
        gaps = collector.samples.query(None, None)["gaps"]
        stopped = [gap for gap in gaps if gap["reason"] == "collector_stopped"]
        self.assertEqual(len(stopped), 1)
        self.assertTrue(stopped[0]["ongoing"])

    def test_clean_restart_closes_open_collector_stopped_gap(self):
        collector = make_collector(self.store, self.clock, self.sampler,
                                   policy=self.policy)
        self.sampler.on_call = stop_on_sampler_call(
            {"collector": collector}, 1)
        first = collector.run()
        self.assertEqual(first["stop_reason"], "requested")
        gaps = collector.samples.query(None, None)["gaps"]
        open_gap = [gap for gap in gaps
                    if gap["reason"] == "collector_stopped" and gap["ongoing"]]
        self.assertEqual(len(open_gap), 1)
        first_start = open_gap[0]["start_at"]
        self.clock.advance(10)
        second_sampler = FakeSampler(self.clock)
        second = make_collector(self.store, self.clock, second_sampler,
                                policy=self.policy,
                                run_id_counter={"value": 1})
        summary = second.run(once=True)
        self.assertTrue(summary["startup"]["closed_open_gaps"])
        gaps = second.samples.query(None, None)["gaps"]
        stopped = [gap for gap in gaps if gap["reason"] == "collector_stopped"]
        self.assertTrue(stopped)
        self.assertTrue(all(not gap["ongoing"] for gap in stopped))
        self.assertAlmostEqual(stopped[-1]["start_at"], first_start)
        self.assertGreater(stopped[-1]["end_at"], stopped[-1]["start_at"])
        sample = second.samples.query(None, None)["samples"][0]
        self.assertGreaterEqual(sample["observed_at"], stopped[-1]["end_at"])

    def test_wall_clock_rollback_closes_open_gap_by_identity(self):
        collector = make_collector(self.store, self.clock, self.sampler,
                                   policy=self.policy)
        self.sampler.on_call = stop_on_sampler_call(
            {"collector": collector}, 1)
        collector.run()
        gaps = collector.samples.query(None, None)["gaps"]
        open_gap = [gap for gap in gaps
                    if gap["reason"] == "collector_stopped" and gap["ongoing"]]
        self.assertEqual(len(open_gap), 1)
        first_start = open_gap[0]["start_at"]

        self.clock.jump_wall(-3600)
        second_sampler = FakeSampler(self.clock)
        second = make_collector(self.store, self.clock, second_sampler,
                                policy=self.policy,
                                run_id_counter={"value": 1})
        summary = second.run(once=True)
        self.assertEqual(summary["startup"]["closed_open_gap_count"], 1)
        self.assertTrue(summary["startup"]["closed_open_gaps"][0]
                        ["wall_clock_regression"])
        self.assertEqual(second.samples.status()["open_gap_count"], 0)
        stopped = [gap for gap in second.samples.query(None, None)["gaps"]
                   if gap["reason"] == "collector_stopped"]
        self.assertEqual(len(stopped), 1)
        self.assertFalse(stopped[0]["ongoing"])
        self.assertEqual(stopped[0]["start_at"], stopped[0]["end_at"])
        self.assertLess(stopped[0]["end_at"], first_start)
        self.assertTrue(stopped[0]["detail"]["wall_clock_regression"])
        self.assertEqual(stopped[0]["detail"]["raw_start_at"], first_start)

    def test_unclean_restart_records_gap_and_boot_change(self):
        samples = SampleStore(self.store)
        old_policy = make_policy(purpose="old")
        old_boot = boot("boot-a")
        started = self.clock.time()
        samples.start_run("old-run", old_policy, make_policy_evidence(old_policy),
                          started_at=started, boot=old_boot, pid=111)
        self.clock.advance(1)
        samples.append_sample(
            "old-run", observed_at=self.clock.time(),
            monotonic_at=self.clock.monotonic(), boot=old_boot,
            host={"cpu": {"available": True}}, sources={
                "cpu": {"available": True, "attempted_at": self.clock.time(),
                        "success_at": self.clock.time()}},
            sampling=self.policy["sampling"])
        self.assertIsNotNone(samples.status()["active_run"])
        self.clock.advance(5)
        new_boot = boot("boot-b")
        sampler = FakeSampler(self.clock, boot_value=new_boot)
        collector = make_collector(
            self.store, self.clock, sampler, policy=self.policy,
            boot_sampler=lambda policy: new_boot)
        summary = collector.run(once=True)
        self.assertTrue(summary["startup"]["unclean_stop"])
        self.assertTrue(summary["startup"]["host_reboot"])
        gaps = collector.samples.query(None, None)["gaps"]
        unclean = [gap for gap in gaps if gap["reason"] == "unclean_stop"]
        reboot = [gap for gap in gaps if gap["reason"] == "host_reboot"]
        self.assertEqual(len(unclean), 1)
        self.assertEqual(unclean[0]["run_id"], "old-run")
        self.assertTrue(unclean[0]["detail"]["collector_stopped"])
        self.assertTrue(unclean[0]["detail"]["host_reboot"])
        self.assertEqual(len(reboot), 1)
        rows = run_rows(self.store)
        old = [row for row in rows if row[0] == "old-run"][0]
        self.assertEqual(old[1], "superseded")
        page = collector.samples.query(None, None, limit=10)
        new_samples = [row for row in page["samples"] if row["run_id"] != "old-run"]
        self.assertEqual(len(new_samples), 1)
        self.assertEqual(new_samples[0]["boot"]["boot_id"], "boot-b")

    def test_unclean_restart_without_first_sample_uses_run_start(self):
        samples = SampleStore(self.store)
        old_policy = make_policy(purpose="old-no-sample")
        started = self.clock.time()
        samples.start_run("old-run", old_policy, make_policy_evidence(old_policy),
                          started_at=started, boot=boot("boot-a"), pid=111)
        self.clock.advance(7)
        collector = make_collector(self.store, self.clock,
                                   FakeSampler(self.clock), policy=self.policy,
                                   boot_sampler=lambda policy: boot("boot-a"))
        summary = collector.run(once=True)
        self.assertTrue(summary["startup"]["unclean_stop"])
        gaps = collector.samples.query(None, None)["gaps"]
        unclean = [gap for gap in gaps if gap["reason"] == "unclean_stop"][0]
        self.assertAlmostEqual(unclean["start_at"], started)
        self.assertGreaterEqual(unclean["end_at"], unclean["start_at"])

    def test_startup_applies_validated_limits_and_evidence(self):
        limits = {"command_bytes": 262144, "file_bytes": 131072,
                  "total_bytes": 16 * 1024 * 1024}
        policy = make_policy(purpose="startup-limits", limits=limits)
        collector = make_collector(self.store, self.clock,
                                   FakeSampler(self.clock), policy=policy)
        summary = collector.run(once=True)
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(self.store.limits, limits)
        self.assertEqual(self.store.policy_evidence["policy_digest"],
                         policy_digest(policy))
        self.assertEqual(summary["policy_digest"], policy_digest(policy))

    def test_hot_switch_applies_new_limits_and_evidence(self):
        policy_a = make_policy(purpose="limits-A", limits=dict(LIMITS))
        policy_b = make_policy(
            purpose="limits-B",
            limits={"command_bytes": 262144, "file_bytes": 32768,
                    "total_bytes": 2 * 1024 * 1024})
        reader = ScriptedReader([policy_a, policy_a, policy_b])
        sampler = FakeSampler(self.clock)
        collector = make_collector(
            self.store, self.clock, sampler, reader=reader,
            wait=advancing_wait(self.clock), stop_lock_timeout=0.0)
        sampler.on_call = stop_on_sampler_call({"collector": collector}, 2)
        summary = collector.run()
        self.assertEqual(summary["run_changes"], 1)
        self.assertEqual(self.store.limits, policy_b["limits"])
        self.assertEqual(self.store.policy_evidence["policy_digest"],
                         policy_digest(policy_b))
        self.assertEqual(summary["policy_digest"], policy_digest(policy_b))
        page = collector.samples.query(None, None, limit=10)
        self.assertEqual(len(page["samples"]), 2)
        by_run = {sample["run_id"]: sample for sample in page["samples"]}
        self.assertEqual(by_run["run-2"]["run"]["policy"]["purpose"], "limits-B")
        self.assertEqual(by_run["run-2"]["run"]["evidence"]["policy_digest"],
                         policy_digest(policy_b))

    def test_hot_switch_budget_rejection_restores_old_limits_and_evidence(self):
        policy_a = make_policy(purpose="reject-A", limits=dict(LIMITS))
        policy_b = make_policy(
            purpose="reject-B",
            limits={"command_bytes": 262144, "file_bytes": 32768,
                    "total_bytes": 1})
        reader = ScriptedReader([policy_a, policy_a, policy_b])
        sampler = FakeSampler(self.clock)
        collector = make_collector(
            self.store, self.clock, sampler, reader=reader,
            wait=advancing_wait(self.clock), stop_lock_timeout=0.0)
        with self.assertRaises(StewardError) as caught:
            collector.run()
        self.assertIn("容量", str(caught.exception))
        self.assertEqual(len(sampler.calls), 1)
        self.assertEqual(self.store.limits, policy_a["limits"])
        self.assertEqual(self.store.policy_evidence["policy_digest"],
                         policy_digest(policy_a))
        self.assertEqual(collector._policy_state.digest, policy_digest(policy_a))
        detail = state_detail(self.store)
        self.assertEqual(detail["phase"], "config_switch_failed")
        self.assertEqual(detail["policy_digest"], policy_digest(policy_a))
        self.assertEqual(detail["rejected_policy_digest"],
                         policy_digest(policy_b))
        rows = run_rows(self.store)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "config_changed")
        self.assertIn("reject-A", rows[0][2])
        self.assertNotIn("reject-B", rows[0][2])
        page = collector.samples.query(None, None, limit=10)
        self.assertEqual(len(page["samples"]), 1)
        self.assertIn("reject-A", json.dumps(
            page["samples"][0]["run"]["policy"], ensure_ascii=False))

    def test_config_change_switches_run_and_keeps_old_digest(self):
        policy_a = make_policy(purpose="A")
        policy_b = make_policy(purpose="B")
        reader = ScriptedReader([policy_a, policy_a, policy_b])
        sampler = FakeSampler(self.clock)
        collector = make_collector(
            self.store, self.clock, sampler, reader=reader,
            wait=advancing_wait(self.clock),
            stop_lock_timeout=0.0)
        sampler.on_call = stop_on_sampler_call({"collector": collector}, 2)
        summary = collector.run()
        self.assertEqual(summary["run_changes"], 1)
        self.assertEqual(summary["last_config_event"]["kind"], "config_changed")
        self.assertEqual(summary["last_cycle"]["status"], "ok")
        self.assertEqual(summary["stop_reason"], "requested")
        rows = run_rows(self.store)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][1], "config_changed")
        self.assertEqual(rows[1][1], "requested")
        page = collector.samples.query(None, None, limit=10)
        self.assertEqual(len(page["samples"]), 2)
        by_run = {sample["run_id"]: sample for sample in page["samples"]}
        self.assertEqual(by_run["run-1"]["run"]["policy"]["purpose"], "A")
        self.assertEqual(by_run["run-2"]["run"]["policy"]["purpose"], "B")
        self.assertEqual(by_run["run-1"]["run"]["evidence"]["policy_digest"],
                         policy_digest(policy_a))
        self.assertEqual(by_run["run-2"]["run"]["evidence"]["policy_digest"],
                         policy_digest(policy_b))

    def test_invalid_config_pauses_then_recovers_with_new_run(self):
        policy_a = make_policy(purpose="recover")
        invalid = StewardError("invalid host.json: duplicate key")
        reader = ScriptedReader([policy_a, policy_a, invalid, invalid, policy_a])
        sampler = FakeSampler(self.clock)
        collector = make_collector(
            self.store, self.clock, sampler, reader=reader,
            wait=advancing_wait(self.clock), stop_lock_timeout=0.0)
        sampler.on_call = stop_on_sampler_call({"collector": collector}, 2)
        summary = collector.run()
        self.assertEqual(summary["config_errors"], 2)
        self.assertEqual(summary["run_changes"], 1)
        self.assertEqual(summary["samples"], 2)
        self.assertEqual(summary["last_config_event"]["kind"], "config_recovered")
        rows = run_rows(self.store)
        self.assertEqual(rows[0][1], "config_recovered")
        self.assertEqual(rows[1][1], "requested")
        gaps = collector.samples.query(None, None)["gaps"]
        config_gaps = [gap for gap in gaps if gap["reason"] == "config_error"]
        self.assertEqual(len(config_gaps), 1)
        self.assertFalse(config_gaps[0]["ongoing"])
        self.assertIn("Traceback", config_gaps[0]["detail"]["error"]["traceback"])
        self.assertIn("invalid host.json", config_gaps[0]["detail"]["error"]["message"])
        page = collector.samples.query(None, None, limit=10)
        self.assertEqual({sample["run_id"] for sample in page["samples"]},
                         {"run-1", "run-2"})

    def test_invalid_config_updates_heartbeat_and_closes_gap_on_stop(self):
        policy_a = make_policy(purpose="heartbeat")
        invalid = StewardError("invalid host.json: heartbeat case")
        reader = ScriptedReader([policy_a, policy_a, invalid])
        sampler = FakeSampler(self.clock)
        collector_ref = {"collector": None}
        wait_calls = {"count": 0}

        def wait(timeout):
            self.clock.advance(timeout)
            wait_calls["count"] += 1
            if wait_calls["count"] >= 2:
                collector_ref["collector"].request_stop()
            return False

        collector = make_collector(
            self.store, self.clock, sampler, reader=reader, wait=wait,
            stop_lock_timeout=0.0)
        collector_ref["collector"] = collector
        summary = collector.run()
        self.assertEqual(summary["config_errors"], 1)
        self.assertEqual(summary["samples"], 1)
        status = collector.samples.status()
        self.assertEqual(status["status"], "stopped")
        self.assertGreaterEqual(status["heartbeat_at"],
                                summary["last_sample_at"])
        gaps = collector.samples.query(None, None)["gaps"]
        config_gaps = [gap for gap in gaps if gap["reason"] == "config_error"]
        self.assertEqual(len(config_gaps), 1)
        self.assertFalse(config_gaps[0]["ongoing"])
        self.assertTrue(any(gap["reason"] == "collector_stopped" and gap["ongoing"]
                            for gap in gaps))

    def test_process_cadence_and_none_does_not_overwrite_snapshot(self):
        policy = make_policy(config_sampling=sampling(
            interval=1, process_interval=3, processes=2))
        sampler = FakeSampler(self.clock)
        collector = make_collector(
            self.store, self.clock, sampler, policy=policy,
            wait=advancing_wait(self.clock), stop_lock_timeout=0.0)
        sampler.on_call = stop_on_sampler_call({"collector": collector}, 5)
        summary = collector.run()
        self.assertEqual(sampler.calls, [True, False, False, True, False])
        self.assertEqual(summary["samples"], 5)
        latest = collector.samples.latest_processes()
        self.assertTrue(latest["observed"])
        self.assertEqual(latest["process_count"], 1)
        page = collector.samples.query(None, None, limit=10)
        flags = [sample["process_observed"] for sample in page["samples"]]
        self.assertEqual(flags, [False, True, False, False, True])

    def test_process_failure_keeps_available_false_metadata(self):
        policy = make_policy(config_sampling=sampling(
            interval=1, process_interval=1, processes=2))
        sampler = FakeSampler(self.clock, process_failure=True)
        collector = make_collector(self.store, self.clock, sampler,
                                   policy=policy)
        summary = collector.run(once=True)
        self.assertEqual(summary["status"], "partial")
        latest = collector.samples.latest_processes()
        self.assertTrue(latest["observed"])
        self.assertEqual(latest["process_count"], 0)
        self.assertEqual(latest["meta"]["available"], False)
        self.assertEqual(latest["meta"]["reason"], "ps failed")
        sample = collector.samples.query(None, None)["samples"][0]
        self.assertTrue(sample["process_observed"])
        self.assertEqual(sample["sources"]["processes"]["error"]["type"],
                         "RuntimeError")

    def test_all_failed_batch_returns_failed_and_does_not_append_sample(self):
        sampler = FakeSampler(self.clock, all_failed=True)
        collector = make_collector(self.store, self.clock, sampler,
                                   policy=self.policy)
        summary = collector.run(once=True)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["samples"], 0)
        self.assertEqual(summary["failed_cycles"], 1)
        status = collector.samples.status()
        self.assertIsNone(status["last_sample"])
        self.assertIsNotNone(status["heartbeat_at"])
        gaps = collector.samples.query(None, None)["gaps"]
        failed = [gap for gap in gaps if gap["reason"] == "sample_unavailable"]
        self.assertEqual(len(failed), 1)
        self.assertFalse(failed[0]["ongoing"])
        self.assertIn("Traceback", failed[0]["detail"]["source_errors"][0]["traceback"])
        self.assertEqual(collector.samples.query(None, None)["samples"], [])

    def test_small_file_bytes_bounds_gap_detail_and_keeps_collector_alive(self):
        policy = make_policy(limits={"file_bytes": 1024,
                                     "total_bytes": 8 * 1024 * 1024})
        sampler = FakeSampler(self.clock, all_failed=True)
        collector = make_collector(self.store, self.clock, sampler,
                                   policy=policy)
        summary = collector.run(once=True)
        self.assertEqual(summary["status"], "failed")
        gaps = collector.samples.query(None, None)["gaps"]
        failed = [gap for gap in gaps if gap["reason"] == "sample_unavailable"]
        self.assertEqual(len(failed), 1)
        self.assertTrue(failed[0]["detail"]["truncated"])
        self.assertLessEqual(len(json.dumps(failed[0]["detail"],
                                            ensure_ascii=False).encode()), 1024)

    def test_storage_failure_stops_writes_and_raises_original_error(self):
        collector = make_collector(self.store, self.clock, self.sampler,
                                   policy=self.policy)
        with patch.object(SampleStore, "append_sample",
                          side_effect=DatabaseError("状态容量不足")):
            with self.assertRaises(DatabaseError) as caught:
                collector.run(once=True)
        self.assertIn("状态容量不足", str(caught.exception))
        self.assertEqual(len(self.sampler.calls), 1)
        status = collector.samples.status()
        self.assertIsNone(status["last_sample"])
        self.assertEqual(status["status"], "stopped")
        rows = run_rows(self.store)
        self.assertEqual(rows[-1][1], "storage_error")

    def test_patrol_lock_defers_sample_and_flushes_gap_on_stop(self):
        holder = {"fd": None}

        def lock_patrol():
            path = self.store.target(".lock")
            fd = os.open(os.fspath(path), os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            holder["fd"] = fd

        def release_patrol():
            fd = holder["fd"]
            if fd is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
                holder["fd"] = None

        self.addCleanup(release_patrol)
        sampler = FakeSampler(self.clock)
        collector_ref = {"collector": None}

        def on_call(sampler, process_due):
            if len(sampler.calls) == 1:
                lock_patrol()

        def wait(timeout):
            self.clock.advance(timeout)
            release_patrol()
            collector_ref["collector"].request_stop()
            return False

        sampler.on_call = on_call
        collector = make_collector(
            self.store, self.clock, sampler, policy=self.policy,
            wait=wait, stop_lock_timeout=0.0)
        collector_ref["collector"] = collector
        summary = collector.run()
        self.assertEqual(summary["deferred_cycles"], 1)
        self.assertEqual(summary["samples"], 0)
        status = collector.samples.status()
        self.assertIsNone(status["last_sample"])
        gaps = collector.samples.query(None, None)["gaps"]
        deferred = [gap for gap in gaps if gap["reason"] == "commit_deferred"]
        self.assertEqual(len(deferred), 1)
        self.assertFalse(deferred[0]["ongoing"])
        self.assertGreaterEqual(deferred[0]["end_at"], deferred[0]["start_at"])
        self.assertTrue(any(gap["reason"] == "collector_stopped"
                            for gap in gaps))
        self.assertIsNone(holder["fd"])

    def test_patrol_lock_deferred_gap_flushes_before_next_sample(self):
        holder = {"fd": None}

        def lock_patrol():
            path = self.store.target(".lock")
            fd = os.open(os.fspath(path), os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            holder["fd"] = fd

        def release_patrol():
            fd = holder["fd"]
            if fd is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
                holder["fd"] = None

        self.addCleanup(release_patrol)
        sampler = FakeSampler(self.clock)

        def wait(timeout):
            self.clock.advance(timeout)
            release_patrol()
            return False

        collector = make_collector(
            self.store, self.clock, sampler, policy=self.policy,
            wait=wait, stop_lock_timeout=0.0)
        stop_callback = stop_on_sampler_call({"collector": collector}, 2)

        def on_call(sampler, process_due):
            if len(sampler.calls) == 1:
                lock_patrol()
            stop_callback(sampler, process_due)

        sampler.on_call = on_call
        summary = collector.run()
        self.assertEqual(summary["deferred_cycles"], 1)
        self.assertEqual(summary["samples"], 1)
        page = collector.samples.query(None, None)
        self.assertEqual(len(page["samples"]), 1)
        sample_at = page["samples"][0]["observed_at"]
        deferred = [gap for gap in page["gaps"]
                    if gap["reason"] == "commit_deferred"]
        self.assertEqual(len(deferred), 1)
        self.assertFalse(deferred[0]["ongoing"])
        self.assertEqual(deferred[0]["end_at"], sample_at)
        self.assertIsNone(holder["fd"])

    def test_stop_lock_busy_raises_and_preserves_active_run_evidence(self):
        holder = {"fd": None}

        def lock_patrol():
            path = self.store.target(".lock")
            fd = os.open(os.fspath(path), os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            holder["fd"] = fd

        def release_patrol():
            fd = holder["fd"]
            if fd is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
                holder["fd"] = None

        self.addCleanup(release_patrol)
        sampler = FakeSampler(self.clock)
        collector = make_collector(
            self.store, self.clock, sampler, policy=self.policy,
            stop_lock_timeout=0.0)
        sampler.on_call = lambda sampler, process_due: lock_patrol()
        with self.assertRaises(CollectorBusyError):
            collector.run(once=True)
        self.assertEqual(len(sampler.calls), 1)
        release_patrol()
        status = collector.samples.status()
        self.assertIsNotNone(status["active_run"])
        rows = run_rows(self.store)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0][1])
        gaps = collector.samples.query(None, None)["gaps"]
        self.assertFalse(any(gap["reason"] == "collector_stopped"
                             for gap in gaps))

    def test_long_interval_waits_configured_monotonic_interval(self):
        policy = make_policy(config_sampling=sampling(
            interval=3600, cycle=5, process_interval=3600, processes=2))
        sampler = FakeSampler(self.clock)
        collector = make_collector(
            self.store, self.clock, sampler, policy=policy,
            wait=advancing_wait(self.clock), wait_slice_seconds=3600.0,
            stop_lock_timeout=0.0)
        sampler.on_call = stop_on_sampler_call({"collector": collector}, 2)
        start_mono = self.clock.mono
        summary = collector.run()
        self.assertEqual(summary["cycles"], 2)
        self.assertEqual(summary["samples"], 2)
        self.assertEqual(summary["last_cycle"]["interval_seconds"], 3600)
        self.assertEqual(summary["last_cycle"]["schedule_lag_seconds"], 0.0)
        self.assertAlmostEqual(self.clock.mono - start_mono, 3600.0)

    def test_schedule_lag_and_wall_clock_jump_are_recorded(self):
        sampler = FakeSampler(self.clock)
        sampler.on_call = lambda sampler, process_due: sampler.clock.jump_wall(30)
        collector = make_collector(
            self.store, self.clock, sampler, policy=self.policy,
            wait=advancing_wait(self.clock, extra=10),
            stop_lock_timeout=0.0)
        sampler.on_call = stop_on_sampler_call({"collector": collector}, 2)
        original_on_call = sampler.on_call

        def on_call(sampler, process_due):
            if len(sampler.calls) == 1:
                sampler.clock.jump_wall(30)
            original_on_call(sampler, process_due)

        sampler.on_call = on_call
        summary = collector.run()
        cycle = summary["last_cycle"]
        self.assertGreaterEqual(cycle["schedule_lag_seconds"], 10.0)
        self.assertGreaterEqual(cycle["missed_intervals"], 10)
        self.assertTrue(cycle["wall_clock_jump"])
        self.assertGreaterEqual(cycle["wall_clock_skew_seconds"], 29.0)
        detail = state_detail(self.store)
        self.assertTrue(detail["last_cycle"]["wall_clock_jump"])
        self.assertGreaterEqual(detail["last_cycle"]["schedule_lag_seconds"], 10.0)

    def test_wall_clock_backward_stop_is_marked_and_nondecreasing(self):
        sampler = FakeSampler(self.clock)

        def on_call(sampler, process_due):
            sampler.clock.jump_wall(-60)

        sampler.on_call = on_call
        collector = make_collector(self.store, self.clock, sampler,
                                   policy=self.policy)
        summary = collector.run(once=True)
        self.assertTrue(summary["wall_clock_regression"])
        self.assertEqual(summary["stopped_at"], summary["started_at"])
        sample = collector.samples.query(None, None)["samples"][0]
        self.assertEqual(sample["observed_at"], summary["started_at"] - 60)
        detail = state_detail(self.store)
        self.assertTrue(detail["wall_clock_regression"])
        self.assertEqual(detail["raw_stopped_at"], summary["started_at"] - 60)

    def test_invalid_startup_policy_and_v1_are_explicit_errors(self):
        bad_reader = ScriptedReader([StewardError("broken host.json")])
        collector = make_collector(
            self.store, self.clock, FakeSampler(self.clock), reader=bad_reader)
        with self.assertRaises(CollectorConfigError) as caught:
            collector.run(once=True)
        self.assertIn("broken host.json", str(caught.exception))
        self.assertEqual(collector.samples.status()["status"], "not_started")

        v1 = make_policy()
        v1["version"] = 1
        collector = make_collector(self.store, self.clock,
                                   FakeSampler(self.clock), policy=v1)
        with self.assertRaises(CollectorConfigError) as caught:
            collector.run(once=True)
        self.assertIn("version 2", str(caught.exception))
        self.assertIn("upgrade", str(caught.exception))
        with collector_lease(self.store):
            pass

    def test_run_stopped_before_first_sample_still_has_run_evidence(self):
        collector = make_collector(self.store, self.clock, self.sampler,
                                   policy=self.policy)
        collector.request_stop()
        summary = collector.run()
        self.assertEqual(summary["cycles"], 0)
        self.assertEqual(summary["samples"], 0)
        self.assertEqual(summary["stop_reason"], "requested")
        self.assertEqual(self.sampler.calls, [])
        status = collector.samples.status()
        self.assertEqual(status["status"], "stopped")
        self.assertIsNone(status["last_sample"])
        rows = run_rows(self.store)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "requested")
        gaps = collector.samples.query(None, None)["gaps"]
        self.assertTrue(any(gap["reason"] == "collector_stopped" and gap["ongoing"]
                            for gap in gaps))

    def test_runtime_boot_change_switches_run_and_records_gap(self):
        def factory(sampler, process_due):
            value = boot("boot-a") if len(sampler.calls) == 1 else boot("boot-b")
            return build_result(self.clock, process_due=process_due,
                                boot_value=value)

        sampler = FakeSampler(self.clock, factory=factory)
        collector = make_collector(
            self.store, self.clock, sampler, policy=self.policy,
            boot_sampler=lambda policy: boot("boot-a"),
            wait=advancing_wait(self.clock), stop_lock_timeout=0.0)
        sampler.on_call = stop_on_sampler_call({"collector": collector}, 2)
        summary = collector.run()
        self.assertEqual(summary["run_changes"], 1)
        self.assertEqual(summary["last_boot_event"]["current_boot"]["boot_id"],
                         "boot-b")
        rows = run_rows(self.store)
        self.assertEqual(rows[0][1], "host_reboot")
        self.assertEqual(rows[1][1], "requested")
        gaps = collector.samples.query(None, None)["gaps"]
        reboot = [gap for gap in gaps if gap["reason"] == "host_reboot"]
        self.assertEqual(len(reboot), 1)
        self.assertFalse(reboot[0]["ongoing"])
        page = collector.samples.query(None, None, limit=10)
        self.assertEqual(len(page["samples"]), 2)
        by_run = {sample["run_id"]: sample for sample in page["samples"]}
        self.assertEqual(by_run["run-1"]["boot"]["boot_id"], "boot-a")
        self.assertEqual(by_run["run-2"]["boot"]["boot_id"], "boot-b")

    @unittest.skipUnless(platform.system() == "Darwin", "仅在本机 macOS 跑真实命令")
    def test_macos_collector_once_reads_real_host_json(self):
        root = self.base / "host-json-root"
        root.mkdir()
        limits = {
            "scan_entries": 5000, "scan_seconds": 3, "processes": 200,
            "command_bytes": 262144, "file_bytes": 1048576,
            "total_bytes": 8 * 1024 * 1024, "output_bytes": 32768,
            "change_records": 96, "sample_records": 48,
            "operation_records": 32, "retention_hours": 48,
        }
        policy = {
            "version": 2,
            "purpose": "真实 host.json 读取测试",
            "roots": [{"path": str(root), "max_depth": 1,
                       "exclude_names": [], "exclude_paths": []}],
            "sampling": sampling(interval=15, cycle=5, process_interval=60,
                                 processes=20, records=10, retention_hours=1),
            "residents": [],
            "directory_rules": [],
            "limits": limits,
            "host": {"system": platform.system(), "hostname": platform.node()},
        }
        (self.store.path / "host.json").write_text(
            json.dumps(policy, ensure_ascii=False), encoding="utf-8")
        collector = Collector(self.store, stop_lock_timeout=0.0)
        summary = collector.run(once=True)
        self.assertIn(summary["status"], {"ok", "partial"})
        self.assertEqual(summary["samples"], 1)
        self.assertEqual(summary["policy_digest"], policy_digest(policy))
        self.assertEqual(self.store.limits, limits)
        self.assertEqual(self.store.policy_evidence["policy_digest"],
                         policy_digest(policy))
        sample = collector.samples.query(None, None)["samples"][0]
        self.assertEqual(sample["run"]["policy"]["purpose"],
                         "真实 host.json 读取测试")
        self.assertTrue(sample["host"]["cpu"]["available"])
        print(f"\n[real host.json collector] elapsed={summary['elapsed_seconds']:.3f}s "
              f"status={summary['status']} samples={summary['samples']}")

    @unittest.skipUnless(platform.system() == "Darwin", "仅在本机 macOS 跑真实命令")
    def test_macos_collector_once_with_real_sampler(self):
        root = self.base / "真实观察根"
        root.mkdir()
        policy = make_policy(
            purpose="真实 macOS collector",
            config_sampling=sampling(interval=15, cycle=5,
                                     process_interval=60, processes=20,
                                     records=10, retention_hours=1),
            roots=[str(root)],
            limits={"command_bytes": 262144, "file_bytes": 1048576,
                    "total_bytes": 8 * 1024 * 1024})
        collector = Collector(self.store, policy=policy, stop_lock_timeout=0.0)
        summary = collector.run(once=True)
        self.assertIn(summary["status"], {"ok", "partial"})
        self.assertEqual(summary["samples"], 1)
        self.assertEqual(summary["stop_reason"], "once")
        sample = collector.samples.query(None, None)["samples"][0]
        self.assertTrue(sample["host"]["cpu"]["available"])
        self.assertTrue(sample["host"]["memory"]["available"])
        self.assertTrue(sample["host"]["diskio"]["available"])
        self.assertTrue(sample["host"]["network"]["available"])
        self.assertTrue(sample["host"]["storage"]["available"])
        self.assertIn("success_at", sample["sources"]["cpu"])
        print(f"\n[real macOS collector] elapsed={summary['elapsed_seconds']:.3f}s "
              f"status={summary['status']} samples={summary['samples']}")


if __name__ == "__main__":
    unittest.main()
