"""常驻资源采集调度：前台循环、独立生命周期锁与运行/缺口证据。

采集阶段不持有 ``Store.lock()``；只有 SampleStore 的短写入在
``with store.lock()`` 内执行。巡检或维护长时间持锁时，本批不提交样本，
只保留有界的内存 deferred gap，下一批或停止时补记。

``collector_lease(store)`` 与采集器使用同一个 ``.collector.lock``，供父代理
在 upgrade 等独占操作前阻止活动采集；它不是 PID 文件，也不用于杀进程。
"""

from collections import deque
from contextlib import contextmanager
import fcntl
import json
import os
import signal
import stat
import threading
import time
import uuid

from history_config import resolve_history
from policy import make_policy_evidence, policy_digest, read_policy_with_evidence
from resource_sampler import (
    boot_changed,
    boot_identity,
    boot_summary,
    error_detail,
    sample_boot,
    sample_resources,
    sampling_config,
)
from sample_store import SampleStore
from state_io import DatabaseError, StewardError


class CollectorError(StewardError):
    pass


class CollectorBusyError(CollectorError):
    """已有 collector 运行，或启动写入无法取得巡检锁。"""


class CollectorConfigError(CollectorError):
    """启动时没有有效 v2 配置；父代理可据此回退到历史查询。"""


class _PolicyState:
    __slots__ = ("policy", "evidence", "digest", "sampling", "limits", "history")

    def __init__(self, policy, evidence, digest, sampling, limits, history):
        self.policy = policy
        self.evidence = evidence
        self.digest = digest
        self.sampling = sampling
        self.limits = limits
        self.history = history


def _is_lock_busy(exc):
    if isinstance(exc, BlockingIOError):
        return True
    return isinstance(getattr(exc, "__cause__", None), BlockingIOError)


def _gap_times(start_at, end_at):
    """墙钟倒退时不造负区间：保留原始时间并明确标记。"""
    if end_at is not None and start_at > end_at:
        return end_at, end_at, {
            "wall_clock_regression": True,
            "raw_start_at": start_at,
            "raw_end_at": end_at,
        }
    return start_at, end_at, {}


def _nondecreasing(value, floor):
    """墙钟倒退时让写入时间不低于运行开始时间，并标记原始值。"""
    if floor is not None and value < floor:
        return floor, True
    return value, False


def _clip_text(value, limit):
    if not isinstance(value, str):
        value = str(value)
    payload = value.encode("utf-8")
    if len(payload) <= limit:
        return value, False
    head = payload[:limit // 2].decode("utf-8", "ignore")
    tail = payload[-(limit - limit // 2):].decode("utf-8", "ignore")
    omitted = len(payload) - len(head.encode()) - len(tail.encode())
    return head + f"\n... [省略 {omitted} 字节] ...\n" + tail, True


def _compact_boot(value):
    if not isinstance(value, dict):
        return value
    return {key: value[key] for key in
            ("available", "boot_id", "unix_time", "btime", "identity", "identity_kind")
            if key in value}


def _detail_size(value):
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8"))


def _bounded_detail(detail, limit):
    try:
        payload = json.dumps(detail, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False)
    except (TypeError, ValueError, OverflowError) as exc:
        raise CollectorError("采集状态明细不能编码为有限 JSON") from exc
    raw = payload.encode("utf-8")
    if len(raw) <= limit:
        return detail
    summary = {
        "phase": detail.get("phase"),
        "truncated": True,
        "original_bytes": len(raw),
        "policy_digest": detail.get("policy_digest"),
        "run_id": detail.get("run_id"),
        "sample_status": detail.get("sample_status"),
        "stop_reason": detail.get("stop_reason"),
        "failed_sources": (detail.get("failed_sources") or [])[:16],
        "not_attempted_sources": (detail.get("not_attempted_sources") or [])[:16],
        "message": f"采集状态明细超过 {limit} 字节，已省略完整 traceback 与重复列表",
    }
    for candidate in (summary, {"truncated": True,
                                "message": f"采集状态明细超过 {limit} 字节"}):
        try:
            if _detail_size(candidate) <= limit:
                return candidate
        except (TypeError, ValueError, OverflowError):
            continue
    return None


@contextmanager
def _collector_lock(store):
    try:
        path = store.target(".collector.lock")
    except StewardError as exc:
        raise CollectorError("collector 生命周期锁路径无效；必须是普通文件") from exc
    try:
        fd = os.open(
            os.fspath(path),
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0),
            0o600)
    except OSError as exc:
        raise CollectorError("collector 生命周期锁无法打开；必须是普通文件") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise CollectorError("collector 生命周期锁必须是普通文件")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CollectorBusyError("已有 collector 运行，拒绝重复启动") from exc
        yield fd
    finally:
        os.close(fd)


def collector_lease(store):
    """父代理用于阻止活动 collector 的上下文；异常时同样释放。"""
    return _collector_lock(store)


class Collector:
    """前台常驻资源采集器；不 fork、不写 PID 文件、不创建宿主服务。"""

    def __init__(self, store, policy=None, evidence=None, *, mode="continuous",
                 policy_reader=None, sampler=None, boot_sampler=None,
                 clock=None, wall_clock=None, wait=None, sleep=None,
                 pid=None, run_id_factory=None, stop_lock_timeout=2.0,
                 wait_slice_seconds=0.5, deferred_gap_limit=32,
                 detail_limit=None):
        self.store = store
        self.samples = SampleStore(store)
        self.mode = mode
        self._fixed_policy = policy
        self._fixed_evidence = evidence
        if policy_reader is None and policy is None:
            policy_reader = read_policy_with_evidence
        self._policy_reader = policy_reader
        self._sampler = sampler or sample_resources
        self._boot_sampler = boot_sampler or sample_boot
        self._clock = clock or time.monotonic
        self._wall = wall_clock or time.time
        self._sleep = sleep or time.sleep
        self._stop_event = threading.Event()
        self._wait = wait or self._stop_event.wait
        self.pid = os.getpid() if pid is None else pid
        self._run_id_factory = run_id_factory or (lambda: str(uuid.uuid4()))
        self.stop_lock_timeout = max(0.0, float(stop_lock_timeout))
        self.wait_slice_seconds = max(0.01, float(wait_slice_seconds))
        self._deferred = deque(maxlen=max(1, int(deferred_gap_limit)))
        self._deferred_dropped = 0
        self._detail_limit = detail_limit
        self._policy_state = None
        self._pending_state = None
        self._run_id = None
        self._run_active = False
        self._stopping = False
        self._run_started_at = None
        self._last_committed_observed_at = None
        self._last_committed_boot = None
        self._last_process_mono = None
        self._open_config_gap = None
        self._open_sample_gap = None
        self._config_invalid = False
        self._boot = None
        self._boot_error = None
        self._stop_signal = None
        self._original_handlers = {}
        self._last_summary = None

    def request_stop(self):
        self._stop_event.set()

    def _new_run_id(self):
        value = self._run_id_factory()
        if not isinstance(value, str) or not value:
            raise CollectorError("run_id_factory 必须返回非空字符串")
        return value

    def _make_state(self, policy, evidence):
        try:
            sampling = sampling_config(policy)
            digest = policy_digest(policy)
        except Exception as exc:
            raise CollectorConfigError(str(exc)) from exc
        limits = policy.get("limits")
        if not isinstance(limits, dict):
            raise CollectorConfigError("本机约定缺少 limits")
        for key in ("file_bytes", "total_bytes"):
            value = limits.get(key)
            if type(value) is not int or value <= 0:
                raise CollectorConfigError(f"本机约定 limits.{key} 必须是正整数")
        try:
            history = resolve_history(policy.get("history"))
        except Exception as exc:
            raise CollectorConfigError(f"资源历史保留配置无效：{exc}") from exc
        if evidence is None:
            evidence = getattr(policy, "policy_evidence", None)
        if evidence is None:
            try:
                evidence = make_policy_evidence(policy)
            except Exception as exc:
                raise CollectorConfigError("无法生成配置证据") from exc
        if not isinstance(evidence, dict):
            raise CollectorConfigError("配置证据必须是对象")
        return _PolicyState(policy, evidence, digest, sampling, limits, history)

    @staticmethod
    def _detail_limit_for(limits):
        # 状态明细最终由 file_bytes 硬约束；预算必须小于等于该上限，
        # 不能因为最小 traceback 预留而反过来超过它。
        return max(1, min(65536, int(limits.get("file_bytes", 65536)) // 2))

    def _apply_runtime_policy(self, state):
        """让 Store/SampleStore 的写入预算与保留设置和当前有效 policy 一致。"""
        self.store.limits = dict(state.limits)
        self.store.policy_evidence = state.evidence
        self.store.history = state.history
        self._detail_limit = self._detail_limit_for(state.limits)

    def _read_policy_state(self):
        if self._policy_reader is None:
            if self._fixed_policy is None:
                raise CollectorConfigError("没有可用的本机约定")
            return self._make_state(self._fixed_policy, self._fixed_evidence)
        try:
            policy, evidence = self._policy_reader(str(self.store.path))
        except Exception as exc:
            if isinstance(exc, CollectorConfigError):
                raise
            raise CollectorConfigError(f"本机约定读取或校验失败：{exc}") from exc
        return self._make_state(policy, evidence)

    def _install_signal_handlers(self):
        if threading.current_thread() is not threading.main_thread():
            return
        for number in (signal.SIGTERM, signal.SIGINT):
            try:
                previous = signal.getsignal(number)
                signal.signal(number, self._handle_signal)
            except (ValueError, OSError):
                continue
            self._original_handlers[number] = previous

    def _restore_signal_handlers(self):
        for number, previous in list(self._original_handlers.items()):
            try:
                signal.signal(number, previous)
            except (ValueError, OSError):
                pass
        self._original_handlers.clear()

    def _handle_signal(self, number, frame):
        if self._stop_signal is None:
            self._stop_signal = number
        self._stop_event.set()

    def _probe_boot(self, state):
        try:
            section = self._boot_sampler(state.policy)
        except Exception as exc:
            self._boot_error = error_detail(
                exc, "boot probe", traceback_limit=self._traceback_limit(state))
            return None
        summary = boot_summary(section)
        if summary is None:
            self._boot_error = {
                "type": "BootUnavailable",
                "message": "启动前未取得开机身份；首次批次继续核对",
                "source": "boot probe",
            }
        return summary

    def _traceback_limit(self, state=None):
        state = state or self._policy_state
        file_bytes = 65536
        if state is not None:
            value = state.limits.get("file_bytes", 65536)
            if type(value) is int and value > 0:
                file_bytes = value
        return min(8192, max(2048, file_bytes // 16))

    def _detail(self, phase, **fields):
        limit = self._detail_limit or 16384
        detail = {
            "phase": phase,
            "policy_digest": self._policy_state.digest if self._policy_state else None,
            "run_id": self._run_id,
            "sampler": "resource_sampler",
            "deferred_gaps": len(self._deferred),
            "deferred_gaps_dropped": self._deferred_dropped,
            "config_invalid": self._config_invalid,
        }
        detail.update(fields)
        return _bounded_detail(detail, limit)

    def _gap_detail(self, detail):
        """缺口明细与状态记录共用 file_bytes 上限；超限时保留摘要而不是拒绝缺口。"""
        if detail is None:
            return None
        limit = self.store.limits.get("file_bytes", 65536)
        if type(limit) is not int or limit <= 0:
            return detail
        bounded = _bounded_detail(detail, limit)
        if bounded is not None:
            return bounded
        compact = {"truncated": True, "message": f"缺口明细超过 {limit} 字节"}
        return compact if _detail_size(compact) <= limit else None

    def _source_error_summary(self, result):
        errors = []
        sources = result.get("sources") if isinstance(result.get("sources"), dict) else {}
        per_source = min(2048, max(512, (self._detail_limit or 16384) // 16))
        for name, status in sources.items():
            if not isinstance(status, dict) or not status.get("error"):
                continue
            error = status["error"]
            text = error.get("traceback") if isinstance(error, dict) else None
            if isinstance(text, str):
                text, _ = _clip_text(text, per_source)
            message = error.get("message") if isinstance(error, dict) else str(error)
            message, _ = _clip_text(message, 512)
            errors.append({
                "source": name,
                "type": error.get("type") if isinstance(error, dict) else None,
                "message": message,
                "traceback": text,
            })
            if len(errors) >= 8:
                break
        return errors

    def _new_summary(self, once, started_wall, started_mono):
        return {
            "status": "running",
            "once": once,
            "run_id": None,
            "started_at": started_wall,
            "started_monotonic_at": started_mono,
            "stopped_at": None,
            "stop_reason": None,
            "signal": None,
            "cycles": 0,
            "samples": 0,
            "complete_samples": 0,
            "partial_samples": 0,
            "failed_cycles": 0,
            "deferred_cycles": 0,
            "config_errors": 0,
            "run_changes": 0,
            "deferred_gaps": 0,
            "deferred_gaps_dropped": 0,
            "last_sample_at": None,
            "last_cycle": None,
            "last_error": None,
            "policy_digest": None,
            "wall_clock_regression": False,
            "elapsed_seconds": None,
        }

    def _record_fatal_cleanup(self, exc):
        if not self._run_active or self._stopping:
            return
        summary = self._last_summary or {}
        reason = "storage_error" if isinstance(exc, DatabaseError) else "collector_error"
        try:
            self._stopping = True
            self._finish_run(reason, summary, open_gap=True)
        except Exception as cleanup:
            try:
                setattr(exc, "cleanup_error", cleanup)
            except Exception:
                pass

    def run(self, once=False):
        """运行采集；``once=True`` 时只执行一批且不 sleep。"""
        started_mono = self._clock()
        started_wall = self._wall()
        with _collector_lock(self.store):
            self._install_signal_handlers()
            try:
                return self._execute(bool(once), started_wall, started_mono)
            except Exception as exc:
                self._record_fatal_cleanup(exc)
                raise
            finally:
                self._restore_signal_handlers()

    def _execute(self, once, started_wall, started_mono):
        summary = self._new_summary(once, started_wall, started_mono)
        self._last_summary = summary
        state = self._read_policy_state()
        self._policy_state = state
        self._apply_runtime_policy(state)
        self._boot = self._probe_boot(state)
        status = self.samples.status(now=self._wall())
        page = self.samples.query(None, None, limit=1)
        started_at = self._wall()
        run_id = self._new_run_id()
        try:
            with self.store.lock():
                self.samples.start_run(
                    run_id, state.policy, state.evidence, mode=self.mode,
                    started_at=started_at, boot=self._boot, pid=self.pid)
                self._run_id = run_id
                self._run_active = True
                self._run_started_at = started_at
                startup = self._reconcile_startup_locked(status, page, started_at)
                self.samples.update_state(detail=self._detail(
                    "running", started_at=started_at, startup=startup,
                    boot_error=self._boot_error))
        except StewardError as exc:
            if _is_lock_busy(exc):
                raise CollectorBusyError(
                    "collector 启动写入时已有巡检或维护持锁；拒绝启动") from exc
            raise
        summary["run_id"] = run_id
        summary["policy_digest"] = state.digest
        summary["startup"] = startup
        interval = state.sampling["interval_seconds"]
        last_start_mono = None
        last_start_wall = None
        next_due = self._clock()

        while True:
            if self._stop_event.is_set():
                break
            if last_start_mono is not None:
                self._wait_until(next_due)
                if self._stop_event.is_set():
                    break
            batch_start_mono = self._clock()
            batch_start_wall = self._wall()
            schedule = self._schedule_fields(
                last_start_mono, last_start_wall, batch_start_mono,
                batch_start_wall, interval)
            config_event = None
            try:
                new_state = self._read_policy_state()
            except Exception as exc:
                config_event = self._record_config_invalid(
                    exc, batch_start_wall, schedule, summary)
                cycle_status = "config_error"
            else:
                if (self._pending_state is not None
                        and new_state.digest == self._policy_state.digest):
                    self._pending_state = None
                if (self._config_invalid
                        or new_state.digest != self._policy_state.digest):
                    switched = self._try_switch(
                        new_state, batch_start_wall, summary,
                        recovered=self._config_invalid)
                    if switched:
                        interval = new_state.sampling["interval_seconds"]
                        config_event = summary.get("last_config_event")
                process_due = self._process_due(batch_start_mono)
                try:
                    result = self._sampler(
                        self._policy_state.policy, process_due=process_due)
                except Exception as exc:
                    cycle_status = self._sampler_failure(
                        exc, batch_start_wall, schedule, summary)
                else:
                    cycle_status = self._commit_batch(
                        result, process_due, batch_start_mono,
                        batch_start_wall, schedule, summary)
            summary["cycles"] += 1
            summary["last_cycle"] = {
                "status": cycle_status,
                "started_at": batch_start_wall,
                "started_monotonic_at": batch_start_mono,
                "config_event": config_event,
                **schedule,
            }
            last_start_mono = batch_start_mono
            last_start_wall = batch_start_wall
            next_due = self._next_due(last_start_mono, interval)
            if once:
                break

        if once:
            stop_reason = "signal" if self._stop_signal is not None else "once"
            open_gap = False
        elif self._stop_signal is not None:
            stop_reason = "signal"
            open_gap = True
        else:
            stop_reason = "requested"
            open_gap = True
        self._stopping = True
        self._finish_run(stop_reason, summary, open_gap=open_gap)
        summary["stopped_at"] = summary.get("stopped_at") or self._wall()
        summary["stop_reason"] = stop_reason
        summary["signal"] = self._stop_signal
        summary["deferred_gaps"] = len(self._deferred)
        summary["deferred_gaps_dropped"] = self._deferred_dropped
        summary["elapsed_seconds"] = max(0.0, self._clock() - started_mono)
        summary["policy_digest"] = self._policy_state.digest
        if once:
            cycle_status = summary["last_cycle"]["status"] if summary["last_cycle"] else None
            if cycle_status is None:
                summary["status"] = "stopped"
            else:
                summary["status"] = {
                    "ok": "ok", "partial": "partial", "failed": "failed",
                    "deferred": "deferred", "config_error": "config_error",
                }.get(cycle_status, "failed")
        else:
            summary["status"] = "stopped"
        self._stopping = False
        return summary

    def _wait_until(self, deadline):
        while not self._stop_event.is_set():
            remaining = deadline - self._clock()
            if remaining <= 0:
                return
            if self._wait(min(remaining, self.wait_slice_seconds)):
                return

    def _next_due(self, last_start_mono, interval):
        due = last_start_mono + interval
        now = self._clock()
        if due > now:
            return due
        lag = now - due
        if lag >= interval:
            missed = int(lag // interval)
            due += missed * interval
            while due <= now:
                due += interval
        return max(due, now)

    def _schedule_fields(self, last_start_mono, last_start_wall,
                         batch_start_mono, batch_start_wall, interval):
        if last_start_mono is None:
            return {
                "schedule_lag_seconds": 0.0,
                "missed_intervals": 0,
                "wall_clock_jump": False,
                "wall_clock_skew_seconds": 0.0,
                "interval_seconds": interval,
            }
        expected = last_start_mono + interval
        lag = max(0.0, batch_start_mono - expected)
        missed = int(lag // interval) if interval > 0 else 0
        mono_delta = batch_start_mono - last_start_mono
        wall_delta = batch_start_wall - last_start_wall
        skew = wall_delta - mono_delta
        jump = abs(skew) > max(1.0, abs(mono_delta) * 0.05)
        return {
            "schedule_lag_seconds": round(lag, 6),
            "missed_intervals": missed,
            "wall_clock_jump": jump,
            "wall_clock_skew_seconds": round(skew, 6),
            "interval_seconds": interval,
        }

    def _process_due(self, batch_start_mono):
        if self._last_process_mono is None:
            return True
        interval = self._policy_state.sampling["process_interval_seconds"]
        return batch_start_mono - self._last_process_mono >= interval

    def _defer_gap(self, start_at, end_at, reason, detail):
        start_at, end_at, extra = _gap_times(start_at, end_at)
        merged_detail = dict(detail or {})
        merged_detail.update(extra)
        if self._deferred:
            last = self._deferred[-1]
            if last["reason"] == reason and last["run_id"] == self._run_id:
                last["start_at"] = min(last["start_at"], start_at)
                last["end_at"] = max(last["end_at"], end_at)
                return
        if len(self._deferred) == self._deferred.maxlen:
            self._deferred_dropped += 1
        self._deferred.append({
            "start_at": start_at,
            "end_at": end_at,
            "reason": reason,
            "run_id": self._run_id,
            "detail": merged_detail,
        })

    def _flush_deferred_locked(self, end_at=None):
        dropped = self._deferred_dropped
        self._deferred_dropped = 0
        while self._deferred:
            gap = self._deferred[0]
            detail = gap["detail"]
            if dropped:
                detail = dict(detail or {})
                detail["dropped_intervals"] = dropped
                dropped = 0
            gap_end = gap["end_at"]
            if end_at is not None and len(self._deferred) == 1 and end_at > gap_end:
                gap_end = end_at
                detail = dict(detail or {})
                detail["gap_end_extended_to"] = end_at
            start_at, end_at_value, extra = _gap_times(gap["start_at"], gap_end)
            if extra:
                detail = dict(detail or {})
                detail.update(extra)
            self.samples.record_gap(
                start_at, end_at_value, gap["reason"],
                run_id=gap["run_id"], detail=detail or None)
            self._deferred.popleft()
        if dropped:
            self._deferred_dropped = dropped

    def _close_runtime_gaps_locked(self, wall_now, closing, *, include_config=True):
        if include_config and self._open_config_gap is not None:
            start_at, end_at, extra = _gap_times(self._open_config_gap, wall_now)
            self.samples.record_gap(
                start_at, end_at, "config_error", run_id=self._run_id,
                detail={"recovered": True, "closed_by": closing, **extra})
            self._open_config_gap = None
        if self._open_sample_gap is not None:
            start_at, end_at, extra = _gap_times(self._open_sample_gap, wall_now)
            self.samples.record_gap(
                start_at, end_at, "sample_unavailable", run_id=self._run_id,
                detail={"recovered": True, "closed_by": closing, **extra})
            self._open_sample_gap = None

    def _reconcile_startup_locked(self, status, page, started_at):
        active = status.get("active_run")
        latest_run = status.get("latest_run") or status.get("run")
        samples = page.get("samples") if isinstance(page.get("samples"), list) else []
        latest_sample = samples[0] if samples else None
        previous_boot = None
        if latest_sample is not None:
            previous_boot = latest_sample.get("boot")
        elif active is not None:
            previous_boot = active.get("boot")
        elif latest_run is not None:
            previous_boot = latest_run.get("boot")
        host_reboot = boot_changed(previous_boot, self._boot)
        startup = {
            "previous_run": active.get("run_id") if active else
                            (latest_run.get("run_id") if latest_run else None),
            "unclean_stop": bool(active),
            "host_reboot": host_reboot,
            "boot_error": self._boot_error,
            "closed_open_gaps": [],
        }
        if active is not None:
            if latest_sample is not None and latest_sample.get("run_id") == active.get("run_id"):
                start_at = latest_sample.get("observed_at")
            else:
                start_at = active.get("started_at")
            start_at, end_at, extra = _gap_times(start_at, started_at)
            detail = {
                "collector_stopped": True,
                "previous_run": active.get("run_id"),
                "host_reboot": host_reboot,
                "previous_boot": _compact_boot(previous_boot),
                "current_boot": _compact_boot(self._boot),
                **extra,
            }
            self.samples.record_gap(
                start_at, end_at, "unclean_stop",
                run_id=active.get("run_id"), detail=detail)
            if host_reboot:
                self.samples.record_gap(
                    start_at, end_at, "host_reboot",
                    run_id=active.get("run_id"),
                    detail={"previous_boot": _compact_boot(previous_boot),
                            "current_boot": _compact_boot(self._boot), **extra})
        elif host_reboot and latest_run is not None:
            start_at = (latest_sample.get("observed_at") if latest_sample is not None
                        else latest_run.get("stopped_at") or latest_run.get("started_at"))
            if start_at is not None:
                start_at, end_at, extra = _gap_times(start_at, started_at)
                self.samples.record_gap(
                    start_at, end_at, "host_reboot",
                    run_id=latest_run.get("run_id"),
                    detail={"previous_boot": _compact_boot(previous_boot),
                            "current_boot": _compact_boot(self._boot), **extra})
        for gap in page.get("gaps", []):
            if not gap.get("ongoing"):
                continue
            _, _, extra = _gap_times(gap.get("start_at"), started_at)
            closed = self.samples.close_gap(
                gap.get("gap_id"), started_at,
                detail={"closed_by": "collector_start", **extra})
            startup["closed_open_gaps"].append({
                "reason": gap.get("reason"), "run_id": gap.get("run_id"),
                "start_at": gap.get("start_at"), "end_at": closed["end_at"],
                "wall_clock_regression": bool(extra.get("wall_clock_regression")),
            })
        startup["closed_open_gap_count"] = len(startup["closed_open_gaps"])
        startup["closed_open_gaps"] = startup["closed_open_gaps"][:16]
        self._last_committed_observed_at = (
            latest_sample.get("observed_at") if latest_sample is not None else None)
        self._last_committed_boot = (
            latest_sample.get("boot") if latest_sample is not None else None)
        return startup

    def _try_switch(self, new_state, wall_now, summary, *, recovered):
        old_run = self._run_id
        old_digest = self._policy_state.digest
        old_limits = self.store.limits
        old_evidence = self.store.policy_evidence
        old_history = getattr(self.store, "history", None)
        old_detail_limit = self._detail_limit
        switch_at, regressed = _nondecreasing(wall_now, self._run_started_at)
        try:
            with self.store.lock():
                self._flush_deferred_locked(switch_at)
                self._close_runtime_gaps_locked(switch_at, "config_switch")
                if recovered and new_state.digest == old_digest:
                    reason = "config_recovered"
                else:
                    reason = "config_changed"
                # 旧 run 的收尾仍使用旧 limits；新 limits 只用于新 run 及其后续样本。
                self.samples.finish_run(old_run, stopped_at=switch_at, reason=reason)
                self._run_active = False
                new_run = self._new_run_id()
                self._apply_runtime_policy(new_state)
                try:
                    self.samples.start_run(
                        new_run, new_state.policy, new_state.evidence,
                        mode=self.mode, started_at=switch_at,
                        boot=self._boot, pid=self.pid)
                except BaseException as start_error:
                    # 新 run 未提交时恢复旧内存预算/证据/保留设置，不能留下
                    # “新 policy + 旧 limits”或“旧 policy + 新 history”的混合状态。
                    self.store.limits = old_limits
                    self.store.policy_evidence = old_evidence
                    self.store.history = old_history
                    self._detail_limit = old_detail_limit
                    if isinstance(start_error, Exception):
                        try:
                            self.samples.update_state(detail=self._detail(
                                "config_switch_failed",
                                error=error_detail(
                                    start_error, "configuration switch",
                                    traceback_limit=self._traceback_limit()),
                                previous_run=old_run,
                                rejected_policy_digest=new_state.digest,
                                policy_digest=old_digest))
                        except Exception as detail_error:
                            try:
                                setattr(start_error, "cleanup_error", detail_error)
                            except Exception:
                                pass
                    raise
                self._run_id = new_run
                self._run_active = True
                self._run_started_at = switch_at
                self._policy_state = new_state
                self.samples.update_state(detail=self._detail(
                    "running", config_event=reason, previous_run=old_run,
                    previous_policy_digest=old_digest,
                    policy_digest=new_state.digest,
                    wall_clock_regression=regressed,
                    raw_switch_at=wall_now if regressed else None))
        except StewardError as exc:
            if _is_lock_busy(exc):
                self._pending_state = new_state
                summary["last_error"] = {
                    "type": "LockBusy",
                    "message": "配置切换等待巡检锁；下批重试",
                    "source": "collector",
                }
                return False
            raise
        self._pending_state = None
        self._config_invalid = False
        self._open_config_gap = None
        self._last_process_mono = None
        summary["run_id"] = self._run_id
        summary["policy_digest"] = new_state.digest
        summary["run_changes"] += 1
        summary["last_config_event"] = {
            "kind": reason, "previous_run": old_run, "run_id": self._run_id,
            "previous_policy_digest": old_digest,
            "policy_digest": new_state.digest, "at": wall_now,
        }
        return True

    def _record_config_invalid(self, exc, wall_now, schedule, summary):
        self._pending_state = None
        self._config_invalid = True
        if self._open_config_gap is None:
            self._open_config_gap = (
                self._last_committed_observed_at
                or self._run_started_at
                or wall_now)
        detail = error_detail(
            exc, "host.json", traceback_limit=self._traceback_limit())
        state_detail = self._detail(
            "config_invalid", error=detail,
            config_since=self._open_config_gap,
            last_success_at=self._last_committed_observed_at,
            **schedule)
        try:
            with self.store.lock():
                start_at, end_at, extra = _gap_times(
                    self._open_config_gap, None)
                self.samples.record_gap(
                    start_at, end_at, "config_error", run_id=self._run_id,
                    detail=self._gap_detail({
                        "error": detail,
                        "config_since": self._open_config_gap, **extra}))
                self.samples.update_state(
                    heartbeat_at=wall_now, detail=state_detail)
        except StewardError as lock_error:
            if not _is_lock_busy(lock_error):
                raise
        summary["config_errors"] += 1
        summary["last_error"] = {
            "type": type(exc).__name__,
            "message": str(exc)[:512],
            "source": "host.json",
            "at": wall_now,
        }
        return {
            "kind": "config_error",
            "error_type": type(exc).__name__,
            "message": str(exc)[:512],
            "at": wall_now,
        }

    def _sampler_failure(self, exc, wall_now, schedule, summary):
        self._open_sample_gap = self._open_sample_gap or (
            self._last_committed_observed_at
            or self._run_started_at
            or wall_now)
        detail = error_detail(
            exc, "sampler", traceback_limit=self._traceback_limit())
        state_detail = self._detail(
            "running", sample_status="failed", sampler_error=detail,
            last_success_at=self._last_committed_observed_at,
            **schedule)
        try:
            with self.store.lock():
                self._flush_deferred_locked(wall_now)
                start_at, end_at, extra = _gap_times(
                    self._open_sample_gap, None)
                self.samples.record_gap(
                    start_at, end_at, "sample_unavailable", run_id=self._run_id,
                    detail=self._gap_detail({"error": detail, **extra}))
                self.samples.update_state(
                    heartbeat_at=wall_now, detail=state_detail)
        except StewardError as lock_error:
            if not _is_lock_busy(lock_error):
                raise
        summary["failed_cycles"] += 1
        summary["last_error"] = {
            "type": type(exc).__name__,
            "message": str(exc)[:512],
            "source": "sampler",
            "at": wall_now,
        }
        return "failed"

    def _record_sample_failure(self, result, observed_at, schedule, summary):
        self._open_sample_gap = self._open_sample_gap or (
            self._last_committed_observed_at
            or self._run_started_at
            or observed_at)
        state_detail = self._detail(
            "running", sample_status="failed",
            failed_sources=result.get("failed_sources", [])[:16],
            not_attempted_sources=result.get("not_attempted_sources", [])[:16],
            budget_exhausted=bool(result.get("budget_exhausted")),
            source_errors=self._source_error_summary(result),
            observed_at=observed_at,
            elapsed_seconds=result.get("elapsed_seconds"),
            last_success_at=self._last_committed_observed_at,
            **schedule)
        try:
            with self.store.lock():
                self._flush_deferred_locked(observed_at)
                start_at, end_at, extra = _gap_times(
                    self._open_sample_gap, None)
                self.samples.record_gap(
                    start_at, end_at, "sample_unavailable",
                    run_id=self._run_id,
                    detail=self._gap_detail({
                        "failed_sources": result.get("failed_sources", [])[:16],
                        "not_attempted_sources": result.get("not_attempted_sources", [])[:16],
                        "source_errors": self._source_error_summary(result),
                        "budget_exhausted": bool(result.get("budget_exhausted")),
                        **extra}))
                self.samples.update_state(
                    heartbeat_at=observed_at, detail=state_detail)
        except StewardError as lock_error:
            if not _is_lock_busy(lock_error):
                raise
        summary["failed_cycles"] += 1
        summary["last_error"] = {
            "type": "SamplingFailed",
            "message": "本批资源事实全部失败；未写入空样本",
            "source": "resource_sampler",
            "failed_sources": result.get("failed_sources", [])[:16],
            "at": observed_at,
        }
        return "failed"

    def _boot_transition_locked(self, boot, observed_at, summary):
        old_run = self._run_id
        transition_at, regressed = _nondecreasing(observed_at, self._run_started_at)
        start_at = (self._last_committed_observed_at or self._run_started_at
                    or transition_at)
        start_at, end_at, extra = _gap_times(start_at, transition_at)
        detail = {
            "previous_boot": _compact_boot(self._boot or self._last_committed_boot),
            "current_boot": _compact_boot(boot),
            "previous_run": old_run,
            "wall_clock_regression": regressed,
            "raw_observed_at": observed_at if regressed else None,
            **extra,
        }
        self.samples.record_gap(start_at, end_at, "host_reboot",
                                run_id=old_run, detail=detail)
        self.samples.finish_run(old_run, stopped_at=transition_at,
                                reason="host_reboot")
        self._run_active = False
        new_run = self._new_run_id()
        self.samples.start_run(
            new_run, self._policy_state.policy, self._policy_state.evidence,
            mode=self.mode, started_at=transition_at, boot=boot, pid=self.pid)
        self._run_id = new_run
        self._run_active = True
        self._run_started_at = transition_at
        self._last_process_mono = None
        self._boot = boot
        summary["run_id"] = new_run
        summary["run_changes"] += 1
        summary["last_boot_event"] = {
            "previous_run": old_run, "run_id": new_run,
            "previous_boot": _compact_boot(self._last_committed_boot),
            "current_boot": _compact_boot(boot), "at": observed_at,
            "wall_clock_regression": regressed,
        }
        return detail

    def _commit_batch(self, result, process_due, batch_start_mono,
                      batch_start_wall, schedule, summary):
        if not isinstance(result, dict):
            raise CollectorError("采样器必须返回对象")
        try:
            observed_at = float(result["observed_at"])
            monotonic_at = result.get("monotonic_at")
            host = result["host"]
            sources = result["sources"]
        except (KeyError, TypeError, ValueError) as exc:
            raise CollectorError("采样器返回缺少 host/sources/observed_at") from exc
        if not isinstance(host, dict) or not isinstance(sources, dict):
            raise CollectorError("采样器 host/sources 必须是对象")
        boot = result.get("boot")
        compare_boot = self._boot if self._boot is not None else self._last_committed_boot
        reboot = boot_changed(compare_boot, boot)
        if result.get("usable") is not True:
            return self._record_sample_failure(
                result, observed_at, schedule, summary)
        processes = result.get("processes")
        complete = bool(result.get("complete"))
        cycle_status = result.get("status") or (
            "ok" if complete else "partial")
        deferred_detail = {
            "policy_digest": self._policy_state.digest,
            "failed_sources": result.get("failed_sources", [])[:16],
            "observed_at": observed_at,
        }
        try:
            with self.store.lock():
                self._flush_deferred_locked(observed_at)
                self._close_runtime_gaps_locked(
                    observed_at, "sample_recovered", include_config=False)
                boot_event = None
                if reboot:
                    boot_event = self._boot_transition_locked(
                        boot, observed_at, summary)
                state_detail = self._detail(
                    "running", sample_status=cycle_status,
                    complete=complete, usable=True,
                    failed_sources=result.get("failed_sources", [])[:16],
                    not_attempted_sources=result.get("not_attempted_sources", [])[:16],
                    budget_exhausted=bool(result.get("budget_exhausted")),
                    source_errors=self._source_error_summary(result),
                    observed_at=observed_at,
                    elapsed_seconds=result.get("elapsed_seconds"),
                    last_success_at=observed_at if complete else self._last_committed_observed_at,
                    boot_event=boot_event,
                    **schedule)
                self.samples.append_sample(
                    self._run_id, observed_at=observed_at,
                    monotonic_at=monotonic_at, boot=boot, host=host,
                    sources=sources, processes=processes,
                    sampling=self._policy_state.sampling,
                    state_detail=state_detail,
                    last_complete_at=observed_at if complete else None)
        except StewardError as exc:
            if _is_lock_busy(exc):
                start_at = (self._open_sample_gap
                            or self._last_committed_observed_at
                            or self._run_started_at or observed_at)
                self._defer_gap(start_at, observed_at, "commit_deferred",
                                deferred_detail)
                summary["deferred_cycles"] += 1
                summary["last_error"] = {
                    "type": "LockBusy",
                    "message": "巡检或维护持锁，本批样本未提交；已记录 deferred gap",
                    "source": "collector",
                    "at": observed_at,
                }
                return "deferred"
            raise
        self._last_committed_observed_at = observed_at
        if boot_identity(boot) is not None:
            self._last_committed_boot = boot
            self._boot = boot
        if process_due and processes is not None:
            self._last_process_mono = batch_start_mono
        summary["samples"] += 1
        summary["last_sample_at"] = observed_at
        summary["last_error"] = None
        if complete:
            summary["complete_samples"] += 1
        else:
            summary["partial_samples"] += 1
        return cycle_status

    def _finish_run(self, reason, summary, *, open_gap):
        if not self._run_active or self._run_id is None:
            return
        raw_wall = self._wall()
        wall_now, regressed = _nondecreasing(raw_wall, self._run_started_at)
        deadline = self._clock() + self.stop_lock_timeout
        while True:
            try:
                with self.store.lock():
                    self._flush_deferred_locked(wall_now)
                    self._close_runtime_gaps_locked(wall_now, "collector_stop")
                    if open_gap:
                        # 先留下停止后的 open 缺口；即使随后 finish/update 失败或进程被杀，
                        # 下个启动仍能读到这段未采集区间。
                        self.samples.record_gap(
                            wall_now, None, "collector_stopped",
                            run_id=self._run_id,
                            detail={"reason": reason,
                                    "signal": self._stop_signal})
                    self.samples.finish_run(
                        self._run_id, stopped_at=wall_now, reason=reason)
                    self._run_active = False
                    detail = self._detail(
                        "stopped", stop_reason=reason, stopped_at=wall_now,
                        signal=self._stop_signal,
                        wall_clock_regression=regressed,
                        raw_stopped_at=raw_wall if regressed else None,
                        last_cycle=summary.get("last_cycle"),
                        last_sample_at=summary.get("last_sample_at"),
                        boot_error=self._boot_error)
                    self.samples.update_state(
                        heartbeat_at=wall_now, stopped_at=wall_now,
                        detail=detail)
                break
            except StewardError as exc:
                if _is_lock_busy(exc):
                    if self._clock() < deadline:
                        self._sleep(0.05)
                        continue
                    raise CollectorBusyError(
                        "停止清理无法取得巡检写锁；运行记录保持 active") from exc
                raise
        summary["stopped_at"] = wall_now
        summary["stop_reason"] = reason
        summary["wall_clock_regression"] = regressed


def collect(store, *, once=False, policy=None, evidence=None, **kwargs):
    """便捷入口；父代理 CLI 可直接 ``collect(store, once=args.once)``。"""
    return Collector(store, policy=policy, evidence=evidence, **kwargs).run(once=once)
