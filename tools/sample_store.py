"""资源历史的追加、有限保留、范围查询与采集状态。

写方法只执行一个短事务，自身不获取巡检锁；调用方（collector）应在提交前
短暂持有 ``Store.lock()``，采集阶段不要持有该锁。读方法不取巡检锁。
本模块只依赖 ``store.limits`` 与现有 SQLite 状态库，不读取 host.json。
"""

from contextlib import contextmanager
import math
import time

from database import DatabaseError
from state_io import decode, dumps


DEFAULT_QUERY_LIMIT = 40
MAX_QUERY_LIMIT = 200
RUN_LIMIT = 256
GAP_LIMIT = 256
SOURCE_LIMIT = 64
RUN_RETENTION_HOURS = 24 * 7
GAP_RETENTION_HOURS = 24 * 7
_STATE_FIELDS = frozenset({"run_id", "heartbeat_at", "last_complete_at", "stopped_at", "detail"})
_STATE_MARKER = "__host_steward_collector_state_v1__"
_UNSET = object()
SQLITE_INT_MAX = 2 ** 63 - 1


class _ReadBudget:
    """读取历史时的单条与总量预算；长度在取回 JSON 文本前由 SQL 计算。"""

    def __init__(self, file_limit, total_limit):
        self.file_limit = file_limit
        self.total_limit = total_limit
        self.total = 0

    def add(self, lengths, label):
        for length in lengths:
            length = 0 if length is None else int(length)
            if self.file_limit is not None and length > self.file_limit:
                raise DatabaseError(f"{label}超过单条状态记录读取上限")
            self.total += length
        if self.total_limit is not None and self.total > self.total_limit:
            raise DatabaseError("资源历史读取超过状态总容量预算；请缩小查询窗口或核对历史容量")


def _encode(value, label):
    try:
        return dumps(value)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise DatabaseError(f"{label} 不能编码为有限 JSON") from exc


def _decode(payload, label):
    try:
        return decode(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise DatabaseError(f"{label} 包含损坏的 JSON") from exc


def _timestamp(value, label, allow_none=False):
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DatabaseError(f"{label} 必须是有限时间")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise DatabaseError(f"{label} 超出可表示的有限时间范围") from exc
    if not math.isfinite(result):
        raise DatabaseError(f"{label} 必须是有限时间")
    return result


def _positive_int(value, label):
    if type(value) is not int or not 1 <= value <= SQLITE_INT_MAX:
        raise DatabaseError(f"{label} 必须是正整数且不超过 SQLite 整数范围，布尔值无效")
    return value


class SampleStore:
    """在现有 Store 上读写 schema 2 资源历史；不重写 current/inventory/operations。"""

    def __init__(self, store):
        self.store = store

    @property
    def _file_limit(self):
        return self.store.limits["file_bytes"]

    def _budget(self):
        return _ReadBudget(self.store.limits["file_bytes"],
                           self.store.limits["total_bytes"])

    def _key(self, value, label):
        if not isinstance(value, str) or not value or "\x00" in value:
            raise DatabaseError(f"{label} 必须是非空字符串")
        if len(value.encode("utf-8")) > self._file_limit:
            raise DatabaseError(f"{label} 超过单条状态记录上限")
        return value

    def _entry(self, value, label):
        payload = _encode(value, label)
        if len(payload.encode("utf-8")) > self._file_limit:
            raise DatabaseError(f"{label} 超过单条状态记录上限")
        return payload

    @contextmanager
    def _write(self):
        database = self.store._database()
        outside = self.store._database_outside(database)
        with database._transaction(
                write=True, total_bytes=self.store.limits["total_bytes"],
                outside_bytes=outside, require_version=2) as connection:
            yield connection

    @contextmanager
    def _read(self):
        database = self.store._database()
        with database._transaction(require_version=2) as connection:
            yield connection

    @staticmethod
    def _database_stats(connection, path):
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        pages = connection.execute("PRAGMA page_count").fetchone()[0]
        free_pages = connection.execute("PRAGMA freelist_count").fetchone()[0]
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise DatabaseError("SQLite 状态库无法检查") from exc
        return {"page_size": page_size, "pages": pages,
                "free_pages": free_pages, "bytes": size}

    def _sampling(self, sampling):
        if not isinstance(sampling, dict):
            raise DatabaseError("sampling 必须是对象")
        records = _positive_int(sampling.get("records"), "sampling.records")
        hours = _positive_int(sampling.get("retention_hours"), "sampling.retention_hours")
        budget = sampling.get("processes")
        if budget is not None:
            _positive_int(budget, "sampling.processes")
        for field in ("interval_seconds", "cycle_seconds", "process_interval_seconds"):
            if field in sampling:
                _positive_int(sampling[field], f"sampling.{field}")
        return records, hours, budget

    def _validate_sources(self, sources):
        if not isinstance(sources, dict):
            raise DatabaseError("sources 必须是按来源名称索引的对象")
        if len(sources) > SOURCE_LIMIT:
            raise DatabaseError(f"单次来源状态超过 {SOURCE_LIMIT} 项上限")
        for name, status in sources.items():
            self._key(name, "来源名称")
            if not isinstance(status, dict):
                raise DatabaseError(f"来源 {name} 状态必须是对象")
            available = status.get("available")
            if available is not None and type(available) is not bool:
                raise DatabaseError(f"来源 {name}.available 必须是布尔值或 null")
            for field in ("attempted_at", "success_at", "error_at"):
                if field in status:
                    _timestamp(status[field], f"来源 {name}.{field}", allow_none=True)
            self._entry(status, f"来源 {name} 状态")
        return sources

    def _processes(self, processes, observed_at, budget):
        if processes is None:
            return 0, False, None, None, [], 0
        if isinstance(processes, list):
            items, truncated, process_observed_at, meta = processes, False, observed_at, {}
        elif isinstance(processes, dict):
            if "items" in processes:
                items = processes["items"]
            elif "processes" in processes:
                items = processes["processes"]
            else:
                # 已尝试但失败的进程采样仍保留 available/reason 等原始元数据。
                items = []
            if not isinstance(items, list):
                raise DatabaseError("进程采样 items 必须是数组")
            truncated = processes.get("truncated", False)
            if type(truncated) is not bool:
                raise DatabaseError("进程采样 truncated 必须是布尔值")
            observed_value = processes.get("observed_at", observed_at)
            process_observed_at = _timestamp(
                observed_at if observed_value is None else observed_value,
                "进程采样 observed_at")
            meta = {key: value for key, value in processes.items()
                    if key not in {"items", "processes"}}
            if "available" in meta and meta["available"] is not None \
                    and type(meta["available"]) is not bool:
                raise DatabaseError("进程采样 available 必须是布尔值或 null")
            self._entry(meta, "进程采样元数据")
        else:
            raise DatabaseError("processes 必须是进程数组、采样对象或 null")
        if budget is not None and len(items) > budget:
            raise DatabaseError(f"进程样本数量 {len(items)} 超过 sampling.processes={budget}")
        rows, seen = [], set()
        for position, item in enumerate(items):
            if not isinstance(item, dict):
                raise DatabaseError("进程样本条目必须是对象")
            identity = self._key(item.get("identity"), "进程 identity")
            if identity in seen:
                raise DatabaseError(f"同一进程采样中 identity 重复：{identity}")
            seen.add(identity)
            rows.append((position, identity, self._entry(item, f"进程 {identity} 样本")))
        meta_json = None if not meta else self._entry(meta, "进程采样元数据")
        return 1, truncated, process_observed_at, meta_json, rows, len(rows)

    def start_run(self, run_id, policy, evidence, *, mode="continuous",
                  started_at=None, boot=None, pid=None):
        run_id = self._key(run_id, "run_id")
        mode = self._key(mode, "运行模式")
        if not isinstance(policy, dict):
            raise DatabaseError("policy 必须是对象")
        if not isinstance(evidence, dict):
            raise DatabaseError("evidence 必须是对象")
        started_at = time.time() if started_at is None else _timestamp(started_at, "started_at")
        if pid is not None and (type(pid) is not int or not 1 <= pid <= SQLITE_INT_MAX):
            raise DatabaseError("pid 必须是 SQLite 整数范围内的正整数或 null")
        policy_json = self._entry(policy, "运行配置证据")
        evidence_json = self._entry(evidence, "运行来源证据")
        boot_json = None if boot is None else self._entry(boot, "启动标识")
        with self._write() as connection:
            if connection.execute("SELECT 1 FROM collector_runs WHERE run_id=?",
                                  (run_id,)).fetchone():
                raise DatabaseError(f"run_id 已存在，拒绝覆盖运行证据：{run_id}")
            state = self._read_state(connection)
            current = state["run_id"]
            closed = None
            if current is not None:
                row = connection.execute(
                    "SELECT started_at, stopped_at FROM collector_runs WHERE run_id=?",
                    (current,)).fetchone()
                if row is not None and row[1] is None:
                    # 新运行开始说明旧运行没有正常收尾；由 start_run 统一关闭并保留原因。
                    closed_at = max(started_at, float(row[0]))
                    connection.execute(
                        "UPDATE collector_runs SET stopped_at=?, stop_reason=? "
                        "WHERE run_id=? AND stopped_at IS NULL",
                        (closed_at, "superseded", current))
                    closed = {"run_id": current, "stopped_at": closed_at,
                              "stop_reason": "superseded"}
            connection.execute(
                "INSERT INTO collector_runs(run_id, mode, started_at, stopped_at, stop_reason, "
                "boot_json, pid, policy_json, evidence_json) "
                "VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?)",
                (run_id, mode, started_at, boot_json, pid, policy_json, evidence_json))
            self._upsert_state(connection, run_id=run_id, heartbeat_at=started_at,
                               stopped_at=None)
            self._prune_auxiliary(connection, started_at)
            run_count = connection.execute(
                "SELECT COUNT(*) FROM collector_runs").fetchone()[0]
            if run_count > RUN_LIMIT:
                raise DatabaseError(
                    f"运行记录达到硬上限 {RUN_LIMIT}；旧运行仍被保留样本、缺口引用"
                    "或尚未关闭，无法在不删除证据的情况下清理，拒绝新增运行。"
                    "请核对采样保留窗口与预算")
            run = self._run(connection, run_id)
        return {"status": "started", "run": run, "closed_run": closed}

    def finish_run(self, run_id, *, stopped_at=None, reason="signal"):
        run_id = self._key(run_id, "run_id")
        reason = self._key(reason, "停止原因")
        provided_stop = stopped_at is not None
        stopped_at = time.time() if not provided_stop \
            else _timestamp(stopped_at, "stopped_at")
        with self._write() as connection:
            row = connection.execute(
                "SELECT started_at, stopped_at FROM collector_runs WHERE run_id=?",
                (run_id,)).fetchone()
            if row is None:
                raise DatabaseError(f"运行记录不存在：{run_id}")
            already = row[1] is not None
            if not already:
                if stopped_at < row[0]:
                    if provided_stop:
                        raise DatabaseError("stopped_at 不能早于运行 started_at")
                    stopped_at = float(row[0])
                connection.execute(
                    "UPDATE collector_runs SET stopped_at=?, stop_reason=? WHERE run_id=?",
                    (stopped_at, reason, run_id))
            state = self._read_state(connection)
            if state["run_id"] == run_id:
                # 保留 state.run_id 作为“最近启动运行”的持久标识；是否在运行看 run.stopped_at。
                self._upsert_state(
                    connection, run_id=run_id,
                    stopped_at=state["stopped_at"] if state["stopped_at"] is not None else stopped_at)
            self._prune_auxiliary(
                connection, stopped_at if not already else max(stopped_at, float(row[1])),
                protect_run_id=run_id)
            run = self._run(connection, run_id)
        return {"status": "already_stopped" if already else "stopped", "run": run}

    def append_sample(self, run_id, *, observed_at, monotonic_at, boot, host, sources,
                      processes=None, sampling, state_detail=None,
                      last_complete_at=None):
        run_id = self._key(run_id, "run_id")
        observed_at = _timestamp(observed_at, "observed_at")
        monotonic_at = _timestamp(monotonic_at, "monotonic_at", allow_none=True)
        if not isinstance(host, dict):
            raise DatabaseError("host 必须是对象")
        if state_detail is not None:
            if not isinstance(state_detail, dict):
                raise DatabaseError("采集状态明细必须是对象")
            self._entry(state_detail, "采集状态明细")
        if last_complete_at is not None:
            last_complete_at = _timestamp(last_complete_at, "state.last_complete_at")
        sources = self._validate_sources(sources)
        records, hours, process_budget = self._sampling(sampling)
        host_json = self._entry(host, "host 样本")
        sources_json = self._entry(sources, "来源样本")
        sampling_json = self._entry(sampling, "采样配置")
        boot_json = None if boot is None else self._entry(boot, "启动标识")
        process_observed, process_truncated, process_observed_at, process_meta_json, \
            process_rows, process_count = self._processes(
                processes, observed_at, process_budget)
        cutoff = observed_at - hours * 3600
        with self._write() as connection:
            row = connection.execute(
                "SELECT stopped_at FROM collector_runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise DatabaseError(f"运行记录不存在，请先 start_run：{run_id}")
            if row[0] is not None:
                raise DatabaseError("运行已停止，不能继续追加样本")
            state = self._read_state(connection)
            if state["run_id"] is not None and state["run_id"] != run_id:
                raise DatabaseError("采集状态指向另一个最近运行，拒绝追加；请核对运行记录")
            known_sources = {item[0] for item in connection.execute(
                "SELECT source FROM collector_sources")}
            if len(known_sources | set(sources)) > SOURCE_LIMIT:
                raise DatabaseError(f"来源状态达到 {SOURCE_LIMIT} 项上限，拒绝新增来源")
            before_age = connection.execute(
                "SELECT COUNT(*) FROM resource_samples").fetchone()[0]
            connection.execute("DELETE FROM resource_samples WHERE observed_at < ?", (cutoff,))
            expired_by_age = before_age - connection.execute(
                "SELECT COUNT(*) FROM resource_samples").fetchone()[0]
            current_count = connection.execute(
                "SELECT COUNT(*) FROM resource_samples").fetchone()[0]
            evicted_by_count = max(0, current_count - records + 1)
            if evicted_by_count:
                connection.execute(
                    "DELETE FROM resource_samples WHERE sample_id IN ("
                    "SELECT sample_id FROM resource_samples ORDER BY sample_id ASC LIMIT ?)",
                    (evicted_by_count,))
            cursor = connection.execute(
                "INSERT INTO resource_samples(run_id, observed_at, monotonic_at, boot_json, "
                "host_json, sources_json, sampling_json, process_observed, process_truncated, "
                "process_observed_at, process_count, process_meta_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, observed_at, monotonic_at, boot_json, host_json, sources_json,
                 sampling_json, process_observed, int(process_truncated),
                 process_observed_at, process_count, process_meta_json, time.time()))
            sample_id = cursor.lastrowid
            if process_rows:
                connection.executemany(
                    "INSERT INTO process_samples(sample_id, position, identity, payload_json) "
                    "VALUES (?, ?, ?, ?)",
                    [(sample_id, position, identity, payload)
                     for position, identity, payload in process_rows])
            for name, status in sources.items():
                available = status.get("available")
                attempted = _timestamp(status.get("attempted_at"),
                                        f"来源 {name}.attempted_at", allow_none=True) \
                    if "attempted_at" in status else None
                success = _timestamp(status.get("success_at"),
                                      f"来源 {name}.success_at", allow_none=True) \
                    if "success_at" in status else None
                error_present = "error" in status and status["error"] is not None
                if "error_at" in status and status["error_at"] is not None:
                    error_at = _timestamp(status["error_at"],
                                          f"来源 {name}.error_at", allow_none=True)
                else:
                    error_at = attempted if error_present else None
                error_json = self._entry(status["error"], f"来源 {name} 错误") \
                    if error_present else None
                detail_json = self._entry(status, f"来源 {name} 状态")
                connection.execute(
                    "INSERT INTO collector_sources(source, available, attempted_at, "
                    "success_at, error_at, error_json, detail_json, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(source) DO UPDATE SET "
                    "available=COALESCE(excluded.available, collector_sources.available), "
                    "attempted_at=COALESCE(excluded.attempted_at, collector_sources.attempted_at), "
                    "success_at=COALESCE(excluded.success_at, collector_sources.success_at), "
                    "error_at=COALESCE(excluded.error_at, collector_sources.error_at), "
                    "error_json=COALESCE(excluded.error_json, collector_sources.error_json), "
                    "detail_json=excluded.detail_json, updated_at=excluded.updated_at",
                    (name, None if available is None else int(available), attempted,
                     success, error_at, error_json, detail_json, observed_at))
            state_fields = {"run_id": run_id, "heartbeat_at": observed_at,
                            "stopped_at": None}
            if state_detail is not None:
                detail = dict(state_detail)
                detail["sample_id"] = sample_id
                state_fields["detail"] = detail
            if last_complete_at is not None:
                state_fields["last_complete_at"] = last_complete_at
            self._upsert_state(connection, **state_fields)
            self._prune_auxiliary(connection, observed_at)
            retention = self._retention_stats(
                connection, sample_id, observed_at, records, hours, expired_by_age,
                evicted_by_count, cutoff)
            self._upsert_state(connection, retention=retention)
            stats = self._database_stats(connection, self.store.database_path)
            state = self._read_state(connection)
        return {"status": "appended", "sample_id": sample_id, "run_id": run_id,
                "observed_at": observed_at, "retention": retention,
                "last_append": retention,
                "process": {"observed": bool(process_observed),
                            "truncated": process_truncated,
                            "observed_at": process_observed_at,
                            "count": process_count},
                "database": stats, "state": state}

    def record_gap(self, start_at, end_at, reason, *, run_id=None, detail=None):
        start_at = _timestamp(start_at, "gap start_at")
        end_at = _timestamp(end_at, "gap end_at", allow_none=True)
        if end_at is not None and end_at < start_at:
            raise DatabaseError("gap end_at 不能早于 start_at")
        reason = self._key(reason, "gap reason")
        if run_id is not None:
            run_id = self._key(run_id, "gap run_id")
        detail_json = None if detail is None else self._entry(detail, "gap 明细")
        now = start_at if end_at is None else end_at
        with self._write() as connection:
            if run_id is not None and not connection.execute(
                    "SELECT 1 FROM collector_runs WHERE run_id=?", (run_id,)).fetchone():
                raise DatabaseError(f"gap 引用的运行不存在：{run_id}")
            existing = self._find_gap(connection, start_at, end_at, reason, run_id)
            if existing is None:
                count = connection.execute("SELECT COUNT(*) FROM collector_gaps").fetchone()[0]
                if count >= GAP_LIMIT:
                    # 先为新缺口留出位置；未关闭缺口不会为了条数被删除。
                    self._prune_gaps(connection, now, keep=GAP_LIMIT - 1)
                    count = connection.execute(
                        "SELECT COUNT(*) FROM collector_gaps").fetchone()[0]
                    if count >= GAP_LIMIT:
                        raise DatabaseError("缺口记录达到上限，且没有可淘汰的已关闭缺口")
                cursor = connection.execute(
                    "INSERT INTO collector_gaps(run_id, start_at, end_at, reason, detail_json, "
                    "recorded_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (run_id, start_at, end_at, reason, detail_json, now, now))
                gap_id, merged = cursor.lastrowid, False
            else:
                gap_id, old_start, old_end, old_has_detail = existing
                new_start = min(old_start, start_at)
                if end_at is None:
                    new_end = None
                elif old_end is None:
                    new_end = end_at
                else:
                    new_end = max(old_end, end_at)
                connection.execute(
                    "UPDATE collector_gaps SET start_at=?, end_at=?, updated_at=? "
                    "WHERE gap_id=?", (new_start, new_end, now, gap_id))
                if not old_has_detail and detail_json is not None:
                    connection.execute(
                        "UPDATE collector_gaps SET detail_json=? WHERE gap_id=?",
                        (detail_json, gap_id))
                merged = True
            self._prune_auxiliary(connection, now, protect_gap_id=gap_id)
            gap = self._gap(connection, gap_id)
        return {"status": "merged" if merged else "recorded", "gap": gap}

    def update_state(self, **fields):
        unknown = sorted(set(fields) - _STATE_FIELDS)
        if unknown:
            raise DatabaseError("采集状态字段无效：" + "、".join(unknown))
        values = {}
        if "run_id" in fields:
            values["run_id"] = None if fields["run_id"] is None \
                else self._key(fields["run_id"], "state.run_id")
        for field in ("heartbeat_at", "last_complete_at", "stopped_at"):
            if field in fields:
                values[field] = _timestamp(fields[field], f"state.{field}", allow_none=True)
        if "detail" in fields:
            if fields["detail"] is not None:
                self._entry(fields["detail"], "采集状态明细")
            values["detail"] = fields["detail"]
        if not values:
            with self._read() as connection:
                return self._read_state(connection, self._budget())
        with self._write() as connection:
            if values.get("run_id") is not None and not connection.execute(
                    "SELECT 1 FROM collector_runs WHERE run_id=?",
                    (values["run_id"],)).fetchone():
                raise DatabaseError(f"state.run_id 引用的运行不存在：{values['run_id']}")
            self._upsert_state(connection, **values)
            times = [value for key, value in values.items()
                     if key in {"heartbeat_at", "last_complete_at", "stopped_at"}
                     and value is not None]
            if times:
                self._prune_auxiliary(connection, max(times))
            return self._read_state(connection)

    @staticmethod
    def _sampling_threshold(run):
        if not isinstance(run, dict) or not isinstance(run.get("policy"), dict):
            return None
        sampling = run["policy"].get("sampling")
        if not isinstance(sampling, dict):
            return None
        interval = sampling.get("interval_seconds")
        cycle = sampling.get("cycle_seconds")
        if type(interval) is not int or interval <= 0 \
                or type(cycle) is not int or cycle <= 0 or cycle > interval:
            return None
        return 2 * interval + cycle

    def _lifecycle(self, state, active_run, latest_run, now):
        heartbeat = state["heartbeat_at"]
        age = None if heartbeat is None else max(0.0, now - heartbeat)
        if latest_run is None and active_run is None:
            return {"status": "not_started", "status_reason": "没有运行记录",
                    "stale_after_seconds": None, "heartbeat_age_seconds": age}
        if active_run is None:
            return {"status": "stopped", "status_reason": "没有未关闭的运行",
                    "stale_after_seconds": self._sampling_threshold(latest_run),
                    "heartbeat_age_seconds": age}
        threshold = self._sampling_threshold(active_run)
        if threshold is None:
            return {"status": "unknown",
                    "status_reason": "运行策略缺少有效 sampling.interval_seconds/"
                                     "cycle_seconds，不能判断心跳是否过期",
                    "stale_after_seconds": None, "heartbeat_age_seconds": age}
        if age is None:
            return {"status": "stale", "status_reason": "运行未关闭但没有 heartbeat",
                    "stale_after_seconds": threshold, "heartbeat_age_seconds": None}
        if age <= threshold:
            return {"status": "running",
                    "status_reason": f"heartbeat 在 2*interval+cycle={threshold} 秒内",
                    "stale_after_seconds": threshold, "heartbeat_age_seconds": age}
        return {"status": "stale",
                "status_reason": f"heartbeat 已超过 2*interval+cycle={threshold} 秒",
                "stale_after_seconds": threshold, "heartbeat_age_seconds": age}

    def status(self, now=None):
        now = time.time() if now is None else _timestamp(now, "status now")
        budget = self._budget()
        with self._read() as connection:
            state = self._read_state(connection, budget)
            latest_run = self._latest_run(connection, state, budget)
            active_run = self._active_run(connection, state, budget)
            last_sample = self._last_sample(connection)
            last_process = self._last_process_sample(connection, budget)
            open_gaps = connection.execute(
                "SELECT COUNT(*) FROM collector_gaps WHERE end_at IS NULL").fetchone()[0]
            retention = self._retention(connection, state, budget)
            retention["last_append"] = state["retention"]
            sources = self._sources(connection, budget)
            stats = self._database_stats(connection, self.store.database_path)
        stopped_at = state["stopped_at"]
        if stopped_at is None and latest_run is not None:
            stopped_at = latest_run["stopped_at"]
        life = self._lifecycle(state, active_run, latest_run, now)
        return {
            "status": life["status"],
            "status_reason": life["status_reason"],
            "run": latest_run,
            "latest_run": latest_run,
            "active_run": active_run,
            "heartbeat_at": state["heartbeat_at"],
            "heartbeat_age_seconds": life["heartbeat_age_seconds"],
            "stale_after_seconds": life["stale_after_seconds"],
            "last_sample": last_sample,
            "last_sample_age_seconds": None if last_sample is None
            else max(0.0, now - last_sample["observed_at"]),
            "last_process_sample": last_process,
            "last_complete_at": state["last_complete_at"],
            "stopped_at": stopped_at,
            "open_gap_count": open_gaps,
            "sources": sources,
            "retention": retention,
            "last_append": state["retention"],
            "database": stats,
        }

    def query(self, since, until, *, limit=DEFAULT_QUERY_LIMIT, before=None,
              process=None, now=None):
        since = _timestamp(since, "query since", allow_none=True)
        until = _timestamp(until, "query until", allow_none=True)
        now = time.time() if now is None else _timestamp(now, "query now")
        if since is not None and until is not None and since > until:
            raise DatabaseError("query since 不能晚于 until")
        if type(limit) is not int or not 1 <= limit <= MAX_QUERY_LIMIT:
            raise DatabaseError(f"query limit 必须是 1..{MAX_QUERY_LIMIT} 的整数")
        if before is not None and (type(before) is not int
                                   or not 1 <= before <= SQLITE_INT_MAX):
            raise DatabaseError("query before 必须是 SQLite 整数范围内的正样本编号")
        if process is not None:
            process = self._key(process, "query process identity")
        budget = self._budget()
        with self._read() as connection:
            conditions, parameters = [], []
            if since is not None:
                conditions.append("r.observed_at >= ?")
                parameters.append(since)
            if until is not None:
                conditions.append("r.observed_at <= ?")
                parameters.append(until)
            if before is not None:
                conditions.append("r.sample_id < ?")
                parameters.append(before)
            if process is not None:
                conditions.append(
                    "EXISTS (SELECT 1 FROM process_samples p "
                    "WHERE p.sample_id=r.sample_id AND p.identity=?)")
                parameters.append(process)
            where = " AND ".join(conditions) if conditions else "1"
            length_rows = connection.execute(
                "SELECT r.sample_id, "
                "COALESCE(length(CAST(r.boot_json AS BLOB)), 0), "
                "COALESCE(length(CAST(r.host_json AS BLOB)), 0), "
                "COALESCE(length(CAST(r.sources_json AS BLOB)), 0), "
                "COALESCE(length(CAST(r.sampling_json AS BLOB)), 0), "
                "COALESCE(length(CAST(r.process_meta_json AS BLOB)), 0), "
                "COALESCE(length(CAST(c.boot_json AS BLOB)), 0), "
                "COALESCE(length(CAST(c.policy_json AS BLOB)), 0), "
                "COALESCE(length(CAST(c.evidence_json AS BLOB)), 0) "
                "FROM resource_samples r JOIN collector_runs c ON c.run_id=r.run_id "
                "WHERE " + where + " ORDER BY r.sample_id DESC LIMIT ?",
                (*parameters, limit + 1)).fetchall()
            truncated = len(length_rows) > limit
            for row in length_rows[:limit]:
                budget.add(row[1:], "资源历史样本")
            rows = connection.execute(
                "SELECT r.sample_id, r.run_id, r.observed_at, r.monotonic_at, r.boot_json, "
                "r.host_json, r.sources_json, r.sampling_json, r.process_observed, "
                "r.process_truncated, r.process_observed_at, r.process_count, "
                "r.process_meta_json, c.mode, c.started_at, c.stopped_at, c.stop_reason, "
                "c.boot_json, c.pid, c.policy_json, c.evidence_json "
                "FROM resource_samples r JOIN collector_runs c ON c.run_id=r.run_id "
                "WHERE " + where + " ORDER BY r.sample_id DESC LIMIT ?",
                (*parameters, limit))
            samples = []
            for row in rows:
                policy = _decode(row[19], "运行配置证据")
                evidence = _decode(row[20], "运行来源证据")
                host = _decode(row[5], "host 样本")
                sources_value = _decode(row[6], "来源样本")
                sampling = _decode(row[7], "采样配置")
                process_meta = None if row[12] is None \
                    else _decode(row[12], "进程采样元数据")
                if not isinstance(policy, dict) or not isinstance(evidence, dict) \
                        or not isinstance(host, dict) or not isinstance(sources_value, dict) \
                        or not isinstance(sampling, dict) \
                        or (process_meta is not None and not isinstance(process_meta, dict)):
                    raise DatabaseError("运行配置、host、来源、采样或进程元数据损坏")
                samples.append({
                    "sample_id": row[0],
                    "run_id": row[1],
                    "observed_at": row[2],
                    "monotonic_at": row[3],
                    "boot": None if row[4] is None else _decode(row[4], "样本启动标识"),
                    "host": host,
                    "sources": sources_value,
                    "sampling": sampling,
                    "process_observed": bool(row[8]),
                    "process_truncated": bool(row[9]),
                    "process_observed_at": row[10],
                    "process_count": row[11],
                    "process_meta": process_meta,
                    "run": {
                        "run_id": row[1], "mode": row[13], "started_at": row[14],
                        "stopped_at": row[15], "stop_reason": row[16],
                        "boot": None if row[17] is None else _decode(row[17], "运行启动标识"),
                        "pid": row[18], "policy": policy, "evidence": evidence,
                    },
                })
            if process is not None and samples:
                ids = [sample["sample_id"] for sample in samples]
                placeholders = ",".join("?" for _ in ids)
                length_rows = connection.execute(
                    "SELECT sample_id, position, identity, "
                    "COALESCE(length(CAST(payload_json AS BLOB)), 0) "
                    "FROM process_samples WHERE sample_id IN (" + placeholders + ") "
                    "AND identity=? ORDER BY sample_id DESC, position",
                    (*ids, process)).fetchall()
                for row in length_rows:
                    budget.add([row[3]], "进程样本")
                grouped = {}
                for sample_id, position, identity, payload in connection.execute(
                        "SELECT sample_id, position, identity, payload_json "
                        "FROM process_samples WHERE sample_id IN (" + placeholders + ") "
                        "AND identity=? ORDER BY sample_id DESC, position",
                        (*ids, process)):
                    grouped.setdefault(sample_id, []).append(
                        {"position": position, "identity": identity,
                         "payload": _decode(payload, f"进程 {identity} 样本")})
                for sample in samples:
                    sample["processes"] = grouped.get(sample["sample_id"], [])
            gaps = self._gaps(connection, since, until, budget)
            gap_count, oldest_gap_start = connection.execute(
                "SELECT COUNT(*), MIN(start_at) FROM collector_gaps").fetchone()
            state = self._read_state(connection, budget)
            latest_run = self._latest_run(connection, state, budget)
            active_run = self._active_run(connection, state, budget)
            latest_processes = self._latest_processes(connection, until, False, budget)
            last_sample = self._last_sample(connection)
            retention = self._retention(connection, state, budget)
            retention["last_append"] = state["retention"]
            sources = self._sources(connection, budget)
            stats = self._database_stats(connection, self.store.database_path)
        life = self._lifecycle(state, active_run, latest_run, now)
        reference = until if until is not None else now
        complete_since = reference - GAP_RETENTION_HOURS * 3600
        count_limited = gap_count >= GAP_LIMIT
        if count_limited and oldest_gap_start is not None:
            # 条数淘汰只保留最老的已关闭缺口；再早的区间可能已经缺记录。
            complete_since = max(complete_since, oldest_gap_start)
        gap_history = {
            "retention_hours": GAP_RETENTION_HOURS,
            "complete_since": complete_since,
            "count_limit": GAP_LIMIT,
            "count_limited": count_limited,
            "semantics": "缺口早于 complete_since 可能已淘汰；该时间前无缺口不等于连续",
        }
        latest_processes["within_window"] = (
            latest_processes["observed_at"] is not None
            and (since is None or latest_processes["observed_at"] >= since))
        return {
            "window": {"since": since, "until": until, "before": before,
                       "process": process},
            "samples": samples,
            "next_before": samples[-1]["sample_id"] if truncated and samples else None,
            "truncated": truncated,
            "page": {"limit": limit, "returned": len(samples),
                     "truncated": truncated},
            "gaps": gaps,
            "gap_history": gap_history,
            "latest_processes": latest_processes,
            "collector": {
                "status": life["status"], "status_reason": life["status_reason"],
                "now": now,
                "heartbeat_at": state["heartbeat_at"],
                "heartbeat_age_seconds": life["heartbeat_age_seconds"],
                "stale_after_seconds": life["stale_after_seconds"],
                "run": latest_run, "latest_run": latest_run,
                "active_run": active_run,
                "state": state, "last_sample": last_sample,
            },
            "sources": sources,
            "retention": retention,
            "last_append": state["retention"],
            "database": stats,
        }

    def latest_processes(self, *, until=None, successful_only=False):
        until = _timestamp(until, "latest_processes until", allow_none=True)
        if type(successful_only) is not bool:
            raise DatabaseError("successful_only 必须是布尔值")
        with self._read() as connection:
            return self._latest_processes(connection, until, successful_only,
                                          self._budget())

    def latest_successful_processes(self, *, until=None):
        return self.latest_processes(until=until, successful_only=True)

    def _read_state(self, connection, budget=None):
        budget = budget or self._budget()
        length_row = connection.execute(
            "SELECT COALESCE(length(CAST(detail_json AS BLOB)), 0) "
            "FROM collector_state WHERE singleton=1").fetchone()
        if length_row is None:
            return {"run_id": None, "heartbeat_at": None, "last_complete_at": None,
                    "stopped_at": None, "detail": None, "retention": None}
        budget.add([length_row[0]], "采集状态明细")
        row = connection.execute(
            "SELECT run_id, heartbeat_at, last_complete_at, stopped_at, detail_json "
            "FROM collector_state WHERE singleton=1").fetchone()
        raw = None if row[4] is None else _decode(row[4], "采集状态明细")
        detail, retention = raw, None
        if isinstance(raw, dict) and set(raw) == {_STATE_MARKER, "detail", "retention"} \
                and raw.get(_STATE_MARKER) == 1:
            detail, retention = raw["detail"], raw["retention"]
            if retention is not None and not isinstance(retention, dict):
                raise DatabaseError("采集保留摘要损坏")
        return {"run_id": row[0], "heartbeat_at": row[1], "last_complete_at": row[2],
                "stopped_at": row[3], "detail": detail, "retention": retention}

    def _state_entry(self, detail, retention):
        return self._entry({_STATE_MARKER: 1, "detail": detail, "retention": retention},
                           "采集状态明细")

    def _upsert_state(self, connection, *, retention=_UNSET, **fields):
        current = self._read_state(connection)
        merged = dict(current)
        merged.update(fields)
        if retention is _UNSET:
            retention = current["retention"]
        detail_json = self._state_entry(merged["detail"], retention)
        connection.execute(
            "INSERT INTO collector_state(singleton, run_id, heartbeat_at, last_complete_at, "
            "stopped_at, detail_json) VALUES (1, ?, ?, ?, ?, ?) "
            "ON CONFLICT(singleton) DO UPDATE SET run_id=excluded.run_id, "
            "heartbeat_at=excluded.heartbeat_at, last_complete_at=excluded.last_complete_at, "
            "stopped_at=excluded.stopped_at, detail_json=excluded.detail_json",
            (merged["run_id"], merged["heartbeat_at"], merged["last_complete_at"],
             merged["stopped_at"], detail_json))

    def _run_from_row(self, row):
        policy = _decode(row[7], "运行配置证据")
        evidence = _decode(row[8], "运行来源证据")
        if not isinstance(policy, dict) or not isinstance(evidence, dict):
            raise DatabaseError("运行配置或来源证据损坏")
        return {"run_id": row[0], "mode": row[1], "started_at": row[2],
                "stopped_at": row[3], "stop_reason": row[4],
                "boot": None if row[5] is None else _decode(row[5], "运行启动标识"),
                "pid": row[6], "policy": policy, "evidence": evidence}

    def _run(self, connection, run_id, budget=None):
        budget = budget or self._budget()
        lengths = connection.execute(
            "SELECT COALESCE(length(CAST(boot_json AS BLOB)), 0), "
            "COALESCE(length(CAST(policy_json AS BLOB)), 0), "
            "COALESCE(length(CAST(evidence_json AS BLOB)), 0) "
            "FROM collector_runs WHERE run_id=?", (run_id,)).fetchone()
        if lengths is None:
            raise DatabaseError(f"运行记录不存在：{run_id}")
        budget.add(lengths, "运行配置证据")
        row = connection.execute(
            "SELECT run_id, mode, started_at, stopped_at, stop_reason, boot_json, pid, "
            "policy_json, evidence_json FROM collector_runs WHERE run_id=?",
            (run_id,)).fetchone()
        if row is None:
            raise DatabaseError(f"运行记录不存在：{run_id}")
        return self._run_from_row(row)

    def _latest_run(self, connection, state=None, budget=None):
        budget = budget or self._budget()
        if state is None:
            state = self._read_state(connection, budget)
        # state.run_id 是最近启动运行的持久标识；时钟倒退时不用 wall time 重排。
        if state["run_id"] is not None:
            lengths = connection.execute(
                "SELECT COALESCE(length(CAST(boot_json AS BLOB)), 0), "
                "COALESCE(length(CAST(policy_json AS BLOB)), 0), "
                "COALESCE(length(CAST(evidence_json AS BLOB)), 0) "
                "FROM collector_runs WHERE run_id=?", (state["run_id"],)).fetchone()
            if lengths is not None:
                budget.add(lengths, "运行配置证据")
                row = connection.execute(
                    "SELECT run_id, mode, started_at, stopped_at, stop_reason, boot_json, pid, "
                    "policy_json, evidence_json FROM collector_runs WHERE run_id=?",
                    (state["run_id"],)).fetchone()
                if row is not None:
                    return self._run_from_row(row)
        row = connection.execute(
            "SELECT run_id FROM collector_runs "
            "ORDER BY started_at DESC, run_id DESC LIMIT 1").fetchone()
        return None if row is None else self._run(connection, row[0], budget)

    def _active_run(self, connection, state=None, budget=None):
        budget = budget or self._budget()
        if state is None:
            state = self._read_state(connection, budget)
        if state["run_id"] is not None:
            row = connection.execute(
                "SELECT stopped_at FROM collector_runs WHERE run_id=?",
                (state["run_id"],)).fetchone()
            if row is not None and row[0] is None:
                return self._run(connection, state["run_id"], budget)
        row = connection.execute(
            "SELECT run_id FROM collector_runs WHERE stopped_at IS NULL "
            "ORDER BY started_at DESC, run_id DESC LIMIT 1").fetchone()
        return None if row is None else self._run(connection, row[0], budget)

    def _last_sample(self, connection):
        row = connection.execute(
            "SELECT sample_id, observed_at, run_id FROM resource_samples "
            "ORDER BY sample_id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        return {"sample_id": row[0], "observed_at": row[1], "run_id": row[2]}

    def _last_process_sample(self, connection, budget=None):
        budget = budget or self._budget()
        row = connection.execute(
            "SELECT sample_id, observed_at, COALESCE(process_observed_at, observed_at), "
            "run_id, process_truncated, process_count, "
            "COALESCE(length(CAST(process_meta_json AS BLOB)), 0) "
            "FROM resource_samples WHERE process_observed=1 "
            "ORDER BY COALESCE(process_observed_at, observed_at) DESC, sample_id DESC "
            "LIMIT 1").fetchone()
        if row is None:
            return None
        budget.add([row[6]], "进程采样元数据")
        meta_json = connection.execute(
            "SELECT process_meta_json FROM resource_samples WHERE sample_id=?",
            (row[0],)).fetchone()[0]
        meta = None if meta_json is None else _decode(meta_json, "进程采样元数据")
        if meta is not None and not isinstance(meta, dict):
            raise DatabaseError("进程采样元数据损坏")
        available = meta.get("available") if meta is not None else None
        if available is not None and type(available) is not bool:
            raise DatabaseError("进程采样 available 损坏")
        return {"sample_id": row[0], "observed_at": row[2],
                "sample_observed_at": row[1], "run_id": row[3],
                "truncated": bool(row[4]), "process_count": row[5],
                "attempted": True, "available": available}

    def _retention_stats(self, connection, sample_id, observed_at, records, hours,
                         expired, evicted, cutoff):
        count, oldest, newest = connection.execute(
            "SELECT COUNT(*), MIN(observed_at), MAX(observed_at) FROM resource_samples"
        ).fetchone()
        processes = connection.execute("SELECT COUNT(*) FROM process_samples").fetchone()[0]
        span = None if count == 0 else max(0.0, float(newest) - float(oldest))
        return {"sample_id": sample_id, "observed_at": observed_at,
                "records_limit": records, "retention_hours": hours,
                "expired_by_age": expired, "evicted_by_count": evicted,
                "records": count, "processes": processes,
                "oldest_observed_at": oldest, "newest_observed_at": newest,
                "span_seconds": span, "age_cutoff": cutoff}

    def _latest_sampling(self, connection, state=None, budget=None):
        budget = budget or self._budget()
        row = connection.execute(
            "SELECT sample_id, COALESCE(length(CAST(sampling_json AS BLOB)), 0) "
            "FROM resource_samples ORDER BY sample_id DESC LIMIT 1").fetchone()
        if row is not None:
            budget.add([row[1]], "采样配置")
            sampling = _decode(connection.execute(
                "SELECT sampling_json FROM resource_samples WHERE sample_id=?",
                (row[0],)).fetchone()[0], "采样配置")
            if not isinstance(sampling, dict):
                raise DatabaseError("采样配置损坏")
            return sampling
        run_filter, parameters = "", ()
        if state is not None and state["run_id"] is not None:
            run_filter, parameters = " WHERE run_id=?", (state["run_id"],)
        row = connection.execute(
            "SELECT run_id, COALESCE(length(CAST(policy_json AS BLOB)), 0) "
            "FROM collector_runs" + run_filter +
            " ORDER BY started_at DESC, run_id DESC LIMIT 1", parameters).fetchone()
        if row is None and run_filter:
            row = connection.execute(
                "SELECT run_id, COALESCE(length(CAST(policy_json AS BLOB)), 0) "
                "FROM collector_runs ORDER BY started_at DESC, run_id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        budget.add([row[1]], "运行配置证据")
        policy = _decode(connection.execute(
            "SELECT policy_json FROM collector_runs WHERE run_id=?", (row[0],)
        ).fetchone()[0], "运行配置证据")
        if not isinstance(policy, dict):
            raise DatabaseError("运行配置证据损坏")
        sampling = policy.get("sampling")
        return sampling if isinstance(sampling, dict) else None

    def _retention(self, connection, state=None, budget=None):
        budget = budget or self._budget()
        count, oldest, newest = connection.execute(
            "SELECT COUNT(*), MIN(observed_at), MAX(observed_at) FROM resource_samples"
        ).fetchone()
        processes = connection.execute("SELECT COUNT(*) FROM process_samples").fetchone()[0]
        sampling = self._latest_sampling(connection, state, budget)
        if sampling is None:
            limit = hours = None
        else:
            limit = sampling.get("records")
            hours = sampling.get("retention_hours")
            if type(limit) is not int or limit <= 0:
                raise DatabaseError("采样配置 records 损坏")
            if type(hours) is not int or hours <= 0:
                raise DatabaseError("采样配置 retention_hours 损坏")
        span = None if count == 0 else max(0.0, float(newest) - float(oldest))
        return {"records": count, "processes": processes,
                "records_limit": limit, "retention_hours": hours,
                "oldest_observed_at": oldest, "newest_observed_at": newest,
                "span_seconds": span}

    def _sources(self, connection, budget=None):
        budget = budget or self._budget()
        length_rows = connection.execute(
            "SELECT source, COALESCE(length(CAST(detail_json AS BLOB)), 0), "
            "COALESCE(length(CAST(error_json AS BLOB)), 0) "
            "FROM collector_sources ORDER BY source").fetchall()
        for source, detail_length, error_length in length_rows:
            budget.add([detail_length, error_length], f"来源 {source} 状态")
        result = {}
        rows = connection.execute(
            "SELECT source, available, attempted_at, success_at, error_at, error_json, "
            "detail_json, updated_at FROM collector_sources ORDER BY source")
        for source, available, attempted, success, error_at, error_json, detail_json, \
                updated_at in rows:
            detail = _decode(detail_json, f"来源 {source} 状态")
            if not isinstance(detail, dict):
                raise DatabaseError(f"来源 {source} 状态损坏")
            last_error = None if error_json is None \
                else _decode(error_json, f"来源 {source} 错误")
            item = dict(detail)
            item.update({
                "source": source,
                # available 是当前状态；success_at/error_at 是跨轮保留的历史事实。
                "available": None if available is None else bool(available),
                "attempted_at": attempted, "success_at": success,
                "error_at": error_at, "error": last_error,
                "last_success_at": success, "last_error_at": error_at,
                "last_error": last_error,
                "updated_at": updated_at,
            })
            result[source] = item
        return result

    def close_gap(self, gap_id, end_at, *, detail=None):
        """按 gap_id 关闭 open 缺口；墙钟回拨时把区间压到关闭点并保留原始时间。

        按时间区间查找在回拨后会匹配不到原缺口，导致缺口永久保持 open。
        """
        if type(gap_id) is not int or gap_id <= 0:
            raise DatabaseError("gap_id 必须是正整数")
        end_at = _timestamp(end_at, "gap end_at")
        detail_json = None if detail is None else self._entry(detail, "gap 明细")
        with self._write() as connection:
            row = connection.execute(
                "SELECT start_at, end_at, detail_json FROM collector_gaps WHERE gap_id=?",
                (gap_id,)).fetchone()
            if row is None:
                raise DatabaseError(f"缺口记录不存在：{gap_id}")
            old_start, old_end, old_detail_json = row
            if old_end is not None:
                return self._gap(connection, gap_id)
            new_start = min(old_start, end_at)
            new_end = max(new_start, end_at)
            if old_detail_json is not None:
                old_detail = _decode(old_detail_json, "缺口明细")
                if detail is None:
                    detail_json = old_detail_json
                elif isinstance(old_detail, dict) and isinstance(detail, dict):
                    merged = dict(old_detail)
                    merged.update(detail)
                    try:
                        detail_json = self._entry(merged, "gap 明细")
                    except DatabaseError:
                        # 合并后的明细超预算时保留原明细，关闭动作不能因此失败。
                        detail_json = old_detail_json
                else:
                    detail_json = old_detail_json
            connection.execute(
                "UPDATE collector_gaps SET start_at=?, end_at=?, detail_json=?, updated_at=? "
                "WHERE gap_id=?", (new_start, new_end, detail_json, end_at, gap_id))
            self._prune_auxiliary(connection, end_at, protect_gap_id=gap_id)
            return self._gap(connection, gap_id)

    def _find_gap(self, connection, start_at, end_at, reason, run_id):
        if end_at is None:
            return connection.execute(
                "SELECT gap_id, start_at, end_at, detail_json IS NOT NULL "
                "FROM collector_gaps WHERE reason=? AND run_id IS ? AND end_at IS NULL "
                "ORDER BY gap_id DESC LIMIT 1", (reason, run_id)).fetchone()
        return connection.execute(
            "SELECT gap_id, start_at, end_at, detail_json IS NOT NULL "
            "FROM collector_gaps WHERE reason=? AND run_id IS ? AND start_at <= ? "
            "AND (end_at IS NULL OR end_at >= ?) "
            "ORDER BY start_at DESC, gap_id DESC LIMIT 1",
            (reason, run_id, end_at, start_at)).fetchone()

    def _gap(self, connection, gap_id, budget=None):
        budget = budget or self._budget()
        length = connection.execute(
            "SELECT COALESCE(length(CAST(detail_json AS BLOB)), 0) "
            "FROM collector_gaps WHERE gap_id=?", (gap_id,)).fetchone()
        if length is None:
            raise DatabaseError(f"缺口记录不存在：{gap_id}")
        budget.add([length[0]], "缺口明细")
        row = connection.execute(
            "SELECT gap_id, run_id, start_at, end_at, reason, detail_json, recorded_at, "
            "updated_at FROM collector_gaps WHERE gap_id=?", (gap_id,)).fetchone()
        if row is None:
            raise DatabaseError(f"缺口记录不存在：{gap_id}")
        return {"gap_id": row[0], "run_id": row[1], "start_at": row[2], "end_at": row[3],
                "ongoing": row[3] is None, "reason": row[4],
                "detail": None if row[5] is None else _decode(row[5], "缺口明细"),
                "recorded_at": row[6], "updated_at": row[7]}

    def _gaps(self, connection, since, until, budget=None):
        budget = budget or self._budget()
        conditions, parameters = [], []
        if until is not None:
            conditions.append("start_at <= ?")
            parameters.append(until)
        if since is not None:
            conditions.append("(end_at IS NULL OR end_at >= ?)")
            parameters.append(since)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        for row in connection.execute(
                "SELECT gap_id, COALESCE(length(CAST(detail_json AS BLOB)), 0) "
                "FROM collector_gaps" + where + " ORDER BY start_at, gap_id", parameters):
            budget.add([row[1]], "缺口明细")
        sql = ("SELECT gap_id, run_id, start_at, end_at, reason, detail_json, recorded_at, "
               "updated_at FROM collector_gaps" + where + " ORDER BY start_at, gap_id")
        result = []
        for row in connection.execute(sql, parameters):
            result.append({"gap_id": row[0], "run_id": row[1], "start_at": row[2],
                           "end_at": row[3], "ongoing": row[3] is None, "reason": row[4],
                           "detail": None if row[5] is None else _decode(row[5], "缺口明细"),
                           "recorded_at": row[6], "updated_at": row[7]})
        return result

    def _latest_processes(self, connection, until, successful_only=False, budget=None):
        budget = budget or self._budget()
        conditions, parameters = ["process_observed=1"], []
        if until is not None:
            conditions.append("COALESCE(process_observed_at, observed_at) <= ?")
            parameters.append(until)
        sql = ("SELECT sample_id, run_id, observed_at, "
               "COALESCE(process_observed_at, observed_at), process_truncated, process_count, "
               "COALESCE(length(CAST(process_meta_json AS BLOB)), 0) "
               "FROM resource_samples WHERE " + " AND ".join(conditions) +
               " ORDER BY COALESCE(process_observed_at, observed_at) DESC, sample_id DESC")
        chosen, saw_attempt = None, False
        for row in connection.execute(sql, parameters):
            saw_attempt = True
            budget.add([row[6]], "进程采样元数据")
            meta_json = connection.execute(
                "SELECT process_meta_json FROM resource_samples WHERE sample_id=?",
                (row[0],)).fetchone()[0]
            meta = None if meta_json is None else _decode(meta_json, "进程采样元数据")
            if meta is not None and not isinstance(meta, dict):
                raise DatabaseError("进程采样元数据损坏")
            available = meta.get("available") if meta is not None else None
            if available is not None and type(available) is not bool:
                raise DatabaseError("进程采样 available 损坏")
            if successful_only and available is False:
                continue
            chosen = (row, meta, available)
            break
        if chosen is None:
            return {"observed": False, "attempted": saw_attempt,
                    "available": False if saw_attempt else None,
                    "successful": False, "sample_id": None, "run_id": None,
                    "observed_at": None, "sample_observed_at": None,
                    "truncated": False, "process_count": 0, "meta": None,
                    "processes": [],
                    "reason": "没有成功的进程快照" if saw_attempt
                    else "没有进程采样记录"}
        row, meta, available = chosen
        length_rows = connection.execute(
            "SELECT position, identity, COALESCE(length(CAST(payload_json AS BLOB)), 0) "
            "FROM process_samples WHERE sample_id=? ORDER BY position",
            (row[0],)).fetchall()
        if len(length_rows) != row[5]:
            raise DatabaseError("进程样本数量与样本记录不一致")
        for _, _, length in length_rows:
            budget.add([length], "进程样本")
        processes = []
        for position, identity, payload_json in connection.execute(
                "SELECT position, identity, payload_json FROM process_samples "
                "WHERE sample_id=? ORDER BY position", (row[0],)):
            processes.append(_decode(payload_json, f"进程 {identity} 样本"))
        return {"observed": True, "attempted": True, "available": available,
                "successful": available is not False,
                "sample_id": row[0], "run_id": row[1],
                "observed_at": row[3], "sample_observed_at": row[2],
                "truncated": bool(row[4]), "process_count": row[5],
                "meta": meta, "processes": processes}

    def _prune_auxiliary(self, connection, now, protect_gap_id=None,
                         protect_run_id=None):
        self._prune_gaps(connection, now, protect_gap_id)
        self._prune_runs(connection, now, protect_run_id)

    def _prune_gaps(self, connection, now, protect_gap_id=None, keep=None):
        keep = GAP_LIMIT if keep is None else keep
        cutoff = now - GAP_RETENTION_HOURS * 3600
        if protect_gap_id is None:
            connection.execute(
                "DELETE FROM collector_gaps WHERE end_at IS NOT NULL AND end_at < ?",
                (cutoff,))
        else:
            connection.execute(
                "DELETE FROM collector_gaps WHERE end_at IS NOT NULL AND end_at < ? "
                "AND gap_id != ?", (cutoff, protect_gap_id))
        excess = connection.execute(
            "SELECT COUNT(*) FROM collector_gaps").fetchone()[0] - keep
        if excess <= 0:
            return
        if protect_gap_id is None:
            connection.execute(
                "DELETE FROM collector_gaps WHERE gap_id IN ("
                "SELECT gap_id FROM collector_gaps WHERE end_at IS NOT NULL "
                "ORDER BY end_at ASC, gap_id ASC LIMIT ?)", (excess,))
        else:
            connection.execute(
                "DELETE FROM collector_gaps WHERE gap_id IN ("
                "SELECT gap_id FROM collector_gaps WHERE end_at IS NOT NULL AND gap_id != ? "
                "ORDER BY end_at ASC, gap_id ASC LIMIT ?)",
                (protect_gap_id, excess))

    def _prune_runs(self, connection, now, protect_run_id=None):
        state = self._read_state(connection)
        current = state["run_id"] or ""
        protected = protect_run_id or ""
        cutoff = now - RUN_RETENTION_HOURS * 3600
        unreferenced = (
            "NOT EXISTS (SELECT 1 FROM resource_samples s "
            "WHERE s.run_id=collector_runs.run_id) "
            "AND NOT EXISTS (SELECT 1 FROM collector_gaps g "
            "WHERE g.run_id=collector_runs.run_id)")
        connection.execute(
            "DELETE FROM collector_runs WHERE run_id != ? AND run_id != ? "
            "AND stopped_at IS NOT NULL AND stopped_at < ? AND " + unreferenced,
            (current, protected, cutoff))
        excess = connection.execute(
            "SELECT COUNT(*) FROM collector_runs").fetchone()[0] - RUN_LIMIT
        if excess > 0:
            connection.execute(
                "DELETE FROM collector_runs WHERE run_id IN ("
                "SELECT run_id FROM collector_runs WHERE run_id != ? AND run_id != ? "
                "AND stopped_at IS NOT NULL AND " + unreferenced +
                " ORDER BY stopped_at ASC, run_id ASC LIMIT ?)",
                (current, protected, excess))
