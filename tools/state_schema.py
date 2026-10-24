"""运行状态的读取与结构校验；无效记录在动作前阻断。"""

import math
import os
from pathlib import Path
import re

from files import SCOPE_SAMPLE_LIMIT, within
from state import StewardError


def require(condition, name, detail):
    if not condition:
        raise StewardError(f"{name} 结构错误：{detail}；保留原状态")


def integer(value):
    return type(value) is int


def number(value):
    return type(value) is int or (type(value) is float and math.isfinite(value))


def timestamp_seconds(value):
    return number(value) and -10**12 <= value <= 10**12


def object_field(data, key, name):
    if key not in data:
        return {}
    require(isinstance(data[key], dict), name, f"{key} 必须是对象")
    return data[key]


def list_field(data, key, name):
    if key in data:
        require(isinstance(data[key], list), name, f"{key} 必须是数组")


def valid_path(value):
    return isinstance(value, str) and bool(value) and len(value.encode()) <= 4096 and "\x00" not in value \
        and Path(value).is_absolute() and os.path.normpath(value) == value


def validate_scope(scope, root, name):
    require(isinstance(scope, dict), name, "scope 必须是对象")
    version = scope.get("version")
    require(integer(version) and version in {1, 2}, name, "scope.version 必须是整数 1 或 2")
    expected = {"version", "root", "device", "exclude_names", "state_path", "volume_policy", "other_volumes"}
    expected |= {"scan_depth"} if version == 1 else {"max_depth", "exclude_paths"}
    require(set(scope) == expected, name, "scope 字段与版本不符")
    require(scope.get("root") == root and valid_path(root), name, "scope.root 与基线不符")
    device = scope.get("device")
    require(device is None or (integer(device) and device >= 0), name, "scope.device 无效")
    names = scope.get("exclude_names")
    require(isinstance(names, list) and all(isinstance(value, str) and value and value not in {".", ".."}
            and "/" not in value and "\x00" not in value for value in names), name, "scope.exclude_names 无效")
    require(names == sorted(set(names)), name, "scope.exclude_names 必须排序去重")
    require(scope.get("state_path") is None or valid_path(scope["state_path"]), name, "scope.state_path 无效")
    if version == 1:
        require(integer(scope.get("scan_depth")) and scope["scan_depth"] >= 0, name, "scope.scan_depth 无效")
    else:
        require(integer(scope.get("max_depth")) and scope["max_depth"] >= 0, name, "scope.max_depth 无效")
        exclude_paths = scope.get("exclude_paths")
        require(isinstance(exclude_paths, list) and all(
            isinstance(value, str) and bool(value) and value not in {".", ".."} and "\x00" not in value
            and Path(value).parts and not Path(value).is_absolute()
            and os.path.normpath(value) == value
            and all(part not in {"", ".", ".."} for part in Path(value).parts)
            for value in exclude_paths), name, "scope.exclude_paths 无效")
        require(exclude_paths == sorted(set(exclude_paths)), name, "scope.exclude_paths 必须排序去重")
    require(scope.get("volume_policy") == "root_device_only", name, "scope.volume_policy 无效")
    boundaries = scope.get("other_volumes")
    require(isinstance(boundaries, dict), name, "scope.other_volumes 必须是对象")
    count, digest, samples = boundaries.get("count"), boundaries.get("digest"), boundaries.get("samples")
    require(integer(count) and count >= 0, name, "scope.other_volumes.count 无效")
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            name, "scope.other_volumes.digest 无效")
    require(isinstance(samples, list) and len(samples) == min(count, SCOPE_SAMPLE_LIMIT), name, "scope 边界样例数量无效")
    require(type(boundaries.get("truncated")) is bool and boundaries["truncated"] == (count > SCOPE_SAMPLE_LIMIT),
            name, "scope 边界截断标志无效")
    paths = set()
    for sample in samples:
        require(isinstance(sample, dict) and valid_path(sample.get("path")), name, "scope 边界路径无效")
        require(integer(sample.get("device")) and sample["device"] >= 0, name, "scope 边界设备无效")
        path = sample["path"]
        require(path.startswith(root.rstrip(os.sep) + os.sep) and path not in paths, name, "scope 边界越界或重复")
        paths.add(path)


def validate_events(events, name):
    for key in ["available", "baseline", "history_complete", "history_invalid", "rescan_required", "cursor_pending"]:
        if key in events:
            require(type(events[key]) is bool, name, f"events.{key} 必须是布尔值")
    if "cursor" in events:
        require(events["cursor"] is None or (integer(events["cursor"]) and events["cursor"] >= 0),
                name, "events.cursor 必须是非负整数或 null")
    if "retry_count" in events:
        require(integer(events["retry_count"]) and events["retry_count"] >= 0, name, "events.retry_count 必须是非负整数")
    if "devices" in events:
        require(isinstance(events["devices"], dict), name, "events.devices 必须是对象")
        require(all(isinstance(key, str) and (value is None or integer(value)) for key, value in events["devices"].items()),
                name, "events.devices 的设备号必须是整数或 null")


def validate_baselines(baselines, name):
    for root, snapshot in baselines.items():
        require(isinstance(root, str) and isinstance(snapshot, dict), name, "baseline 条目必须是对象")
        require(type(snapshot.get("complete")) is bool, name, f"baseline {root} 缺少布尔 complete")
        if "scope" in snapshot:
            validate_scope(snapshot["scope"], root, name)
        if "measured_at" in snapshot:
            require(timestamp_seconds(snapshot["measured_at"]), name, f"baseline {root} measured_at 超出有效秒级时间范围")
        gaps = snapshot.get("gaps", [])
        require(isinstance(gaps, list) and all(isinstance(reason, str) for reason in gaps), name, f"baseline {root} gaps 无效")
        if "records" in snapshot:
            require(isinstance(snapshot["records"], dict), name, f"baseline {root}.records 必须是对象")
        if "directories" in snapshot:
            require(isinstance(snapshot["directories"], dict), name, f"baseline {root}.directories 必须是对象")
        if not snapshot["complete"]:
            continue
        require(isinstance(snapshot.get("root_id"), str), name, f"baseline {root} 缺少 root_id")
        require("records" in snapshot and "directories" in snapshot, name, f"完整 baseline {root} 缺少 records/directories")
        for path, record in snapshot["records"].items():
            require(isinstance(path, str) and isinstance(record, dict), name, f"baseline {root} 的记录无效")
            require(isinstance(record.get("id"), str) and isinstance(record.get("kind"), str), name, f"baseline {root} 记录身份无效")
            require(integer(record.get("size")) and record["size"] >= 0 and integer(record.get("mtime")),
                    name, f"baseline {root} 记录大小或时间无效")
            if "birth" in record:
                require(record["birth"] is None or timestamp_seconds(record["birth"]), name, f"baseline {root} birth 无效")
        for path, summary in snapshot["directories"].items():
            require(isinstance(path, str) and isinstance(summary, dict), name, f"baseline {root} 的目录摘要无效")
            require(integer(summary.get("bytes")) and summary["bytes"] >= 0, name, f"baseline {root} 目录字节数无效")


def validate_event_recheck(state, name):
    """事件待复核队列必须可解释；损坏时阻断巡检并指向显式重置入口。"""
    require(isinstance(state, dict), name, "event_recheck 必须是对象")
    expected = {"version", "limit", "items", "truncated", "aggregated", "dropped",
                "source_truncated", "degraded"}
    require(set(state) == expected, name, "event_recheck 字段缺失或含未知字段")
    require(integer(state.get("version")) and state["version"] == 1, name,
            "event_recheck.version 必须是整数 1")
    limit = state.get("limit")
    require(integer(limit) and 1 <= limit <= 1024, name, "event_recheck.limit 必须是 1–1024 的整数")
    items = state.get("items")
    require(isinstance(items, list) and len(items) <= limit, name,
            "event_recheck.items 必须是数组且不超过 limit；"
            "如队列已损坏，可用 patrol --discard-event-recheck 清除后重建")
    seen = set()
    base_fields = {"root", "path", "first_at", "last_at", "count"}
    for item in items:
        require(isinstance(item, dict) and set(item) in (base_fields, base_fields | {"token"}),
                name, "event_recheck 条目字段无效")
        if "token" in item:
            require(number(item["token"]), name, "event_recheck 条目的稳定事件身份必须是有限数值")
        root, path = item.get("root"), item.get("path")
        require(valid_path(root) and valid_path(path) and within(path, root), name,
                "event_recheck 条目的 root/path 无效或越界")
        require(path not in seen, name, f"event_recheck 路径重复：{path[:160]}")
        seen.add(path)
        require(timestamp_seconds(item.get("first_at")) and timestamp_seconds(item.get("last_at")),
                name, "event_recheck 条目的时间必须是有限秒级数值")
        require(item["first_at"] <= item["last_at"], name, "event_recheck 条目的首次时间晚于最近时间")
        require(integer(item.get("count")) and item["count"] >= 1, name,
                "event_recheck 条目的次数必须是正整数")
    require(type(state.get("truncated")) is bool and type(state.get("source_truncated")) is bool,
            name, "event_recheck 截断标志必须是布尔值")
    for key in ("aggregated", "dropped"):
        require(integer(state.get(key)) and state[key] >= 0, name,
                f"event_recheck.{key} 必须是非负整数")
    degraded = state.get("degraded")
    require(degraded is None or (isinstance(degraded, dict) and set(degraded) == {"reason", "since"}
                                 and isinstance(degraded.get("reason"), str) and bool(degraded["reason"])
                                 and timestamp_seconds(degraded.get("since"))),
            name, "event_recheck.degraded 必须是 null 或含 reason/since 的对象")


def validate_scan_progress(progress, name):
    """续扫进度必须能按 root 恢复；损坏时阻断本轮并保留上次状态。"""
    require(isinstance(progress, dict), name, "scan_progress 必须是对象")
    if "next_index" in progress:
        require(integer(progress["next_index"]) and progress["next_index"] >= 0,
                name, "scan_progress.next_index 必须是非负整数")
    for root, entry in progress.items():
        if root == "next_index":
            continue
        require(valid_path(root) and isinstance(entry, dict), name, "scan_progress 条目必须是按绝对路径索引的对象")
        require(isinstance(entry.get("root_id"), str) and bool(entry["root_id"]),
                name, f"scan_progress {root} 缺少 root_id")
        validate_scope(entry.get("scope"), root, name)
        for path, record in object_field(entry, "records", name).items():
            require(valid_path(path) and within(path, root) and isinstance(record, dict),
                    name, f"scan_progress {root} 的记录无效或越过 root")
            require(isinstance(record.get("id"), str) and isinstance(record.get("kind"), str),
                    name, f"scan_progress {root} 记录身份无效")
            require(integer(record.get("size")) and record["size"] >= 0 and integer(record.get("mtime")),
                    name, f"scan_progress {root} 记录大小或时间无效")
            if "birth" in record:
                require(record["birth"] is None or timestamp_seconds(record["birth"]),
                        name, f"scan_progress {root} birth 无效")
        queue = entry.get("queue")
        require(isinstance(queue, list) and bool(queue), name,
                f"scan_progress {root} 的待扫队列为空或无效；"
                "如进度已损坏，可用 patrol --discard-scan-progress 清除后重建")
        for item in queue:
            require(isinstance(item, dict) and valid_path(item.get("path"))
                    and within(item["path"], root),
                    name, f"scan_progress {root} 的待扫目录条目无效或越过 root")
            require(integer(item.get("depth")) and item["depth"] >= 0,
                    name, f"scan_progress {root} 的待扫目录深度无效")
            require(item.get("cursor") is None or isinstance(item.get("cursor"), str),
                    name, f"scan_progress {root} 的目录游标无效")
            dir_id = item.get("dir_id")
            require(dir_id is None or (isinstance(dir_id, dict) and isinstance(dir_id.get("id"), str)
                                       and integer(dir_id.get("mtime"))),
                    name, f"scan_progress {root} 的目录身份无效")
            restarts = item.get("restarts", 0)
            require(integer(restarts) and restarts >= 0,
                    name, f"scan_progress {root} 的目录重启计数无效")
        excluded = object_field(entry, "excluded", name)
        require(all(isinstance(key, str) and integer(value) and value >= 0
                    for key, value in excluded.items()), name, f"scan_progress {root} 的排除计数无效")
        for path, counts in object_field(entry, "excluded_by_dir", name).items():
            require(isinstance(path, str) and isinstance(counts, dict) and all(
                isinstance(key, str) and integer(value) and value >= 0 for key, value in counts.items()),
                name, f"scan_progress {root} 的按目录排除计数无效")
        allocated = object_field(entry, "allocated", name)
        require(all(isinstance(key, str) and integer(value) and value >= 0
                    for key, value in allocated.items()), name, f"scan_progress {root} 的分配字节无效")
        boundaries = entry.get("boundaries", [])
        require(isinstance(boundaries, list) and all(
            isinstance(pair, (list, tuple)) and len(pair) == 2 and valid_path(pair[0]) and integer(pair[1])
            for pair in boundaries), name, f"scan_progress {root} 的跨卷边界无效")
        for key in ("rounds", "entries"):
            require(integer(entry.get(key)) and entry[key] >= 0,
                    name, f"scan_progress {root} 的 {key} 必须是非负整数")
        gaps = entry.get("gaps")
        require(isinstance(gaps, list) and all(isinstance(reason, str) for reason in gaps),
                name, f"scan_progress {root} 的 gaps 无效")
        vanished = entry.get("vanished", [])
        require(isinstance(vanished, list) and all(isinstance(path, str) and bool(path) for path in vanished),
                name, f"scan_progress {root} 的消失目录记录无效")
        done = entry.get("recheck_done", {})
        require(isinstance(done, dict), name, f"scan_progress {root} 的待复核完成标记必须是对象")
        for path, token in done.items():
            require(valid_path(path) and within(path, root) and number(token),
                    name, f"scan_progress {root} 的待复核完成标记无效或越界")
        active = entry.get("recheck_active", {})
        require(isinstance(active, dict), name, f"scan_progress {root} 的复核中标记必须是对象")
        for path, token in active.items():
            require(valid_path(path) and within(path, root) and number(token),
                    name, f"scan_progress {root} 的复核中标记无效或越界")
        pending = entry.get("recheck_pending", {})
        require(isinstance(pending, dict), name, f"scan_progress {root} 的复核待办标记必须是对象")
        for path, token in pending.items():
            require(valid_path(path) and within(path, root) and number(token),
                    name, f"scan_progress {root} 的复核待办标记无效或越界")
        failed = entry.get("recheck_failed", [])
        require(isinstance(failed, list) and all(valid_path(path) and within(path, root) for path in failed),
                name, f"scan_progress {root} 的待复核失败记录无效")


def validate_pending(rows, name, field, seen):
    for row in rows:
        require(isinstance(row, dict), name, f"{field} 行必须是对象")
        key = row.get("key")
        require(isinstance(key, str) and bool(key) and len(key.encode()) <= 512, name, f"{field}.key 无效或超过 512 字节")
        require(key not in seen, name, f"pending key 重复：{key[:160]}")
        seen.add(key)
        for stamp in ["observed_at", "first_observed_at"]:
            if stamp in row:
                require(timestamp_seconds(row[stamp]), name, f"{field}.{stamp} 必须是有限数值")


def read_current(store, fields=None):
    name = "current.json"
    data = store.read(name, {}, fields=fields) if fields is not None else store.read(name, {})
    require(isinstance(data, dict), name, "顶层必须是对象")
    if not data:
        return data
    require(integer(data.get("version")) and data["version"] == 1, name, "version 必须是整数 1")
    if "last_run" in data:
        require(data["last_run"] is None or isinstance(data["last_run"], dict), name, "last_run 必须是对象或 null")
    object_field(data, "host", name)
    events = object_field(data, "events", name)
    validate_events(events, name)
    validate_baselines(object_field(data, "baselines", name), name)
    if "scan_progress" in data:
        try:
            validate_scan_progress(data["scan_progress"], name)
        except StewardError as exc:
            message = str(exc)
            if "--discard-scan-progress" not in message:
                message += ("；如续扫进度已损坏无法接续，可用 patrol --discard-scan-progress "
                            "在锁内清除进度后重建（保留 baselines）")
            raise StewardError(message) from exc
    if "event_recheck" in data:
        try:
            validate_event_recheck(data["event_recheck"], name)
        except StewardError as exc:
            message = str(exc)
            if "--discard-event-recheck" not in message:
                message += ("；如待复核队列已损坏，可用 patrol --discard-event-recheck "
                            "在锁内清除队列后重建（保留 baselines 与续扫进度）")
            raise StewardError(message) from exc
    for root, coverage in object_field(data, "coverage_scope", name).items():
        require(valid_path(root) and isinstance(coverage, dict), name, "coverage_scope 条目无效")
        require(type(coverage.get("complete")) is bool, name, "coverage_scope.complete 必须是布尔值")
        if coverage.get("scope") is not None:
            validate_scope(coverage["scope"], root, name)
        excluded = object_field(coverage, "excluded", name)
        require(all(isinstance(key, str) and integer(value) and value >= 0 for key, value in excluded.items()),
                name, "coverage_scope.excluded 必须是非负整数计数")
    for key in ["directory_index", "coverage_gaps", "comparison_gaps", "observation_gaps", "changes", "samples",
                "pending", "pending_overflow", "pending_history"]:
        list_field(data, key, name)
    for row in data.get("directory_index", []):
        require(isinstance(row, dict) and isinstance(row.get("root"), str) and isinstance(row.get("path"), str),
                name, "directory_index 行必须包含字符串 root/path")
    for key in ["coverage_gaps", "comparison_gaps", "observation_gaps"]:
        require(all(isinstance(row, dict) for row in data.get(key, [])), name, f"{key} 行必须是对象")
    if "change_retention" in data:
        retention = object_field(data, "change_retention", name)
        for key in ["retention_hours", "record_limit", "expired_by_age", "evicted_by_count"]:
            value = retention.get(key)
            minimum = 1 if key in ["retention_hours", "record_limit"] else 0
            require(integer(value) and value >= minimum, name, f"change_retention.{key} 无效")
        for key in ["oldest_observed_at", "newest_observed_at"]:
            value = retention.get(key)
            require(value is None or timestamp_seconds(value), name, f"change_retention.{key} 必须是有限时间或 null")
        span = retention.get("span_hours")
        require(span is None or (number(span) and span >= 0), name, "change_retention.span_hours 必须是非负有限数值或 null")
    for row in data.get("changes", []):
        require(isinstance(row, dict) and isinstance(row.get("path"), str) and timestamp_seconds(row.get("observed_at")),
                name, "changes 行必须包含 path 和有限 observed_at")
    for row in data.get("samples", []):
        require(isinstance(row, dict) and timestamp_seconds(row.get("time")) and isinstance(row.get("processes"), list),
                name, "samples 行必须包含有限 time 和 processes 数组")
        for process in row["processes"]:
            require(isinstance(process, dict) and isinstance(process.get("identity"), str)
                    and integer(process.get("rss_bytes")) and process["rss_bytes"] >= 0,
                    name, "进程样本 identity/rss_bytes 无效")
        if row.get("host") is not None:
            require(isinstance(row["host"], dict), name, "samples 行 host 必须是对象")
    seen = set()
    validate_pending(data.get("pending", []), name, "pending", seen)
    validate_pending(data.get("pending_overflow", []), name, "pending_overflow", seen)
    for row in data.get("pending_history", []):
        require(isinstance(row, dict) and isinstance(row.get("key"), str), name, "pending_history 行必须包含字符串 key")
        if "resolved_at" in row:
            require(timestamp_seconds(row["resolved_at"]), name, "pending_history.resolved_at 必须是有限数值")
        if "resolution_reason" in row:
            require(isinstance(row["resolution_reason"], str), name, "resolution_reason 必须是字符串")
    for key in ["change_records_dropped", "pending_history_dropped"]:
        if key in data:
            require(integer(data[key]) and data[key] >= 0, name, f"{key} 必须是非负整数")
    return data


def read_operations(store):
    name = "operations.json"
    records = store.read(name, [])
    require(isinstance(records, list), name, "顶层必须是数组")
    seen = set()
    for row in records:
        require(isinstance(row, dict), name, "操作记录必须是对象")
        operation_id = row.get("id")
        require(isinstance(operation_id, str) and re.fullmatch(r"[0-9a-f]{32}", operation_id) is not None,
                name, "操作 id 必须是 32 位小写十六进制")
        require(operation_id not in seen, name, f"操作 id 重复：{operation_id}")
        seen.add(operation_id)
        kind, status = row.get("kind"), row.get("status")
        require(isinstance(kind, str) and bool(kind) and isinstance(status, str) and bool(status),
                name, "操作 kind/status 必须是非空字符串")
        if "created_at" in row:
            require(timestamp_seconds(row["created_at"]), name, "created_at 必须是有限数值")
        if kind == "directory_note":
            require(status in ["planned", "verified", "failed"], name, "directory_note 状态无效")
        elif kind == "quarantine":
            require(status in ["planned", "quarantined", "restoring", "restored", "failed"], name, "quarantine 状态无效")
            require(valid_path(row.get("source")) and valid_path(row.get("target")), name, "quarantine source/target 路径无效")
            identity = row.get("identity")
            require(isinstance(identity, dict) and isinstance(identity.get("id"), str)
                    and integer(identity.get("size")) and identity["size"] >= 0
                    and integer(identity.get("mtime")),
                    name, "quarantine identity 无效")
    return records
