"""运行状态的读取与结构校验；无效记录在动作前阻断。"""

import math
import os
from pathlib import Path
import re

from files import SCOPE_SAMPLE_LIMIT
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


def object_field(data, key, name, default=None):
    if key not in data:
        return {} if default is None else default
    require(isinstance(data[key], dict), name, f"{key} 必须是对象")
    return data[key]


def list_field(data, key, name):
    if key not in data:
        return []
    require(isinstance(data[key], list), name, f"{key} 必须是数组")
    return data[key]


def valid_path(value):
    return isinstance(value, str) and bool(value) and len(value.encode()) <= 4096 and "\x00" not in value \
        and Path(value).is_absolute() and os.path.normpath(value) == value


def validate_scope(scope, root, name):
    require(isinstance(scope, dict), name, "scope 必须是对象")
    require({"version", "root", "device", "exclude_names", "state_path", "scan_depth", "volume_policy", "other_volumes"}
            <= scope.keys(), name, "scope 缺少必要字段")
    require(integer(scope.get("version")) and scope["version"] == 1, name, "scope.version 必须是整数 1")
    require(scope.get("root") == root and valid_path(root), name, "scope.root 与基线不符")
    device = scope.get("device")
    require(device is None or (integer(device) and device >= 0), name, "scope.device 无效")
    names = scope.get("exclude_names")
    require(isinstance(names, list) and all(isinstance(value, str) and value and value not in {".", ".."}
            and "/" not in value and "\x00" not in value for value in names), name, "scope.exclude_names 无效")
    require(names == sorted(set(names)), name, "scope.exclude_names 必须排序去重")
    require(scope.get("state_path") is None or valid_path(scope["state_path"]), name, "scope.state_path 无效")
    require(integer(scope.get("scan_depth")) and scope["scan_depth"] >= 0, name, "scope.scan_depth 无效")
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


def read_current(store):
    name = "current.json"
    data = store.read(name, {})
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
    for root, coverage in object_field(data, "coverage_scope", name).items():
        require(valid_path(root) and isinstance(coverage, dict), name, "coverage_scope 条目无效")
        require(type(coverage.get("complete")) is bool, name, "coverage_scope.complete 必须是布尔值")
        if coverage.get("scope") is not None:
            validate_scope(coverage["scope"], root, name)
        excluded = object_field(coverage, "excluded", name)
        require(all(isinstance(key, str) and integer(value) and value >= 0 for key, value in excluded.items()),
                name, "coverage_scope.excluded 必须是非负整数计数")
    for key in ["directory_index", "coverage_gaps", "observation_gaps", "changes", "samples",
                "pending", "pending_overflow", "pending_history"]:
        list_field(data, key, name)
    for row in data.get("directory_index", []):
        require(isinstance(row, dict) and isinstance(row.get("root"), str) and isinstance(row.get("path"), str),
                name, "directory_index 行必须包含字符串 root/path")
    for key in ["coverage_gaps", "observation_gaps"]:
        require(all(isinstance(row, dict) for row in data.get(key, [])), name, f"{key} 行必须是对象")
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
    if "changes_window" in data:
        window = data["changes_window"]
        require(isinstance(window, dict), name, "changes_window 必须是对象")
        require(number(window.get("hours")) and window["hours"] >= 0, name, "changes_window.hours 无效")
        require(integer(window.get("declared_hours")) and window["declared_hours"] >= 0,
                name, "changes_window.declared_hours 必须是非负整数")
        require(type(window.get("truncated_by_count")) is bool, name, "changes_window.truncated_by_count 必须是布尔值")
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
