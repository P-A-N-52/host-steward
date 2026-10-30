#!/usr/bin/env python3
"""供本地 agent 直接调用的 macOS/Linux 单轮工具入口。"""

import argparse
import math
import os
from pathlib import Path
import platform
import stat
import sys
import time

from baseline import resumable_scan
import files
from files import canonical_path, compare, within
from events import read_events
import recheck
from observe import command, observe, sample_facts
from policy import (LIMIT_FIELDS, make_policy_evidence, new_root, policy_digest,
                    read_policy_with_evidence, root_paths, validate as validate_policy)
from state import PolicyChangedError, Store, StewardError, decode, encode, read_regular_bytes
from state_schema import read_current, read_operations

PROJECT = Path(__file__).resolve().parent.parent


def scan(progress, limits, roots, exclude_names=(), state_path=None, recheck=None):
    """patrol 的续扫入口；limits 保持第二个参数，便于核对本轮实际预算。"""
    return resumable_scan(progress, roots, limits, exclude_names, state_path, recheck)


def validate(policy):
    return validate_policy(policy)


def read_policy(directory):
    return read_policy_with_evidence(directory)[0]


def evidence_for(policy):
    return dict(getattr(policy, "policy_evidence", None) or make_policy_evidence(policy))


def refresh_policy_locked(store):
    policy = read_policy(store.path)
    store.limits = dict(policy["limits"])
    store.policy_evidence = evidence_for(policy)
    return policy


def ensure_policy_locked(store, expected):
    try:
        current = read_policy(store.path)
    except (StewardError, OSError) as exc:
        raise PolicyChangedError("执行前无法重新核对本机约定，旧计划未提交；请修复约定后重新运行") from exc
    expected_evidence = getattr(expected, "policy_evidence", None)
    current_evidence = getattr(current, "policy_evidence", None)
    expected_digest = policy_digest(expected)
    semantic_changed = (current_evidence is not None and current_evidence.get("policy_digest") != expected_digest)
    # 只有 expected 的证据确实对应当前语义时才比较原始字节；直接调用方可能持有旧证据。
    source_changed = (expected_evidence is not None and current_evidence is not None
                      and expected_evidence.get("policy_digest") == expected_digest
                      and expected_evidence.get("policy_source_digest") != current_evidence.get("policy_source_digest"))
    if current != expected or semantic_changed or source_changed:
        raise PolicyChangedError("本机约定在本轮执行期间变化，旧计划未提交；请重新运行")


def load(directory):
    policy = read_policy(directory)
    store = Store(directory, policy["limits"])
    store.policy_evidence = evidence_for(policy)
    return store, policy


def initialize(directory, roots, purpose, max_depth=32):
    if not Path(directory).is_absolute():
        raise StewardError("init --state 只接受绝对路径")
    if type(max_depth) is not int or max_depth < 0:
        raise StewardError("init --max-depth 必须是非负整数")
    resolved = []
    for root in roots:
        value = os.fspath(root)
        if not isinstance(value, str) or not value or "\x00" in value or not Path(value).is_absolute():
            raise StewardError("init --root 只接受已确认的绝对路径；不展开相对路径、波浪号或服务账户 home")
        target = canonical_path(value)
        if target is None:
            raise StewardError("观察根目录路径无效")
        try:
            info = os.lstat(target)
        except OSError as exc:
            raise StewardError(f"观察根目录无法访问：输入 {value}，实际目标 {target}；{exc}") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise StewardError(f"观察根目录必须是目录：输入 {value}，实际目标 {target}")
        resolved.append(target)
    for index, root in enumerate(resolved):
        for other in resolved[:index]:
            if os.path.samefile(root, other):
                raise StewardError(f"观察根目录不能是同一对象的 samefile 别名：{root} 与 {other}")
    policy = decode(read_regular_bytes(PROJECT / "state/host.example.json", 32768))
    if policy.get("version") != 2:
        raise StewardError("初始化模板必须使用 v2 配置")
    policy.update(purpose=purpose, roots=[new_root(root, max_depth) for root in resolved],
                  host={"system": platform.system(), "hostname": platform.node()})
    validate(policy)
    store = Store(directory, policy["limits"])
    if any(within(root, str(store.path)) for root in root_paths(policy)):
        raise StewardError("状态目录不能包含观察根目录")
    with store.lock():
        if any(path.name != ".lock" for path in store.path.iterdir()):
            raise StewardError("初始化仅接受空状态目录；已有记录或指导必须保留，请先核对恢复，不覆盖或重置")
        payloads = {"steward.sqlite3": store.empty_database_bytes()}
        for file in sorted((PROJECT / "guidance").rglob("*.md")):
            payloads["guidance/" + str(file.relative_to(PROJECT / "guidance"))] = read_regular_bytes(file, policy["limits"]["file_bytes"])
        payloads["adaptation.json"] = encode({"source_version": "0.2.0", "removed_sections": [],
                                              "reason": "保留通用说明；具体能力和权限以观测结果、本机约定为准"})
        payloads["host.json"] = encode(policy)
        if len(payloads["host.json"]) > min(32768, policy["limits"]["file_bytes"]):
            raise StewardError("初始化约定超过 host.json 或状态单文件预算")
        if any(len(payload) > policy["limits"]["file_bytes"]
               for name, payload in payloads.items() if name != "steward.sqlite3"):
            raise StewardError("初始化内容超过状态单文件预算")
        directories = sorted({parent for name in payloads for parent in Path(name).parents if parent != Path(".")},
                             key=lambda path: (len(path.parts), str(path)))
        if len(payloads) + len(directories) + 2 > 1024:
            raise StewardError("初始化对象数超过状态区上限")
        store.check_capacity(sum(map(len, payloads.values())) + max(map(len, payloads.values())))
        created, created_directories = {}, {}
        try:
            for relative in directories:
                target = store.target(relative)
                target.mkdir(mode=0o700)
                info = target.lstat()
                created_directories[str(relative)] = (info.st_dev, info.st_ino)
            for name, payload in payloads.items():
                store.write_bytes(name, payload, exclusive=True, created=created)
        except (OSError, StewardError) as exc:
            try:
                rollback_initialization(store, payloads, created, created_directories)
            except (OSError, StewardError) as rollback_error:
                raise StewardError(
                    f"初始化失败，回滚未完成，状态目录有残留；请逐项核对后再重试：{rollback_error}") from rollback_error
            raise StewardError("初始化失败，本次创建内容已回滚，未覆盖原有文件") from exc
    loaded, evidence = read_policy_with_evidence(store.path)
    store.policy_evidence = evidence
    return store, loaded


def rollback_initialization(store, payloads, created, directories):
    def remove_created(name):
        target = store.target(name)
        try:
            info = target.lstat()
        except FileNotFoundError:
            return
        observed = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        if not stat.S_ISREG(info.st_mode) or observed != created[name]:
            raise StewardError(f"初始化回滚停止，文件身份已变化：{target}")
        if read_regular_bytes(target, max(1, len(payloads[name]))) != payloads[name]:
            raise StewardError(f"初始化回滚停止，文件内容已变化：{target}")
        info = target.lstat()
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != created[name]:
            raise StewardError(f"初始化回滚停止，文件身份已变化：{target}")
        try:
            target.unlink()
        except OSError as exc:
            raise StewardError(f"初始化回滚停止，无法删除 {target}：{exc}") from exc

    try:
        store.target("host.json").lstat()
    except FileNotFoundError:
        pass
    else:
        if "host.json" not in created:
            raise StewardError("初始化回滚停止，host.json 不是本次创建的文件")
        remove_created("host.json")
    for name in reversed(created):
        if name != "host.json":
            remove_created(name)
    for relative in reversed(directories):
        try:
            target = store.target(relative)
            info = target.lstat()
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != directories[relative]:
                raise StewardError(f"初始化回滚停止，目录身份已变化：{target}")
            target.rmdir()
        except FileNotFoundError:
            pass


def event_since(previous, devices):
    old = previous.get("events", {})
    if not isinstance(old, dict):
        return None
    cursor = old.get("cursor")
    if old.get("devices") != devices or any(value is None for value in devices.values()):
        return None
    if type(cursor) is not int or cursor < 0:
        return None
    if "history_invalid" in old:
        if old["history_invalid"]:
            return None
    elif not old.get("history_complete") or old.get("rescan_required"):
        return None
    return cursor


def finalize_events(candidate, previous, snapshots, roots):
    if candidate.get("source") != "macos_fsevents":
        return candidate
    result = dict(candidate)
    complete = set(snapshots) == set(roots) and all(snapshot.get("complete") for snapshot in snapshots.values())
    history_ready = candidate.get("available") and not candidate.get("history_invalid") and (
        candidate.get("baseline") or candidate.get("history_complete"))
    if complete and history_ready and type(candidate.get("cursor")) is int:
        result["cursor_pending"] = False
        return result
    old = previous.get("events", {})
    old_cursor = old.get("cursor")
    same_devices = old.get("devices") == candidate.get("devices")
    result["history_invalid"] = bool(candidate.get("history_invalid") or old.get("history_invalid"))
    result["cursor"] = old_cursor if same_devices and type(old_cursor) is int and not old.get("history_invalid") else None
    result["cursor_pending"] = True
    return result


def event_rebuild_gap(events, previous):
    """已有事件游标后又回到基线模式时，说明监听需要重建。"""
    old = previous.get("events") or {}
    if events.get("source") == "macos_fsevents" and events.get("baseline") \
            and type(old.get("cursor")) is int:
        return {"kind": "events", "reason": "baseline_rebuild"}
    return None


def _event_reason(events):
    if not events.get("available"):
        return "unavailable"
    if events.get("history_invalid"):
        return "history_invalid"
    if events.get("cursor_pending"):
        return "cursor_pending"
    if not events.get("history_complete") and not events.get("baseline"):
        return "history_incomplete"
    return None


def event_gap(events):
    if events.get("source") != "macos_fsevents":
        return None
    reason = _event_reason(events)
    return {"kind": "events", "reason": reason} if reason else None


def _root_rules(policy):
    return [files._root_rule(configured, policy["limits"], policy.get("exclude_names", ()))
            for configured in policy["roots"]]


def apply_event_clues(state, policy, events, now, state_path=None, previous_events=None):
    """把本轮事件路径线索并入待复核队列；线索不直接生成变化。"""
    rules = _root_rules(policy)
    recheck.prune_roots(state, [rule["path"] for rule in rules])
    # source_truncated 描述本轮来源截断，不是队列状态；每轮重新计算。
    state["source_truncated"] = False
    if events.get("source") != "macos_fsevents":
        # 没有可核对的平台事件来源时，旧线索不能冒充当前事件覆盖。
        recheck.clear(state, "snapshot_only", now)
        return state
    if events.get("history_invalid"):
        # 系统已明确报告历史失效，过期游标对应的线索一并清除。
        recheck.clear(state, "history_invalid", now)
        return state
    if events.get("baseline"):
        old = previous_events or {}
        rebuilt = type(old.get("cursor")) is int
        recheck.clear(state, "baseline_rebuild" if rebuilt else None, now)
        return state
    paths = events.get("paths", [])
    if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):
        raise ValueError("原生事件 paths 必须是字符串数组")
    path_ids = events.get("path_ids")
    if path_ids is not None:
        if not isinstance(path_ids, list) or len(path_ids) != len(paths) or any(
                type(token) not in (int, float) or not math.isfinite(token) for token in path_ids):
            raise ValueError("原生事件 path_ids 必须与 paths 等长且为有限数值")
        event_ids = dict(zip(paths, path_ids))
    else:
        event_ids = events.get("event_ids", {})
        if not isinstance(event_ids, dict) or any(
                not isinstance(path, str) or type(token) not in (int, float) or not math.isfinite(token)
                for path, token in event_ids.items()):
            raise ValueError("原生事件 event_ids 必须是路径到有限数值的对象")
    if events.get("available"):
        for root, directories in recheck.event_targets(paths, rules, state_path, event_ids).items():
            for path, token in directories.items():
                recheck.add(state, root, path, now, token)
    if events.get("paths_truncated"):
        state["source_truncated"] = True
    return state


def degrade_event_clues(state, events, now, previous_events=None):
    if events.get("source") != "macos_fsevents":
        return state
    if events.get("history_invalid"):
        recheck.clear(state, "history_invalid", now)
        return state
    if not events.get("available"):
        reason = "unavailable"
    elif events.get("baseline"):
        old = previous_events or {}
        reason = "baseline_rebuild" if type(old.get("cursor")) is int else None
    else:
        reason = _event_reason(events)
    recheck.degrade(state, reason, now)
    return state


def consume_recheck(state, snapshots):
    """完整 pass 覆盖 root 全部范围；未完成 pass 只消费已复核子树。"""
    covered = {}
    for root, snapshot in snapshots.items():
        if snapshot.get("complete"):
            covered.setdefault(root, set()).add(root)
            continue
        info = snapshot.get("recheck")
        if isinstance(info, dict):
            values = set(info.get("targets", ())) | set(info.get("covered", ())) | set(info.get("skipped", ()))
            if values:
                covered[root] = values
    recheck.consume(state, covered)
    return covered


def native_events(policy, previous):
    roots = root_paths(policy)
    devices = {}
    for root in roots:
        try:
            info = os.stat(root)
            devices[root] = info.st_dev if stat.S_ISDIR(info.st_mode) else None
        except OSError:
            devices[root] = None
    since = event_since(previous, devices)
    if sys.platform == "darwin":
        try:
            text = command([sys.executable, str(PROJECT / "tools/events.py")], max_bytes=65536, timeout=3,
                           input_bytes=encode({"roots": roots, "since": since}))
        except (TimeoutError, StewardError, OSError) as exc:
            # 子进程失败或超时按“事件源不可用”记缺口，继续用快照全量核对。
            result = {"source": "macos_fsevents", "available": False,
                      "reason": f"原生事件读取失败：{exc}"[:300]}
        else:
            result = decode(text)
            if not isinstance(result, dict):
                raise ValueError("原生事件读取结果必须是对象")
    else:
        result = read_events(roots, since)
    result["devices"] = devices
    result["verification"] = "bounded metadata snapshots; native events are advisory"
    return result


PENDING_HISTORY_LIMIT = 32


def pending_items(current):
    # 旧溢出队列并入同一列表，保留事项内容；后续写入只保存 pending。
    return {row["key"]: row for field in ["pending", "pending_overflow"] for row in current.get(field, [])}


def update_pending(store, key, reason, resolve=False):
    if not isinstance(key, str) or not key or len(key.encode()) > 512:
        raise StewardError("待核验事项 key 无效或超过 512 字节")
    if not isinstance(reason, str) or not reason.strip() or len(reason.encode()) > 512:
        raise StewardError("事项说明需为 1–512 字节的非空文本")
    current = read_current(store)
    pending = pending_items(current)
    now = time.time()
    if resolve:
        row = pending.pop(key, None)
        if row is None:
            raise StewardError("未找到当前待核验事项；不重复写入解决历史")
    else:
        row = pending.get(key, {})
        pending[key] = dict(row, key=key, reason=reason, observed_at=now,
                            first_observed_at=row.get("first_observed_at", row.get("observed_at", now)))
    history = list(current.get("pending_history", []))
    if resolve:
        history.append(dict(row, status="resolved", resolved_at=now, resolution_reason=reason))
    dropped = current.get("pending_history_dropped", 0) + max(0, len(history) - PENDING_HISTORY_LIMIT)
    current.pop("pending_overflow", None)
    current.update(version=1, pending=list(pending.values()),
                   pending_history=history[-PENDING_HISTORY_LIMIT:], pending_history_dropped=dropped)
    store.write("current.json", current)
    return {"status": "resolved" if resolve else "tracked", "key": key,
            "pending_count": len(pending), "pending_history_dropped": dropped}


def preserve_incomplete_comparison_gaps(previous, snapshots, current_rows):
    rows = [dict(row, reasons=list(row["reasons"])) for row in current_rows]
    by_root = {row["root"]: row for row in rows}
    for old in previous.get("comparison_gaps", []):
        root = old.get("root")
        if root not in snapshots or snapshots[root]["complete"]:
            continue
        row = by_root.get(root)
        if row is None:
            row = dict(old, reasons=[])
            rows.append(row)
            by_root[root] = row
        for reason in old.get("reasons", []):
            if reason not in row["reasons"] and len(row["reasons"]) < 16:
                row["reasons"].append(reason)
    return rows


def patrol(store, policy, discard_scan_progress=False, discard_event_recheck=False):
    started, now = time.monotonic(), time.time()
    with store.lock():
        policy = refresh_policy_locked(store)
        evidence = store.policy_evidence
        roots = root_paths(policy)
        discarded = discarded_events = False
        if discard_scan_progress or discard_event_recheck:
            # 损坏的进度或队列无法通过常规校验，先在锁内整体读回、只移除目标字段再写回。
            if not store.capacity()["writable"]:
                raise StewardError(
                    "状态已到可写容量上限，无法清除续扫进度或待复核队列；用 status 查看 capacity 中的上限与余量，"
                    "核对采集范围、记录保留或本机 total_bytes 后重试")
            current = store.read("current.json", {})
            if not isinstance(current, dict):
                raise StewardError("current 数据集不是对象，不能只清除续扫进度或待复核队列；按恢复指导核对")
            changed = False
            if discard_scan_progress and "scan_progress" in current:
                current.pop("scan_progress")
                discarded = changed = True
            if discard_event_recheck and "event_recheck" in current:
                current.pop("event_recheck")
                discarded_events = changed = True
            if changed:
                store.write("current.json", current)
        previous = read_current(store)
        if not isinstance(previous, dict) or (previous and previous.get("version") != 1):
            raise StewardError("巡检状态格式或版本不符，保留原状态")
        if not store.capacity()["writable"]:
            raise StewardError(
                "状态已到可写容量上限，本轮先不观察；用 status 查看 capacity 中的上限与余量，"
                "核对采集范围、记录保留或本机 total_bytes 后重试")
        event_recheck = recheck.restore(previous.get("event_recheck"))
        old_evidence = (previous.get("last_run") or {}).get("policy_evidence") or {}
        if old_evidence.get("policy_digest") not in (None, evidence.get("policy_digest")):
            # 范围或预算改变后，旧路径线索不再代表当前观察范围，退回全量复核。
            recheck.clear(event_recheck, "policy_changed", now)
        events = native_events(policy, previous)
        event_recheck = apply_event_clues(event_recheck, policy, events, now, str(store.path),
                                          previous.get("events"))
        recheck_targets = recheck.targets(event_recheck, roots)
        host = observe(policy)
        observation_gaps = [{"kind": name, "reason": host[name].get("reason", "unavailable")}
                            for name in ["memory", "processes", "services"] if not host[name].get("available")]
        # 平台缺口（例如旧内核没有 MemAvailable）不是采集失败，也要进入 agent 的固定告警通道。
        for gap in (host.get("memory") or {}).get("platform_gaps") or []:
            observation_gaps.append({"kind": "memory", "field": gap.get("field"),
                                     "reason": gap.get("reason", "unavailable")})
        for item in host.get("storage", []):
            if not item.get("available"):
                observation_gaps.append({"kind": "storage", "root": item.get("path"),
                                         "reason": item.get("reason", "unavailable")})
        if events.get("source") == "macos_fsevents":
            for root, device in events.get("devices", {}).items():
                if device is None:
                    observation_gaps.append({"kind": "events", "root": root, "reason": "root_unavailable"})
        snapshots, scan_progress = scan(previous.get("scan_progress"), policy["limits"], policy["roots"],
                                        policy.get("exclude_names", ()), str(store.path), recheck_targets)
        events = finalize_events(events, previous, snapshots, roots)
        event_recheck = degrade_event_clues(event_recheck, events, now, previous.get("events"))
        # 先取本轮摘要：consume 会移除已覆盖条目，不能让它抹掉本轮线索截断信号。
        queue_summary = recheck.summary(event_recheck)
        consume_recheck(event_recheck, snapshots)
        gap = event_gap(events)
        if gap:
            observation_gaps.append(gap)
        rebuild = event_rebuild_gap(events, previous)
        if rebuild:
            observation_gaps.append(rebuild)
        for snapshot in snapshots.values():
            snapshot["measured_at"] = now
        baselines = {root: snapshot for root, snapshot in previous.get("baselines", {}).items() if root in roots}
        delta = compare(baselines, snapshots, policy["limits"]["change_records"])
        comparison_gaps = preserve_incomplete_comparison_gaps(previous, snapshots, delta["comparison_gaps"])
        coverage_scope = {}
        for root, snapshot in snapshots.items():
            coverage = {"scope": snapshot.get("scope"), "excluded": snapshot.get("excluded", {}),
                        "complete": snapshot["complete"]}
            if isinstance(snapshot.get("resumable"), dict):
                coverage["resumable"] = snapshot["resumable"]
            if root in recheck_targets or queue_summary["degraded"] is not None:
                info = snapshot.get("recheck") if isinstance(snapshot.get("recheck"), dict) else {}
                requested = info["requested"] if "requested" in info else len(recheck_targets.get(root, ()))
                covered = len(info.get("covered", ()))
                coverage["event_recheck"] = {
                    "requested": requested,
                    "covered": covered,
                    "pending": len(info.get("pending", ())) if "requested" in info
                    else max(0, requested - covered),
                    "skipped": len(info.get("skipped", ())),
                    "truncated": queue_summary["truncated"],
                    "source_truncated": queue_summary["source_truncated"],
                    "degraded": (queue_summary["degraded"] or {}).get("reason"),
                }
            coverage_scope[root] = coverage
        for root, snapshot in snapshots.items():
            if snapshot["complete"]:
                baselines[root] = snapshot
        changes = [dict(row, observed_at=now) for row in delta["changes"]]
        for change in changes:
            old_time = previous.get("baselines", {}).get(change["root"], {}).get("measured_at")
            duration = now - old_time if old_time is not None else None
            change["measurement_from"] = old_time
            change["measurement_to"] = now
            rate = None
            if duration and duration > 0 and not change.get("continuity_gap") and not change.get("migration_delta"):
                try:
                    rate = round(change["byte_delta"] / duration, 2)
                except (OverflowError, ValueError):
                    rate = None
                if rate is None or not math.isfinite(rate):
                    change["growth_rate_gap"] = "numeric_range"
                    rate = None
            change["average_growth_bytes_per_second"] = rate
        previous_changes = previous.get("changes", [])
        recent = [row for row in previous_changes
                  if now - row["observed_at"] <= policy["limits"]["retention_hours"] * 3600]
        expired = len(previous_changes) - len(recent)
        recent.extend(changes)
        dropped = max(0, len(recent) - policy["limits"]["change_records"])
        recent = recent[-policy["limits"]["change_records"]:]
        oldest = min((row["observed_at"] for row in recent), default=None)
        newest = max((row["observed_at"] for row in recent), default=None)
        change_retention = {"retention_hours": policy["limits"]["retention_hours"],
                            "record_limit": policy["limits"]["change_records"],
                            "expired_by_age": expired, "evicted_by_count": dropped,
                            "oldest_observed_at": oldest, "newest_observed_at": newest,
                            "span_hours": (newest - oldest) / 3600 if recent else None}
        samples = previous.get("samples", []) + [{"time": now,
                                                  "processes": [{key: row[key] for key in ["identity", "rss_bytes", "cpu_percent"]}
                                                                for row in host["processes"]["items"][:20]],
                                                  "host": sample_facts(host)}]
        samples = samples[-policy["limits"]["sample_records"]:]
        pending = list(pending_items(previous).values())
        history = list(previous.get("pending_history", []))
        history_dropped = previous.get("pending_history_dropped", 0) + max(0, len(history) - PENDING_HISTORY_LIMIT)
        history = history[-PENDING_HISTORY_LIMIT:]
        rules_by_path = {rule["path"]: rule for rule in policy["directory_rules"]}
        previous_index = {}
        for row in previous.get("directory_index", []):
            previous_index.setdefault(row["root"], []).append(row)
        directory_index = []
        for root, snapshot in snapshots.items():
            old_rows = previous_index.get(root, [])
            if not snapshot["complete"] and old_rows:
                directory_index.extend(dict(row, complete=False, stale=True) for row in old_rows)
                continue
            for path, row in snapshot["directories"].items():
                rule = rules_by_path.get(path)
                directory_index.append(dict(path=path, root=root, id=row["id"], bytes=row["bytes"],
                                            files=row["files"], directories=row["directories"], agents=row["agents"],
                                            purpose=rule["purpose"] if rule else "unknown", measured_at=now,
                                            complete=snapshot["complete"]))
        state = dict(previous)
        state.pop("pending_overflow", None)
        state.update({"version": 1, "last_run": {"observed_at": now, "elapsed_seconds": round(time.monotonic() - started, 3),
                      "coverage_complete": set(snapshots) == set(roots) and all(snapshot["complete"] for snapshot in snapshots.values()),
                      "policy_evidence": evidence, "state_bytes_before": store.usage()},
                      "host": host, "events": events, "baselines": baselines, "directory_index": directory_index,
                      "coverage_gaps": delta["gaps"], "comparison_gaps": comparison_gaps,
                      "coverage_scope": coverage_scope, "observation_gaps": observation_gaps,
                      "scan_progress": scan_progress, "event_recheck": event_recheck,
                      "changes": recent, "change_retention": change_retention, "change_records_dropped": dropped,
                      "samples": samples, "pending": pending,
                      "pending_history": history, "pending_history_dropped": history_dropped})
        ensure_policy_locked(store, policy)
        store.write("current.json", state)
        capacity = store.capacity()
        host_summary = {key: host[key] for key in
                        ["system", "architecture", "boot", "cpu", "memory", "gpu", "model_usage",
                         "storage", "diskio", "network", "power"] if key in host}
        network = host_summary.get("network")
        if isinstance(network, dict) and isinstance(network.get("interfaces"), dict) \
                and len(network["interfaces"].get("items", [])) > 6:
            ranked = sorted(network["interfaces"]["items"],
                            key=lambda row: row.get("ibytes", 0) + row.get("obytes", 0), reverse=True)
            host_summary["network"] = dict(
                network, interfaces=dict(network["interfaces"], items=ranked[:6], trimmed_for_report=True))
        overview = sorted(directory_index, key=lambda row: (-row["bytes"], row["path"]))[:12]
        report = {"status": "observed", "state": str(store.path), "last_run": state["last_run"],
                  "policy_version": policy["version"], "policy": policy, "policy_evidence": evidence,
                  "roots": policy["roots"],
                  "host": host_summary,
                  "processes": dict(host["processes"], items=host["processes"]["items"][:8]),
                  "services": dict(host["services"], items=host["services"]["items"][:12]),
                  "events": events, "directories": overview, "changes": changes, "gaps": delta["gaps"],
                  "comparison_gaps": comparison_gaps,
                  "observation_gaps": observation_gaps, "coverage_scope": coverage_scope,
                  "new_baselines": delta["new_baselines"], "pending": pending, "pending_history_dropped": history_dropped,
                  "change_retention": change_retention, "change_records_dropped": dropped,
                  "capacity": capacity, "state_bytes": capacity["state_bytes"],
                  "observations_changed": bool(changes or delta["gaps"] != previous.get("coverage_gaps", [])
                                               or comparison_gaps != previous.get("comparison_gaps", [])
                                               or observation_gaps != previous.get("observation_gaps", []) or delta["new_baselines"])}
        if discard_scan_progress:
            report["scan_progress_discarded"] = discarded
        if discard_event_recheck:
            report["event_recheck_discarded"] = discarded_events
        return report


def emit(value, limit=32768):
    payload = encode(value)
    if len(payload) > limit:
        payload = encode({"status": value.get("status", "output_limited"), "output_limited": True,
                          "message": "工具输出达到预算，完整输出未返回；请缩小查询范围或分页读取"})
    if len(payload) > limit:
        payload = b'{"output_limited":true}\n'
    sys.stdout.buffer.write(payload)


def load_readonly(directory):
    try:
        store, policy = load(directory)
    except (StewardError, OSError) as current_error:
        from policy import read_recorded_policy
        try:
            policy, evidence, run_id = read_recorded_policy(directory)
        except (StewardError, OSError) as history_error:
            raise history_error from current_error
        store = Store(directory, dict(policy["limits"]))
        store.policy_evidence = evidence
        causes, error = [], current_error
        while error is not None and len(causes) < 4:
            causes.append({"type": type(error).__name__, "message": str(error)[:1024]})
            error = error.__cause__
        context = {
            "policy_source": "last_valid_collector_run", "current_policy_valid": False,
            "current_policy_adopted": False, "current_policy_error": causes[0],
            "current_policy_error_chain": causes, "budget_run_id": run_id,
            "policy_note": "当前配置无效；仅按最后已验证运行的归档预算读取历史，不用于采集、升级或维护授权",
        }
    else:
        context = {"policy_source": "current_host_json", "current_policy_valid": True}
    context["query_policy_evidence"] = store.policy_evidence
    return store, policy, context


def collector_status_report(store, schema_version):
    if schema_version != 2:
        return {"status": "unavailable", "reason": "资源历史需要显式 upgrade 到 schema 2"}
    from sample_store import SampleStore
    result = SampleStore(store).status()
    for name in ("run", "latest_run", "active_run"):
        run = result.get(name)
        if isinstance(run, dict):
            result[name] = {key: run[key] for key in (
                "run_id", "mode", "started_at", "stopped_at", "stop_reason", "boot", "pid", "evidence") if key in run}
            result[name]["sampling"] = run.get("policy", {}).get("sampling")
    for source in result.get("sources", {}).values():
        for key in ("error", "last_error"):
            error = source.get(key)
            if isinstance(error, dict):
                source[key] = {name: str(error[name])[:512] for name in ("type", "message", "source") if name in error}
        source.pop("detail", None)
        if isinstance(source.get("reason"), str):
            source["reason"] = source["reason"][:512]
    return result


def status_report(store, policy, *, limit=20, offset=0, path=None):
    if not 1 <= limit <= 50 or offset < 0:
        raise StewardError("查询 limit 为 1–50，offset 不得为负数")
    current = read_current(store, fields=(
        "version", "last_run", "directory_index", "changes", "events", "coverage_scope",
        "coverage_gaps", "comparison_gaps", "observation_gaps", "change_retention",
        "pending", "pending_overflow", "pending_history", "pending_history_dropped",
        "event_recheck"))
    selected_path = canonical_path(path) if path is not None else None
    if path is not None and selected_path is None:
        raise StewardError("查询路径无效，无法归一为绝对路径")

    def matches_path(row):
        candidate = canonical_path(row["path"]) if selected_path else None
        return selected_path is None or bool(candidate and within(candidate, selected_path))

    directories = [row for row in current.get("directory_index", []) if matches_path(row)]
    changes = [row for row in current.get("changes", []) if matches_path(row)]
    pending = list(pending_items(current).values())
    scopes = {root: coverage for root, coverage in current.get("coverage_scope", {}).items()
              if selected_path is None or within(root, selected_path) or within(selected_path, root)}
    queue = recheck.restore(current.get("event_recheck"))
    queue_items = [item for item in queue["items"]
                   if selected_path is None or within(item["path"], selected_path)
                   or within(selected_path, item["path"])]
    event_recheck = {
        "limit": queue["limit"], "pending": len(queue_items), "truncated": queue["truncated"],
        "aggregated": queue["aggregated"], "dropped": queue["dropped"],
        "source_truncated": queue["source_truncated"], "degraded": queue["degraded"],
        "items": queue_items[offset:offset + limit],
    }
    capacity = store.capacity()
    storage = dict(store.database_info(), capacity=capacity)
    last_run = current.get("last_run")
    last_evidence = last_run.get("policy_evidence") if isinstance(last_run, dict) else None
    policy_matches = bool(last_evidence is not None and store.policy_evidence is not None
                          and last_evidence.get("policy_digest") == store.policy_evidence.get("policy_digest"))
    source_matches = bool(last_evidence is not None and store.policy_evidence is not None
                          and last_evidence.get("policy_source_digest") == store.policy_evidence.get("policy_source_digest"))
    return {
        "storage": storage, "last_run": last_run,
        "policy_version": policy["version"], "policy": policy, "policy_evidence": store.policy_evidence,
        "coverage_policy_evidence": last_evidence, "policy_matches_last_run": policy_matches,
        "policy_source_matches_last_run": source_matches,
        "coverage_note": "coverage_scope 来自上次成功提交的巡检，按 last_run.policy_evidence 解释；查询所用配置来源由 policy_source 标明。"
                        "本报告跨多个只读事务读取，是近似快照：并发提交时各字段可能来自相邻时点",
        "roots": policy["roots"],
        "coverage_scope": dict(sorted(scopes.items())[offset:offset + limit]),
        "coverage_scope_count": len(scopes), "pending": pending[offset:offset + limit],
        "pending_count": len(pending), "pending_history": current.get("pending_history", [])[-5:],
        "pending_history_count": len(current.get("pending_history", [])),
        "pending_history_dropped": current.get("pending_history_dropped", 0), "events": current.get("events"),
        "event_recheck": event_recheck, "event_recheck_count": len(queue_items),
        "observation_gaps": current.get("observation_gaps", []), "coverage_gaps": current.get("coverage_gaps", []),
        "comparison_gaps": current.get("comparison_gaps", []), "change_retention": current.get("change_retention"),
        "directory_count": len(directories), "change_count": len(changes),
        "directory_index": directories[offset:offset + limit], "recent_changes": changes[offset:offset + limit],
        "operations": read_operations(store)[-limit:], "state_bytes": capacity["state_bytes"],
        "collector": collector_status_report(store, storage["schema_version"]),
    }


def main():
    if sys.platform not in ["darwin", "linux"]:
        raise StewardError("当前工具仅支持 macOS 和 Linux")
    parser = argparse.ArgumentParser(description="Host Steward 0.2 — 有界巡检、本机档案与只读调查")
    commands = parser.add_subparsers(dest="action", required=True)
    init = commands.add_parser("init", help="建立本机约定；默认只读维护范围")
    init.add_argument("--state", required=True)
    init.add_argument("--root", action="append", required=True)
    init.add_argument("--max-depth", type=int, default=32)
    init.add_argument("--purpose", required=True)
    collector = commands.add_parser("collect", help="前台持续采集资源；由宿主管理进程生命周期")
    collector.add_argument("--state", required=True)
    collector.add_argument("--once", action="store_true", help="只采一批并退出，不等待下一周期")
    samples = commands.add_parser("samples", help="只读查询有界资源历史、进程和采集缺口")
    samples.add_argument("--state", required=True)
    samples.add_argument("--minutes", type=float, default=10)
    samples.add_argument("--since", type=float, help="固定窗口起点，Unix 秒")
    samples.add_argument("--until", type=float, help="固定窗口终点，Unix 秒")
    samples.add_argument("--limit", type=int, default=41)
    samples.add_argument("--before", type=int, help="排除该样本编号及之后记录；需同时提供 since/until")
    samples.add_argument("--process", help="精确进程 identity，不按 PID 拼接不同生命周期")
    samples.add_argument("--raw", action="store_true", help="保留本页完整原始事实与错误明细")
    samples.add_argument("--output", help="在状态区外独占创建本页完整 JSON；不受终端输出预算裁剪")
    check = commands.add_parser("check", help="列出或运行本机约定授权的自定义检查脚本")
    check.add_argument("--state", required=True)
    selection = check.add_mutually_exclusive_group()
    selection.add_argument("--name", help="运行指定名称的自定义检查")
    selection.add_argument("--all", action="store_true", help="在 scan_seconds 总预算内依次运行全部检查")
    for action in ["patrol", "note", "quarantine", "restore", "track", "resolve", "status", "inventory", "inspect",
                   "migrate", "export", "backup", "upgrade"]:
        child = commands.add_parser(action)
        child.add_argument("--state", required=True)
        if action in ["track", "resolve"]:
            child.add_argument("--key", required=True)
            child.add_argument("--reason", required=True)
        if action in ["note", "quarantine"]:
            child.add_argument("--path", required=True)
        if action == "restore":
            child.add_argument("--operation", required=True)
        if action in ["note", "quarantine", "restore", "migrate", "upgrade"]:
            child.add_argument("--apply", action="store_true", help="执行本机约定允许的已展示动作")
        if action == "upgrade":
            child.add_argument("--backup", help="升级执行前独占创建的状态区外绝对路径备份目录")
        if action == "export":
            child.add_argument("--dataset", choices=["current", "inventory", "operations"], required=True)
            child.add_argument("--output", help="独占创建 JSON 导出文件；省略时按输出预算返回")
        if action == "backup":
            child.add_argument("--output", required=True, help="在状态目录之外独占创建 SQLite 备份")
        if action == "patrol":
            child.add_argument("--quiet", action="store_true")
            child.add_argument("--discard-scan-progress", action="store_true",
                               help="在锁内清除损坏的续扫进度后重建（保留 baselines）")
            child.add_argument("--discard-event-recheck", action="store_true",
                               help="在锁内清除损坏的事件待复核队列后重建（保留 baselines 与续扫进度）")
        if action in ["status", "inventory"]:
            child.add_argument("--limit", type=int, default=20)
            child.add_argument("--offset", type=int, default=0)
        if action == "status":
            child.add_argument("--path", help="按目录范围查询索引和变化")
        if action == "inventory":
            selection = child.add_mutually_exclusive_group()
            selection.add_argument("--path", help="按目录范围查询，同时返回相关上级资源")
            selection.add_argument("--id", help="按稳定资源 id 直接读回")
            selection.add_argument("--record", help="登记或替换一份资源定义 JSON，只写本机档案")
        if action == "inspect":
            target = child.add_mutually_exclusive_group(required=True)
            target.add_argument("--id", help="调查已登记对象，并保存最新证据")
            target.add_argument("--path", help="只读调查观察 roots 内的文件或目录")
            target.add_argument("--service", help="明确 manager:scope/name，例如 launchd:user/com.example.job")
    args = parser.parse_args()
    if args.action == "init":
        store, policy = initialize(args.state, args.root, args.purpose, args.max_depth)
        resolution = [{"input": value, "path": root["path"]}
                      for value, root in zip(args.root, policy["roots"])]
        emit({"status": "initialized", "state": str(store.path), "roots": policy["roots"],
              "root_resolution": resolution, "max_depth": args.max_depth,
              "policy_version": policy["version"], "policy": policy,
              "policy_evidence": store.policy_evidence,
              "maintenance": "observation only until directory rules are explicitly configured"})
        return
    if args.action in ["status", "samples"]:
        store, policy, context = load_readonly(args.state)
        if args.action == "status":
            report = status_report(store, policy, limit=args.limit, offset=args.offset, path=args.path)
            report.update(context)
            limit_bytes = store.limits["output_bytes"]
            output_trimmed = len(encode(report)) > limit_bytes
            emit(report, limit_bytes)
            if output_trimmed:
                raise SystemExit(2)
            return
        from resource_query import fit_history_output, history_report
        if args.before is not None and (args.since is None or args.until is None):
            raise StewardError("samples --before 必须同时提供上一页返回的 --since 和 --until，避免分页窗口移动")
        report = history_report(
            store, minutes=args.minutes, since=args.since, until=args.until,
            limit=args.limit, before=args.before, process=args.process, raw=args.raw)
        report.setdefault("status", "resource_history")
        report.update(context)
        if args.output:
            from storage_tools import _output_path, _write_output
            path = _output_path(store, args.output)
            payload = encode(report)
            _write_output(path, payload)
            receipt = {"status": "resource_history_exported", "output": str(path), "bytes": len(payload),
                       "raw": args.raw, "window": report["window"], "raw_count": report["raw_count"],
                       "next_before": report.get("next_before"), **context}
            emit(receipt, store.limits["output_bytes"])
            return
        report = fit_history_output(report, store.limits["output_bytes"])
        emit(report, store.limits["output_bytes"])
        if (report.get("output_limited") or report.get("pagination_blocked_by_output")
                or report.get("status") == "output_limited"):
            raise SystemExit(2)
        return
    store, policy = load(args.state)
    if args.action == "check":
        from custom_checks import check_report

        def policy_guard():
            ensure_policy_locked(store, policy)

        report = check_report(policy, store.path, store.limits, name=args.name, run_all=args.all,
                              policy_guard=policy_guard)
        limit_bytes = store.limits["output_bytes"]
        output_trimmed = len(encode(report)) > limit_bytes
        emit(report, limit_bytes)
        if output_trimmed or (report["status"] == "custom_check_results" and not report["complete"]):
            raise SystemExit(2)
        return
    if args.action == "collect":
        from collector import collect
        report = collect(store, once=args.once, mode="once" if args.once else "continuous")
        emit(report, store.limits["output_bytes"])
        if report.get("status") in ["failed", "config_error", "deferred"]:
            raise SystemExit(2)
        return
    if args.action == "upgrade":
        from contextlib import nullcontext
        from storage_tools import upgrade_state
        lease = store.lock(".collector.lock") if args.apply else nullcontext()
        with lease, store.lock():
            policy = refresh_policy_locked(store)
            report = upgrade_state(store, policy, args.backup, args.apply,
                                   lambda: ensure_policy_locked(store, policy))
        emit(report, store.limits["output_bytes"])
        return
    if args.action == "patrol":
        report = patrol(store, policy, discard_scan_progress=args.discard_scan_progress,
                        discard_event_recheck=args.discard_event_recheck)
        if not args.quiet or report["observations_changed"] or args.discard_scan_progress \
                or args.discard_event_recheck:
            emit(report, store.limits["output_bytes"])
        return
    with store.lock():
        policy = refresh_policy_locked(store)

        def policy_guard():
            ensure_policy_locked(store, policy)

        if args.action in ["migrate", "export", "backup"]:
            from storage_tools import backup_database, export_dataset, migrate_json
            if args.action == "migrate":
                report = migrate_json(store, args.apply, policy_guard)
            elif args.action == "export":
                report = export_dataset(store, args.dataset, args.output)
            else:
                report = backup_database(store, args.output)
        elif args.action == "inventory":
            from inventory import query, read_definition, register
            report = register(store, read_definition(args.record)) if args.record else query(
                store, policy, args.id, args.path, args.limit, args.offset)
        elif args.action == "inspect":
            from investigate import inspect_target
            report = inspect_target(store, policy, args.id, args.path, args.service)
        elif args.action in ["track", "resolve"]:
            report = update_pending(store, args.key, args.reason, resolve=args.action == "resolve")
        elif args.action == "note":
            from maintain import annotate
            report = annotate(store, policy, args.path, args.apply, policy_guard)
        elif args.action == "quarantine":
            from maintain import quarantine
            report = quarantine(store, policy, args.path, args.apply, policy_guard)
        else:
            from maintain import restore
            report = restore(store, policy, args.operation, args.apply, policy_guard)
        emit(report, store.limits["output_bytes"])


if __name__ == "__main__":
    main()
