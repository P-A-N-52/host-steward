#!/usr/bin/env python3
"""供本地 agent 直接调用的 macOS/Linux 单轮工具入口。"""

import argparse
import json
import math
import os
from pathlib import Path
import platform
import stat
import sys
import time

from files import canonical_path, compare, is_canonical_path, scan, within
from inventory import query, read_definition, register
from investigate import inspect_target
from maintain import annotate, quarantine, restore
from observe import command, observe, sample_facts
from state import PolicyChangedError, Store, StewardError, decode, encode, read_regular_bytes
from state_schema import read_current, read_operations

PROJECT = Path(__file__).resolve().parent.parent

# 预算键集契约：模板 state/host.example.json 只提供 init 默认值，运行期校验以此常量为准
LIMIT_FIELDS = frozenset([
    "scan_entries", "scan_seconds", "scan_depth", "processes", "command_bytes",
    "file_bytes", "total_bytes", "output_bytes", "change_records", "sample_records",
    "operation_records", "retention_hours"])


def validate(policy):
    if not isinstance(policy, dict) or type(policy.get("version")) is not int or policy["version"] != 1 or not isinstance(policy.get("purpose"), str):
        raise StewardError("本机约定版本或用途无效")
    limits = policy.get("limits", {})
    if not isinstance(limits, dict) or any(type(value) is not int or value <= 0 for value in limits.values()):
        raise StewardError("预算字段必须完整，且为正整数")
    missing = sorted(LIMIT_FIELDS - set(limits))
    unknown = sorted(str(key) for key in set(limits) - LIMIT_FIELDS)
    if missing or unknown:
        detail = "；".join(part for part in (f"缺失 {'、'.join(missing)}" if missing else "",
                                             f"未知 {'、'.join(unknown)}" if unknown else "") if part)
        raise StewardError(f"预算字段必须完整，且为正整数；{detail}")
    if limits["scan_entries"] > 10000 or limits["scan_seconds"] > 30 or limits["scan_depth"] > 64:
        raise StewardError("demo 扫描上限为 10000 项、30 秒、64 层")
    if limits["file_bytes"] > 8 * 1024**2 or limits["total_bytes"] > 64 * 1024**2:
        raise StewardError("demo 状态上限为单文件 8 MiB、总计 64 MiB")
    if limits["processes"] > 500 or limits["command_bytes"] > 1024**2 or limits["output_bytes"] > 1024**2:
        raise StewardError("demo 进程或命令输出预算过大")
    if limits["output_bytes"] < 256 or limits["file_bytes"] < 1024:
        raise StewardError("工具输出至少需要 256 字节、状态单文件至少需要 1 KiB")
    if any(limits[key] > 256 for key in ["change_records", "sample_records", "operation_records"]):
        raise StewardError("demo 各类历史记录最多 256 条")
    roots = policy.get("roots", [])
    if not isinstance(roots, list) or not roots or len(roots) > 8 or not all(isinstance(root, str) for root in roots) or len(roots) != len(set(roots)):
        raise StewardError("请明确指定 1–8 个不重叠的观察目录")
    for root in roots:
        if not is_canonical_path(root):
            raise StewardError("观察目录必须是规范的绝对路径")
        if any(root != other and within(root, other) for other in roots):
            raise StewardError("观察目录不能相互包含")
    if not isinstance(policy.get("exclude_names"), list) or not isinstance(policy.get("residents"), list):
        raise StewardError("排除项和常驻清单格式无效")
    if any(not isinstance(name, str) or not name or name in {".", ".."} or "/" in name or "\x00" in name
           for name in policy["exclude_names"]):
        raise StewardError("排除项必须是非空单层文件名")
    if len(policy["residents"]) > 64:
        raise StewardError("demo 常驻约定最多 64 项")
    for resident in policy["residents"]:
        if not isinstance(resident, dict) or not isinstance(resident.get("executable"), str) or not isinstance(resident.get("reason"), str):
            raise StewardError("常驻约定需包含 executable 和 reason")
    if not isinstance(policy.get("directory_rules"), list) or len(policy["directory_rules"]) > 64:
        raise StewardError("目录约定格式或数量无效")
    rule_paths = set()
    for rule in policy["directory_rules"]:
        if not isinstance(rule, dict) or not is_canonical_path(rule.get("path")) or not any(within(rule["path"], root) for root in roots):
            raise StewardError("目录约定必须是规范绝对路径且位于观察范围内")
        if rule["path"] in rule_paths:
            raise StewardError("同一规范路径不能重复配置目录约定")
        rule_paths.add(rule["path"])
        if any(key in rule and type(rule[key]) is not bool for key in ["allow_notes", "allow_quarantine"]):
            raise StewardError("维护授权字段必须为布尔值")
        kind = rule.get("kind")
        if not isinstance(kind, str) or not kind.strip() or len(kind.encode()) > 64 or not isinstance(rule.get("purpose"), str):
            raise StewardError("目录约定需包含明确类别与用途")
        if "retention_days" in rule and (type(rule["retention_days"]) is not int or rule["retention_days"] < 0):
            raise StewardError("保留天数无效")
        if rule.get("allow_quarantine") and (type(rule.get("recycle_bytes")) is not int or rule["recycle_bytes"] <= 0):
            raise StewardError("允许回收的目录必须设置正整数 recycle_bytes")
    return policy


def read_policy(directory):
    path = Path(directory).absolute() / "host.json"
    try:
        content = read_regular_bytes(path, 32768)
    except FileNotFoundError as exc:
        raise StewardError("缺少本机约定；仅新建空状态目录可 init，已有状态请先恢复原 host.json，不要重新初始化") from exc
    except OSError as exc:
        raise StewardError("无法读取本机约定，保留状态并停止执行") from exc
    try:
        policy = validate(decode(content))
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise StewardError("本机约定格式错误，保留原文件") from exc
    if policy.get("host") != {"system": platform.system(), "hostname": platform.node()}:
        raise StewardError("本机约定的主机标识与当前环境不符，停止执行")
    return policy


def refresh_policy_locked(store):
    policy = read_policy(store.path)
    store.limits = dict(policy["limits"])
    return policy


def ensure_policy_locked(store, expected):
    try:
        current = read_policy(store.path)
    except (StewardError, OSError) as exc:
        raise PolicyChangedError("执行前无法重新核对本机约定，旧计划未提交；请修复约定后重新运行") from exc
    if current != expected:
        raise PolicyChangedError("本机约定在本轮执行期间变化，旧计划未提交；请重新运行")


def load(directory):
    policy = read_policy(directory)
    return Store(directory, policy["limits"]), policy


def initialize(directory, roots, purpose):
    policy = decode(read_regular_bytes(PROJECT / "state/host.example.json", 32768))
    resolved = [canonical_path(root) for root in roots]
    if any(root is None for root in resolved):
        raise StewardError("观察根目录路径无效")
    policy.update(purpose=purpose, roots=resolved,
                  host={"system": platform.system(), "hostname": platform.node()})
    validate(policy)
    store = Store(directory, policy["limits"])
    if str(store.path) in policy["roots"]:
        raise StewardError("状态目录不能本身作为观察根目录")
    with store.lock():
        if any(path.name != ".lock" for path in store.path.iterdir()):
            raise StewardError("初始化仅接受空状态目录；已有记录或指导必须保留，请先核对恢复，不覆盖或重置")
        payloads = {"steward.sqlite3": store.empty_database_bytes()}
        for file in sorted((PROJECT / "guidance").rglob("*.md")):
            payloads["guidance/" + str(file.relative_to(PROJECT / "guidance"))] = read_regular_bytes(file, policy["limits"]["file_bytes"])
        payloads["adaptation.json"] = encode({"source_version": "0.2.0-demo", "removed_sections": [],
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
            residual = rollback_initialization(store, payloads, created, created_directories)
            detail = ("存在残留或变更内容，请人工核对，不要重新初始化：" + ", ".join(residual[:8])) if residual else "本次创建内容已回滚，未覆盖原有文件"
            raise StewardError(f"初始化失败；{detail}；{exc}") from exc
    return store, policy


def rollback_initialization(store, payloads, created, directories):
    def remove_created(name):
        try:
            target = store.target(name)
            info = target.lstat()
            observed = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            if not stat.S_ISREG(info.st_mode) or observed != created[name]:
                return False
            if read_regular_bytes(target, max(1, len(payloads[name]))) != payloads[name]:
                return False
            info = target.lstat()
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != created[name]:
                return False
            target.unlink()
            return True
        except FileNotFoundError:
            return True
        except (OSError, StewardError):
            return False

    try:
        store.target("host.json").lstat()
    except FileNotFoundError:
        pass
    except (OSError, StewardError):
        return ["host.json"]
    else:
        if "host.json" not in created or not remove_created("host.json"):
            return ["host.json"]
    residual = [name for name in reversed(created) if name != "host.json" and not remove_created(name)]
    for relative in reversed(directories):
        try:
            target = store.target(relative)
            info = target.lstat()
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != directories[relative]:
                residual.append(relative)
                continue
            target.rmdir()
        except FileNotFoundError:
            pass
        except (OSError, StewardError):
            residual.append(relative)
    return residual


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
        result["retry_count"] = 0
        return result
    old = previous.get("events", {})
    if not isinstance(old, dict):
        old = {}
    old_cursor = old.get("cursor")
    same_devices = old.get("devices") == candidate.get("devices")
    retries = old.get("retry_count", 0)
    retries = retries if type(retries) is int else 0
    result["retry_count"] = 0 if candidate.get("baseline") else retries + 1
    result["history_invalid"] = bool(candidate.get("history_invalid") or old.get("history_invalid"))
    result["cursor"] = old_cursor if same_devices and type(old_cursor) is int and not old.get("history_invalid") else None
    if result["retry_count"] >= 3:
        result["cursor"] = None
        result["history_invalid"] = True
    result["cursor_pending"] = True
    return result


def event_gap(events):
    if events.get("source") != "macos_fsevents":
        return None
    if not events.get("available"):
        return {"kind": "events", "reason": "unavailable"}
    if events.get("history_invalid"):
        return {"kind": "events", "reason": "history_invalid"}
    if events.get("cursor_pending"):
        return {"kind": "events", "reason": "cursor_pending"}
    if not events.get("history_complete") and not events.get("baseline"):
        return {"kind": "events", "reason": "history_incomplete"}
    return None


def native_events(policy, previous):
    devices = {}
    for root in policy["roots"]:
        try:
            devices[root] = os.stat(root).st_dev
        except OSError:
            devices[root] = None
    since = event_since(previous, devices)
    response = command([sys.executable, str(PROJECT / "tools/events.py")], max_bytes=8192, timeout=3,
                       input_bytes=encode({"roots": policy["roots"], "since": since}))
    try:
        result = json.loads(response["text"]) if response["ok"] else {"available": False, "reason": response["reason"]}
        if not isinstance(result, dict):
            raise ValueError("event result is not an object")
    except (ValueError, TypeError):
        result = {"available": False, "reason": "原生事件读取未返回有效结果"}
    result.setdefault("source", "macos_fsevents" if sys.platform == "darwin" else "metadata_snapshot")
    result.setdefault("baseline", since is None)
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


def patrol(store, policy):
    started, now = time.monotonic(), time.time()
    with store.lock():
        policy = refresh_policy_locked(store)
        previous = read_current(store)
        if not isinstance(previous, dict) or (previous and previous.get("version") != 1):
            raise StewardError("巡检状态格式或版本不符，保留原状态")
        if not store.capacity()["writable"]:
            raise StewardError(
                "状态已到可写容量上限，本轮先不观察；用 status 查看 capacity 中的上限与余量，"
                "核对采集范围、记录保留或本机 total_bytes 后重试")
        events = native_events(policy, previous)
        host = observe(policy)
        observation_gaps = [{"kind": name, "reason": host[name].get("reason", "unavailable")}
                            for name in ["memory", "processes", "services"] if not host[name].get("available")]
        snapshots = scan(policy["roots"], policy["limits"], policy["exclude_names"], str(store.path))
        events = finalize_events(events, previous, snapshots, policy["roots"])
        gap = event_gap(events)
        if gap:
            observation_gaps.append(gap)
        for snapshot in snapshots.values():
            snapshot["measured_at"] = now
        baselines = {root: snapshot for root, snapshot in previous.get("baselines", {}).items() if root in policy["roots"]}
        delta = compare(baselines, snapshots, policy["limits"]["change_records"])
        coverage_scope = {root: {"scope": snapshot.get("scope"), "excluded": snapshot.get("excluded", {}),
                                 "complete": snapshot["complete"]} for root, snapshot in snapshots.items()}
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
                except OverflowError:
                    change["growth_rate_gap"] = "numeric_range"
                if rate is not None and not math.isfinite(rate):
                    change["growth_rate_gap"] = "numeric_range"
                    rate = None
            change["average_growth_bytes_per_second"] = rate
        recent = [row for row in previous.get("changes", [])
                  if now - row["observed_at"] <= policy["limits"]["retention_hours"] * 3600] + changes
        dropped = max(0, len(recent) - policy["limits"]["change_records"])
        # 被条数上限挤掉的记录都还在保留期内（recent 已按 retention_hours 过滤），
        # 所以 dropped 非零即表示条数上限挤走了窗口内的记录。
        truncated_by_count = dropped > 0
        recent = recent[-policy["limits"]["change_records"]:]
        # 实际可用窗口：条数上限先于时间上限生效时，声明的 retention_hours 达不到。
        window_hours = policy["limits"]["retention_hours"]
        if recent:
            observed = [row["observed_at"] for row in recent]
            window_hours = round((max(observed) - min(observed)) / 3600, 2)
        changes_window = {"hours": window_hours,
                          "declared_hours": policy["limits"]["retention_hours"],
                          "truncated_by_count": truncated_by_count}
        samples = previous.get("samples", []) + [{"time": now,
                                                  "processes": [{key: row[key] for key in ["identity", "rss_bytes", "cpu_percent"]}
                                                                for row in host["processes"]["items"][:20]],
                                                  "host": sample_facts(host)}]
        samples = samples[-policy["limits"]["sample_records"]:]
        pending = list(pending_items(previous).values())
        history = list(previous.get("pending_history", []))
        history_dropped = previous.get("pending_history_dropped", 0) + max(0, len(history) - PENDING_HISTORY_LIMIT)
        history = history[-PENDING_HISTORY_LIMIT:]
        directory_index = []
        for root, snapshot in snapshots.items():
            old_rows = [row for row in previous.get("directory_index", []) if row["root"] == root]
            if not snapshot["complete"] and old_rows:
                directory_index.extend(dict(row, complete=False, stale=True) for row in old_rows)
                continue
            for path, row in snapshot["directories"].items():
                rule = next((rule for rule in policy["directory_rules"] if rule["path"] == path), None)
                directory_index.append(dict(path=path, root=root, id=row["id"], bytes=row["bytes"],
                                            files=row["files"], directories=row["directories"], agents=row["agents"],
                                            purpose=rule["purpose"] if rule else "unknown", measured_at=now,
                                            complete=snapshot["complete"]))
        state = dict(previous)
        state.pop("pending_overflow", None)
        state.update({"version": 1, "last_run": {"observed_at": now, "elapsed_seconds": round(time.monotonic() - started, 3),
                      "coverage_complete": set(snapshots) == set(policy["roots"]) and all(snapshot["complete"] for snapshot in snapshots.values()),
                      "state_bytes_before": store.usage()},
                      "host": host, "events": events, "baselines": baselines, "directory_index": directory_index,
                      "coverage_gaps": delta["gaps"], "coverage_scope": coverage_scope, "observation_gaps": observation_gaps,
                      "changes": recent, "change_records_dropped": dropped, "changes_window": changes_window,
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
        return {"status": "observed", "state": str(store.path), "last_run": state["last_run"],
                "host": host_summary,
                "processes": dict(host["processes"], items=host["processes"]["items"][:8]),
                "services": dict(host["services"], items=host["services"]["items"][:12]),
                "events": events, "directories": overview, "changes": changes, "gaps": delta["gaps"],
                "observation_gaps": observation_gaps, "coverage_scope": coverage_scope,
                "new_baselines": delta["new_baselines"], "pending": pending, "pending_history_dropped": history_dropped,
                "change_records_dropped": dropped, "changes_window": changes_window,
                "capacity": capacity, "state_bytes": capacity["state_bytes"],
                "observations_changed": bool(changes or delta["gaps"] != previous.get("coverage_gaps", [])
                                             or observation_gaps != previous.get("observation_gaps", []) or delta["new_baselines"])}


def emit(value, limit=32768):
    payload = encode(value)
    if len(payload) > limit:
        payload = encode({"status": value.get("status", "output_limited"), "output_limited": True,
                          "message": "工具输出达到预算，完整输出未返回；请缩小查询范围或分页读取"})
    if len(payload) > limit:
        payload = b'{"output_limited":true}\n'
    sys.stdout.buffer.write(payload)


def main():
    if sys.platform not in ["darwin", "linux"]:
        raise StewardError("当前工具仅支持 macOS 和 Linux")
    parser = argparse.ArgumentParser(description="Host Steward 0.2 — 有界巡检、本机档案与只读调查")
    commands = parser.add_subparsers(dest="action", required=True)
    init = commands.add_parser("init", help="建立本机约定；默认只读维护范围")
    init.add_argument("--state", required=True)
    init.add_argument("--root", action="append", required=True)
    init.add_argument("--purpose", required=True)
    for action in ["patrol", "note", "quarantine", "restore", "track", "resolve", "status", "inventory", "inspect",
                   "migrate", "export", "backup"]:
        child = commands.add_parser(action)
        child.add_argument("--state", required=True)
        if action in ["track", "resolve"]:
            child.add_argument("--key", required=True)
            child.add_argument("--reason", required=True)
        if action in ["note", "quarantine"]:
            child.add_argument("--path", required=True)
        if action == "restore":
            child.add_argument("--operation", required=True)
        if action in ["note", "quarantine", "restore", "migrate"]:
            child.add_argument("--apply", action="store_true", help="执行本机约定允许的已展示动作")
        if action == "export":
            child.add_argument("--dataset", choices=["current", "inventory", "operations"], required=True)
            child.add_argument("--output", help="独占创建 JSON 导出文件；省略时按输出预算返回")
        if action == "backup":
            child.add_argument("--output", required=True, help="在状态目录之外独占创建 SQLite 备份")
        if action == "patrol":
            child.add_argument("--quiet", action="store_true")
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
    demo_parser = commands.add_parser("demo", help="在空目录内运行样例并生成中文报告")
    demo_parser.add_argument("--workspace", default=str(PROJECT / ".demo"))
    args = parser.parse_args()
    if args.action == "demo":
        from demo import run_demo
        emit(run_demo(args.workspace))
        return
    if args.action == "init":
        store, policy = initialize(args.state, args.root, args.purpose)
        emit({"status": "initialized", "state": str(store.path), "roots": policy["roots"],
              "maintenance": "observation only until directory rules are explicitly configured"})
        return
    store, policy = load(args.state)
    if args.action == "patrol":
        report = patrol(store, policy)
        if not args.quiet or report["observations_changed"]:
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
            report = register(store, read_definition(args.record)) if args.record else query(
                store, policy, args.id, args.path, args.limit, args.offset)
        elif args.action == "inspect":
            report = inspect_target(store, policy, args.id, args.path, args.service)
        elif args.action == "status":
            if not 1 <= args.limit <= 50 or args.offset < 0:
                raise StewardError("查询 limit 为 1–50，offset 不得为负数")
            current = read_current(store)
            path = canonical_path(args.path) if args.path is not None else None
            if args.path is not None and path is None:
                raise StewardError("查询路径无效，无法归一为绝对路径")

            def matches_path(row):
                candidate = canonical_path(row["path"]) if path else None
                return path is None or bool(candidate and within(candidate, path))

            directories = [row for row in current.get("directory_index", []) if matches_path(row)]
            changes = [row for row in current.get("changes", []) if matches_path(row)]
            pending = list(pending_items(current).values())
            scopes = {root: coverage for root, coverage in current.get("coverage_scope", {}).items()
                      if path is None or within(root, path) or within(path, root)}
            capacity = store.capacity()
            storage = dict(store.database_info(), capacity=capacity)
            report = {"storage": storage, "last_run": current.get("last_run"),
                      "coverage_scope": dict(sorted(scopes.items())[args.offset:args.offset + args.limit]),
                      "coverage_scope_count": len(scopes), "pending": pending[args.offset:args.offset + args.limit],
                      "pending_count": len(pending),
                      "pending_history": current.get("pending_history", [])[-5:],
                      "pending_history_count": len(current.get("pending_history", [])),
                      "pending_history_dropped": current.get("pending_history_dropped", 0), "events": current.get("events"),
                      "observation_gaps": current.get("observation_gaps", []), "coverage_gaps": current.get("coverage_gaps", []),
                      "directory_count": len(directories), "change_count": len(changes),
                      "directory_index": directories[args.offset:args.offset + args.limit],
                      "recent_changes": changes[args.offset:args.offset + args.limit],
                      "operations": read_operations(store)[-args.limit:], "state_bytes": capacity["state_bytes"]}
        elif args.action in ["track", "resolve"]:
            report = update_pending(store, args.key, args.reason, resolve=args.action == "resolve")
        elif args.action == "note":
            report = annotate(store, policy, args.path, args.apply, policy_guard)
        elif args.action == "quarantine":
            report = quarantine(store, policy, args.path, args.apply, policy_guard)
        else:
            report = restore(store, policy, args.operation, args.apply, policy_guard)
        emit(report, store.limits["output_bytes"])


if __name__ == "__main__":
    try:
        main()
    except (StewardError, OSError, ValueError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, ensure_ascii=False), file=sys.stderr)
        sys.exit(2)
