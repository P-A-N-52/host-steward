"""相邻资源样本的可比性与累计计数器差分。"""

import math


def _number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _boot_identity(value):
    if isinstance(value, dict):
        if value.get("available") is False:
            return None
        for key in ("boot_id", "id", "unix_time", "boot_time"):
            if value.get(key) is not None:
                return key, value[key]
        return None
    return value


def _available(value):
    return isinstance(value, dict) and value.get("available", True) is True


def _unavailable(reason):
    return {"comparable": False, "reason": reason}


def _counter_delta(before, after, fields):
    if any(not _number(before.get(key)) or not _number(after.get(key)) for key in fields):
        return None, "counter_missing"
    if any(before[key] < 0 or after[key] < before[key] for key in fields):
        return None, "counter_reset"
    return {key: after[key] - before[key] for key in fields}, None


def _continuity(before, after, gaps):
    reasons = []
    if not before.get("run_id") or before.get("run_id") != after.get("run_id"):
        reasons.append("run_changed")
    old_boot, new_boot = _boot_identity(before.get("boot")), _boot_identity(after.get("boot"))
    if old_boot is None or new_boot is None:
        reasons.append("boot_identity_missing")
    elif old_boot != new_boot:
        reasons.append("host_reboot")
    start, end = before.get("observed_at"), after.get("observed_at")
    mono_start, mono_end = before.get("monotonic_at"), after.get("monotonic_at")
    interval = None
    if not all(_number(value) for value in (start, end, mono_start, mono_end)):
        reasons.append("timestamp_missing")
    else:
        interval = mono_end - mono_start
        if interval <= 0 or end <= start:
            reasons.append("time_not_increasing")
        elif abs((end - start) - interval) > max(1.0, interval * 0.05):
            reasons.append("clock_jump")
        for gap in gaps:
            gap_start, gap_end = gap.get("start_at"), gap.get("end_at")
            if _number(gap_start) and gap_start < end and (gap_end is None or (_number(gap_end) and gap_end > start)):
                reasons.append("collection_gap")
                break
    return {"comparable": not reasons, "reasons": reasons, "interval_seconds": interval}


def _cpu(before, after, interval):
    if not _available(before) or not _available(after):
        return _unavailable("source_unavailable")
    old, new = before.get("counters"), after.get("counters")
    if not isinstance(old, dict) or not isinstance(new, dict):
        return _unavailable("instantaneous_measurement")
    fields = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
    delta, reason = _counter_delta(old, new, fields)
    if reason:
        return _unavailable(reason)
    total = sum(delta.values())
    if total <= 0:
        return _unavailable("counter_not_advanced")
    hz = after.get("hz")
    seconds = {key: value / hz for key, value in delta.items()} if _number(hz) and hz > 0 and hz == before.get("hz") else None
    return {"comparable": True, "counter_delta": delta,
            "percent": {key: round(value * 100 / total, 4) for key, value in delta.items()},
            "busy_percent": round((total - delta["idle"] - delta["iowait"]) * 100 / total, 4),
            "cpu_seconds": seconds, "interval_seconds": interval,
            "semantics": "累计 CPU 计数器差分；busy 不含 idle 与 iowait，guest 不重复叠加"}


def _count(value):
    return value if type(value) is int and value >= 0 else None


def _coverage(value):
    """描述一个对象列表能否代表完整集合；不能代表时明确为有界快照。"""
    if isinstance(value, list):
        return {"available": True, "complete": True, "partial": False,
                "truncated": False, "observed": len(value), "returned": len(value),
                "limit": None, "reason": None, "filtered": False, "loaded": True}
    if not isinstance(value, dict):
        return {"available": None, "complete": False, "partial": False,
                "truncated": False, "observed": None, "returned": None,
                "limit": None, "reason": "source_unavailable", "filtered": False,
                "loaded": None}
    available = value.get("available")
    if type(available) is not bool:
        available = True if "available" not in value else None
    truncated = value.get("truncated") is True
    partial = value.get("partial") is True
    complete_value = value.get("complete")
    complete = complete_value if type(complete_value) is bool else True
    complete = complete and not truncated and not partial
    if value.get("loaded") is False:
        complete = False
    reason = value.get("reason") if isinstance(value.get("reason"), str) else None
    return {"available": available, "complete": complete, "partial": partial,
            "truncated": truncated, "observed": _count(value.get("observed")),
            "returned": _count(value.get("returned")),
            "limit": _count(value.get("limit")), "reason": reason,
            "filtered": value.get("filtered") is True,
            "loaded": value.get("loaded") is not False}


def _device_rows(section, kind):
    if not _available(section):
        return None, _coverage(section)
    if kind == "network":
        interfaces = section.get("interfaces")
        if not _available(interfaces):
            coverage = _coverage(interfaces)
            coverage["reason"] = coverage.get("reason") or "interface_list_unavailable"
            return None, coverage
        rows = interfaces.get("items")
        if not isinstance(rows, list):
            coverage = _coverage(interfaces)
            coverage["complete"] = False
            coverage["reason"] = "object_list_missing"
            return None, coverage
        coverage = _coverage(interfaces)
        top = _coverage(section)
        coverage["truncated"] = coverage["truncated"] or top["truncated"]
        coverage["partial"] = coverage["partial"] or top["partial"]
        coverage["complete"] = coverage["complete"] and top["complete"]
        return rows, coverage
    rows = section.get("disks", section.get("devices"))
    if not isinstance(rows, list):
        coverage = _coverage(section)
        coverage["complete"] = False
        coverage["reason"] = "object_list_missing"
        return None, coverage
    return rows, _coverage(section)


def _devices(before, after, kind, interval):
    old_rows, old_coverage = _device_rows(before, kind)
    new_rows, new_coverage = _device_rows(after, kind)
    if old_rows is None or new_rows is None:
        return {"items": [], "comparable": False, "reason": "source_unavailable",
                "complete": False,
                "partial": old_coverage["partial"] or new_coverage["partial"],
                "truncated": old_coverage["truncated"] or new_coverage["truncated"],
                "coverage": {"before": old_coverage, "after": new_coverage}}
    old = {row["name"]: row for row in old_rows}
    new = {row["name"]: row for row in new_rows}
    fields = ("ibytes", "obytes", "ipackets", "opackets", "ierrs", "oerrs") if kind == "network" else ("read_bytes", "write_bytes")
    complete = old_coverage["complete"] and new_coverage["complete"]
    result = []
    for name in sorted(old.keys() | new.keys()):
        if name not in old or name not in new:
            if complete:
                reason = "object_added" if name not in old else "object_not_observed"
            else:
                reason = "entered_bounded_snapshot" if name not in old else "left_bounded_snapshot"
            result.append(dict(name=name, comparable=False, reason=reason,
                               coverage_complete=complete, bounded_snapshot=not complete))
            continue
        a, b = old[name], new[name]
        identity_fields = ("identity", "major", "minor", "ifindex", "generation")
        if any(a.get(key) != b.get(key) for key in identity_fields):
            result.append(dict(name=name, **_unavailable("object_identity_changed")))
            continue
        delta, reason = _counter_delta(a, b, fields)
        if reason:
            if kind == "diskio" and "mb_per_second" in b:
                reason = "instantaneous_measurement"
            result.append(dict(name=name, **_unavailable(reason)))
            continue
        lifecycle_fields = ("identity", "generation", "ifindex") if kind == "network" else ("identity", "generation")
        if not any(a.get(key) is not None and b.get(key) is not None for key in lifecycle_fields):
            result.append(dict(name=name, **_unavailable("object_identity_missing")))
            continue
        row = {"name": name, "comparable": True, "counter_delta": delta,
               "per_second": {key: round(value / interval, 4) for key, value in delta.items()},
               "coverage_complete": complete}
        if not complete:
            row["bounded_snapshot"] = True
        result.append(row)
    return {"items": result, "comparable": True, "interval_seconds": interval,
            "complete": complete, "partial": old_coverage["partial"] or new_coverage["partial"],
            "truncated": old_coverage["truncated"] or new_coverage["truncated"],
            "coverage": {"before": old_coverage, "after": new_coverage},
            "semantics": "逐对象计数器差分；设备、分区、虚拟设备或接口之间不求和；"
                         "有界 topN 中缺失的对象只表示未出现在该快照，不表示新增或退出"}


def _memory(before, after):
    if not _available(before) or not _available(after):
        return _unavailable("source_unavailable")
    keys = ("total_bytes", "available_bytes")
    delta = {key: after[key] - before[key] for key in keys
             if _number(before.get(key)) and _number(after.get(key))}
    old_swap, new_swap = before.get("swap"), after.get("swap")
    if _available(old_swap) and _available(new_swap) and _number(old_swap.get("used_bytes")) and _number(new_swap.get("used_bytes")):
        delta["swap_used_bytes"] = new_swap["used_bytes"] - old_swap["used_bytes"]
    return {"comparable": bool(delta), "gauge_delta": delta,
            "semantics": "内存与 swap 当前量的时点差，不是累计事件速率"}


def _processes(before, after, interval):
    if before is None or after is None:
        return {"comparable": False, "reason": "process_snapshot_not_observed", "items": []}
    if (isinstance(before, dict) and before.get("loaded") is False) \
            or (isinstance(after, dict) and after.get("loaded") is False):
        return {"comparable": False, "reason": "process_changes_not_loaded", "items": [],
                "loaded": False,
                "semantics": "本次查询没有加载进程行，不能据此推断进程启动或退出；"
                             "需要进程差分时用 --process 精确过滤下钻"}
    for section in (before, after):
        if isinstance(section, dict) and not _available(section):
            before_coverage, after_coverage = _coverage(before), _coverage(after)
            return {"comparable": False, "reason": "source_unavailable", "items": [],
                    "complete": False,
                    "partial": before_coverage["partial"] or after_coverage["partial"],
                    "truncated": before_coverage["truncated"] or after_coverage["truncated"],
                    "coverage": {"before": before_coverage, "after": after_coverage}}
    if isinstance(before, dict) and isinstance(after, dict):
        start, end = before.get("observed_at"), after.get("observed_at")
        if _number(start) and _number(end):
            interval = end - start
        if interval <= 0:
            return {"comparable": False, "reason": "process_snapshot_not_advanced", "items": []}
    old_rows = before.get("items", before.get("processes", [])) if isinstance(before, dict) else before
    new_rows = after.get("items", after.get("processes", [])) if isinstance(after, dict) else after
    old_coverage, new_coverage = _coverage(before), _coverage(after)
    missing_list = False
    for section, coverage in ((before, old_coverage), (after, new_coverage)):
        if isinstance(section, dict) and "items" not in section and "processes" not in section:
            coverage["complete"] = False
            coverage["reason"] = coverage.get("reason") or "process_list_missing"
            missing_list = True
    if not isinstance(old_rows, list) or not isinstance(new_rows, list) or missing_list:
        return {"comparable": False, "reason": "process_snapshot_incomplete", "items": [],
                "coverage": {"before": old_coverage, "after": new_coverage}}
    old = {row["identity"]: row for row in old_rows}
    new = {row["identity"]: row for row in new_rows}
    complete = old_coverage["complete"] and new_coverage["complete"]
    rows = []
    for identity in sorted(old.keys() | new.keys()):
        if identity not in old or identity not in new:
            if complete:
                reason = "process_added" if identity not in old else "process_not_observed"
            else:
                reason = "entered_bounded_snapshot" if identity not in old else "left_bounded_snapshot"
            rows.append(dict(identity=identity, comparable=False, reason=reason,
                             coverage_complete=complete, bounded_snapshot=not complete))
            continue
        a, b = old[identity], new[identity]
        row = {"identity": identity, "comparable": True,
               "coverage_complete": complete}
        if not complete:
            row["bounded_snapshot"] = True
        if _number(a.get("rss_bytes")) and _number(b.get("rss_bytes")):
            row["rss_bytes_delta"] = b["rss_bytes"] - a["rss_bytes"]
        hz = b.get("hz")
        old_ticks, new_ticks = a.get("cpu_ticks"), b.get("cpu_ticks")
        old_ticks = old_ticks.get("total") if isinstance(old_ticks, dict) else old_ticks
        new_ticks = new_ticks.get("total") if isinstance(new_ticks, dict) else new_ticks
        delta, reason = _counter_delta({"cpu_ticks": old_ticks}, {"cpu_ticks": new_ticks}, ("cpu_ticks",))
        if not reason and _number(hz) and hz > 0 and a.get("hz") == hz:
            row["interval_cpu_percent"] = round(delta["cpu_ticks"] / hz / interval * 100, 4)
        else:
            row["interval_cpu_percent"] = None
            row["cpu_gap"] = reason or "counter_unit_changed"
        rows.append(row)
    return {"comparable": True, "items": rows, "interval_seconds": interval,
            "complete": complete, "partial": old_coverage["partial"] or new_coverage["partial"],
            "truncated": old_coverage["truncated"] or new_coverage["truncated"],
            "filtered": old_coverage["filtered"] or new_coverage["filtered"],
            "coverage": {"before": old_coverage, "after": new_coverage},
            "semantics": "同一身份的 RSS 时点差；CPU 为累计 ticks 差分，100% 表示一个核心；"
                         "不完整 topN/部分枚举只比较重叠身份，缺失对象不推断启动或退出"}


def resource_changes(before, after, gaps=()):
    continuity = _continuity(before, after, gaps)
    result = {"from": before.get("observed_at"), "to": after.get("observed_at"), "continuity": continuity}
    if not continuity["comparable"]:
        return result
    old = before.get("host")
    new = after.get("host")
    old = old if isinstance(old, dict) else {}
    new = new if isinstance(new, dict) else {}
    interval = continuity["interval_seconds"]
    result.update(cpu=_cpu(old.get("cpu"), new.get("cpu"), interval),
                  memory=_memory(old.get("memory"), new.get("memory")),
                  diskio=_devices(old.get("diskio"), new.get("diskio"), "diskio", interval),
                  network=_devices(old.get("network"), new.get("network"), "network", interval),
                  processes=_processes(before.get("processes"), after.get("processes"), interval))
    return result
