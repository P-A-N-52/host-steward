"""资源历史的有界摘要、连续性解释与输出分页。"""

import math
import time

from resource_changes import resource_changes
from sample_store import SampleStore
from state_io import StewardError, decode, encode


DEFAULT_HISTORY_LIMIT = 41
CONTEXT_BYTE_LIMIT = 4096
CONTEXT_TEXT_LIMIT = 512
CONTEXT_MAX_ITEMS = 16
CONTEXT_MAX_DEPTH = 4

_CONTEXT_PRIORITY = {
    "reason": 0, "type": 0, "kind": 0, "status": 0, "available": 0,
    "phase": 0, "run_id": 0, "sample_status": 0, "stop_reason": 0,
    "failed_sources": 1, "not_attempted_sources": 1, "dropped_intervals": 1,
    "last_success_at": 1, "observed_at": 1, "elapsed_seconds": 1,
    "previous_boot": 2, "current_boot": 2, "closed_by": 2, "recovered": 2,
    "source": 3, "source_errors": 3, "budget_exhausted": 3,
    "error": 4, "message": 5, "traceback": 6,
}


def _selected(value, keys):
    return {key: value[key] for key in keys if key in value} if isinstance(value, dict) else {}


def _clip_text(value, limit):
    """按 UTF-8 字节截断，并在文本中明确省略数量。"""
    if not isinstance(value, str):
        value = str(value)
    payload = value.encode("utf-8")
    if len(payload) <= limit:
        return value, False, 0
    marker = "\n... [省略 {} 字节] ...\n"
    reserve = len(marker.format(len(payload)).encode("utf-8"))
    allowance = max(0, limit - reserve)
    head_bytes = allowance // 2
    tail_bytes = allowance - head_bytes
    head = payload[:head_bytes].decode("utf-8", "ignore")
    tail = payload[-tail_bytes:].decode("utf-8", "ignore") if tail_bytes else ""
    omitted = len(payload) - len(head.encode("utf-8")) - len(tail.encode("utf-8"))
    return head + marker.format(omitted) + tail, True, omitted


def _spend(state, amount):
    state["remaining"] = max(0, state["remaining"] - max(0, amount))


def _context_order(item):
    return _CONTEXT_PRIORITY.get(item[0], 10)


def _context_text(value, state, text_limit):
    text, truncated, omitted = _clip_text(
        value, min(text_limit, max(0, state["remaining"] - 32)))
    if truncated:
        state["truncated"] = True
        text = text + f"（省略 {omitted} 字节）" if omitted and "省略" not in text else text
    _spend(state, len(text.encode("utf-8")) + 8)
    return text


def _context_value(value, *, depth, state, text_limit, max_items, max_depth):
    if value is None or isinstance(value, bool):
        _spend(state, 8)
        return value
    if isinstance(value, (int, float)):
        _spend(state, 16)
        return value
    if isinstance(value, str):
        return _context_text(value, state, text_limit)
    if depth >= max_depth:
        state["truncated"] = True
        _spend(state, 40)
        return f"... [省略 {type(value).__name__} 的嵌套内容] ..."
    if isinstance(value, list):
        result = []
        omitted = 0
        for position, item in enumerate(value):
            if position >= max_items or state["remaining"] <= 32:
                omitted = len(value) - position
                break
            remaining_items = len(value) - position
            share = max(64, state["remaining"] // remaining_items)
            child = {"remaining": min(share, state["remaining"]), "truncated": False}
            result.append(_context_value(item, depth=depth + 1, state=child,
                                         text_limit=text_limit, max_items=max_items,
                                         max_depth=max_depth))
            _spend(state, share - child["remaining"])
            state["truncated"] = state["truncated"] or child["truncated"]
        if omitted:
            marker = f"... [省略 {omitted} 项] ..."
            result.append(marker)
            state["truncated"] = True
            _spend(state, len(marker.encode("utf-8")) + 8)
        return result
    if isinstance(value, dict):
        result = {}
        omitted = 0
        items = sorted(value.items(), key=_context_order)
        for position, (key, item) in enumerate(items):
            if len(result) >= max_items or state["remaining"] <= 32:
                omitted = len(items) - position
                break
            remaining_items = len(items) - position
            share = max(64, state["remaining"] // remaining_items)
            child = {"remaining": min(share, state["remaining"]), "truncated": False}
            result[str(key)] = _context_value(item, depth=depth + 1, state=child,
                                              text_limit=text_limit, max_items=max_items,
                                              max_depth=max_depth)
            _spend(state, share - child["remaining"])
            state["truncated"] = state["truncated"] or child["truncated"]
        if omitted:
            result["_context_omitted_keys"] = omitted
            state["truncated"] = True
            _spend(state, 24)
        return result
    return _context_text(str(value), state, text_limit)


def _context_summary(value, *, byte_limit=CONTEXT_BYTE_LIMIT,
                     text_limit=CONTEXT_TEXT_LIMIT, max_items=CONTEXT_MAX_ITEMS,
                     max_depth=CONTEXT_MAX_DEPTH):
    """把任意来源明细压成有界上下文，保留原因、来源和恢复线索。"""
    if value is None:
        return None
    if type(byte_limit) is not int or byte_limit <= 0:
        byte_limit = CONTEXT_BYTE_LIMIT
    if type(text_limit) is not int or text_limit <= 0:
        text_limit = CONTEXT_TEXT_LIMIT
    if type(max_items) is not int or max_items <= 0:
        max_items = CONTEXT_MAX_ITEMS
    limits, current = [], byte_limit
    while current >= 64 and len(limits) < 5:
        if current not in limits:
            limits.append(current)
        next_limit = current // 2
        if next_limit < 64:
            break
        current = next_limit
    if byte_limit >= 64 and 64 not in limits:
        limits.append(64)
    for limit in limits:
        state = {"remaining": limit, "truncated": False}
        summary = _context_value(value, depth=0, state=state, text_limit=text_limit,
                                 max_items=max_items, max_depth=max_depth)
        if state["truncated"]:
            if isinstance(summary, dict):
                summary = dict(summary)
                summary["context_truncated"] = True
            else:
                summary = {"value": summary, "context_truncated": True}
        try:
            fits = len(encode(summary)) <= byte_limit
        except (TypeError, ValueError, OverflowError, RecursionError):
            fits = False
        if fits:
            return summary
    return {"context_truncated": True, "reason": "summary_over_budget"}


def _error_summary(value, limit=512):
    """错误记录保留类型、消息和来源；traceback 等长字段只标已省略。"""
    if value is None:
        return None
    if isinstance(value, dict):
        result = _selected(value, ("type", "kind", "message", "reason", "errno", "source"))
        result["detail_omitted"] = any(key not in result for key in value)
        for key, item in list(result.items()):
            if isinstance(item, str) and len(item.encode("utf-8")) > limit:
                item, _, _ = _clip_text(item, limit)
                result[key] = item
                result["text_truncated"] = True
        return result
    text, truncated, omitted = _clip_text(value, limit)
    result = {"message": text, "text_truncated": truncated}
    if omitted:
        result["omitted_bytes"] = omitted
    return result


def _source_summary(sources):
    result = {}
    for name, row in sources.items():
        if not isinstance(row, dict):
            result[name] = {"available": None, "current_available": None,
                            "reason": "source_status_invalid", "scope": "global_latest"}
            continue
        last_error = row.get("last_error")
        if last_error is None:
            last_error = row.get("error")
        bounded_error = _error_summary(last_error)
        item = _selected(row, ("available", "attempted_at", "success_at", "error_at",
                               "last_success_at", "last_error_at", "updated_at",
                               "reason", "source"))
        available = row.get("available")
        item.update({
            "current_available": available if type(available) is bool else None,
            "last_success": row.get("last_success_at", row.get("success_at")),
            "last_error": bounded_error,
            "current_error": bounded_error if available is False else None,
            "recovered": available is True and bounded_error is not None,
            "scope": "global_latest",
        })
        if available is True:
            item["status"] = "recovered" if bounded_error is not None else "available"
        elif available is False:
            item["status"] = "failed"
        else:
            item["status"] = "unknown"
        # 兼容旧字段，但只表示当前失败，不把恢复后的历史错误当现行错误。
        item["error"] = item["current_error"]
        result[name] = item
    return result


def _source_status_scope(sources):
    updated = [row.get("updated_at") for row in sources.values()
               if isinstance(row, dict) and type(row.get("updated_at")) in (int, float)
               and math.isfinite(row["updated_at"])]
    return {
        "scope": "global_latest",
        "window_independent": True,
        "as_of": max(updated) if updated else None,
        "note": "sources 是数据库中全局最新来源状态，不是查询窗口内每个样本的状态；"
                "current_available/current_error 表示当前状态，last_error 只是历史错误，"
                "恢复后不应据此判定当前失败",
    }


def _run_summary(run):
    if not isinstance(run, dict):
        return None
    result = _selected(run, ("run_id", "mode", "started_at", "stopped_at", "stop_reason", "pid", "boot", "evidence"))
    policy = run.get("policy")
    result["sampling"] = policy.get("sampling") if isinstance(policy, dict) else None
    return result


def _collector_summary(collector):
    if not isinstance(collector, dict):
        return collector
    result = {key: value for key, value in collector.items()
              if key not in {"run", "active_run", "latest_run"}}
    for name in ("run", "active_run", "latest_run"):
        if name in collector:
            result[name] = _run_summary(collector[name])
    state = result.get("state")
    if isinstance(state, dict):
        state = dict(state)
        if state.get("detail") is not None:
            state["detail"] = _context_summary(
                state["detail"], byte_limit=CONTEXT_BYTE_LIMIT,
                text_limit=CONTEXT_TEXT_LIMIT, max_items=CONTEXT_MAX_ITEMS)
            if isinstance(state["detail"], dict) and state["detail"].get("context_truncated"):
                state["detail_truncated"] = True
        result["state"] = state
    elif state is not None:
        result["state"] = _context_summary(state, byte_limit=1024, text_limit=256, max_items=8)
    if result.get("last_error") is not None:
        result["last_error"] = _context_summary(
            result["last_error"], byte_limit=1024, text_limit=256, max_items=8)
    result["state_scope"] = "全局最新采集状态；嵌套明细已按字节和元素预算摘要"
    return result


def _host_section(host, name):
    if not isinstance(host, dict) or name not in host:
        return None, {"available": None, "reason": "host_section_missing",
                      "source": name,
                      "summary": "样本没有该 host 子段，不能当作 available=True 或空统计"}
    value = host.get(name)
    if value is None:
        return None, {"available": None, "reason": "host_section_null",
                      "source": name,
                      "summary": "host 子段是显式 null，来源不可用或未知，不能伪造成功或空统计"}
    if not isinstance(value, dict):
        return None, {"available": None, "reason": "host_section_invalid",
                      "source": name, "value_type": type(value).__name__,
                      "summary": "host 子段不是对象，来源不可用或未知"}
    return value, None


def _host_summary(host):
    host = host if isinstance(host, dict) else {}
    result = {}

    cpu, base = _host_section(host, "cpu")
    result["cpu"] = base if base else _selected(
        cpu, ("available", "reason", "source", "cores", "load_average", "utilization", "counters", "hz"))

    memory, base = _host_section(host, "memory")
    if base:
        result["memory"] = base
    else:
        summary = _selected(memory, ("available", "reason", "source", "total_bytes",
                                     "available_bytes", "page_size", "swap"))
        counters = memory.get("counters")
        counters = counters if isinstance(counters, dict) else {}
        components = _selected(counters, ("Pages free", "Pages active", "Pages inactive",
                                          "Pages wired down", "Pages occupied by compressor",
                                          "Anonymous pages", "AnonPages", "Cached",
                                          "SReclaimable"))
        if components:
            summary["components"] = components
            summary["component_units"] = "vm_stat 保留页数，Linux kB 来源已换字节；不混合相加"
        result["memory"] = summary

    diskio, base = _host_section(host, "diskio")
    if base:
        result["diskio"] = dict(base, disks=None)
    else:
        summary = _selected(diskio, ("available", "reason", "source", "interval_seconds",
                                     "non_additive", "aggregation"))
        disks = diskio.get("disks", diskio.get("devices"))
        if isinstance(disks, list):
            summary["disks"] = [_selected(row, ("name", "identity", "major", "minor", "partition",
                                                "read_bytes", "write_bytes", "mb_per_second",
                                                "transfers_per_second"))
                               for row in disks]
        else:
            summary["disks"] = None
            summary["disks_reason"] = "object_list_missing"
        result["diskio"] = summary

    network, base = _host_section(host, "network")
    if base:
        result["network"] = dict(base, interfaces={
            "available": None, "reason": base["reason"], "items": None})
    else:
        summary = _selected(network, ("available", "reason", "source", "tcp_states"))
        interfaces = network.get("interfaces")
        if isinstance(interfaces, dict):
            interface_summary = _selected(interfaces, ("available", "reason", "truncated",
                                                       "partial", "complete", "observed",
                                                       "returned", "omitted", "limit"))
            items = interfaces.get("items")
            if isinstance(items, list):
                interface_summary["items"] = [_selected(row, ("name", "identity", "ifindex",
                                                              "ibytes", "obytes", "ipackets",
                                                              "opackets", "ierrs", "oerrs"))
                                              for row in items]
            else:
                interface_summary["items"] = None
                interface_summary["items_reason"] = "object_list_missing"
            summary["interfaces"] = interface_summary
        else:
            summary["interfaces"] = {"available": None, "reason": "interfaces_not_provided",
                                     "items": None}
        result["network"] = summary

    if "storage" in host:
        result["storage"] = host["storage"]
    return result


def _process_sample(sample, process=None):
    rows = sample.get("processes")
    if rows is None:
        return None
    items = [row.get("payload", row) for row in rows]
    meta = dict(sample.get("process_meta") or {})
    meta.update(items=items, observed_at=sample.get("process_observed_at"), loaded=True)
    if process is not None:
        meta["filtered"] = True
        meta["filter_identity"] = process
    return meta


def _process_view(sample, process):
    if process is None:
        return {"loaded": False, "items": None}
    section = _process_sample(sample, process)
    if section is None:
        return {"loaded": True, "items": None, "available": None,
                "reason": "process_snapshot_not_observed"}
    return section


def _range(values):
    values = [value for value in values if type(value) in (int, float) and math.isfinite(value)]
    return {"minimum": min(values), "maximum": max(values), "latest": values[-1]} if values else None


def _boundary_report(store, page, since, until, process, view):
    samples = page.get("samples") or []
    if not samples:
        return {"status": "no_samples", "change": None,
                "page_oldest_sample_id": None, "page_oldest_observed_at": None,
                "predecessor_sample_id": None, "predecessor_observed_at": None,
                "in_window": False, "included_in_samples": False,
                "included_in_cursor": False, "included_in_summary": False,
                "scope": "本页没有样本，未计算边界差分"}
    oldest = samples[-1]
    predecessor_page = store.query(since, until, limit=1,
                                   before=oldest["sample_id"], process=process)
    predecessor = predecessor_page["samples"][0] if predecessor_page["samples"] else None
    result = {
        "page_oldest_sample_id": oldest["sample_id"],
        "page_oldest_observed_at": oldest["observed_at"],
        "predecessor_sample_id": None,
        "predecessor_observed_at": None,
        "included_in_samples": False,
        "included_in_cursor": False,
        "included_in_summary": False,
        "scope": "只用于本页最老样本的边界差分；前驱不计入本页样本数量、游标或摘要统计",
    }
    if predecessor is None:
        status = "first_observation" if page["window"].get("before") is None \
            else "predecessor_not_available"
        result.update(status=status, in_window=False, change=None,
                      reason="查询窗口内没有更早的同条件样本，不能把窗口外差分当作窗口内变化")
        return result
    old = dict(predecessor, processes=view(predecessor))
    new = dict(oldest, processes=view(oldest))
    change = resource_changes(old, new, page["gaps"], page.get("gap_history"))
    predecessor_at = predecessor.get("observed_at")
    in_window = type(predecessor_at) in (int, float) and math.isfinite(predecessor_at) \
        and (since is None or predecessor_at >= since)
    result.update({
        "predecessor_sample_id": predecessor["sample_id"],
        "predecessor_observed_at": predecessor_at,
        "status": "computed" if in_window else "predecessor_outside_window",
        "in_window": in_window,
        "change": change,
    })
    if not in_window:
        result["reason"] = "前驱不在查询窗口内，只作边界线索，不能当作窗口内完整变化"
    return result


def history_report(store, *, minutes=10, since=None, until=None,
                   limit=DEFAULT_HISTORY_LIMIT, before=None, process=None, raw=False):
    if type(minutes) not in (int, float) or not math.isfinite(minutes) or minutes <= 0:
        raise StewardError("查询 minutes 必须是有限正数")
    until = time.time() if until is None else until
    since = until - minutes * 60 if since is None else since
    sample_store = SampleStore(store)
    page = sample_store.query(since, until, limit=limit, before=before, process=process)
    chronological = list(reversed(page["samples"]))
    changes = {}
    for previous, current in zip(chronological, chronological[1:]):
        previous = dict(previous, processes=_process_view(previous, process))
        current = dict(current, processes=_process_view(current, process))
        changes[current["sample_id"]] = resource_changes(
            previous, current, page["gaps"], page.get("gap_history"))
    discontinuities = [change for change in changes.values()
                       if not change["continuity"]["comparable"]]
    busy = []
    memory_values, swap_values = [], []
    for sample in chronological:
        host = sample.get("host") if isinstance(sample.get("host"), dict) else {}
        cpu = host.get("cpu")
        utilization = cpu.get("utilization") if isinstance(cpu, dict) else None
        utilization = utilization if isinstance(utilization, dict) else {}
        if utilization.get("available") and type(utilization.get("idle_percent")) in (int, float):
            busy.append(100 - utilization["idle_percent"])
        else:
            cpu_change = changes.get(sample["sample_id"], {}).get("cpu", {})
            if cpu_change.get("comparable"):
                busy.append(cpu_change["busy_percent"])
        memory = host.get("memory")
        if isinstance(memory, dict) and memory.get("available", True) is True:
            memory_values.append(memory.get("available_bytes"))
            swap = memory.get("swap")
            swap_values.append(swap.get("used_bytes") if isinstance(swap, dict) else None)
    boundary = _boundary_report(sample_store, page, since, until, process,
                                lambda sample: _process_view(sample, process))
    boundary_complete = boundary["status"] == "computed" and boundary["in_window"]
    summary = {
        "evaluated_samples": len(chronological),
        "observed_from": min((row["observed_at"] for row in chronological), default=None),
        "observed_to": max((row["observed_at"] for row in chronological), default=None),
        "cpu_busy_percent": _range(busy), "available_memory_bytes": _range(memory_values),
        "swap_used_bytes": _range(swap_values), "overlapping_gap_count": len(page["gaps"]),
        "discontinuity_count": len(discontinuities),
        "discontinuities": [{"from": row["from"], "to": row["to"],
                             "reasons": row["continuity"]["reasons"]}
                            for row in discontinuities[:16]],
        "discontinuities_omitted": max(0, len(discontinuities) - 16),
        "boundary_status": boundary["status"],
        "boundary_change_evaluated": boundary_complete,
        "boundary_discontinuity": bool(boundary_complete
                                       and not boundary["change"]["continuity"]["comparable"]),
        "scope": "summary 描述本次 SQL 页面内的已保存样本；边界前驱只用于 boundary 元数据，"
                 "不计入 evaluated_samples 或游标。时间范围不代表已连续采满",
    }
    source_scope = _source_status_scope(page["sources"])
    if raw:
        result = dict(page)
        result["boundary"] = boundary
        result["source_status_scope"] = source_scope
        result["evaluated_sample_count"] = len(page["samples"])
        result["raw_count"] = len(page["samples"])
        result["page"] = dict(result.get("page") or {}, evaluated=len(page["samples"]))
        result["summary"] = summary
        result["detail_scope"] = "原始来源明细；复杂字段仍保留原始结构"
        for point in result["samples"]:
            point["change_from_previous"] = changes.get(point["sample_id"])
        return result
    result = {key: value for key, value in page.items()
              if key not in {"samples", "sources", "collector"}}
    result["samples"] = [{
        "sample_id": row["sample_id"], "run_id": row["run_id"],
        "observed_at": row["observed_at"], "boot": row.get("boot"),
        "policy_evidence": row["run"]["evidence"],
        "host": _host_summary(row["host"]),
        "source_available": {key: value.get("available") if isinstance(value, dict) else None
                             for key, value in row["sources"].items()},
        "process_observed": row["process_observed"],
    } for row in page["samples"]]
    result["sources"] = _source_summary(page["sources"])
    result["source_status_scope"] = source_scope
    result["collector"] = _collector_summary(page["collector"])
    result["gaps"] = [dict(row, detail=_context_summary(
        row.get("detail"), byte_limit=1024, text_limit=256, max_items=12))
        for row in page["gaps"]]
    latest = dict(page["latest_processes"])
    latest["processes"] = [_selected(row, ("identity", "pid", "parent_pid", "started",
                                           "executable", "executable_status", "rss_bytes",
                                           "cpu_percent", "cpu_ticks", "hz", "protection"))
                           for row in latest["processes"]]
    if latest.get("meta") is not None:
        latest["meta"] = _context_summary(latest["meta"], byte_limit=1024,
                                          text_limit=256, max_items=12)
    latest.update(page_scoped=False, scope="global_latest_at_or_before_until",
                  as_of=page["window"].get("until"),
                  note="latest_processes 是截至 until 的全局最新进程快照，"
                       "不是本页样本或 before 旧页内的最新快照")
    result["latest_processes"] = latest
    result["boundary"] = boundary
    result["evaluated_sample_count"] = len(page["samples"])
    result["raw_count"] = len(page["samples"])
    result["page"] = dict(result.get("page") or {}, evaluated=len(page["samples"]))
    for point in result["samples"]:
        point["change_from_previous"] = changes.get(point["sample_id"])
    result.update(status="resource_history", summary=summary, raw=False,
                  detail_scope="gaps/collector/latest_processes 明细按字节与元素预算摘要；"
                               "原始来源明细用 --raw 分页查询或 --output 导出")
    return result


def _compact_output_details(result):
    """输出预算不足时先压缩非样本明细，保留运行状态、时间和 gap 原因。"""
    changed = False
    collector = result.get("collector")
    if isinstance(collector, dict):
        state = collector.get("state")
        if isinstance(state, dict) and state.get("detail") is not None:
            state["detail"] = _context_summary(state["detail"], byte_limit=512,
                                               text_limit=192, max_items=8)
            state["detail_truncated"] = True
            changed = True
        if collector.get("last_error") is not None:
            collector["last_error"] = _context_summary(
                collector["last_error"], byte_limit=512, text_limit=192, max_items=8)
            collector["last_error_truncated"] = True
            changed = True
    gaps = result.get("gaps")
    if isinstance(gaps, list):
        for gap in gaps:
            if isinstance(gap, dict) and gap.get("detail") is not None:
                gap["detail"] = _context_summary(gap["detail"], byte_limit=384,
                                                 text_limit=160, max_items=8)
                gap["detail_truncated"] = True
                changed = True
    latest = result.get("latest_processes")
    if isinstance(latest, dict) and latest.get("meta") is not None:
        latest["meta"] = _context_summary(latest["meta"], byte_limit=384,
                                          text_limit=160, max_items=8)
        latest["meta_truncated"] = True
        changed = True
    sources = result.get("sources")
    if isinstance(sources, dict):
        for item in sources.values():
            if not isinstance(item, dict):
                continue
            for key in ("last_error", "current_error", "error"):
                if item.get(key) is not None:
                    item[key] = _error_summary(item[key])
                    changed = True
    history = result.get("gap_history")
    if isinstance(history, dict):
        compact = _selected(history, ("retention_hours", "complete_since",
                                      "count_limit", "count_limited"))
        if compact != history:
            result["gap_history"] = compact
            result["gap_history_trimmed"] = True
            changed = True
    return changed


def _compact_boundary_change(result):
    boundary = result.get("boundary")
    if not isinstance(boundary, dict) or not isinstance(boundary.get("change"), dict):
        return False
    change = boundary["change"]
    compact = {}
    for key, value in change.items():
        if key in {"from", "to", "continuity"}:
            compact[key] = value
            continue
        if isinstance(value, dict):
            kept = _selected(value, ("comparable", "reason", "complete", "partial",
                                     "truncated", "interval_seconds", "busy_percent",
                                     "coverage", "semantics"))
            if isinstance(value.get("items"), list):
                kept["items_omitted"] = len(value["items"])
            if isinstance(value.get("gauge_delta"), dict):
                kept["gauge_delta"] = value["gauge_delta"]
            compact[key] = kept
        else:
            compact[key] = value
    boundary["change"] = compact
    boundary["change_trimmed"] = True
    return True


def _compact_for_output(result):
    """更紧的预算下压缩非样本结构，但保留运行状态、时间与 gap 原因。"""
    changed = False
    collector = result.get("collector")
    if isinstance(collector, dict):
        keep = _selected(collector, ("status", "status_reason", "now", "heartbeat_at",
                                     "heartbeat_age_seconds", "stale_after_seconds",
                                     "last_sample"))
        for name in ("run", "active_run", "latest_run"):
            run = collector.get(name)
            if run is not None:
                keep[name] = _selected(run, ("run_id", "mode", "started_at",
                                             "stopped_at", "stop_reason"))
        state = collector.get("state")
        if isinstance(state, dict):
            keep["state"] = _selected(state, ("run_id", "heartbeat_at", "last_complete_at",
                                              "stopped_at", "detail", "detail_truncated"))
        keep["output_trimmed"] = True
        result["collector"] = keep
        changed = True
    retention = result.get("retention")
    if isinstance(retention, dict):
        result["retention"] = _selected(retention, (
            "records", "records_limit", "retention_hours", "oldest_observed_at",
            "newest_observed_at", "span_seconds"))
        changed = True
    for key in ("database", "last_append"):
        if key in result:
            result.pop(key)
            changed = True
    if changed:
        result["output_metadata_trimmed"] = True
    gaps = result.get("gaps")
    if isinstance(gaps, list):
        result["gaps"] = [_selected(gap, ("gap_id", "run_id", "start_at", "end_at",
                                          "ongoing", "reason", "detail",
                                          "detail_truncated"))
                          if isinstance(gap, dict) else gap for gap in gaps]
        changed = True
    boundary = result.get("boundary")
    if isinstance(boundary, dict) and isinstance(boundary.get("change"), dict):
        change = boundary["change"]
        boundary["change"] = {"from": change.get("from"), "to": change.get("to"),
                              "continuity": change.get("continuity")}
        boundary["change_trimmed"] = True
        changed = True
    scope = result.get("source_status_scope")
    if isinstance(scope, dict):
        result["source_status_scope"] = _selected(
            scope, ("scope", "window_independent", "as_of"))
        changed = True
    if "detail_scope" in result:
        result["detail_scope"] = "输出预算内已裁剪；完整明细用 --output 导出"
        changed = True
    return changed


def _compact_sample_changes(result):
    changed = False
    for sample in result.get("samples") or []:
        change = sample.get("change_from_previous")
        if not isinstance(change, dict):
            continue
        compact = {}
        for key, value in change.items():
            if key in {"from", "to", "continuity"}:
                compact[key] = value
            elif isinstance(value, dict):
                kept = _selected(value, ("comparable", "reason", "complete", "partial",
                                         "truncated", "interval_seconds", "busy_percent",
                                         "gauge_delta"))
                if isinstance(value.get("items"), list):
                    kept["items_omitted"] = len(value["items"])
                compact[key] = kept
            else:
                compact[key] = value
        sample["change_from_previous"] = compact
        changed = True
    if changed:
        result["output_change_trimmed"] = True
    return changed


def fit_history_output(report, byte_limit):
    if type(byte_limit) is not int or byte_limit <= 0:
        raise StewardError("输出预算必须为正整数")
    # 报告本身是 JSON 值；一次编码往返比递归 deepcopy 更快，也留下独立副本。
    result = decode(encode(report))
    evaluated = len(report.get("samples") or [])
    if "evaluated_sample_count" not in result:
        result["evaluated_sample_count"] = evaluated
    if "raw_count" not in result:
        result["raw_count"] = evaluated
    if len(encode(result)) <= byte_limit:
        return result
    result["output_trimmed"] = True
    result["output_sample_omitted"] = result.get("output_sample_omitted", 0)
    details_changed = _compact_output_details(result)
    if details_changed:
        result["output_detail_trimmed"] = True
        size_exceeds = len(encode(result)) > byte_limit
    else:
        size_exceeds = True
    if size_exceeds:
        output_changed = _compact_for_output(result)
        if output_changed:
            size_exceeds = len(encode(result)) > byte_limit
    if size_exceeds:
        output_changed = _compact_sample_changes(result)
        if output_changed:
            size_exceeds = len(encode(result)) > byte_limit
    latest = result.get("latest_processes")
    if size_exceeds and isinstance(latest, dict) and isinstance(latest.get("processes"), list) \
            and latest["processes"]:
        original_processes = len(latest["processes"])
        while len(encode(result)) > byte_limit and latest["processes"]:
            latest["processes"].pop()
        if len(latest["processes"]) < original_processes:
            latest["output_omitted"] = original_processes - len(latest["processes"])
            latest["output_truncated"] = True
        size_exceeds = len(encode(result)) > byte_limit
    if size_exceeds and result.get("gaps"):
        original_gaps = len(result["gaps"])
        while len(encode(result)) > byte_limit and result.get("gaps"):
            result["gaps"].pop()
        if len(result["gaps"]) < original_gaps:
            result["output_gap_omitted"] = original_gaps - len(result["gaps"])
        size_exceeds = len(encode(result)) > byte_limit
    if size_exceeds and result.get("sources"):
        original_sources = len(result["sources"])
        while len(encode(result)) > byte_limit and result.get("sources"):
            result["sources"].pop(next(reversed(result["sources"])))
        if len(result["sources"]) < original_sources:
            result["output_source_omitted"] = original_sources - len(result["sources"])
        size_exceeds = len(encode(result)) > byte_limit
    if size_exceeds:
        if _compact_boundary_change(result):
            size_exceeds = len(encode(result)) > byte_limit
    def _apply_sample_trim(target):
        samples = target.get("samples") or []
        target["truncated"] = True
        target["raw_count"] = len(samples)
        page = dict(target.get("page") or {})
        page.update(returned=len(samples), truncated=True,
                    evaluated=target.get("evaluated_sample_count", evaluated))
        target["page"] = page
        summary = target.get("summary")
        if isinstance(summary, dict):
            summary = dict(summary)
            summary["output_samples"] = len(samples)
            target["summary"] = summary
        if samples:
            target["next_before"] = samples[-1]["sample_id"]
            target.pop("pagination_blocked_by_output", None)
        else:
            target["next_before"] = None
            target["pagination_blocked_by_output"] = True
            target["detail_scope"] = "本页样本未返回，游标未前进；用 --output 导出或提高输出预算"

    sample_count = len(result.get("samples") or [])
    sample_omitted = result["output_sample_omitted"]

    def _trimmed_candidate(keep, *, popped=True):
        candidate = dict(result)
        # 旧实现首次 pop 后 k>0 的 trim 会移除该键，k=0 时再追加到末尾。
        if popped and sample_count > 1:
            candidate.pop("pagination_blocked_by_output", None)
        if sample_count:
            candidate["samples"] = result["samples"][:keep]
        candidate["output_sample_omitted"] = sample_omitted + sample_count - keep
        _apply_sample_trim(candidate)
        return candidate

    fits = not size_exceeds
    if fits:
        if sample_omitted:
            result = _trimmed_candidate(sample_count, popped=False)
            fits = len(encode(result)) <= byte_limit
    elif sample_count:
        lower, upper = 0, sample_count - 1
        best = None
        while lower <= upper:
            middle = (lower + upper) // 2
            candidate = _trimmed_candidate(middle)
            if len(encode(candidate)) <= byte_limit:
                best = candidate
                lower = middle + 1
            else:
                upper = middle - 1
        if best is not None:
            result = best
            fits = True
        else:
            result = _trimmed_candidate(0)
            fits = len(encode(result)) <= byte_limit
    elif sample_omitted:
        result = _trimmed_candidate(0, popped=False)
        fits = len(encode(result)) <= byte_limit
    if not fits:
        result = {"status": "output_limited", "message": "输出预算不足，请用 --output 导出或缩小查询范围"}
        if len(encode(result)) > byte_limit:
            result = {"output_limited": True}
    return result
