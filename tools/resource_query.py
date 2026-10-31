"""资源历史的有界摘要、连续性解释与输出分页。"""

import math
import time

from resource_changes import resource_changes
from sample_store import MAX_QUERY_LIMIT, SampleStore
from state_io import StewardError, decode, encode


DEFAULT_HISTORY_LIMIT = 41
MAX_HISTORY_LIMIT = MAX_QUERY_LIMIT
# 新增字段不升版本；只有破坏性变更才升 version。
RESOURCE_HISTORY_CONTRACT = {"name": "host-steward.resource_history", "version": 1}
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


def _memory_projection(memory, counters):
    """投影非字节计数与平台缺口；平台没有这些字段时不输出空噪音。"""
    summary = {}
    units = memory.get("units")
    if isinstance(units, dict):
        non_byte = sorted((str(key), value) for key, value in units.items()
                          if value != "bytes")
        selected = non_byte[:CONTEXT_MAX_ITEMS]
        omitted = len(non_byte) - len(selected)
        if selected:
            source_units = memory.get("source_units")
            source_units = source_units if isinstance(source_units, dict) else {}
            summary["non_byte_units"] = {
                key: {"units": value, "source_units": source_units.get(key)}
                for key, value in selected}
            summary["non_byte_counters"] = {
                key: counters.get(key) for key, _ in selected}
            if omitted:
                summary["non_byte_units_omitted"] = omitted
                summary["non_byte_counters_omitted"] = omitted
    reason = memory.get("available_reason")
    if reason is not None:
        summary["available_reason"] = _clip_text(reason, 512)[0]
    gaps = memory.get("platform_gaps")
    if isinstance(gaps, list) and gaps:
        items = []
        for row in gaps[:8]:
            if isinstance(row, dict):
                item = _selected(row, ("field", "reason", "source"))
                for key, value in list(item.items()):
                    if isinstance(value, str):
                        item[key] = _clip_text(value, 256)[0]
                items.append(item)
            else:
                items.append(_clip_text(str(row), 256)[0])
        summary["platform_gaps"] = items
        if len(gaps) > 8:
            summary["platform_gaps_omitted"] = len(gaps) - 8
    return summary


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
            units = memory.get("units")
            if isinstance(units, dict) and units:
                summary["component_units"] = (
                    "components 均为已换算的 bytes 口径；其余 counters 的单位见 non_byte_units，"
                    "HugePages_* 为无单位计数")
            else:
                summary["component_units"] = "vm_stat 保留页数；不混合相加"
        summary.update(_memory_projection(memory, counters))
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
    if type(limit) is not int or not 1 <= limit <= MAX_HISTORY_LIMIT:
        raise StewardError(
            f"samples --limit 必须是 1–{MAX_HISTORY_LIMIT} 的整数（默认 {DEFAULT_HISTORY_LIMIT}）；"
            f"超过 {MAX_HISTORY_LIMIT} 不会静默截断，请用 --before 沿固定窗口分页")
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
        result["contract"] = dict(RESOURCE_HISTORY_CONTRACT)
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
    result.update(status="resource_history", contract=dict(RESOURCE_HISTORY_CONTRACT),
                  summary=summary, raw=False,
                  detail_scope="gaps/collector/latest_processes 明细按字节与元素预算摘要；"
                               "原始来源明细用 --raw 分页查询或 --output 导出")
    return result


DEFAULT_CHANGES_MINUTES = 60
DEFAULT_MAX_CHANGES = 200
MAX_CHANGES_LIMIT = 10000
CHANGE_TRACE_LIMIT = 16
CHANGE_RESOURCES = ("cpu", "memory", "diskio", "network", "sources")
# 新增字段不升版本；只有破坏性变更才升 version。
RESOURCE_CHANGES_CONTRACT = {"name": "host-steward.resource_changes", "version": 1}
_CPU_COUNTERS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
_DEVICE_UNITS = {
    "diskio": {"read_bytes": "bytes", "write_bytes": "bytes",
               "mb_per_second": "mb_per_second", "transfers_per_second": "per_second",
               "kb_per_transfer": "kb"},
    "network": {"ibytes": "bytes", "obytes": "bytes", "ipackets": "count",
                "opackets": "count", "ierrs": "count", "oerrs": "count"},
}
_DEVICE_IDENTITY_FIELDS = frozenset({"name", "identity", "major", "minor",
                                     "ifindex", "generation"})


def _change_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _change_resources(values):
    if values is None:
        return tuple(CHANGE_RESOURCES)
    selected = []
    for value in values:
        for item in str(value).split(","):
            item = item.strip()
            if not item:
                continue
            if item not in CHANGE_RESOURCES:
                raise StewardError("changes --resource 只接受 " + "、".join(CHANGE_RESOURCES)
                                   + "；可重复传入或用逗号分隔")
            if item not in selected:
                selected.append(item)
    return tuple(selected) or tuple(CHANGE_RESOURCES)


def _available_flag(section):
    if not isinstance(section, dict):
        return None
    value = section.get("available")
    return value if type(value) is bool else None


def _coverage_flags(section, kind):
    """只投影会改变“这个列表能否代表完整集合”的字段。"""
    if not isinstance(section, dict):
        return None
    layers = [section]
    if kind == "network" and isinstance(section.get("interfaces"), dict):
        layers.append(section["interfaces"])
    flags = {}
    for key in ("complete", "partial", "truncated", "observed", "returned", "limit"):
        for layer in layers:
            if key in layer:
                flags[key] = layer[key]
    return flags or None


def _trace_point(sample, value):
    return {"sample_id": sample["sample_id"], "observed_at": sample["observed_at"],
            "run_id": sample.get("run_id"), "value": value}


def _bounded_points(points, limit=CHANGE_TRACE_LIMIT):
    if len(points) <= limit:
        return points, 0
    head = (limit + 1) // 2
    tail = limit - head
    return points[:head] + (points[-tail:] if tail else []), len(points) - limit


def _unique_run_ids(samples):
    values = []
    for sample in samples:
        run_id = sample.get("run_id")
        if run_id and run_id not in values:
            values.append(run_id)
    return values


def _value_observation(resource, path, unit, before, after, *, counter=False):
    delta, reason = None, None
    if _change_number(before) and _change_number(after):
        delta = after - before
        changed = delta != 0
        if counter and delta < 0:
            reason, delta = "counter_reset", None
    else:
        changed = before != after
    return {"resource": resource, "path": path, "kind": "value_change", "unit": unit,
            "before": before, "after": after, "delta": delta,
            "counter": counter, "changed": changed, "reason": reason}


def _discrete_descriptor(resource, path, kind, *, before=None, after=None, unit=None,
                         reason=None, object_name=None):
    return {"resource": resource, "path": path, "kind": kind, "unit": unit,
            "before": before, "after": after, "delta": None, "reason": reason,
            "object": object_name}


def _cpu_observations(before, after):
    if isinstance(before, dict) and before.get("available") is False:
        return []
    if isinstance(after, dict) and after.get("available") is False:
        return []
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}
    observations = []
    old_counters, new_counters = before.get("counters"), after.get("counters")
    if isinstance(old_counters, dict) and isinstance(new_counters, dict):
        for field in _CPU_COUNTERS:
            old_value, new_value = old_counters.get(field), new_counters.get(field)
            if _change_number(old_value) and _change_number(new_value):
                observations.append(_value_observation(
                    "cpu", f"cpu.counters.{field}", "ticks",
                    old_value, new_value, counter=True))
    old_util, new_util = before.get("utilization"), after.get("utilization")
    if isinstance(old_util, dict) and isinstance(new_util, dict) \
            and old_util.get("available") is not False \
            and new_util.get("available") is not False:
        for field in ("idle_percent", "user_percent", "system_percent"):
            old_value, new_value = old_util.get(field), new_util.get(field)
            if _change_number(old_value) and _change_number(new_value):
                observations.append(_value_observation(
                    "cpu", f"cpu.utilization.{field}", "percent",
                    old_value, new_value))
    return observations


def _memory_observations(before, after):
    if isinstance(before, dict) and before.get("available") is False:
        return []
    if isinstance(after, dict) and after.get("available") is False:
        return []
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}
    observations = []
    for field in ("total_bytes", "available_bytes"):
        old_value, new_value = before.get(field), after.get(field)
        if _change_number(old_value) and _change_number(new_value):
            observations.append(_value_observation(
                "memory", f"memory.{field}", "bytes", old_value, new_value))
    old_swap, new_swap = before.get("swap"), after.get("swap")
    if isinstance(old_swap, dict) and isinstance(new_swap, dict) \
            and old_swap.get("available") is not False \
            and new_swap.get("available") is not False:
        old_value, new_value = old_swap.get("used_bytes"), new_swap.get("used_bytes")
        if _change_number(old_value) and _change_number(new_value):
            observations.append(_value_observation(
                "memory", "memory.swap.used_bytes", "bytes", old_value, new_value))
    return observations


def _device_base(kind, name):
    if kind == "diskio":
        return f"diskio.disks.{name}"
    return f"network.interfaces.{name}"


def _device_rows(section, kind):
    if not isinstance(section, dict):
        return {}
    if kind == "network":
        interfaces = section.get("interfaces")
        rows = interfaces.get("items") if isinstance(interfaces, dict) else None
    else:
        rows = section.get("disks", section.get("devices"))
    return {row["name"]: row for row in rows or []
            if isinstance(row, dict) and isinstance(row.get("name"), str)}


def _device_identity(row):
    if not isinstance(row, dict):
        return None
    return {key: row.get(key) for key in
            ("identity", "major", "minor", "ifindex", "generation") if key in row}


def _device_observations(change_section, before_section, after_section, kind):
    if not isinstance(change_section, dict):
        return [], []
    old_rows = _device_rows(before_section, kind)
    new_rows = _device_rows(after_section, kind)
    units = _DEVICE_UNITS.get(kind, {})
    observations, discrete = [], []
    for item in change_section.get("items") or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str):
            continue
        base = _device_base(kind, name)
        reason = item.get("reason")
        if item.get("comparable") and isinstance(item.get("counter_delta"), dict):
            old_row, new_row = old_rows.get(name, {}), new_rows.get(name, {})
            for field in item["counter_delta"]:
                old_value, new_value = old_row.get(field), new_row.get(field)
                if _change_number(old_value) and _change_number(new_value):
                    observations.append(_value_observation(
                        kind, f"{base}.{field}", units.get(field, "number"),
                        old_value, new_value, counter=True))
            continue
        if reason in ("object_added", "object_not_observed"):
            added = reason == "object_added"
            row = new_rows.get(name) if added else old_rows.get(name)
            value = row.get("name") if isinstance(row, dict) else name
            discrete.append(_discrete_descriptor(
                kind, base, "object_added" if added else "object_not_observed",
                before=None if added else value, after=value if added else None,
                reason=reason, object_name=name))
            continue
        if reason == "counter_reset":
            old_row, new_row = old_rows.get(name, {}), new_rows.get(name, {})
            for field in units:
                old_value, new_value = old_row.get(field), new_row.get(field)
                if _change_number(old_value) and _change_number(new_value):
                    observations.append(_value_observation(
                        kind, f"{base}.{field}", units[field],
                        old_value, new_value, counter=True))
            continue
        if reason == "instantaneous_measurement":
            old_row, new_row = old_rows.get(name, {}), new_rows.get(name, {})
            for field in sorted((set(old_row) & set(new_row)) - _DEVICE_IDENTITY_FIELDS):
                old_value, new_value = old_row.get(field), new_row.get(field)
                if _change_number(old_value) and _change_number(new_value):
                    observations.append(_value_observation(
                        kind, f"{base}.{field}", units.get(field, "number"),
                        old_value, new_value))
            continue
        if reason == "object_identity_changed":
            discrete.append(_discrete_descriptor(
                kind, f"{base}.identity", "coverage_change",
                before=_device_identity(old_rows.get(name)),
                after=_device_identity(new_rows.get(name)),
                reason=reason, object_name=name))
            continue
        if reason in ("entered_bounded_snapshot", "left_bounded_snapshot"):
            discrete.append(_discrete_descriptor(
                kind, f"{kind}.coverage", "coverage_change",
                before=name in old_rows, after=name in new_rows,
                reason=reason, object_name=name))
            continue
        if reason:
            discrete.append(_discrete_descriptor(
                kind, f"{base}.coverage", "coverage_change", reason=reason,
                before=name in old_rows, after=name in new_rows, object_name=name))
    return observations, discrete


def _source_observations(before_sources, after_sources):
    old = before_sources if isinstance(before_sources, dict) else {}
    new = after_sources if isinstance(after_sources, dict) else {}
    result = []
    for name in sorted(set(old) | set(new)):
        if not isinstance(name, str):
            continue
        old_row, new_row = old.get(name), new.get(name)
        old_available = old_row.get("available") if isinstance(old_row, dict) else None
        new_available = new_row.get("available") if isinstance(new_row, dict) else None
        if name not in old:
            result.append(_discrete_descriptor(
                "sources", f"sources.{name}.available", "object_added",
                after=new_available, unit="bool", reason="source_first_observed",
                object_name=name))
        elif name not in new:
            result.append(_discrete_descriptor(
                "sources", f"sources.{name}.available", "object_not_observed",
                before=old_available, unit="bool", reason="source_not_observed",
                object_name=name))
        elif old_available != new_available:
            result.append(_discrete_descriptor(
                "sources", f"sources.{name}.available", "availability_change",
                before=old_available, after=new_available, unit="bool",
                reason="availability_changed", object_name=name))
    return result


def _process_available(view):
    if not isinstance(view, dict):
        return None
    value = view.get("available")
    return value if type(value) is bool else None


def _process_value_map(view):
    rows = view.get("items") if isinstance(view, dict) else None
    result = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        identity = row.get("identity")
        if not isinstance(identity, str):
            continue
        ticks = row.get("cpu_ticks")
        if isinstance(ticks, dict):
            ticks = ticks.get("total")
        result[identity] = {"rss_bytes": row.get("rss_bytes"), "cpu_ticks": ticks}
    return result


def _process_observations(change_section, before_view, after_view, process):
    if process is None or not isinstance(change_section, dict):
        return [], []
    if not change_section.get("comparable"):
        reason = change_section.get("reason")
        if reason == "process_changes_not_loaded":
            return [], []
        before_available = _process_available(before_view)
        after_available = _process_available(after_view)
        if reason == "source_unavailable" and before_available is None \
                and after_available is None:
            reason = (before_view or {}).get("reason") \
                or (after_view or {}).get("reason") \
                or "process_snapshot_not_observed"
        if before_available is not None or after_available is not None:
            return [], [_discrete_descriptor(
                "processes", "processes.available", "availability_change",
                before=before_available, after=after_available, unit="bool",
                reason=reason)]
        return [], [_discrete_descriptor(
            "processes", "processes.coverage", "coverage_change",
            before=before_available, after=after_available,
            reason=reason or "process_snapshot_incomplete")]
    old_values = _process_value_map(before_view)
    new_values = _process_value_map(after_view)
    observations, discrete = [], []
    for item in change_section.get("items") or []:
        if not isinstance(item, dict):
            continue
        identity = item.get("identity")
        if not isinstance(identity, str):
            continue
        base = f"processes.{identity}"
        if item.get("comparable"):
            old_value = old_values.get(identity, {})
            new_value = new_values.get(identity, {})
            for field, unit, counter in (("rss_bytes", "bytes", False),
                                         ("cpu_ticks", "ticks", True)):
                old_ticks, new_ticks = old_value.get(field), new_value.get(field)
                if _change_number(old_ticks) and _change_number(new_ticks):
                    observations.append(_value_observation(
                        "processes", f"{base}.{field}", unit,
                        old_ticks, new_ticks, counter=counter))
            continue
        reason = item.get("reason")
        if reason in ("process_added", "process_not_observed"):
            added = reason == "process_added"
            discrete.append(_discrete_descriptor(
                "processes", base, "object_added" if added else "object_not_observed",
                before=None if added else identity, after=identity if added else None,
                reason=reason, object_name=identity))
            continue
        if reason:
            discrete.append(_discrete_descriptor(
                "processes", f"{base}.coverage", "coverage_change",
                before=identity in old_values, after=identity in new_values,
                reason=reason, object_name=identity))
    return observations, discrete


def _pair_observations(before, after, change, *, resources, process,
                       before_view, after_view):
    old_host = before.get("host") if isinstance(before.get("host"), dict) else {}
    new_host = after.get("host") if isinstance(after.get("host"), dict) else {}
    observations, discrete = [], []
    for name in ("cpu", "memory", "diskio", "network"):
        if name not in resources:
            continue
        old_available = _available_flag(old_host.get(name))
        new_available = _available_flag(new_host.get(name))
        if old_available != new_available:
            discrete.append(_discrete_descriptor(
                name, f"{name}.available", "availability_change",
                before=old_available, after=new_available, unit="bool",
                reason="source_availability_changed"))
        if name in ("diskio", "network"):
            old_coverage = _coverage_flags(old_host.get(name), name)
            new_coverage = _coverage_flags(new_host.get(name), name)
            if old_coverage != new_coverage and (old_coverage or new_coverage):
                discrete.append(_discrete_descriptor(
                    name, f"{name}.coverage", "coverage_change",
                    before=old_coverage, after=new_coverage,
                    reason="coverage_changed"))
        section_change = change.get(name)
        if isinstance(section_change, dict) and not section_change.get("comparable") \
                and section_change.get("reason") == "source_unavailable" \
                and old_available is True and new_available is True:
            # host 段自称可用但对象列表缺失时，也要明确覆盖不可比。
            discrete.append(_discrete_descriptor(
                name, f"{name}.coverage", "coverage_change",
                reason="object_list_missing"))
    if "cpu" in resources:
        observations += _cpu_observations(old_host.get("cpu"), new_host.get("cpu"))
    if "memory" in resources:
        observations += _memory_observations(
            old_host.get("memory"), new_host.get("memory"))
    if "diskio" in resources:
        found, events = _device_observations(
            change.get("diskio"), old_host.get("diskio"),
            new_host.get("diskio"), "diskio")
        observations += found
        discrete += events
    if "network" in resources:
        found, events = _device_observations(
            change.get("network"), old_host.get("network"),
            new_host.get("network"), "network")
        observations += found
        discrete += events
    if "sources" in resources:
        discrete += _source_observations(
            before.get("sources"), after.get("sources"))
    found, events = _process_observations(
        change.get("processes"), before_view, after_view, process)
    observations += found
    discrete += events
    return observations, discrete


def _change_entry(descriptor, from_sample, to_sample):
    entry = {
        "resource": descriptor["resource"],
        "field": descriptor["path"],
        "path": descriptor["path"],
        "kind": descriptor["kind"],
        "unit": descriptor.get("unit"),
        "before": descriptor.get("before"),
        "after": descriptor.get("after"),
        "delta": descriptor.get("delta"),
        "first_sample_id": to_sample["sample_id"],
        "first_observed_at": to_sample["observed_at"],
        "last_sample_id": to_sample["sample_id"],
        "last_observed_at": to_sample["observed_at"],
        "baseline_sample_id": from_sample["sample_id"],
        "baseline_observed_at": from_sample["observed_at"],
        "run_ids": _unique_run_ids([from_sample, to_sample]),
        "samples": [_trace_point(from_sample, descriptor.get("before")),
                    _trace_point(to_sample, descriptor.get("after"))],
        "samples_omitted": 0,
        "continuity": {"comparable": True, "reasons": []},
    }
    if descriptor.get("reason"):
        entry["reason"] = descriptor["reason"]
    if descriptor.get("object"):
        entry["object"] = descriptor["object"]
    return entry


def _new_episode(pair, observation, direction):
    return {"resource": observation["resource"], "path": observation["path"],
            "unit": observation.get("unit"), "direction": direction,
            "before": observation["before"], "after": observation["after"],
            "baseline_sample": pair["from_sample"],
            "points": [_trace_point(pair["to_sample"], observation["after"])],
            "pairs": 1,
            "run_ids": _unique_run_ids([pair["from_sample"], pair["to_sample"]])}


def _extend_episode(episode, pair, observation):
    episode["after"] = observation["after"]
    episode["points"].append(_trace_point(pair["to_sample"], observation["after"]))
    episode["pairs"] += 1
    for run_id in _unique_run_ids([pair["from_sample"], pair["to_sample"]]):
        if run_id not in episode["run_ids"]:
            episode["run_ids"].append(run_id)


def _episode_entry(episode):
    points = [_trace_point(episode["baseline_sample"], episode["before"])] \
        + episode["points"]
    samples, omitted = _bounded_points(points)
    first, last = episode["points"][0], episode["points"][-1]
    entry = {
        "resource": episode["resource"], "field": episode["path"],
        "path": episode["path"], "kind": "value_change", "unit": episode["unit"],
        "before": episode["before"], "after": episode["after"],
        "delta": episode["after"] - episode["before"],
        "first_sample_id": first["sample_id"],
        "first_observed_at": first["observed_at"],
        "last_sample_id": last["sample_id"],
        "last_observed_at": last["observed_at"],
        "baseline_sample_id": episode["baseline_sample"]["sample_id"],
        "baseline_observed_at": episode["baseline_sample"]["observed_at"],
        "run_ids": episode["run_ids"][:CHANGE_TRACE_LIMIT],
        "samples": samples, "samples_omitted": omitted,
        "continuity": {"comparable": True, "reasons": []},
        "pairs": episode["pairs"],
        "direction": "increase" if episode["direction"] > 0 else "decrease",
    }
    if len(episode["run_ids"]) > CHANGE_TRACE_LIMIT:
        entry["run_ids_omitted"] = len(episode["run_ids"]) - CHANGE_TRACE_LIMIT
    return entry


def _discontinuity_entry(pair):
    continuity = pair["change"]["continuity"]
    return {"from_sample_id": pair["from_sample"]["sample_id"],
            "from_observed_at": pair["from_sample"]["observed_at"],
            "to_sample_id": pair["to_sample"]["sample_id"],
            "to_observed_at": pair["to_sample"]["observed_at"],
            "reasons": list(continuity.get("reasons") or []),
            "interval_seconds": continuity.get("interval_seconds")}


def _count_changes(changes):
    by_resource, by_kind, episodes = {}, {}, 0
    for row in changes:
        resource, kind = row.get("resource"), row.get("kind")
        by_resource[resource] = by_resource.get(resource, 0) + 1
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if kind == "value_change" and row.get("pairs"):
            episodes += 1
    return {"by_resource": by_resource, "by_kind": by_kind, "episodes": episodes}


def _aggregate_changes(pairs, max_changes):
    changes, discontinuities = [], []
    open_episodes = {}
    for pair in pairs:
        if not pair["comparable"]:
            changes.extend(_episode_entry(episode)
                           for episode in open_episodes.values())
            open_episodes.clear()
            discontinuities.append(_discontinuity_entry(pair))
            continue
        observed_paths = {item["path"] for item in pair["observations"]}
        for path in list(open_episodes):
            if path not in observed_paths:
                changes.append(_episode_entry(open_episodes.pop(path)))
        for observation in pair["observations"]:
            path = observation["path"]
            episode = open_episodes.get(path)
            if not observation["changed"]:
                if episode is not None:
                    changes.append(_episode_entry(open_episodes.pop(path)))
                continue
            if observation.get("delta") is None:
                # 计数器回退：结束旧 episode，回退本身作为单点变化保留。
                if episode is not None:
                    changes.append(_episode_entry(open_episodes.pop(path)))
                changes.append(_change_entry(
                    observation, pair["from_sample"], pair["to_sample"]))
                continue
            direction = 1 if observation["delta"] > 0 else -1
            if episode is not None and episode["direction"] == direction:
                _extend_episode(episode, pair, observation)
            else:
                if episode is not None:
                    changes.append(_episode_entry(open_episodes.pop(path)))
                open_episodes[path] = _new_episode(pair, observation, direction)
        for descriptor in pair["discrete"]:
            changes.append(_change_entry(
                descriptor, pair["from_sample"], pair["to_sample"]))
    changes.extend(_episode_entry(episode) for episode in open_episodes.values())
    changes.sort(key=lambda row: (row["first_observed_at"], row["resource"],
                                  row["path"], row["kind"]))
    counts = _count_changes(changes)
    total = len(changes)
    omitted = max(0, total - max_changes)
    return (changes[:max_changes] if omitted else changes,
            discontinuities, total, omitted, counts)


def _changes_summary(counts, total, omitted, discontinuities, gaps, process,
                     evaluated_samples, evaluated_pairs, boundary):
    reasons = {}
    for row in discontinuities:
        for reason in row.get("reasons") or []:
            reasons[reason] = reasons.get(reason, 0) + 1
    summary = {
        "evaluated_samples": evaluated_samples,
        "evaluated_pairs": evaluated_pairs,
        "changes_evaluated": total,
        "changes_returned": total - omitted,
        "changes_omitted": omitted,
        "episodes": counts["episodes"],
        "by_resource": counts["by_resource"],
        "by_kind": counts["by_kind"],
        "discontinuity_count": len(discontinuities),
        "discontinuity_reasons": reasons,
        "gap_count": len(gaps),
        "boundary_status": boundary.get("status"),
        "boundary_in_window": boundary.get("in_window"),
        "scope": "changes 只描述已保存样本之间的观测变化；gaps 是采集缺口，"
                 "discontinuities 是不可比原因；episode 在同一 (resource,path) 的"
                 "连续可比对中合并，稳定、反向或计数器回退时断开",
    }
    if process is None:
        summary.update(process_changes_loaded=False,
                       process_changes_not_loaded=True,
                       process_changes_reason="process_changes_not_loaded")
    else:
        summary["process_changes_loaded"] = True
    return summary


def _sample_ref(sample):
    return {"sample_id": sample["sample_id"], "observed_at": sample["observed_at"],
            "run_id": sample.get("run_id"), "boot": sample.get("boot"),
            "monotonic_at": sample.get("monotonic_at")}


def _changes_boundary(sample_store, page, since, until, process):
    raw = _boundary_report(sample_store, page, since, until, process,
                           lambda sample: _process_view(sample, process))
    boundary = {key: raw.get(key) for key in (
        "status", "page_oldest_sample_id", "page_oldest_observed_at",
        "predecessor_sample_id", "predecessor_observed_at", "in_window")}
    change = raw.get("change") if isinstance(raw.get("change"), dict) else None
    boundary["comparable"] = None if change is None \
        else change["continuity"]["comparable"]
    boundary["reasons"] = [] if change is None \
        else list(change["continuity"].get("reasons") or [])
    boundary["included_in_changes"] = False
    boundary["note"] = ("边界前驱只用于说明页首接缝，不并入本页 changes 或 episode；"
                        "需要跨页衔接时用 --before 读取更早一页，或按 first/last_sample_id 对齐")
    return boundary


def _bounded_gaps(gaps):
    return [dict(row, detail=_context_summary(
        row.get("detail"), byte_limit=1024, text_limit=256, max_items=12))
        for row in gaps]


def _range_changes_report(store, *, minutes, since, until, limit, before, process,
                          resources, raw, max_changes):
    explicit_since = since is not None
    minutes = DEFAULT_CHANGES_MINUTES if minutes is None else minutes
    if type(minutes) not in (int, float) or not math.isfinite(minutes) or minutes <= 0:
        raise StewardError("changes --minutes 必须是有限正数")
    until = time.time() if until is None else until
    since = until - minutes * 60 if since is None else since
    sample_store = SampleStore(store)
    page = sample_store.query(since, until, limit=limit, before=before, process=process)
    chronological = list(reversed(page["samples"]))
    pairs = []
    for previous, current in zip(chronological, chronological[1:]):
        previous_view = _process_view(previous, process)
        current_view = _process_view(current, process)
        change = resource_changes(
            dict(previous, processes=previous_view),
            dict(current, processes=current_view),
            page["gaps"], page.get("gap_history"))
        pair = {"from_sample": previous, "to_sample": current, "change": change,
                "comparable": change["continuity"]["comparable"],
                "observations": [], "discrete": []}
        if pair["comparable"]:
            pair["observations"], pair["discrete"] = _pair_observations(
                previous, current, change, resources=resources, process=process,
                before_view=previous_view, after_view=current_view)
        pairs.append(pair)
    changes, discontinuities, total, omitted, counts = _aggregate_changes(
        pairs, max_changes)
    boundary = _changes_boundary(sample_store, page, since, until, process)
    gaps = _bounded_gaps(page["gaps"])
    summary = _changes_summary(counts, total, omitted, discontinuities, gaps,
                               process, len(chronological), len(pairs), boundary)
    result = {
        "status": "resource_changes",
        "contract": dict(RESOURCE_CHANGES_CONTRACT),
        "mode": "range",
        "window": {"since": since, "until": until, "before": before,
                   "minutes": None if explicit_since else minutes,
                   "process": process, "resources": list(resources)},
        "evaluated_samples": len(chronological),
        "evaluated_pairs": len(pairs),
        "changes": changes,
        "changes_omitted": omitted,
        "truncated": bool(page["truncated"] or omitted),
        "next_before": page["next_before"],
        "discontinuities": discontinuities,
        "gaps": gaps,
        "gap_history": dict(page["gap_history"]),
        "boundary": boundary,
        "summary": summary,
        "page": {"limit": limit, "returned": len(page["samples"]),
                 "truncated": bool(page["truncated"]),
                 "evaluated": len(chronological)},
        "raw": bool(raw),
    }
    if raw:
        result["pairs"] = [{
            "from_sample_id": pair["from_sample"]["sample_id"],
            "to_sample_id": pair["to_sample"]["sample_id"],
            "continuity": pair["change"]["continuity"],
            "change": pair["change"],
        } for pair in pairs]
    return result


def _pair_changes_report(store, from_sample, to_sample, *, process, resources,
                         raw, max_changes):
    pair = SampleStore(store).sample_pair(
        from_sample, to_sample, process=process)
    baseline, target = pair["baseline"], pair["target"]
    baseline_view = _process_view(baseline, process)
    target_view = _process_view(target, process)
    change = resource_changes(
        dict(baseline, processes=baseline_view),
        dict(target, processes=target_view),
        pair["gaps"], pair["gap_history"])
    comparable = change["continuity"]["comparable"]
    observations, discrete = ([], [])
    if comparable:
        observations, discrete = _pair_observations(
            baseline, target, change, resources=resources, process=process,
            before_view=baseline_view, after_view=target_view)
    entries = [_change_entry(item, baseline, target)
               for item in observations if item["changed"]]
    entries += [_change_entry(item, baseline, target) for item in discrete]
    entries.sort(key=lambda row: (row["resource"], row["path"], row["kind"]))
    counts = _count_changes(entries)
    total = len(entries)
    omitted = max(0, total - max_changes)
    changes = entries[:max_changes] if omitted else entries
    discontinuities = [] if comparable else [{
        "from_sample_id": baseline["sample_id"],
        "from_observed_at": baseline["observed_at"],
        "to_sample_id": target["sample_id"],
        "to_observed_at": target["observed_at"],
        "reasons": list(change["continuity"].get("reasons") or []),
        "interval_seconds": change["continuity"].get("interval_seconds"),
    }]
    gaps = _bounded_gaps(pair["gaps"])
    boundary = {"status": "pair_mode", "in_window": None, "comparable": None,
                "included_in_changes": False,
                "note": "两点模式直接比较 baseline 与 target，不做 episode 聚合"}
    summary = _changes_summary(counts, total, omitted, discontinuities, gaps,
                               process, 2, 1, boundary)
    result = {
        "status": "resource_changes",
        "contract": dict(RESOURCE_CHANGES_CONTRACT),
        "mode": "pair",
        "pair": {"from_sample": from_sample, "to_sample": to_sample},
        "baseline": _sample_ref(baseline),
        "target": _sample_ref(target),
        "evaluated_samples": 2,
        "evaluated_pairs": 1,
        "changes": changes,
        "changes_omitted": omitted,
        "truncated": bool(omitted),
        "next_before": None,
        "discontinuities": discontinuities,
        "gaps": gaps,
        "gap_history": dict(pair["gap_history"]),
        "boundary": boundary,
        "summary": summary,
        "raw": bool(raw),
    }
    if raw:
        result["change"] = change
    return result


def changes_report(store, *, minutes=None, since=None, until=None,
                   limit=DEFAULT_HISTORY_LIMIT, before=None, process=None,
                   resources=None, raw=False, from_sample=None, to_sample=None,
                   max_changes=DEFAULT_MAX_CHANGES):
    """对比资源样本，输出 episode 聚合变化、不可比断点与采集缺口。"""
    selected = _change_resources(resources)
    if type(max_changes) is not int or not 1 <= max_changes <= MAX_CHANGES_LIMIT:
        raise StewardError(
            f"changes --max-changes 必须是 1–{MAX_CHANGES_LIMIT} 的整数")
    pair_mode = from_sample is not None or to_sample is not None
    if pair_mode:
        if from_sample is None or to_sample is None:
            raise StewardError("changes 两点模式必须同时提供 --from-sample 和 --to-sample")
        if minutes is not None or since is not None or until is not None \
                or before is not None:
            raise StewardError(
                "changes 两点模式不能同时使用 --minutes/--since/--until/--before")
        return _pair_changes_report(
            store, from_sample, to_sample, process=process,
            resources=selected, raw=raw, max_changes=max_changes)
    if before is not None and (since is None or until is None):
        raise StewardError(
            "changes --before 必须同时提供上一页返回的 --since 和 --until，避免分页窗口移动")
    return _range_changes_report(
        store, minutes=minutes, since=since, until=until, limit=limit,
        before=before, process=process, resources=selected, raw=raw,
        max_changes=max_changes)


def _compact_changes_details(result):
    changed = False
    gaps = result.get("gaps")
    if isinstance(gaps, list):
        compacted = []
        for gap in gaps:
            if not isinstance(gap, dict):
                compacted.append(gap)
                continue
            item = _selected(gap, ("gap_id", "run_id", "start_at", "end_at",
                                   "ongoing", "reason"))
            if gap.get("detail") is not None:
                item["detail"] = _context_summary(
                    gap["detail"], byte_limit=384, text_limit=160, max_items=8)
                item["detail_truncated"] = True
            compacted.append(item)
        result["gaps"] = compacted
        changed = True
    history = result.get("gap_history")
    if isinstance(history, dict):
        compact = _selected(history, (
            "retention_hours", "retention_source", "complete_since", "count_limit",
            "count_limited", "pruned_through", "declared_retention_hours",
            "declared_count_limit", "hard_count_limit", "over_target",
            "gap_history_degraded"))
        if compact != history:
            result["gap_history"] = compact
            result["gap_history_trimmed"] = True
            changed = True
    boundary = result.get("boundary")
    if isinstance(boundary, dict):
        compact = _selected(boundary, (
            "status", "page_oldest_sample_id", "page_oldest_observed_at",
            "predecessor_sample_id", "predecessor_observed_at", "in_window",
            "comparable", "reasons", "included_in_changes", "note"))
        if compact != boundary:
            result["boundary"] = compact
            changed = True
    return changed


def _trim_change_traces(result, keep):
    changed = False
    for change in result.get("changes") or []:
        if not isinstance(change, dict):
            continue
        points = change.get("samples")
        if not isinstance(points, list):
            continue
        total = change.get("samples_total")
        if total is None:
            total = len(points) + int(change.get("samples_omitted") or 0)
        if len(points) <= keep:
            continue
        if keep <= 0:
            kept = []
        else:
            head = (keep + 1) // 2
            tail = keep - head
            kept = points[:head] + (points[-tail:] if tail else [])
        change["samples"] = kept
        change["samples_total"] = total
        change["samples_omitted"] = total - len(kept)
        changed = True
    return changed


def _trim_change_sequence(result, key, keep, omitted_key):
    value = result.get(key)
    if not isinstance(value, list) or len(value) <= keep:
        return False
    removed = len(value) - keep
    result[key] = value[:keep]
    result[omitted_key] = result.get(omitted_key, 0) + removed
    return True


def _changes_candidate(result, keep, base_omitted):
    changes = result.get("changes") or []
    candidate = dict(result)
    candidate["changes"] = changes[:keep]
    omitted = base_omitted + len(changes) - keep
    candidate["changes_omitted"] = omitted
    candidate["truncated"] = True
    summary = dict(candidate.get("summary") or {})
    summary["changes_returned"] = keep
    summary["changes_omitted"] = omitted
    candidate["summary"] = summary
    if keep == 0 and changes:
        candidate["pagination_blocked_by_output"] = True
    return candidate


def _minimal_changes_result(result):
    minimal = {}
    for key in ("status", "contract", "mode", "window", "pair", "baseline",
                "target", "evaluated_samples", "evaluated_pairs", "next_before",
                "changes_omitted", "pagination_blocked_by_output", "raw"):
        if key in result:
            minimal[key] = result[key]
    minimal["changes"] = []
    minimal["truncated"] = True
    minimal["output_trimmed"] = True
    summary = result.get("summary") or {}
    minimal["summary"] = {
        key: summary[key] for key in (
            "evaluated_samples", "evaluated_pairs", "changes_evaluated",
            "changes_omitted", "process_changes_not_loaded") if key in summary}
    minimal["summary"]["changes_returned"] = 0
    minimal["detail_scope"] = "输出预算内已裁剪到最小元数据；完整结果用 --output 导出"
    return minimal


def _changes_output_counts(result):
    if not isinstance(result, dict):
        return result
    changes = result.get("changes")
    if isinstance(changes, list):
        summary = result.get("summary")
        if isinstance(summary, dict):
            summary = dict(summary)
            summary["changes_returned"] = len(changes)
            summary["changes_omitted"] = result.get("changes_omitted", 0)
            result["summary"] = summary
    return result


def fit_changes_output(report, byte_limit):
    if type(byte_limit) is not int or byte_limit <= 0:
        raise StewardError("输出预算必须为正整数")
    result = decode(encode(report))

    def fits():
        return len(encode(result)) <= byte_limit

    if fits():
        return _changes_output_counts(result)
    result["output_trimmed"] = True
    if isinstance(result.get("pairs"), list) and result["pairs"]:
        result["raw_pairs_omitted"] = len(result.pop("pairs"))
        result["output_raw_trimmed"] = True
    if result.get("mode") == "pair" and "change" in result:
        result.pop("change")
        result["raw_change_omitted"] = True
        result["output_raw_trimmed"] = True
    if not fits() and _compact_changes_details(result):
        result["output_detail_trimmed"] = True
    for keep in (8, 4, 2, 0):
        if fits():
            break
        if _trim_change_traces(result, keep):
            result["output_trace_trimmed"] = True
    if not fits() and _trim_change_sequence(
            result, "discontinuities", 8, "discontinuities_omitted"):
        result["output_discontinuity_trimmed"] = True
    if not fits() and _trim_change_sequence(
            result, "gaps", 8, "output_gap_omitted"):
        result["output_gap_trimmed"] = True
    if not fits():
        changes = result.get("changes") or []
        base_omitted = result.get("changes_omitted", 0)
        original = len(changes)
        lower, upper, best = 0, original - 1, None
        while lower <= upper:
            middle = (lower + upper) // 2
            candidate = _changes_candidate(result, middle, base_omitted)
            if len(encode(candidate)) <= byte_limit:
                best = candidate
                lower = middle + 1
            else:
                upper = middle - 1
        if best is not None:
            result = best
        else:
            result = _changes_candidate(result, 0, base_omitted)
            if original:
                result["pagination_blocked_by_output"] = True
            if not fits():
                result = _minimal_changes_result(result)
                if not fits():
                    result = {"status": "output_limited", "output_limited": True,
                              "message": "输出预算不足，请用 --output 导出或缩小查询范围"}
                if not fits():
                    result = {"output_limited": True}
    return _changes_output_counts(result)


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
        compact = _selected(history, ("retention_hours", "retention_source",
                                      "complete_since", "count_limit", "count_limited",
                                      "pruned_through", "declared_retention_hours",
                                      "declared_count_limit", "hard_count_limit",
                                      "over_target", "gap_history_degraded"))
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
        compact = _selected(retention, (
            "records", "records_limit", "retention_hours", "oldest_observed_at",
            "newest_observed_at", "span_seconds", "gap_history_degraded"))
        history = retention.get("history")
        if isinstance(history, dict):
            compact["history"] = _selected(history, (
                "retention_source", "effective", "declared", "counts",
                "over_target", "hard_limits"))
        result["retention"] = compact
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
