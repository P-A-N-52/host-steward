"""跨轮可恢复的文件基线扫描：持久进度、目录内断点与多 root 公平轮转。

``files.scan`` 是本模块的语义来源；本模块把同一次遍历拆到多轮，并在轮间保存
候选记录、待扫队列与已处理到的子名。只有完整走完且没有覆盖缺口的 pass 才输出
可比较的基线；普通未完成 pass 继续保留在 ``scan_progress`` 中推进，mtime 覆盖
缺口或目录消失会让本轮不更新基线并清空进度，下一轮从头复核。
"""

from collections import Counter
import math
import os
from pathlib import Path
import stat
import time

import files
import recheck


GAP_BUDGET = "扫描达到时间或条目预算，本轮结果不用于判断删除"
GAP_FAIR = "续扫本轮未推进（公平调度）"
GAP_RANGE = "范围变化重建基线"
GAP_VANISHED = "扫描期间目录消失，本轮结果不用于判断删除"
GAP_MTIME = "扫描期间目录 mtime 变化，已从游标续扫，该目录覆盖不完整"
GAP_MTIME_PASS = "存在 mtime 覆盖不完整的目录，本 pass 不更新基线，下一轮从头复核"
GAP_RECHECK = "待复核目标在复核期间不可继续扫描，本 pass 不用于判断删除"
MAX_ENTRY_GAPS = 16
SCOPE_FIELDS = ("version", "root", "device", "exclude_names", "state_path", "volume_policy",
                "scan_depth", "max_depth", "exclude_paths", "other_volumes")


def _token(value):
    """只接受整数事件身份；旧版浮点时间 token 一律按 0 处理。"""
    return value if type(value) is int else 0


def _retain(mapping, requested):
    """只保留仍覆盖 requested 路径的复核标记，并归一 token。"""
    return {path: _token(token) for path, token in mapping.items()
            if any(_in_subtree(value, path) for value in requested)}


def _rule_scope(rule, root_info, state_path):
    return files._make_scope(rule["path"], root_info.st_dev, sorted(set(rule["exclude_names"])),
                             state_path, rule["max_depth"], (), tuple(rule["exclude_paths"]),
                             rule["version"])


def _exhausted(budget):
    return budget["entries"] <= 0 or time.monotonic() - budget["started"] >= budget["seconds"]


def _strictly_under(path, parent):
    return path != parent and files.within(path, parent)


def _new_entry(root, root_id, scope, gaps=None):
    return {
        "root_id": root_id,
        "scope": scope,
        # 候选记录只保留 baseline 记录形状；分配字节单独保存，完成时用于目录聚合。
        "records": {},
        "allocated": {},
        "queue": [{"path": root, "depth": 0, "cursor": None, "dir_id": None}],
        "excluded": {},
        "excluded_by_dir": {},
        "boundaries": [],
        "rounds": 0,
        "entries": 0,
        "gaps": list(gaps or ()),
        "vanished": [],
        "recheck_failed": [],
        "recheck_done": {},
        "recheck_active": {},
        "recheck_pending": {},
    }


def _clone_entry(entry):
    # 记录字典本身不再改写，浅拷贝即可避免修改调用方持有的进度对象。
    clone = dict(entry)
    clone["records"] = dict(entry.get("records") or {})
    clone["allocated"] = dict(entry.get("allocated") or {})
    clone["queue"] = [dict(item) for item in entry.get("queue") or ()]
    clone["excluded_by_dir"] = {path: dict(counts)
                                for path, counts in (entry.get("excluded_by_dir") or {}).items()}
    clone["boundaries"] = [list(pair) for pair in entry.get("boundaries") or ()]
    clone["excluded"] = dict(entry.get("excluded") or {})
    clone["gaps"] = list(entry.get("gaps") or ())
    clone["vanished"] = list(entry.get("vanished") or ())
    clone["recheck_failed"] = list(entry.get("recheck_failed") or ())
    clone["recheck_done"] = dict(entry.get("recheck_done") or {})
    clone["recheck_active"] = dict(entry.get("recheck_active") or {})
    clone["recheck_pending"] = {path: _token(token)
                                for path, token in (entry.get("recheck_pending") or {}).items()}
    clone["rounds"] = entry.get("rounds", 0)
    clone["entries"] = entry.get("entries", 0)
    return clone


def _check_record(where, path, record):
    if not isinstance(path, str) or not path:
        raise ValueError(f"{where} 的记录路径无效")
    if not isinstance(record, dict):
        raise ValueError(f"{where} 的记录必须是对象：{path[:300]}")
    if not isinstance(record.get("id"), str) or not isinstance(record.get("kind"), str):
        raise ValueError(f"{where} 的记录身份无效：{path[:300]}")
    if type(record.get("size")) is not int or record["size"] < 0 or type(record.get("mtime")) is not int:
        raise ValueError(f"{where} 的记录大小或时间无效：{path[:300]}")
    birth = record.get("birth")
    if birth is not None and not isinstance(birth, (int, float)):
        raise ValueError(f"{where} 的记录 birth 无效：{path[:300]}")


def _check_entry(root, entry):
    """校验已持久化的 pass；损坏的续扫进度直接报错，保留原状态。"""
    if not isinstance(entry, dict):
        raise ValueError(f"scan_progress 中 {root} 的续扫进度必须是对象")
    if not isinstance(entry.get("root_id"), str) or not isinstance(entry.get("scope"), dict):
        raise ValueError(f"scan_progress 中 {root} 的续扫进度缺少 root_id 或 scope")
    records = entry.get("records")
    if not isinstance(records, dict):
        raise ValueError(f"scan_progress 中 {root} 的 records 必须是对象")
    for path, record in records.items():
        if not isinstance(path, str) or not os.path.isabs(path) \
                or os.path.normpath(path) != path or not files.within(path, root):
            raise ValueError(f"scan_progress 中 {root} 的记录越过 root：{str(path)[:300]}")
        _check_record(f"scan_progress 中 {root}", path, record)
    allocated = entry.get("allocated", {})
    if not isinstance(allocated, dict) or any(not isinstance(value, int) or value < 0
                                             for value in allocated.values()):
        raise ValueError(f"scan_progress 中 {root} 的 allocated 必须是路径到非负整数的对象")
    queue = entry.get("queue")
    if not isinstance(queue, list) or not queue:
        raise ValueError(f"scan_progress 中 {root} 的待扫队列为空，无法接续；"
                         "如进度已损坏，可用 patrol --discard-scan-progress 清除后重建")
    for item in queue:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) \
                or not os.path.isabs(item["path"]) \
                or os.path.normpath(item["path"]) != item["path"] \
                or not files.within(item["path"], root):
            raise ValueError(f"scan_progress 中 {root} 的待扫目录条目无效或越过 root")
        if type(item.get("depth")) is not int or item["depth"] < 0:
            raise ValueError(f"scan_progress 中 {root} 的待扫目录深度无效")
        cursor = item.get("cursor")
        if cursor is not None and not isinstance(cursor, str):
            raise ValueError(f"scan_progress 中 {root} 的目录游标无效")
        dir_id = item.get("dir_id")
        if dir_id is not None and not (isinstance(dir_id, dict) and isinstance(dir_id.get("id"), str)
                                       and type(dir_id.get("mtime")) is int):
            raise ValueError(f"scan_progress 中 {root} 的目录身份无效")
        restarts = item.get("restarts", 0)
        if type(restarts) is not int or restarts < 0:
            raise ValueError(f"scan_progress 中 {root} 的目录重启计数无效")
    excluded_by_dir = entry.get("excluded_by_dir", {})
    if not isinstance(excluded_by_dir, dict):
        raise ValueError(f"scan_progress 中 {root} 的 excluded_by_dir 必须是对象")
    for path, counts in excluded_by_dir.items():
        if not isinstance(path, str) or not isinstance(counts, dict) or any(
                not isinstance(key, str) or type(value) is not int or value < 0 for key, value in counts.items()):
            raise ValueError(f"scan_progress 中 {root} 的排除计数无效")
    boundaries = entry.get("boundaries", [])
    if not isinstance(boundaries, list) or any(
            not isinstance(pair, (list, tuple)) or len(pair) != 2 or not isinstance(pair[0], str)
            or type(pair[1]) is not int for pair in boundaries):
        raise ValueError(f"scan_progress 中 {root} 的跨卷边界无效")
    for key in ("rounds", "entries"):
        if key in entry and (type(entry[key]) is not int or entry[key] < 0):
            raise ValueError(f"scan_progress 中 {root} 的 {key} 必须是非负整数")
    if not isinstance(entry.get("gaps", []), list) or any(not isinstance(reason, str) for reason in entry["gaps"]):
        raise ValueError(f"scan_progress 中 {root} 的 gaps 无效")
    vanished = entry.get("vanished", [])
    if not isinstance(vanished, list) or any(not isinstance(path, str) or not path for path in vanished):
        raise ValueError(f"scan_progress 中 {root} 的消失目录记录无效")
    done = entry.get("recheck_done", {})
    if not isinstance(done, dict) or any(not isinstance(path, str) or not files.within(path, root)
                                        or type(token) not in (int, float) or not math.isfinite(token)
                                        for path, token in done.items()):
        raise ValueError(f"scan_progress 中 {root} 的待复核完成标记无效")
    active = entry.get("recheck_active", {})
    if not isinstance(active, dict) or any(not isinstance(path, str) or not files.within(path, root)
                                          or type(token) not in (int, float) or not math.isfinite(token)
                                          for path, token in active.items()):
        raise ValueError(f"scan_progress 中 {root} 的复核中标记无效")
    pending = entry.get("recheck_pending", {})
    if not isinstance(pending, dict) or any(not isinstance(path, str) or not files.within(path, root)
                                           or type(token) not in (int, float) or not math.isfinite(token)
                                           for path, token in pending.items()):
        raise ValueError(f"scan_progress 中 {root} 的复核待办标记无效")
    failed = entry.get("recheck_failed", [])
    if not isinstance(failed, list) or any(not isinstance(path, str) or not files.within(path, root)
                                           for path in failed):
        raise ValueError(f"scan_progress 中 {root} 的待复核失败记录无效")


def _load_progress(progress, current_roots):
    if progress is None:
        return {}, 0
    if not isinstance(progress, dict):
        raise ValueError("scan_progress 必须是对象或 null")
    next_index = progress.get("next_index", 0)
    if type(next_index) is not int or next_index < 0:
        next_index = 0
    entries = {}
    for root, entry in progress.items():
        if root == "next_index":
            continue
        if root not in current_roots:
            # 配置中已移除的 root 直接退出进度；不解释为对象删除。
            continue
        try:
            _check_entry(root, entry)
        except ValueError as exc:
            message = str(exc)
            if "--discard-scan-progress" not in message:
                message += "；如进度已损坏无法接续，可用 patrol --discard-scan-progress 清除进度后重建（保留 baselines）"
            raise ValueError(message) from exc
        entries[root] = _clone_entry(entry)
    return entries, next_index


def _range_change(entry, root_info, scope):
    reasons = []
    if entry.get("root_id") != files.identity(root_info):
        reasons.append("root_id 变化")
    stored = entry.get("scope") or {}
    changed = [field for field in SCOPE_FIELDS if stored.get(field) != scope.get(field)]
    if changed:
        reasons.append("scope 变化（" + ", ".join(changed) + "）")
    if not reasons:
        return None
    return "；".join(reasons)


def _renamed_entry(old_entries, current_roots, root_id):
    for path, entry in old_entries.items():
        if path in current_roots or not isinstance(entry, dict):
            continue
        if entry.get("root_id") == root_id:
            return path
    return None


def _count_excluded(entry, directory, kind):
    counts = entry["excluded_by_dir"].setdefault(directory, {})
    counts[kind] = counts.get(kind, 0) + 1


def _excluded_totals(entry):
    if entry is None:
        return {}
    total = Counter()
    for counts in entry.get("excluded_by_dir", {}).values():
        total.update(counts)
    return dict(total)


def _persisted_boundaries(entry):
    return sorted([list(pair) for pair in {tuple(pair) for pair in entry.get("boundaries", [])}])


def _record_gap(entry, reason):
    gaps = entry.setdefault("gaps", [])
    if reason and reason not in gaps and len(gaps) < MAX_ENTRY_GAPS:
        gaps.append(reason)


def _same_directory(dir_id, info):
    return dir_id.get("id") == files.identity(info) and dir_id.get("mtime") == info.st_mtime_ns


_in_subtree = files.within


def _purge_subtree(entry, path, keep_directory):
    """清掉某目录子树在本 pass 的候选记录、分配字节、排除计数与排队项。"""
    entry["records"] = {key: value for key, value in entry["records"].items()
                        if not (key.startswith(path.rstrip(os.sep) + os.sep)
                                or (not keep_directory and key == path))}
    entry["allocated"] = {key: value for key, value in entry["allocated"].items()
                          if not (key.startswith(path.rstrip(os.sep) + os.sep)
                                  or (not keep_directory and key == path))}
    entry["excluded_by_dir"] = {key: value for key, value in entry["excluded_by_dir"].items()
                                if not _in_subtree(key, path)}
    entry["queue"] = [other for other in entry["queue"] if not _strictly_under(other["path"], path)]
    entry["boundaries"] = [pair for pair in entry["boundaries"]
                           if not _strictly_under(str(pair[0]), path)]
    # 子树被清除后，覆盖它的已完成复核标记也不再有效。
    entry["recheck_done"] = {key: value for key, value in entry.get("recheck_done", {}).items()
                             if not (_in_subtree(key, path) or _in_subtree(path, key))}
    entry["recheck_active"] = {key: value for key, value in entry.get("recheck_active", {}).items()
                               if not (_in_subtree(key, path) or _in_subtree(path, key))}
    entry["recheck_pending"] = {key: value for key, value in entry.get("recheck_pending", {}).items()
                                if not (_in_subtree(key, path) or _in_subtree(path, key))}


def _gap_path(reason):
    """从带路径的覆盖缺口消息中取出完整路径；可能被截断或格式不符时返回 None。"""
    if len(reason) >= 300:
        # 旧版本把带路径的缺口消息截断到 300 字符，无法判断路径是否完整；
        # 保守保留，最多让该目录多重置一轮。新消息不再截断。
        return None
    for marker in (GAP_MTIME, GAP_VANISHED, GAP_RECHECK):
        prefix = marker + "："
        if reason.startswith(prefix):
            path = reason[len(prefix):]
            return path or None
    return None


def _clear_path_gaps(entry, path):
    """清掉某子树自己的路径型缺口，保留其他目录与汇总缺口。"""
    kept = []
    for reason in entry.get("gaps", []):
        gap_path = _gap_path(reason)
        if gap_path is None or not _in_subtree(gap_path, path):
            kept.append(reason)
    entry["gaps"] = kept


def _restart_directory(entry, item):
    """目录身份替换后清掉该子树的候选、排队项与旧覆盖缺口，再从头重扫。"""
    path = item["path"]
    _purge_subtree(entry, path, keep_directory=True)
    _clear_path_gaps(entry, path)
    entry["vanished"] = [value for value in entry.get("vanished", []) if not _in_subtree(value, path)]
    item["cursor"] = None
    item["dir_id"] = None


def _vanish_directory(entry, path):
    """扫描期间目录消失：清掉该子树候选，记缺口；本 pass 不据此判断删除。"""
    _purge_subtree(entry, path, keep_directory=False)
    vanished = entry.setdefault("vanished", [])
    if path not in vanished and len(vanished) < MAX_ENTRY_GAPS:
        vanished.append(path)
    _record_gap(entry, f"{GAP_VANISHED}：{path}")


def _covered_by_recheck(entry, path):
    return any(_in_subtree(path, done) for done in entry.get("recheck_done", {}))


def _prepare_recheck(entry, rule, requested, state_path):
    """在正常续扫队列前插入待复核子树；返回本轮目标与无法复核的线索。"""
    root = rule["path"]
    requested = dict(requested or {})
    # 旧版浮点时间 token 按 0 处理；只保留仍与当前线索重叠的标记。
    entry["recheck_done"] = _retain(entry.get("recheck_done", {}), requested)
    targets, skipped = {}, []
    for path in sorted(requested):
        resolved = recheck.clue_target(path, [rule], state_path)
        if resolved is None:
            skipped.append(path)
            continue
        target = resolved[1]
        token = requested[path]
        ancestor = next((value for value in targets if _in_subtree(target, value)), None)
        if ancestor is not None:
            targets[ancestor] = max(targets[ancestor], token)
            continue
        for child in [value for value in targets if _in_subtree(value, target)]:
            token = max(token, targets.pop(child))
        targets[target] = token
    done = entry.get("recheck_done", {})
    in_progress = _retain(entry.get("recheck_active", {}), requested)
    pending = _retain(entry.get("recheck_pending", {}), requested)
    entry["recheck_active"] = in_progress
    entry["recheck_pending"] = pending
    active = {}
    for target, token in targets.items():
        if any(_in_subtree(target, path) and done[path] >= token
               and _token(pending.get(path)) <= done[path] for path in done):
            continue
        previous = in_progress.get(target)
        if previous is not None and any(_in_subtree(item["path"], target) for item in entry["queue"]):
            # 复核仍在推进：active 只保留扫描起点 token；期间的新事件记入 pending，
            # 保留目录游标，不在本轮重扫已处理部分。
            entry["recheck_active"][target] = previous
            if token > previous:
                entry["recheck_pending"][target] = max(pending.get(target, 0), token)
            active[target] = previous
            continue
        _purge_subtree(entry, target, keep_directory=True)
        _clear_path_gaps(entry, target)
        entry["queue"] = [item for item in entry["queue"] if not _in_subtree(item["path"], target)]
        entry["vanished"] = [value for value in entry.get("vanished", [])
                             if not _in_subtree(value, target)]
        entry["recheck_failed"] = [value for value in entry.get("recheck_failed", [])
                                    if not _in_subtree(value, target)]
        entry["queue"].append({"path": target, "depth": _path_depth(target, root),
                               "cursor": None, "dir_id": None})
        # 新一轮复核从当前事件身份开始，旧的 pending 由本轮扫描覆盖。
        entry["recheck_active"][target] = token
        entry["recheck_pending"].pop(target, None)
        active[target] = token
    if active:
        entry["queue"].sort(key=lambda item: 1 if any(
            _in_subtree(item["path"], target) for target in active) else 0)
    return active, skipped


def _record_recheck_failed(entry, path):
    _record_gap(entry, f"{GAP_RECHECK}：{path}")
    values = entry.setdefault("recheck_failed", [])
    if path not in values and len(values) < MAX_ENTRY_GAPS:
        values.append(path)


def _mark_recheck_done(entry, target, token):
    """记录本轮扫描起点的完成身份；有更新事件时保留 pending，不判 covered。"""
    done = entry.setdefault("recheck_done", {})
    done[target] = max(_token(done.get(target)), token)
    pending = entry.setdefault("recheck_pending", {})
    if _token(pending.get(target)) <= done[target]:
        pending.pop(target, None)
    entry.setdefault("recheck_active", {}).pop(target, None)


def _finalize_recheck(entry, targets):
    """复核子树已排空后核对目录身份与时间，并记录完成标记。"""
    for target, token in targets.items():
        if any(_in_subtree(item["path"], target) for item in entry["queue"]):
            continue
        record = entry["records"].get(target)
        if record is None:
            continue
        try:
            info = os.lstat(target)
        except FileNotFoundError:
            _record_gap(entry, f"{GAP_VANISHED}：{target}")
            vanished = entry.setdefault("vanished", [])
            if target not in vanished and len(vanished) < MAX_ENTRY_GAPS:
                vanished.append(target)
            _mark_recheck_done(entry, target, token)
            continue
        except OSError:
            _record_recheck_failed(entry, target)
            _mark_recheck_done(entry, target, token)
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_dev != entry["scope"].get("device"):
            _record_recheck_failed(entry, target)
            _mark_recheck_done(entry, target, token)
        elif record.get("id") != files.identity(info) or record.get("mtime") != info.st_mtime_ns:
            # 目标自身在复核期间仍在变化；本 pass 不完整，下一轮继续复核该子树。
            _record_gap(entry, f"{GAP_MTIME}：{target}")
            entry.get("recheck_active", {}).pop(target, None)
        else:
            _mark_recheck_done(entry, target, token)


def _recheck_summary(entry, requested, skipped):
    done = entry.get("recheck_done", {}) if entry is not None else {}
    outstanding = entry.get("recheck_pending", {}) if entry is not None else {}
    dirty = {target for target in done
             if _token(outstanding.get(target)) > _token(done[target])}
    covered, pending = [], []
    for path, token in requested.items():
        if any(target not in dirty and _in_subtree(path, target) and _token(done[target]) >= token
               for target in done):
            covered.append(path)
        elif path not in skipped:
            pending.append(path)
    targets = sorted({target for target in done
                      if target not in dirty
                      and any(_in_subtree(path, target) for path in covered)})
    return {"requested": len(requested), "covered": sorted(covered),
            "pending": sorted(pending), "skipped": sorted(set(skipped)), "targets": targets}


def _settle_recheck(entry, rule, active, path):
    """本轮内某目标子树排空后立即结算，避免父目录随后重复排队。"""
    if not active:
        return
    candidates = {target: token for target, token in active.items()
                  if _in_subtree(path, target)}
    if not candidates:
        return
    root = rule["path"]
    finished = {target: token for target, token in candidates.items()
                if not any(_in_subtree(item["path"], target) for item in entry["queue"])}
    if finished:
        _finalize_recheck(entry, finished)


def _scan_queue(rule, root_info, entry, budget, state_path, active=None):
    root = rule["path"]
    max_depth = rule["max_depth"]
    excludes = set(rule["exclude_names"])
    exclude_paths = tuple(rule["exclude_paths"])
    while entry["queue"]:
        if _exhausted(budget):
            return [GAP_BUDGET]
        item = entry["queue"].pop()
        path = item["path"]
        depth = item["depth"]
        try:
            info = os.lstat(path)
        except FileNotFoundError as exc:
            if path == root:
                entry["queue"].append(item)
                return [f"观察根访问失败：{exc}"[:300]]
            _vanish_directory(entry, path)
            continue
        except OSError as exc:
            if path == root:
                entry["queue"].append(item)
                return [f"观察根访问失败：{exc}"[:300]]
            raise
        if not stat.S_ISDIR(info.st_mode) or info.st_dev != root_info.st_dev:
            if path == root:
                entry["queue"].append(item)
                return ["观察根在扫描期间被替换或不再是同一目录"]
            raise OSError(f"目录身份或挂载在扫描期间变化：{path}")
        identity = files.identity(info)
        if item.get("dir_id") is None and item.get("cursor") is not None:
            # 只有游标没有目录身份，无法证明已扫段仍然有效，按改动处理。
            _restart_directory(entry, item)
        dir_id = item.get("dir_id")
        if dir_id is not None and not _same_directory(dir_id, info):
            if dir_id.get("id") != identity:
                # 目录身份替换仍从头重扫。
                _restart_directory(entry, item)
                item["restarts"] = 0
            elif item.get("restarts", 0) < 1:
                # 首次 mtime 变化仍从头重扫；之后再次变化改为从游标续扫。
                _restart_directory(entry, item)
                item["restarts"] = 1
            else:
                # 持续写入时不能每轮重启；保留已扫候选，从游标继续并记录覆盖缺口。
                item["dir_id"] = {"id": identity, "mtime": info.st_mtime_ns}
                _record_gap(entry, f"{GAP_MTIME}：{path}")
        if item.get("dir_id") is None:
            item["dir_id"] = {"id": identity, "mtime": info.st_mtime_ns}
        entry["records"][path] = {"id": identity, "kind": "directory", "size": 0,
                                  "mtime": info.st_mtime_ns, "birth": files.birth(info)}
        cursor = item.get("cursor")
        gap = None
        try:
            with os.scandir(path) as scanned:
                ordered = sorted(scanned, key=lambda value: value.name)
        except FileNotFoundError as exc:
            if path == root:
                entry["queue"].append(item)
                return [f"观察根访问失败：{exc}"[:300]]
            _vanish_directory(entry, path)
            continue
        except OSError as exc:
            if path == root:
                entry["queue"].append(item)
                return [f"观察根访问失败：{exc}"[:300]]
            raise
        try:
            for child_entry in ordered:
                name = child_entry.name
                if cursor is not None and name <= cursor:
                    continue
                if _exhausted(budget):
                    gap = GAP_BUDGET
                    break
                budget["entries"] -= 1
                entry["entries"] += 1
                entry_path = child_entry.path
                if name in excludes or (exclude_paths and files.excluded_by_path(entry_path, root, exclude_paths)) \
                        or (state_path and files.within(entry_path, state_path)):
                    _count_excluded(entry, path, "configured")
                    item["cursor"] = name
                    continue
                child = child_entry.stat(follow_symlinks=False)
                if child.st_dev != root_info.st_dev:
                    entry["boundaries"].append([entry_path, int(child.st_dev)])
                    _count_excluded(entry, path, "other_volume")
                    item["cursor"] = name
                    continue
                kind = "directory" if stat.S_ISDIR(child.st_mode) else \
                    "file" if stat.S_ISREG(child.st_mode) else "other"
                if kind == "directory":
                    entry["records"][entry_path] = {"id": files.identity(child), "kind": "directory", "size": 0,
                                                    "mtime": child.st_mtime_ns, "birth": files.birth(child)}
                    if depth >= max_depth:
                        # 已声明的范围边界：只记录边界条目，不遍历、不计入未采集子树。
                        _count_excluded(entry, path, "depth_boundary")
                    elif _covered_by_recheck(entry, entry_path):
                        # 该子树已按事件线索完整重扫；不重复进入，也不把它当作排除项。
                        pass
                    else:
                        entry["queue"].append({"path": entry_path, "depth": depth + 1,
                                               "cursor": None, "dir_id": None})
                    item["cursor"] = name
                    continue
                entry["records"][entry_path] = {"id": files.identity(child), "kind": kind,
                                                "size": child.st_size, "mtime": child.st_mtime_ns,
                                                "birth": files.birth(child)}
                if kind == "file":
                    entry["allocated"][entry_path] = getattr(child, "st_blocks", 0) * 512
                item["cursor"] = name
        except OSError as exc:
            if path == root:
                entry["queue"].append(item)
                return [f"观察根访问失败：{exc}"[:300]]
            raise
        if gap is not None:
            # 当前目录保留在队尾，下一轮从 cursor 继续；已入队的子目录排在其前面。
            entry["queue"].append(item)
            return [gap]
        _settle_recheck(entry, rule, active, path)
    return []


def _path_depth(path, root):
    if path == root:
        return 0
    relative = os.path.relpath(path, root)
    return len(Path(relative).parts)


def _derive_directories(records, allocated, root, max_depth):
    """从候选记录一次性派生目录摘要，再自底向上聚合。"""
    directories = {}
    for path, record in records.items():
        if record["kind"] == "directory":
            directories[path] = {"id": record["id"], "files": 0, "directories": 0, "bytes": 0,
                                 "allocated_bytes": 0, "agents": None}
    seen_data = set()
    for path in sorted(records):
        record = records[path]
        if path == root:
            continue
        parent, name = os.path.split(path)
        summary = directories.get(parent)
        if summary is None:
            continue
        if record["kind"] == "directory":
            summary["directories"] += 1
            if _path_depth(path, root) > max_depth:
                directories[path]["boundary"] = True
            continue
        summary["files"] += 1
        if record["kind"] != "file":
            continue
        if record["id"] not in seen_data:
            seen_data.add(record["id"])
            summary["bytes"] += record["size"]
            summary["allocated_bytes"] += allocated.get(path, 0)
        if name == "AGENTS.md":
            summary["agents"] = path
    for path in sorted(directories, key=lambda value: value.count(os.sep), reverse=True):
        parent = str(Path(path).parent)
        if parent in directories:
            for key in ["files", "directories", "bytes", "allocated_bytes"]:
                directories[parent][key] += directories[path][key]
    return directories


def _resumable_summary(entry):
    if entry is None:
        return {"pass_rounds": 0, "entries_recorded": 0, "queued_directories": 0}
    return {"pass_rounds": int(entry.get("rounds", 0)),
            "entries_recorded": int(entry.get("entries", 0)),
            "queued_directories": len(entry.get("queue", []))}


def _snapshot(rule, root_id, device, entry, gaps, complete, state_path, recheck=None):
    # 快照与持久进度不共享记录对象，调用方修改快照不会改写下一轮候选。
    records = {path: dict(record) for path, record in entry["records"].items()} if entry is not None else {}
    directories = _derive_directories(records, entry["allocated"] if entry is not None else {},
                                      rule["path"], rule["max_depth"]) if records else {}
    scope = files._make_scope(rule["path"], device, sorted(set(rule["exclude_names"])), state_path,
                              rule["max_depth"], [tuple(pair) for pair in entry.get("boundaries", ())]
                              if entry is not None else (),
                              tuple(rule["exclude_paths"]), rule["version"])
    result = {"complete": complete, "root_id": root_id, "gaps": list(gaps),
              "excluded": _excluded_totals(entry), "directories": directories,
              "records": records, "scope": scope}
    if recheck is not None:
        result["recheck"] = recheck
    if not complete:
        result["resumable"] = _resumable_summary(entry)
    return result


def _serve_root(rule, entry, budget, state_path, old_entries, current_roots, requested=None):
    root = rule["path"]
    requested = dict(requested or {})
    summary = _recheck_summary(entry, requested, []) if requested else None
    try:
        root_info = os.lstat(root)
    except OSError as exc:
        reason = f"观察根暂不可见：{exc}" if isinstance(exc, FileNotFoundError) else f"观察根访问失败：{exc}"
        return _snapshot(rule, entry.get("root_id") if entry is not None else None, None,
                         entry, [reason[:300]], False, state_path, summary), entry
    if not stat.S_ISDIR(root_info.st_mode):
        return _snapshot(rule, files.identity(root_info), root_info.st_dev, entry,
                         [f"观察根不是目录：{root}"], False, state_path, summary), entry
    scope = _rule_scope(rule, root_info, state_path)
    if entry is None:
        entry = _new_entry(root, files.identity(root_info), scope)
        renamed = _renamed_entry(old_entries, current_roots, entry["root_id"])
        if renamed is not None:
            entry["gaps"].append(f"{GAP_RANGE}：观察根路径或身份已变化（旧路径 {renamed}）")
    else:
        reason = _range_change(entry, root_info, scope)
        if reason:
            entry = _new_entry(root, files.identity(root_info), scope,
                               [f"{GAP_RANGE}：{reason}"])
    entry["rounds"] += 1
    active, skipped = _prepare_recheck(entry, rule, requested, state_path) if requested \
        else ({}, [])
    round_gaps = _scan_queue(rule, root_info, entry, budget, state_path, active)
    if active:
        _finalize_recheck(entry, active)
    summary = _recheck_summary(entry, requested, skipped) if requested else None
    entry["excluded"] = _excluded_totals(entry)
    entry["boundaries"] = _persisted_boundaries(entry)
    if not entry["queue"]:
        if entry.get("vanished"):
            # 有目录在扫描期间消失，本 pass 的候选不能作为删除依据；清空进度，
            # 下一轮从头重扫，由新的完整 pass 核实该子树是否真的消失。
            gaps = [reason for reason in entry.get("gaps", []) if reason] or [GAP_VANISHED]
            return _snapshot(rule, entry["root_id"], root_info.st_dev, entry, gaps, False,
                             state_path, summary), None
        if entry.get("recheck_failed"):
            # 待复核目标已不再是可扫描目录；不把未复核范围交给删除判断。
            gaps = [reason for reason in entry.get("gaps", []) if reason.startswith(GAP_RECHECK)]
            return _snapshot(rule, entry["root_id"], root_info.st_dev, entry,
                             gaps or [GAP_RECHECK], False, state_path, summary), None
        mtime_gaps = [reason for reason in entry.get("gaps", []) if reason.startswith(GAP_MTIME)]
        if mtime_gaps:
            # 从游标续扫跳过了 cursor 之前的区间，候选快照不完整；本 pass 不更新
            # 基线、不参与删除判断，清空进度并在下一轮从头复核。
            gaps = mtime_gaps + [GAP_MTIME_PASS]
            return _snapshot(rule, entry["root_id"], root_info.st_dev, entry, gaps, False,
                             state_path, summary), None
        if summary is not None and summary["pending"]:
            # 复核目标未完成时不把本轮候选当作完整基线；下一轮继续优先复核。
            return _snapshot(rule, entry["root_id"], root_info.st_dev, entry,
                             [f"{GAP_RECHECK}：待复核范围未完成"], False, state_path, summary), None
        return _snapshot(rule, entry["root_id"], root_info.st_dev, entry, [], True,
                         state_path, summary), None
    gaps = [reason for reason in entry.get("gaps", []) if reason] + round_gaps
    return _snapshot(rule, entry["root_id"], root_info.st_dev, entry, gaps, False,
                     state_path, summary), entry


def _unserved_snapshot(rule, entry, state_path, requested=None):
    try:
        info = os.lstat(rule["path"])
    except OSError:
        info = None
    is_directory = info is not None and stat.S_ISDIR(info.st_mode)
    device = info.st_dev if is_directory else None
    root_id = entry["root_id"] if entry is not None else (files.identity(info) if is_directory else None)
    summary = _recheck_summary(entry, requested, []) if requested else None
    return _snapshot(rule, root_id, device, entry, [GAP_FAIR], False, state_path, summary)


def _normalize_recheck(recheck, rules):
    """只接受 ``{root: {path: token}}``；其他形态明确拒绝。"""
    if recheck is None:
        return {}
    if not isinstance(recheck, dict):
        raise ValueError("recheck 必须是 {root: {path: token}} 对象")
    current = {rule["path"] for rule in rules}
    result = {}
    for root, mapping in recheck.items():
        if root not in current:
            raise ValueError(f"recheck 的 root 不在当前配置：{root!r}")
        if not isinstance(mapping, dict):
            raise ValueError(f"recheck[{root}] 必须是路径到 token 的对象")
        values = result.setdefault(root, {})
        for path, token in mapping.items():
            if not isinstance(path, str) or not os.path.isabs(path):
                raise ValueError(f"待复核路径必须是绝对路径：{path!r}")
            path = os.path.normpath(path)
            if not _in_subtree(path, root):
                raise ValueError(f"待复核路径不在 root 内：{path}")
            if type(token) not in (int, float) or not math.isfinite(token):
                raise ValueError(f"待复核时间标记无效：{path}")
            token = _token(token)
            # 保留整数事件 id；旧浮点 token 按 0 处理。
            values[path] = max(values.get(path, token), token)
    return result


def resumable_scan(progress, roots, limits, exclude_names=(), state_path=None, recheck=None):
    """按轮推进多个 root 的扫描；返回本轮快照与下一轮进度。

    ``progress`` 是上一轮持久化的 ``scan_progress``（``None`` 或按 root 键的对象，
    含跨 root 的 ``next_index``）。快照形状与 :func:`files.scan` 一致；未完成的
    root 额外带 ``resumable``，且不会被当作完整基线。

    ``recheck`` 可选，形如 ``{root: {目录: 线索时间}}``。本轮在这些子树内优先
    排队复核；复核仍走完整 pass 与 :func:`files.compare`，不会直接生成变化。
    """
    started = time.monotonic()
    rules = [files._root_rule(configured, limits, exclude_names) for configured in roots]
    configured_state_path = files.canonical_path(state_path) if state_path is not None else None
    current_roots = {rule["path"] for rule in rules}
    entries, next_index = _load_progress(progress, current_roots)
    requested = _normalize_recheck(recheck, rules)
    if not rules:
        return {}, {}
    if not 0 <= next_index < len(rules):
        next_index = 0
    old_entries = {root: entry for root, entry in (progress or {}).items()
                   if root != "next_index" and root not in current_roots}
    budget = {"entries": limits["scan_entries"], "started": started, "seconds": limits["scan_seconds"]}
    served, stop_index = {}, None
    first = next_index
    for offset in range(len(rules)):
        index = (first + offset) % len(rules)
        if _exhausted(budget):
            stop_index = index
            break
        rule = rules[index]
        root = rule["path"]
        snapshot, entry = _serve_root(rule, entries.get(root), budget, configured_state_path,
                                      old_entries, current_roots, requested.get(root))
        served[root] = snapshot
        entries[root] = entry
    for offset in range(len(rules)):
        rule = rules[(first + offset) % len(rules)]
        root = rule["path"]
        if root not in served:
            served[root] = _unserved_snapshot(rule, entries.get(root), configured_state_path,
                                              requested.get(root))
    remaining = {root: entry for root, entry in entries.items() if entry is not None}
    if remaining or stop_index is not None:
        # 首个 root 恰好用尽预算并完成时 entries 为空，仍要保存下一轮起点，
        # 否则后续 root 永远轮不到。
        remaining["next_index"] = stop_index if stop_index is not None else first
    return {rule["path"]: served[rule["path"]] for rule in rules}, remaining
