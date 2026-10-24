"""事件线索的待复核范围：去重、有界聚合与消费记录。

事件只缩小下一轮扫描的复核范围，不在这里生成变化。路径线索可能重复或密集，
因此同一路径/子树合并为一项；超过上限时向父目录聚合，并保留明确的截断计数。
"""

import math
import os
from pathlib import Path
import stat

import files


MAX_ITEMS = 64
MAX_PATH_BYTES = 4096


def _defaults():
    return {"version": 1, "limit": MAX_ITEMS, "items": [], "truncated": False,
            "aggregated": 0, "dropped": 0, "source_truncated": False, "degraded": None}


def empty():
    return _defaults()


def _token(value):
    """只接受整数事件身份；旧版浮点时间 token 一律按 0 处理。"""
    return value if type(value) is int else 0


def restore(raw):
    """从已通过结构校验的持久字段复制工作副本。"""
    if raw is None:
        return empty()
    state = _defaults()
    for key in state:
        if key != "items" and key in raw:
            state[key] = raw[key]
    if raw.get("degraded"):
        state["degraded"] = dict(raw["degraded"])
    state["items"] = []
    for item in raw.get("items", []):
        value = dict(item)
        value["token"] = _token(value.get("token", 0))
        state["items"].append(value)
    return state


def _ensure(state):
    for key, value in _defaults().items():
        state.setdefault(key, value)
    return state


_within = files.within


def _parent(path, root):
    if path == root:
        return None
    parent = os.path.dirname(path.rstrip(os.sep)) or root
    return parent if _within(parent, root) else root


def _item_token(item):
    """稳定事件身份；旧条目没有或不是整数 token 时按 0 处理。"""
    return _token(item.get("token", 0))


def _merge_into(target, item):
    target["count"] += item["count"]
    target["first_at"] = min(target["first_at"], item["first_at"])
    target["last_at"] = max(target["last_at"], item["last_at"])
    target["token"] = max(_item_token(target), _item_token(item))


def _enforce_limit(state):
    """超过上限时把最深的条目并入父目录；只剩 root 时按最近时间明确丢弃。"""
    limit = state.get("limit") or MAX_ITEMS
    items = state["items"]
    while len(items) > limit:
        movable = [item for item in items if _parent(item["path"], item["root"]) is not None]
        if not movable:
            oldest = min(items, key=lambda item: (item["last_at"], item["path"]))
            items.remove(oldest)
            state["dropped"] += 1
            state["truncated"] = True
            continue
        item = max(movable, key=lambda value: (value["path"].count(os.sep), -value["last_at"]))
        parent = _parent(item["path"], item["root"])
        target = next((value for value in items if value["path"] == parent), None)
        if target is None:
            target = {"root": item["root"], "path": parent, "first_at": item["first_at"],
                      "last_at": item["last_at"], "count": 0, "token": _item_token(item)}
            items.append(target)
        _merge_into(target, item)
        items.remove(item)
        state["aggregated"] += 1
        state["truncated"] = True


def add(state, root, path, now, token=None):
    """加入路径线索；同一稳定事件重放不增加次数，新事件才推进身份。"""
    _ensure(state)
    if type(now) not in (int, float) or not math.isfinite(now):
        raise ValueError(f"待复核线索时间无效：{now!r}")
    if token is not None and (type(token) not in (int, float) or not math.isfinite(token)):
        raise ValueError(f"待复核事件身份无效：{token!r}")
    if not isinstance(root, str) or not os.path.isabs(root):
        raise ValueError(f"待复核 root 必须是绝对路径：{root!r}")
    path = os.path.normpath(path)
    if not os.path.isabs(path) or not _within(path, root) \
            or len(path.encode("utf-8")) > MAX_PATH_BYTES:
        raise ValueError(f"待复核路径必须是 root 内且不超长的绝对路径：{path[:160]}")
    identity = int(now) if token is None else _token(token)
    items = state["items"]
    same = next((item for item in items if item["path"] == path), None)
    if same is not None:
        if token is not None and identity <= _item_token(same):
            # 游标未推进时 FSEvents 会重放同一事件；不刷新 token 或次数。
            return
        same["count"] += 1
        same["last_at"] = max(same["last_at"], now)
        same["token"] = max(_item_token(same), identity)
    else:
        ancestors = [item for item in items if _within(path, item["path"])]
        if ancestors:
            ancestor = max(ancestors, key=lambda item: len(item["path"]))
            if token is not None and identity <= _item_token(ancestor):
                return
            ancestor["count"] += 1
            ancestor["last_at"] = max(ancestor["last_at"], now)
            ancestor["token"] = max(_item_token(ancestor), identity)
        else:
            covered = [item for item in items if item["path"] != path and _within(item["path"], path)]
            item = {"root": root, "path": path, "first_at": now, "last_at": now,
                    "count": 1, "token": identity}
            for child in covered:
                _merge_into(item, child)
                items.remove(child)
            items.append(item)
    _enforce_limit(state)
    state["items"].sort(key=lambda item: item["path"])


def clear(state, reason, now):
    """清空队列；用于历史失效、基线重建或范围变化后不再使用过期线索。"""
    _ensure(state)
    state["items"] = []
    state["truncated"] = False
    state["aggregated"] = 0
    state["dropped"] = 0
    state["source_truncated"] = False
    state["degraded"] = {"reason": reason, "since": now} if reason else None


def degrade(state, reason, now):
    """记录本轮事件线索的覆盖退化；同一原因保留首次时间。"""
    _ensure(state)
    if reason is None:
        state["degraded"] = None
        return
    current = state.get("degraded")
    if not isinstance(current, dict) or current.get("reason") != reason:
        state["degraded"] = {"reason": reason, "since": now}


def consume(state, covered):
    """按 root 的已复核目录移除条目；只移除被目标覆盖的子树。"""
    _ensure(state)
    removed = 0
    kept = []
    for item in state["items"]:
        targets = covered.get(item["root"], ())
        if any(_within(item["path"], target) for target in targets):
            removed += 1
        else:
            kept.append(item)
    state["items"] = kept
    if not kept:
        state["truncated"] = False
        state["aggregated"] = 0
        state["dropped"] = 0
    return removed


def prune_roots(state, roots):
    """移除配置中已不存在的 root；不把范围移出解释为文件删除。"""
    _ensure(state)
    current = set(roots)
    state["items"] = [item for item in state["items"] if item["root"] in current]


def targets(state, roots=None):
    """返回 ``{root: {path: last_at}}``，供续扫优先复核。"""
    _ensure(state)
    selected = set(roots) if roots is not None else None
    result = {}
    for item in state["items"]:
        if selected is not None and item["root"] not in selected:
            continue
        result.setdefault(item["root"], {})[item["path"]] = _item_token(item)
    return result


def summary(state):
    """返回队列数量、截断与退化摘要。"""
    _ensure(state)
    return {"pending": len(state["items"]), "truncated": bool(state.get("truncated")),
            "aggregated": int(state.get("aggregated", 0)), "dropped": int(state.get("dropped", 0)),
            "source_truncated": bool(state.get("source_truncated")),
            "degraded": state.get("degraded")}


def _depth(path, root):
    if path == root:
        return 0
    return len(Path(os.path.relpath(path, root)).parts)


def clue_target(path, rules, state_path=None):
    """把事件路径归一为 root 内可扫描的目录；范围外或排除项返回 None。

    返回 ``(root, directory)``。文件、已删除对象和跨卷条目上移到最近可扫描的
    目录；超过声明深度的线索上移到仍属于观察范围的目录，避免复核扩大范围。
    """
    if not isinstance(path, str) or not path or "\x00" in path:
        return None
    candidate = os.path.normpath(path)
    if not os.path.isabs(candidate) or len(candidate.encode("utf-8")) > MAX_PATH_BYTES:
        return None
    rule = None
    for value in rules:
        if files.within(candidate, value["path"]) and (
                rule is None or len(value["path"]) > len(rule["path"])):
            rule = value
    if rule is None:
        return None
    root = rule["path"]
    excludes = set(rule.get("exclude_names", ()))
    exclude_paths = tuple(rule.get("exclude_paths", ()))
    if candidate != root:
        parts = Path(os.path.relpath(candidate, root)).parts
        if any(part in excludes for part in parts):
            return None
        if exclude_paths and files.excluded_by_path(candidate, root, exclude_paths):
            return None
    canonical_state = files.canonical_path(state_path) if state_path is not None else None
    if canonical_state is not None and files.within(candidate, canonical_state):
        return None
    max_depth = rule["max_depth"]
    while candidate != root and _depth(candidate, root) > max_depth:
        candidate = os.path.dirname(candidate.rstrip(os.sep)) or root
    try:
        root_info = os.lstat(root)
    except OSError:
        return None
    if not stat.S_ISDIR(root_info.st_mode):
        return None
    while True:
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            if candidate == root:
                return None
            candidate = os.path.dirname(candidate.rstrip(os.sep)) or root
            continue
        except OSError:
            return None
        if stat.S_ISDIR(info.st_mode) and info.st_dev == root_info.st_dev:
            return root, candidate
        if candidate == root:
            return None
        candidate = os.path.dirname(candidate.rstrip(os.sep)) or root


def event_targets(paths, rules, state_path=None, event_ids=None):
    """把路径线索归一为 ``{root: {directory: 稳定事件身份}}``。

    FSEvents 的同一事件在游标未推进时会重放，使用事件 id 才能避免把重放
    当成新变化；没有 id 时返回 None，由调用方使用观察时间。
    """
    ids = event_ids or {}
    result = {}
    for path in paths:
        target = clue_target(path, rules, state_path)
        if target is None:
            continue
        root, directory = target
        token = ids.get(path)
        current = result.setdefault(root, {}).get(directory)
        if current is None or (token is not None and token > current):
            result[root][directory] = token
    return result
