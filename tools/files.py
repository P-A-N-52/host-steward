"""Metadata snapshots: bounded traversal, directory totals and verified deltas."""

from collections import Counter, defaultdict
import hashlib
import os
from pathlib import Path
import stat
import time


SCOPE_SAMPLE_LIMIT = 8
SCOPE_VERSION = 1


def _scope_exclude_names(exclude_names):
    return sorted({name for name in exclude_names if isinstance(name, str)})


def _absolute_path(path):
    try:
        value = os.fspath(path)
        if isinstance(value, bytes):
            value = os.fsdecode(value)
        if not isinstance(value, str) or not value or "\x00" in value:
            return None
        return os.path.abspath(value)
    except (OSError, TypeError, ValueError):
        return None


def _scope_digest(boundaries):
    digest = hashlib.sha256()
    digest.update(b"host-steward.scope")
    digest.update(b"\x00version\x00")
    digest.update(str(SCOPE_VERSION).encode())
    digest.update(b"\x00other-volumes\x00")
    for path, device in boundaries:
        encoded_path = path.encode()
        digest.update(str(len(encoded_path)).encode())
        digest.update(b":")
        digest.update(encoded_path)
        digest.update(b"\x00")
        digest.update(str(device).encode())
        digest.update(b"\x00")
    return digest.hexdigest()


def _make_scope(root, device, exclude_names, state_path, scan_depth, boundaries):
    boundaries = sorted(set(boundaries))
    return {
        "version": SCOPE_VERSION,
        "root": str(root),
        "device": int(device) if device is not None else None,
        "exclude_names": list(exclude_names),
        "state_path": state_path,
        "scan_depth": int(scan_depth),
        "volume_policy": "root_device_only",
        "other_volumes": {
            "count": len(boundaries),
            "digest": _scope_digest(boundaries),
            "samples": [{"path": path, "device": device} for path, device in boundaries[:SCOPE_SAMPLE_LIMIT]],
            "truncated": len(boundaries) > SCOPE_SAMPLE_LIMIT,
        },
    }


def _scope_difference(before, after):
    if before is None and after is None:
        return None
    if before is None:
        return "scope: current scan declares range metadata; previous baseline has no scope"
    if after is None:
        return "scope: current scan has no range metadata; previous baseline declared scope"
    changed = []
    for field in ["version", "root", "device", "exclude_names", "state_path", "scan_depth", "volume_policy"]:
        if before.get(field) != after.get(field):
            changed.append(field)
    if before.get("other_volumes") != after.get("other_volumes"):
        changed.append("other_volumes")
    if not changed:
        return None
    return "scope: scan semantics changed (" + ", ".join(changed) + ")"


def identity(info):
    return f"{info.st_dev}:{info.st_ino}"


def birth(info):
    value = getattr(info, "st_birthtime", None)
    return value


def within(path, parent):
    return path == parent or path.startswith(parent.rstrip(os.sep) + os.sep)


def canonical_path(path):
    try:
        value = os.fspath(path)
        if not isinstance(value, str) or not value or "\x00" in value:
            return None
        return str(Path(value).resolve())
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def is_canonical_path(path):
    return isinstance(path, str) and Path(path).is_absolute() and canonical_path(path) == path


def scan(roots, limits, exclude_names=(), state_path=None):
    started = time.monotonic()
    remaining = limits["scan_entries"]
    configured_excludes = _scope_exclude_names(exclude_names)
    configured_state_path = canonical_path(state_path) if state_path is not None else None
    result = {}
    for root in roots:
        records, directories, gaps = {}, {}, []
        excluded, complete = Counter(), True
        seen_data = set()
        other_volume_boundaries = set()

        def gap(reason):
            nonlocal complete
            complete = False
            if len(gaps) < 16:
                gaps.append(reason)

        try:
            root_info = os.lstat(root)
            if not stat.S_ISDIR(root_info.st_mode):
                raise OSError("根路径不是普通目录")
        except OSError as exc:
            result[root] = {"complete": False, "gaps": [str(exc)[:200]], "directories": {}, "records": {},
                            "excluded": dict(excluded),
                            "scope": _make_scope(root, None, configured_excludes, configured_state_path,
                                                  limits["scan_depth"], ())}
            continue
        pending = [(root, 0)]
        while pending:
            path, depth = pending.pop()
            if time.monotonic() - started >= limits["scan_seconds"] or remaining <= 0:
                gap("扫描达到时间或条目预算，本轮结果不用于判断删除")
                break
            try:
                info = os.lstat(path)
                if not stat.S_ISDIR(info.st_mode) or info.st_dev != root_info.st_dev:
                    gap("目录身份或挂载边界变化")
                    continue
                records[path] = {"id": identity(info), "kind": "directory", "size": 0, "mtime": info.st_mtime_ns,
                                 "birth": birth(info)}
                summary = {"id": identity(info), "files": 0, "directories": 0, "bytes": 0, "allocated_bytes": 0,
                           "agents": None}
                directories[path] = summary
                with os.scandir(path) as entries:
                    for entry in entries:
                        if remaining <= 0 or time.monotonic() - started >= limits["scan_seconds"]:
                            gap("扫描达到时间或条目预算，本轮结果不用于判断删除")
                            break
                        remaining -= 1
                        entry_path = _absolute_path(entry.path) or entry.path
                        if entry.name in configured_excludes or (configured_state_path and
                                                                 within(entry_path, configured_state_path)):
                            excluded["configured"] += 1
                            continue
                        try:
                            child = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            gap(f"无法读取：{entry.name[:80]}：{exc}"[:200])
                            continue
                        if child.st_dev != root_info.st_dev:
                            boundary_path = _absolute_path(entry.path)
                            if boundary_path is not None:
                                other_volume_boundaries.add((boundary_path, int(child.st_dev)))
                            excluded["other_volume"] += 1
                            continue
                        kind = "directory" if stat.S_ISDIR(child.st_mode) else "file" if stat.S_ISREG(child.st_mode) else "other"
                        if kind == "directory":
                            summary["directories"] += 1
                            if depth >= limits["scan_depth"]:
                                gap("达到目录深度预算")
                            else:
                                pending.append((entry.path, depth + 1))
                            continue
                        records[entry.path] = {"id": identity(child), "kind": kind, "size": child.st_size,
                                               "mtime": child.st_mtime_ns, "birth": birth(child)}
                        if entry.name == "AGENTS.md" and kind == "file":
                            summary["agents"] = entry.path
                        summary["files"] += 1
                        if kind == "file" and identity(child) not in seen_data:
                            seen_data.add(identity(child))
                            summary["bytes"] += child.st_size
                            summary["allocated_bytes"] += getattr(child, "st_blocks", 0) * 512
            except OSError as exc:
                gap(f"无法扫描：{path}：{exc}"[:200])
        for path in sorted(directories, key=lambda p: p.count(os.sep), reverse=True):
            parent = str(Path(path).parent)
            if parent in directories:
                for key in ["files", "directories", "bytes", "allocated_bytes"]:
                    directories[parent][key] += directories[path][key]
        result[root] = {"complete": complete, "root_id": identity(root_info), "gaps": gaps,
                        "excluded": dict(excluded), "directories": directories, "records": records,
                        "scope": _make_scope(root, root_info.st_dev, configured_excludes, configured_state_path,
                                              limits["scan_depth"], other_volume_boundaries)}
    return result


def compare(previous, current, max_groups=64):
    """Compare complete, same-root snapshots. A missing/incomplete root is a gap."""
    groups, gaps, baselines = {}, [], []
    for root, after in current.items():
        before = previous.get(root)

        def gap(reason):
            row = next((item for item in gaps if item["root"] == root), None)
            if row is None:
                row = {"root": root, "reasons": []}
                gaps.append(row)
            if reason not in row["reasons"] and len(row["reasons"]) < 16:
                row["reasons"].append(reason)

        if not after["complete"]:
            for reason in after["gaps"]:
                gap(reason)
            continue
        if not before or not before.get("complete"):
            baselines.append(root)
            continue
        if before.get("root_id") != after.get("root_id"):
            baselines.append(root)
            gap(f"identity: root changed {before.get('root_id')} -> {after.get('root_id')}"[:500])
            continue
        scope_reason = _scope_difference(before.get("scope"), after.get("scope"))
        if scope_reason:
            baselines.append(root)
            gap(scope_reason)
            continue

        def group(path):
            if path not in groups and len(groups) >= max_groups - 1:
                path = root
            value = groups.setdefault(path, {"path": path, "root": root, "added": 0, "removed": 0,
                                             "modified": 0, "moved": 0, "byte_delta": 0, "samples": []})
            if path == root:
                value["aggregation"] = "root_summary"
            return value

        def event(path, action, sample):
            value = group(path)
            value[action] += 1
            if len(value["samples"]) < 3:
                value["samples"].append(sample)
            return value

        old, new = before["records"], after["records"]
        old_ids, new_ids = defaultdict(list), defaultdict(list)
        for path, info in old.items():
            old_ids[(info["id"], info["kind"])].append(path)
        for path, info in new.items():
            new_ids[(info["id"], info["kind"])].append(path)
        moves, uncertain = {}, set()
        for key in old_ids.keys() & new_ids.keys():
            if len(old_ids[key]) != 1 or len(new_ids[key]) != 1:
                continue
            source, target = old_ids[key][0], new_ids[key][0]
            if source == target:
                continue
            a, b = old[source], new[target]
            if a.get("birth") is not None and b.get("birth") is not None:
                if a["birth"] == b["birth"]:
                    moves[source] = target
            else:
                uncertain.update([source, target])
                gap(f"identity: move uncertain {source} -> {target}"[:500])
        move_sources, move_targets = set(moves), set(moves.values())
        replacements = set()
        for path in old.keys() & new.keys():
            a, b = old[path], new[path]
            generation_changed = a.get("birth") is not None and b.get("birth") is not None and a["birth"] != b["birth"]
            if (a["id"] != b["id"] or a["kind"] != b["kind"] or generation_changed) and not (
                    path in move_sources and path in move_targets):
                replacements.add(path)
        replacement_candidates = {path for path in replacements if old[path]["kind"] == "directory" or new[path]["kind"] == "directory"}
        replacement_dirs = {path for path in replacement_candidates
                            if not any(path != parent and within(path, parent) for parent in replacement_candidates)}

        def in_replacement(path):
            return any(within(path, parent) for parent in replacement_dirs)

        def internal_move(source, target):
            return any(within(source, parent) and within(target, parent) for parent in replacement_dirs)

        for path in sorted(replacements):
            if in_replacement(path) and path not in replacement_dirs:
                continue
            value = event(path, "modified", {"identity_changed": True, "path": path,
                                              "from": {"id": old[path]["id"], "kind": old[path]["kind"]},
                                              "to": {"id": new[path]["id"], "kind": new[path]["kind"]}})
            value["continuity_gap"] = True
            gap(f"identity: {path} changed"[:500])
        directory_moves = sorted([(a, b) for a, b in moves.items() if old[a]["kind"] == "directory" and not internal_move(a, b)],
                                 key=lambda pair: pair[0].count(os.sep))
        outer_moves = []
        for source, target in directory_moves:
            if not any(within(source, a) and target == b + source[len(a):] for a, b in outer_moves):
                outer_moves.append((source, target))
                event(str(Path(target).parent), "moved", {"from": source, "to": target, "kind": "directory"})
        created = {p for p in new.keys() - old.keys() if new[p]["kind"] == "directory" and p not in moves.values() and not in_replacement(p)}
        deleted = {p for p in old.keys() - new.keys() if old[p]["kind"] == "directory" and p not in moves and not in_replacement(p)}
        created = {p for p in created if not any(p != q and within(p, q) for q in created)}
        deleted = {p for p in deleted if not any(p != q and within(p, q) for q in deleted)}
        for path in created:
            event(str(Path(path).parent), "added", {"directory_created": path, "bytes": after["directories"][path]["bytes"]})
        for path in deleted:
            event(str(Path(path).parent), "removed", {"directory_removed": path})
        for source, target in moves.items():
            if old[source]["kind"] == "directory" or internal_move(source, target):
                continue
            covered_move = any(within(source, a) and target == b + source[len(a):] for a, b in outer_moves)
            if not covered_move:
                event(str(Path(target).parent), "moved", {"from": source, "to": target})
            if (old[source]["size"], old[source]["mtime"]) != (new[target]["size"], new[target]["mtime"]):
                event(str(Path(target).parent), "modified", target)
        for path in new.keys() - old.keys() - set(moves.values()):
            if not in_replacement(path) and not any(within(path, p) for p in created) and not any(within(path, b) for _, b in outer_moves):
                event(str(Path(path).parent), "added", path)
        for path in old.keys() - new.keys() - set(moves):
            if not in_replacement(path) and not any(within(path, p) for p in deleted) and not any(within(path, a) for a, _ in outer_moves):
                event(str(Path(path).parent), "removed", path)
        for path in old.keys() & new.keys():
            if path not in replacements and path not in move_sources and path not in move_targets and not in_replacement(path) \
                    and old[path]["kind"] != "directory" and old[path] != new[path]:
                event(str(Path(path).parent), "modified", path)
        continuity_paths = replacements | uncertain
        for path in before["directories"].keys() | after["directories"].keys():
            if any(within(path, parent) for parent in created | deleted):
                continue
            if path not in after["directories"]:
                continue
            old_path = path
            for source, target in outer_moves:
                if within(path, target):
                    old_path = source + path[len(target):]
                    break
            delta = after["directories"][path]["bytes"] - before["directories"].get(old_path, {}).get("bytes", 0)
            if delta:
                value = group(path)
                scope = value["path"]
                if scope != path:
                    delta = after["directories"][scope]["bytes"] - before["directories"].get(scope, {}).get("bytes", 0)
                value["byte_delta"] = delta
                value["current_bytes"] = after["directories"][scope]["bytes"]
                if any(within(source, scope) != within(target, scope) for source, target in moves.items()):
                    value["migration_delta"] = True
                if any(within(scope, item) or within(item, scope) for item in continuity_paths):
                    value["continuity_gap"] = True
                    value["size_scope"] = "subtree; continuity gap; not growth evidence"
                elif value.get("migration_delta"):
                    value["size_scope"] = "subtree; includes migration; not ordinary growth evidence"
                else:
                    value["size_scope"] = "subtree; overlapping parents must not be summed"
    return {"changes": sorted(groups.values(), key=lambda row: (-abs(row["byte_delta"]), row["path"])),
            "gaps": gaps, "new_baselines": baselines}
