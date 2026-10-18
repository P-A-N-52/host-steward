"""Explicit, policy-scoped note writing and reversible file quarantine."""

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time
import uuid

from files import identity, is_canonical_path, within
from state import PolicyChangedError, StewardError, read_regular_bytes
from state_schema import read_operations

BEGIN, END = "<!-- host-steward:begin -->", "<!-- host-steward:end -->"


def protect_path(store, path):
    path = Path(path).absolute()
    if not is_canonical_path(str(path)):
        raise StewardError("维护目标或父目录包含符号链接，拒绝操作")
    if within(str(path), str(store.path)):
        raise StewardError("不能维护状态目录或其内容")
    return path


def target_rule(store, policy, path):
    path = protect_path(store, path)
    if not any(within(str(path), root) for root in policy["roots"]):
        raise StewardError("目标超出本机约定的目录范围")
    rules = [rule for rule in policy["directory_rules"] if within(str(path), rule["path"])]
    if not rules:
        raise StewardError("目录尚无维护约定，只能观察")
    rule = max(rules, key=lambda item: len(item["path"]))
    if not rule.get("directory_id") or identity(Path(rule["path"]).stat()) != rule["directory_id"]:
        raise StewardError("目录身份未确认或已变化，只能观察")
    return path, rule


def read_note(path):
    try:
        payload = read_regular_bytes(path, 8192)
    except FileNotFoundError:
        return ""
    except StewardError as exc:
        raise StewardError("已有目录说明不是可安全更新的短文件") from exc
    except OSError as exc:
        raise StewardError("已有目录说明无法安全读取") from exc
    try:
        return payload.decode()
    except UnicodeDecodeError as exc:
        raise StewardError("已有目录说明不是有效 UTF-8 文本") from exc


def fingerprint(path):
    value = path.lstat()
    return {"id": identity(value), "size": value.st_size, "mtime": value.st_mtime_ns}


def observed_file(path):
    try:
        value = path.lstat()
    except FileNotFoundError:
        return "missing", None
    if not stat.S_ISREG(value.st_mode):
        return "other", None
    return "file", {"id": identity(value), "size": value.st_size, "mtime": value.st_mtime_ns}


def save_operation(store, operation):
    records = read_operations(store)
    records = [row for row in records if row["id"] != operation["id"]] + [operation]
    limit = store.limits["operation_records"]
    while len(records) > limit:
        removable = next((i for i, row in enumerate(records)
                          if (row["kind"] == "directory_note" and row["status"] == "verified")
                          or (row["kind"] == "quarantine" and row["status"] == "restored")), None)
        if removable is None:
            raise StewardError("操作记录预算不足；未完成与待恢复证据保持原样")
        records.pop(removable)
    store.write("operations.json", records)


def annotate(store, policy, directory, apply=False, policy_guard=None):
    path, rule = target_rule(store, policy, directory)
    if str(path) != rule["path"] or not path.is_dir() or not rule.get("allow_notes"):
        raise StewardError("此目录未授权写入目录说明")
    target = protect_path(store, path / "AGENTS.md")
    original = read_note(target)
    block = f"{BEGIN}\n# 本目录用途与维护约定\n\n- 用途：{rule['purpose']}\n- 保留类别：{rule['kind']}\n- 规则来源：本机管理约定的 directory_rules，本说明不新增授权。\n- 索引入口：本机状态 {store.path}，使用 status --path 查询 directory_index。\n{END}"
    if BEGIN in original or END in original:
        if original.count(BEGIN) != 1 or original.count(END) != 1 or original.index(BEGIN) > original.index(END):
            raise StewardError("已有 Steward 标记不完整，保留原文并停止")
        text = original[:original.index(BEGIN)] + block + original[original.index(END) + len(END):]
    else:
        text = original.rstrip() + ("\n\n" if original else "") + block + "\n"
    if len(text.encode()) > 8192:
        raise StewardError("目录说明超过 8 KiB，未写入")
    old_hash = hashlib.sha256(original.encode()).hexdigest()
    operation = {"id": uuid.uuid4().hex, "kind": "directory_note", "path": str(target),
                 "status": "planned", "created_at": time.time(), "before_sha256": old_hash}
    if not apply:
        return {"applied": False, "plan": operation, "proposed_text": text}
    if text == original:
        return {"applied": False, "reason": "说明已与本机约定一致"}
    protect_path(store, target)
    save_operation(store, operation)
    try:
        protect_path(store, target)
        observed = read_note(target)
        if hashlib.sha256(observed.encode()).hexdigest() != old_hash:
            raise StewardError("目录说明在计划后发生变化")
        fd, temporary = tempfile.mkstemp(prefix=".steward-note-", dir=path)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            if policy_guard:
                policy_guard()
            protect_path(store, target)
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
        protect_path(store, target)
        if read_note(target) != text:
            raise StewardError("目录说明写入后验证失败")
        operation.update(status="verified", verified_at=time.time())
        save_operation(store, operation)
        return {"applied": True, "operation": operation}
    except PolicyChangedError:
        raise
    except (OSError, StewardError) as exc:
        operation.update(status="failed", reason=str(exc)[:200])
        save_operation(store, operation)
        raise


def quarantine(store, policy, source, apply=False, policy_guard=None):
    path, rule = target_rule(store, policy, source)
    if ".recycle" in path.relative_to(rule["path"]).parts:
        raise StewardError("不能重复回收待恢复对象")
    if rule["kind"] != "temporary" or not rule.get("allow_quarantine") or not path.is_file() or path.name == "AGENTS.md":
        raise StewardError("仅允许回收明确授权的临时普通文件；长期资料保持原位")
    if "retention_days" not in rule or time.time() - path.stat().st_mtime < rule["retention_days"] * 86400:
        raise StewardError("文件尚未满足本机约定的回收期限")
    recycle = protect_path(store, Path(rule["path"]) / ".recycle")
    recycle_limit = rule.get("recycle_bytes")
    if type(recycle_limit) is not int or recycle_limit <= 0:
        raise StewardError("回收前需在目录约定中设置 recycle_bytes 容量预算")
    recycled_bytes, count = 0, 0
    if recycle.is_symlink():
        raise StewardError("待回收区不能是符号链接")
    for parent, directories, files in os.walk(recycle, followlinks=False):
        for name in directories + files:
            entry = Path(parent) / name
            count += 1
            if entry.is_symlink() or count > 1024:
                raise StewardError("待回收区需要复核，停止迁入")
            if entry.is_file():
                recycled_bytes += entry.stat().st_size
    if recycled_bytes + path.stat().st_size > recycle_limit:
        raise StewardError("待回收区容量不足；未缩短恢复期或删除已有对象")
    operation_id = uuid.uuid4().hex
    destination = protect_path(store, Path(rule["path"]) / ".recycle" / operation_id / path.name)
    operation = {"id": operation_id, "kind": "quarantine", "source": str(path), "target": str(destination),
                 "identity": fingerprint(path), "status": "planned", "created_at": time.time(),
                 "space_released_bytes": 0, "reason": "满足该临时目录的既有回收约定；仍保留恢复副本"}
    if not apply:
        return {"applied": False, "plan": operation}
    protect_path(store, path)
    protect_path(store, recycle)
    protect_path(store, destination)
    save_operation(store, operation)
    try:
        protect_path(store, path)
        protect_path(store, recycle)
        protect_path(store, destination)
        if fingerprint(path) != operation["identity"]:
            raise StewardError("文件在计划后发生变化")
        if recycle.is_symlink():
            raise StewardError("待回收区不能是符号链接")
        if policy_guard:
            policy_guard()
        destination.parent.mkdir(parents=True, exist_ok=False)
        if path.stat().st_dev != destination.parent.stat().st_dev:
            raise StewardError("demo 不进行跨卷回收")
        os.rename(path, destination)
        if path.exists() or fingerprint(destination) != operation["identity"]:
            raise StewardError("回收验证失败；检查原位置与目标位置")
        operation.update(status="quarantined", verified_at=time.time())
        save_operation(store, operation)
        return {"applied": True, "operation": operation}
    except PolicyChangedError:
        raise
    except (OSError, StewardError) as exc:
        operation.update(status="failed", reason=str(exc)[:200])
        save_operation(store, operation)
        raise


def restore(store, policy, operation_id, apply=False, policy_guard=None):
    if not isinstance(operation_id, str) or len(operation_id) != 32 or any(char not in "0123456789abcdef" for char in operation_id):
        raise StewardError("操作编号格式无效")
    operation = next((row for row in read_operations(store) if row["id"] == operation_id), None)
    if not operation or operation["kind"] != "quarantine" or operation["status"] not in ["quarantined", "restoring"]:
        raise StewardError("未找到可恢复的回收记录")
    source, rule = target_rule(store, policy, operation["source"])
    target = protect_path(store, Path(operation["target"]))
    expected = Path(rule["path"]) / ".recycle" / operation_id / source.name
    if target != expected:
        raise StewardError("恢复记录的待回收路径与约定不符")
    if not rule.get("allow_quarantine"):
        raise StewardError("原位置已有对象或约定已变化，停止恢复")
    if str(target.resolve()) != str(target):
        raise StewardError("待回收对象身份不符，停止恢复")
    source_kind, source_observed = observed_file(source)
    target_kind, target_observed = observed_file(target)
    source_matches = source_observed == operation["identity"]
    target_matches = target_observed == operation["identity"]
    if source_kind == "other" or (operation["status"] == "restoring" and source_kind == "file" and not source_matches):
        raise StewardError("原位置已有对象或约定已变化，停止恢复")
    if operation["status"] == "quarantined" and source_kind != "missing":
        raise StewardError("原位置已有对象或约定已变化，停止恢复")
    if target_kind == "other" or (target_kind == "file" and not target_matches):
        raise StewardError("待回收对象身份不符，停止恢复")
    if target_kind == "missing" and not (operation["status"] == "restoring" and source_matches):
        raise StewardError("待回收对象身份不符，停止恢复")
    if not apply:
        return {"applied": False, "plan": {"restore": str(target), "to": str(source)}}
    protect_path(store, source)
    protect_path(store, target)
    if operation["status"] == "quarantined":
        operation.update(status="restoring")
        save_operation(store, operation)
    if source_kind == "missing":
        if policy_guard:
            policy_guard()
        protect_path(store, source)
        protect_path(store, target)
        # link() creates the destination exclusively; an intervening new file is never overwritten.
        os.link(target, source)
        source_kind, source_observed = observed_file(source)
        if source_observed != operation["identity"]:
            raise StewardError("恢复对象验证失败，保留两处对象与 restoring 记录")
    if target_kind == "file":
        source_kind, source_observed = observed_file(source)
        target_kind, target_observed = observed_file(target)
        if source_observed != operation["identity"] or target_observed != operation["identity"]:
            raise StewardError("恢复对象在验证后发生变化，保留 restoring 记录")
        if policy_guard:
            policy_guard()
        protect_path(store, source)
        protect_path(store, target)
        target.unlink()
    source_kind, source_observed = observed_file(source)
    target_kind, target_observed = observed_file(target)
    if source_observed != operation["identity"] or target_kind != "missing":
        raise StewardError("恢复验证失败，保留 restoring 记录")
    operation.update(status="restored", restored_at=time.time())
    save_operation(store, operation)
    cleanup = {"removed": False}
    try:
        target.parent.rmdir()
        cleanup["removed"] = True
    except FileNotFoundError:
        cleanup["removed"] = True
    except OSError as exc:
        cleanup["reason"] = str(exc)[:200]
    return {"applied": True, "operation": operation, "cleanup": cleanup}
