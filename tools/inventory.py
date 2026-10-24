"""长期资源知识；权限仍以 host.json 为准。"""

import os
from pathlib import Path
import re
import time

from files import canonical_path, is_canonical_path, within
from state import StewardError, decode, encode, read_regular_bytes
from state_schema import timestamp_seconds


TEXT_FIELDS = {"purpose": 1024, "owner": 256, "retention": 1024, "maintenance": 2048, "source": 1024}
RECORD_FIELDS = {"id", "kind", "locator", "basis", "dependencies", "evidence_at", "review_after_hours", *TEXT_FIELDS}
SERVICE = re.compile(r"(launchd|systemd):(user|system)/([A-Za-z0-9_][A-Za-z0-9_.@:-]{0,191})\Z")


def service_parts(locator):
    match = SERVICE.fullmatch(locator)
    if not match:
        raise StewardError("服务位置需为 launchd:user/标签、launchd:system/标签 或 systemd:user/名称.service 等明确范围")
    return match.groups()


def validate_record(record, require_canonical=True):
    if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
        raise StewardError("资源档案字段不完整或包含未知字段；档案不能保存授权")
    if not isinstance(record["id"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", record["id"]):
        raise StewardError("资源 id 需为最多 64 个字母、数字、点、下划线或连字符")
    kind = record["kind"]
    if not isinstance(kind, str) or not kind.strip() or len(kind.encode()) > 64 or not isinstance(record["basis"], str) or record["basis"] not in {"observed", "reported", "user_statement"}:
        raise StewardError("资源类别或依据类型无效")
    for key, limit in {**TEXT_FIELDS, "locator": 1024}.items():
        if not isinstance(record[key], str) or not record[key].strip() or len(record[key].encode()) > limit:
            raise StewardError(f"资源 {key} 必须是非空短文本，最多 {limit} 字节")
    if record["kind"] == "service":
        service_parts(record["locator"])
    elif require_canonical and not is_canonical_path(record["locator"]):
        raise StewardError("文件资源的位置需为无符号链接的规范绝对路径")
    elif not require_canonical and (not Path(record["locator"]).is_absolute() or os.path.normpath(record["locator"]) != record["locator"]):
        raise StewardError("文件资源的位置需为规范的绝对路径")
    dependencies = record["dependencies"]
    if not isinstance(dependencies, list) or len(dependencies) > 16 or any(
            not isinstance(value, str) or not value.strip() or len(value.encode()) > 512 for value in dependencies):
        raise StewardError("依赖最多 16 条，每条为最多 512 字节的短文本")
    stamp = record["evidence_at"]
    if not timestamp_seconds(stamp) or not 0 <= stamp <= time.time() + 300:
        raise StewardError("evidence_at 需为有效 Unix 时间，不能用记录时间替换历史证据时间")
    hours = record["review_after_hours"]
    if type(hours) is not int or not 1 <= hours <= 8760:
        raise StewardError("review_after_hours 需为 1–8760 小时")
    if len(encode(record)) > 8192:
        raise StewardError("单条资源定义最多 8 KiB")
    return record


def read_definition(path):
    try:
        content = read_regular_bytes(path, 8192)
    except OSError as exc:
        raise StewardError("资源定义必须是可读取的普通文件") from exc
    try:
        record = decode(content)
    except (ValueError, RecursionError) as exc:
        raise StewardError("资源定义不是有效的有界 JSON 对象") from exc
    return validate_record(record)


def read_inventory(store):
    data = store.read("inventory.json", {"version": 1, "resources": {}})
    if not isinstance(data, dict) or set(data) != {"version", "resources"} or type(data["version"]) is not int or data["version"] != 1:
        raise StewardError("本机档案格式错误，保留原状态")
    resources = data["resources"]
    if not isinstance(resources, dict):
        raise StewardError("资源档案格式无效")
    for key, entry in resources.items():
        if not isinstance(entry, dict) or set(entry) != {"definition", "recorded_at", "anchor", "inspection"}:
            raise StewardError("资源条目损坏，保留原状态")
        definition = validate_record(entry["definition"], require_canonical=False)
        if definition["id"] != key or not timestamp_seconds(entry["recorded_at"]):
            raise StewardError("资源条目的身份或时间无效")
        if entry["anchor"] is not None and not isinstance(entry["anchor"], str):
            raise StewardError("资源身份基准无效")
        report = entry["inspection"]
        if report is not None:
            if (not isinstance(report, dict) or report.get("target") != definition["locator"]
                    or not timestamp_seconds(report.get("observed_at"))
                    or not isinstance(report.get("startup", {}), dict)):
                raise StewardError("资源调查记录无效，保留原状态")
            if ("identity_review_required" in report
                    and type(report["identity_review_required"]) is not bool):
                raise StewardError("资源调查复核标志无效，保留原状态")
    return data


def register(store, record):
    record = validate_record(record)
    data = read_inventory(store)
    old = data["resources"].get(record["id"])
    if old and old["definition"] == record:
        return {"status": "unchanged", "id": record["id"]}
    data["resources"][record["id"]] = {"definition": record, "recorded_at": time.time(),
                                       "anchor": None, "inspection": None}
    store.write("inventory.json", data)
    return {"status": "registered", "id": record["id"], "authority": "host.json; 本次只更新知识"}


def knowledge(entry, now=None):
    now = time.time() if now is None else now
    definition = entry["definition"]
    report = entry["inspection"]
    identity_review_required = report and (
        report.get("identity_review_required") is True or report.get("identity_continuity") == "changed")
    return {"definition": definition, "recorded_at": entry["recorded_at"],
            "review_due": now >= definition["evidence_at"] + definition["review_after_hours"] * 3600,
            "identity_review_required": bool(identity_review_required),
            "provenance_verified_by_tool": False}


def policy_links(definition, policy, executable=None):
    if definition["kind"] != "service":
        locator = definition["locator"] if is_canonical_path(definition["locator"]) else None
        rules = [rule for rule in policy["directory_rules"] if locator and within(locator, rule["path"])]
        selected = max(rules, key=lambda rule: len(rule["path"])) if rules else None
        return {"source": "host.json", "directory_rule_path": selected["path"] if selected else None}
    residents = [rule for rule in policy["residents"] if executable and
                 rule["executable"] in [executable, Path(executable).name]]
    return {"source": "host.json", "resident_executables": [rule["executable"] for rule in residents]}


def query(store, policy, resource_id=None, path=None, limit=20, offset=0):
    if not 1 <= limit <= 50 or offset < 0:
        raise StewardError("查询 limit 为 1–50，offset 不得为负数")
    resources = read_inventory(store)["resources"]
    if resource_id is not None and resource_id not in resources:
        return {"status": "not_registered", "id": resource_id, "resources": [], "total": 0}
    entries = [resources[resource_id]] if resource_id else list(resources.values())
    if path is not None:
        path = canonical_path(path)
        if path is None:
            raise StewardError("查询路径无效，无法归一为绝对路径")
        matched = []
        for entry in entries:
            if entry["definition"]["kind"] == "service":
                continue
            locator = canonical_path(entry["definition"]["locator"])
            if locator and (within(path, locator) or within(locator, path)):
                matched.append(entry)
        entries = matched
    entries.sort(key=lambda entry: entry["definition"]["id"])
    items = []
    for entry in entries[offset:offset + limit]:
        item = knowledge(entry)
        item["legacy_noncanonical"] = (entry["definition"]["kind"] != "service" and
                                       not is_canonical_path(entry["definition"]["locator"]))
        item["inspection"] = entry["inspection"]
        executable = (entry["inspection"] or {}).get("startup", {}).get("resolved_program")
        item["policy"] = policy_links(entry["definition"], policy, executable)
        items.append(item)
    return {"status": "known" if entries else "not_registered", "total": len(entries), "offset": offset,
            "resources": items, "authority": "host.json; 档案的来源与维护说明不构成授权"}


def _same_generation(entry, anchor, identity):
    if anchor == identity:
        return True
    if entry["definition"]["kind"] == "service" or not isinstance(anchor, str) or not isinstance(identity, str):
        return False
    legacy, current = anchor.split(":"), identity.split(":")
    return len(legacy) == 5 and len(current) == 3 and legacy[:3] == current


def _same_object_kind(previous, report):
    if not previous:
        return True
    before, after = previous.get("object"), report.get("object")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return True
    if "kind" not in before or "kind" not in after:
        return True
    return before["kind"] == after["kind"]


def _metadata_fingerprint(report):
    if not isinstance(report, dict) or not isinstance(report.get("object"), dict):
        return None
    observed = report["object"]
    if "kind" not in observed or "size_bytes" not in observed or "mtime_ns" not in observed:
        return None
    return observed["kind"], observed["size_bytes"], observed["mtime_ns"]


def record_inspection(store, data, resource_id, report):
    entry = data["resources"][resource_id]
    previous = entry["inspection"]
    old_latch = bool(previous and (
        previous.get("identity_review_required") is True or previous.get("identity_continuity") == "changed"))
    identity = report.get("identity")
    same = _same_generation(entry, entry["anchor"], identity) and _same_object_kind(previous, report)
    continuity = ("not_observed" if not identity else "baseline_created" if not entry["anchor"]
                  else "same" if same else "changed")
    report["identity_continuity"] = continuity
    report["identity_review_required"] = old_latch or continuity == "changed"
    if entry["definition"]["kind"] != "service":
        before, after = _metadata_fingerprint(previous), _metadata_fingerprint(report)
        report["metadata_continuity"] = (
            "not_observed" if continuity == "not_observed"
            else "baseline_created" if continuity == "baseline_created" and not previous
            else "same" if continuity == "same" and before is not None and before == after
            else "changed" if continuity == "same" and before is not None and after is not None
            else "not_comparable")
    if identity and entry["anchor"] is None:
        entry["anchor"] = identity
    entry["inspection"] = {key: value for key, value in report.items() if key != "knowledge"}
    report["knowledge"] = knowledge(entry)
    store.write("inventory.json", data)
