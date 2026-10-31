"""本机约定的校验、读取、版本证据与观察根路径规则。"""

import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re

from files import canonical_path, is_canonical_path, within
from history_config import DEFAULT_HISTORY, validate_history
from state import StewardError, decode, read_regular_bytes


LEGACY_LIMIT_FIELDS = frozenset([
    "scan_entries", "scan_seconds", "scan_depth", "processes", "command_bytes",
    "file_bytes", "total_bytes", "output_bytes", "change_records", "sample_records",
    "operation_records", "retention_hours"])
LIMIT_FIELDS = LEGACY_LIMIT_FIELDS - {"scan_depth"}
ROOT_FIELDS = frozenset(["path", "max_depth", "exclude_names", "exclude_paths"])
SAMPLING_FIELDS = frozenset([
    "interval_seconds", "cycle_seconds", "process_interval_seconds", "processes", "records", "retention_hours"])
DEFAULT_SAMPLING = {
    "interval_seconds": 15,
    "cycle_seconds": 5,
    "process_interval_seconds": 60,
    "processes": 20,
    "records": 120,
    "retention_hours": 1,
}
DEFAULT_MAX_DEPTH = 32
DEFAULT_ROOT_EXCLUDE_NAMES = [".git", "__pycache__", ".demo", ".recycle"]
CUSTOM_CHECK_FIELDS = frozenset(["name", "command", "purpose"])
CUSTOM_CHECK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
MAX_CUSTOM_CHECKS = 32
MAX_CUSTOM_CHECK_ARGS = 16
MAX_CUSTOM_CHECK_ARG_BYTES = 1024
MAX_CUSTOM_CHECK_PURPOSE_BYTES = 512


class PolicyDocument(dict):
    """字典内容仍是 host.json 本身，读取证据只保存在带外属性中。"""

    def __init__(self, value, evidence):
        super().__init__(value)
        self.policy_evidence = evidence


def policy_digest(policy):
    """返回与 JSON 对象键序和输入格式无关的语义摘要。"""
    normalized = json.dumps(policy, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def make_policy_evidence(policy, source_digest=None):
    return {
        "policy_version": policy["version"],
        "policy_digest": policy_digest(policy),
        "policy_source_digest": source_digest,
    }


def root_paths(policy):
    """按配置顺序返回 v1 字符串 root 或 v2 root 对象的路径。"""
    return [root["path"] if isinstance(root, dict) else root for root in policy.get("roots", [])]


def custom_checks(policy):
    """返回本机约定中的自定义检查；未配置时为空列表。"""
    return list(policy.get("custom_checks", []))


def root_rules(policy):
    """返回 v1/v2 统一的只读规则视图；v1 的排除项与深度来自顶层配置。"""
    result = []
    for configured in policy.get("roots", []):
        if isinstance(configured, dict):
            result.append({
                "path": configured["path"],
                "max_depth": configured["max_depth"],
                "exclude_names": list(configured["exclude_names"]),
                "exclude_paths": list(configured["exclude_paths"]),
            })
        else:
            limits = policy.get("limits", {})
            result.append({
                "path": os.fspath(configured),
                "max_depth": limits.get("scan_depth"),
                "exclude_names": list(policy.get("exclude_names", [])),
                "exclude_paths": [],
            })
    return result


def root_rule(policy, root):
    """返回指定 root 的统一规则视图。"""
    path = os.fspath(root)
    for rule in root_rules(policy):
        if rule["path"] == path:
            return rule
    raise StewardError(f"观察目录未在本机约定中配置：{path}")


def root_rule_for_path(policy, path):
    """按最长包含关系返回所属 root 规则；不在任何 root 内时返回 None。"""
    path = os.fspath(path)
    matched = [rule for rule in root_rules(policy) if within(path, rule["path"])]
    return max(matched, key=lambda rule: len(rule["path"])) if matched else None


def excluded_by_rule(rule, path):
    """判断对象是否落在所属 root 的名称排除或相对路径排除内。"""
    relative = os.path.relpath(os.fspath(path), rule["path"])
    if relative == os.curdir:
        return False
    parts = Path(relative).parts
    if any(part in rule["exclude_names"] for part in parts):
        return True
    for excluded in rule["exclude_paths"]:
        if relative == excluded or relative.startswith(excluded + os.sep):
            return True
    return False


def valid_exclude_path(value):
    if not isinstance(value, str) or not value or value in {".", ".."} or "\x00" in value:
        return False
    path = Path(value)
    if not path.parts or path.is_absolute() or os.path.normpath(value) != value:
        return False
    return all(part not in {"", ".", ".."} for part in path.parts)


def new_root(path, max_depth=DEFAULT_MAX_DEPTH):
    if type(max_depth) is not int or max_depth < 0:
        raise StewardError("root.max_depth 必须是非负整数，布尔值无效")
    return {
        "path": path,
        "max_depth": max_depth,
        "exclude_names": list(DEFAULT_ROOT_EXCLUDE_NAMES),
        "exclude_paths": [],
    }


def _validate_exclude_names(names):
    if not isinstance(names, list):
        raise StewardError("排除项格式无效")
    if any(not isinstance(name, str) or not name or name in {".", ".."} or "/" in name or "\x00" in name
           for name in names):
        raise StewardError("排除项必须是非空单层文件名")


def _validate_limits(limits, fields):
    if not isinstance(limits, dict) or any(type(value) is not int or value <= 0 for value in limits.values()):
        raise StewardError("预算字段必须完整，且为正整数")
    missing = sorted(fields - set(limits))
    unknown = sorted(str(key) for key in set(limits) - fields)
    if missing or unknown:
        detail = "；".join(part for part in (f"缺失 {'、'.join(missing)}" if missing else "",
                                             f"未知 {'、'.join(unknown)}" if unknown else "") if part)
        raise StewardError(f"预算字段必须完整，且为正整数；{detail}")
    if limits["output_bytes"] < 256 or limits["file_bytes"] < 1024:
        raise StewardError("工具输出至少需要 256 字节、状态单文件至少需要 1 KiB")


def _validate_sampling(sampling):
    if not isinstance(sampling, dict) or set(sampling) != SAMPLING_FIELDS:
        raise StewardError("v2 sampling 字段必须完整，且不能包含未知字段")
    if any(type(sampling[key]) is not int or sampling[key] <= 0 for key in SAMPLING_FIELDS):
        raise StewardError("sampling 字段必须为正整数，布尔值无效")
    if sampling["cycle_seconds"] > sampling["interval_seconds"]:
        raise StewardError("sampling.cycle_seconds 是单轮时间预算，不能大于 interval_seconds")
    if sampling["process_interval_seconds"] < sampling["interval_seconds"]:
        raise StewardError("sampling.process_interval_seconds 不能小于 interval_seconds")


def _samefile_alias(first, second):
    try:
        return os.path.samefile(first, second)
    except OSError:
        # 运行期 root 可能离线或权限不足；此时保留配置，由采集轮次报告缺口。
        return False


def _validate_custom_checks(checks):
    if not isinstance(checks, list):
        raise StewardError("custom_checks 必须是数组")
    if len(checks) > MAX_CUSTOM_CHECKS:
        raise StewardError(f"custom_checks 最多配置 {MAX_CUSTOM_CHECKS} 项")
    names = set()
    for check in checks:
        if not isinstance(check, dict) or set(check) != CUSTOM_CHECK_FIELDS:
            raise StewardError("自定义检查需且仅需包含 name、command、purpose")
        name = check["name"]
        if not isinstance(name, str) or not CUSTOM_CHECK_NAME.fullmatch(name):
            raise StewardError("自定义检查 name 必须是 1–64 字节的字母、数字、点、下划线或连字符，且以字母或数字开头")
        if name in names:
            raise StewardError(f"自定义检查 name 重复：{name}")
        names.add(name)
        purpose = check["purpose"]
        if not isinstance(purpose, str) or not purpose.strip() \
                or len(purpose.encode("utf-8")) > MAX_CUSTOM_CHECK_PURPOSE_BYTES:
            raise StewardError("自定义检查 purpose 必须是非空短文本")
        command = check["command"]
        if not isinstance(command, list) or not 1 <= len(command) <= MAX_CUSTOM_CHECK_ARGS:
            raise StewardError(f"自定义检查 command 必须是 1–{MAX_CUSTOM_CHECK_ARGS} 个参数的数组")
        for argument in command:
            if not isinstance(argument, str) or not argument or "\x00" in argument \
                    or len(argument.encode("utf-8")) > MAX_CUSTOM_CHECK_ARG_BYTES:
                raise StewardError("自定义检查 command 参数必须是非空字符串且不超过 1024 字节")
        if not os.path.isabs(command[0]):
            raise StewardError("自定义检查 command 首项必须是绝对路径，不使用 shell 或 PATH 查找")


def _validate_roots(policy, version):
    configured = policy.get("roots", [])
    expected_type = str if version == 1 else dict
    if not isinstance(configured, list) or not configured or not all(isinstance(root, expected_type) for root in configured):
        raise StewardError("请明确指定不重叠的观察目录")
    if version == 2:
        for root in configured:
            if set(root) != ROOT_FIELDS:
                raise StewardError("v2 root 必须完整包含 path、max_depth、exclude_names、exclude_paths")
            if type(root["max_depth"]) is not int or root["max_depth"] < 0:
                raise StewardError("root.max_depth 必须是非负整数，布尔值无效")
            _validate_exclude_names(root["exclude_names"])
            paths = root["exclude_paths"]
            if not isinstance(paths, list) or any(not valid_exclude_path(path) for path in paths):
                raise StewardError("root.exclude_paths 必须是规范相对路径，且不能包含点分量或逃逸 root")
    roots = root_paths(policy)
    if len(roots) != len(set(roots)):
        raise StewardError("请明确指定不重叠的观察目录")
    for root in roots:
        if not is_canonical_path(root):
            raise StewardError("观察目录必须是规范的绝对路径")
        if any(root != other and within(root, other) for other in roots):
            raise StewardError("观察目录不能相互包含")
    for index, root in enumerate(roots):
        for other in roots[:index]:
            if _samefile_alias(root, other):
                raise StewardError(f"观察目录不能是同一对象的 samefile 别名：{root} 与 {other}")
    return roots


def validate(policy):
    if not isinstance(policy, dict):
        raise StewardError("本机约定必须是 JSON 对象")
    if type(policy.get("version")) is not int or policy["version"] not in {1, 2}:
        raise StewardError("本机约定 version 仅支持整数 1 或 2；未知版本不读取")
    if not isinstance(policy.get("purpose"), str):
        raise StewardError("本机约定用途必须是字符串")
    version = policy["version"]
    _validate_limits(policy.get("limits", {}), LEGACY_LIMIT_FIELDS if version == 1 else LIMIT_FIELDS)
    _validate_custom_checks(policy.get("custom_checks", []))
    if version == 1:
        _validate_exclude_names(policy.get("exclude_names"))
        if "sampling" in policy:
            raise StewardError("v1 不能同时配置 sampling；请显式转换为 v2 后再启用采样设置")
        if "history" in policy:
            raise StewardError("v1 不能配置 history；请显式转换为 v2 后再设置资源历史保留")
    else:
        if "exclude_names" in policy:
            raise StewardError("v2 排除项只能配置在各自 root 中，顶层 exclude_names 不是活动规则")
        _validate_sampling(policy.get("sampling"))
        if "history" in policy:
            validate_history(policy["history"])
    roots = _validate_roots(policy, version)
    if not isinstance(policy.get("residents"), list):
        raise StewardError("常驻清单格式无效")
    for resident in policy["residents"]:
        if not isinstance(resident, dict) or not isinstance(resident.get("executable"), str) \
                or not isinstance(resident.get("reason"), str):
            raise StewardError("常驻约定需包含 executable 和 reason")
    if not isinstance(policy.get("directory_rules"), list):
        raise StewardError("目录约定格式无效")
    rule_paths = set()
    for rule in policy["directory_rules"]:
        if not isinstance(rule, dict) or not is_canonical_path(rule.get("path")) \
                or not any(within(rule["path"], root) for root in roots):
            raise StewardError("目录约定必须是规范绝对路径且位于观察范围内")
        if rule["path"] in rule_paths:
            raise StewardError("同一规范路径不能重复配置目录约定")
        rule_paths.add(rule["path"])
        if any(key in rule and type(rule[key]) is not bool for key in ["allow_notes", "allow_quarantine"]):
            raise StewardError("维护授权字段必须为布尔值")
        kind = rule.get("kind")
        if not isinstance(kind, str) or not kind.strip() or len(kind.encode()) > 64 \
                or not isinstance(rule.get("purpose"), str):
            raise StewardError("目录约定需包含明确类别与用途")
        if "retention_days" in rule and (type(rule["retention_days"]) is not int or rule["retention_days"] < 0):
            raise StewardError("保留天数无效")
        if rule.get("allow_quarantine") and (type(rule.get("recycle_bytes")) is not int or rule["recycle_bytes"] <= 0):
            raise StewardError("允许回收的目录必须设置正整数 recycle_bytes")
    return policy


def read_policy_with_evidence(directory):
    """从同一份原字节产生已校验配置、语义摘要与来源摘要，不修改 host.json。"""
    path = Path(directory).absolute() / "host.json"
    try:
        content = read_regular_bytes(path, 32768)
    except FileNotFoundError as exc:
        raise StewardError("缺少本机约定；仅新建空状态目录可 init，已有状态请先恢复原 host.json，不要重新初始化") from exc
    except OSError as exc:
        raise StewardError("无法读取本机约定，保留状态并停止执行") from exc
    try:
        parsed = validate(decode(content))
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise StewardError("本机约定格式错误，保留原文件") from exc
    state_path = canonical_path(Path(directory).absolute()) or str(Path(directory).absolute())
    if any(within(root, state_path) for root in root_paths(parsed)):
        raise StewardError("状态目录不能包含观察根目录")
    if parsed.get("host") != {"system": platform.system(), "hostname": platform.node()}:
        raise StewardError("本机约定的主机标识与当前环境不符，停止执行")
    evidence = make_policy_evidence(parsed, hashlib.sha256(content).hexdigest())
    return PolicyDocument(parsed, evidence), evidence


def read_recorded_policy(directory):
    """只读取最后一次采集运行的归档预算；不得用作采集或维护授权。"""
    from database import Database

    path = Path(directory).absolute()
    if path.is_symlink():
        raise StewardError("状态目录不能是符号链接")
    database = Database(path.resolve() / "steward.sqlite3")
    with database._transaction(require_version=2) as connection:
        lengths = connection.execute(
            "SELECT r.run_id, length(CAST(r.policy_json AS BLOB)), "
            "length(CAST(r.evidence_json AS BLOB)) FROM collector_state AS s "
            "JOIN collector_runs AS r ON r.run_id=s.run_id WHERE s.singleton=1").fetchone()
        if lengths is None or lengths[0] is None:
            raise StewardError("没有已验证的采集运行配置，无法取得只读历史预算；请恢复本机约定")
        if any(length is None or not 1 <= length <= 32768 for length in lengths[1:]):
            raise StewardError("归档采集配置或证据超过 32 KiB 读取上限")
        row = connection.execute(
            "SELECT policy_json, evidence_json FROM collector_runs WHERE run_id=?",
            (lengths[0],)).fetchone()
        try:
            policy, evidence = decode(row[0]), decode(row[1])
        except (ValueError, TypeError, RecursionError) as exc:
            raise StewardError("归档采集配置或证据格式损坏") from exc
    if not isinstance(policy, dict) or type(policy.get("version")) is not int or policy["version"] != 2:
        raise StewardError("只读历史预算要求有效的 v2 归档配置")
    _validate_limits(policy.get("limits"), LIMIT_FIELDS)
    _validate_sampling(policy.get("sampling"))
    if "history" in policy:
        validate_history(policy["history"])
    if policy.get("host") != {"system": platform.system(), "hostname": platform.node()}:
        raise StewardError("归档采集配置不属于当前主机")
    if not isinstance(evidence, dict) or evidence.get("policy_version") != 2 \
            or evidence.get("policy_digest") != policy_digest(policy):
        raise StewardError("归档采集配置与版本证据不一致")
    return PolicyDocument(policy, evidence), evidence, lengths[0]


def convert_v1_policy(policy):
    """纯转换 v1 配置；不写文件，保留扩展、授权与预算，不把旧证据带入 v2。"""
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise StewardError("仅支持从 v1 本机约定显式转换")
    validate(policy)
    result = copy.deepcopy(dict(policy))
    roots = root_paths(result)
    exclude_names = copy.deepcopy(result["exclude_names"])
    limits = copy.deepcopy(result["limits"])
    max_depth = limits.pop("scan_depth")
    result["roots"] = [{
        "path": root,
        "max_depth": max_depth,
        "exclude_names": copy.deepcopy(exclude_names),
        "exclude_paths": [],
    } for root in roots]
    result.pop("exclude_names", None)
    result["limits"] = limits
    result["sampling"] = copy.deepcopy(DEFAULT_SAMPLING)
    result["history"] = copy.deepcopy(DEFAULT_HISTORY)
    result["version"] = 2
    return validate(result)
