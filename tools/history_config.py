"""资源历史保留配置：默认值、字段契约、范围校验与解析。

``history`` 是 host.json 的顶层可选段；整段省略表示全部使用默认值。若提供，
必须完整包含 ``runs`` 与 ``gaps`` 两组，每组都必须同时提供 ``records`` 和
``retention_hours``。字段只接受正整数，布尔值无效。

``records`` 是保留目标值，绝对硬上限不随配置放开：运行记录最多
``RUN_ABSOLUTE_LIMIT`` 条、缺口记录最多 ``GAP_ABSOLUTE_LIMIT`` 条，保留时长
最多 ``RETENTION_HOURS_ABSOLUTE_LIMIT`` 小时。采样存储以此区分“目标值”与
“绝对硬上限”。
"""

import copy

from state import StewardError


HISTORY_GROUPS = ("runs", "gaps")
HISTORY_FIELDS = frozenset(["records", "retention_hours"])
DEFAULT_HISTORY = {
    "runs": {"records": 256, "retention_hours": 168},
    "gaps": {"records": 256, "retention_hours": 168},
}
RUN_RECORDS_MIN = 8
GAP_RECORDS_MIN = 8
RETENTION_HOURS_MIN = 1
RUN_ABSOLUTE_LIMIT = 1024
GAP_ABSOLUTE_LIMIT = 4096
RETENTION_HOURS_ABSOLUTE_LIMIT = 8760


def _field_range(group, field):
    if field == "records":
        low = RUN_RECORDS_MIN if group == "runs" else GAP_RECORDS_MIN
        high = RUN_ABSOLUTE_LIMIT if group == "runs" else GAP_ABSOLUTE_LIMIT
    else:
        low, high = RETENTION_HOURS_MIN, RETENTION_HOURS_ABSOLUTE_LIMIT
    return low, high


def _validate_group(history, group):
    value = history[group]
    if not isinstance(value, dict):
        raise StewardError(f"history.{group} 必须是对象")
    missing = sorted(HISTORY_FIELDS - set(value))
    unknown = sorted(str(key) for key in set(value) - HISTORY_FIELDS)
    if missing or unknown:
        detail = "；".join(part for part in (f"缺失 {'、'.join(missing)}" if missing else "",
                                             f"未知 {'、'.join(unknown)}" if unknown else "") if part)
        raise StewardError(
            f"history.{group} 必须完整包含 records、retention_hours，且不能包含未知字段；{detail}")
    for field in ("records", "retention_hours"):
        number = value[field]
        if type(number) is not int or number <= 0:
            raise StewardError(f"history.{group}.{field} 必须是正整数，布尔值无效")
        low, high = _field_range(group, field)
        if not low <= number <= high:
            raise StewardError(f"history.{group}.{field} 必须在 {low}–{high} 之间")


def validate_history(history):
    """校验显式提供的 history 段；省略整段由调用方决定是否跳过。"""
    if not isinstance(history, dict):
        raise StewardError("history 必须是对象；省略该段表示使用默认保留设置")
    missing = sorted(set(HISTORY_GROUPS) - set(history))
    unknown = sorted(str(key) for key in set(history) - set(HISTORY_GROUPS))
    if missing or unknown:
        detail = "；".join(part for part in (f"缺失 {'、'.join(missing)}" if missing else "",
                                             f"未知 {'、'.join(unknown)}" if unknown else "") if part)
        raise StewardError(f"history 必须完整包含 runs 与 gaps，且不能包含未知字段；{detail}")
    for group in HISTORY_GROUPS:
        _validate_group(history, group)
    return history


def resolve_history(value=None):
    """返回完整有效的历史保留配置；None 表示省略该段并取默认值。"""
    if value is None:
        return copy.deepcopy(DEFAULT_HISTORY)
    validate_history(value)
    return copy.deepcopy(value)
