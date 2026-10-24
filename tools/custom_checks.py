"""本机约定授权的自定义检查：无 shell、有预算地执行并整形结果。"""

import os
import stat
import time

from observe import CommandFailedError, CommandOutputError, command
from policy import custom_checks
from state_io import StewardError, decode, encode


def _executable_available(path):
    try:
        info = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and os.access(path, os.X_OK)


def _definition(check):
    return {"name": check["name"], "purpose": check["purpose"], "command": list(check["command"]),
            "executable_available": _executable_available(check["command"][0])}


def _shape_output(text, limit):
    payload = text.encode("utf-8")
    total = len(payload)
    truncated = total > limit
    if truncated:
        text = payload[:limit].decode("utf-8", "replace")
    returned = len(text.encode("utf-8"))
    parsed = None
    if not truncated:
        try:
            parsed = decode(text)
            if isinstance(parsed, (dict, list)):
                # JSON 里的孤立代理项能被 json.loads 接受，但无法按 UTF-8
                # 写入报告；退回文本，保留原始转义而不是让整次检查崩溃。
                encode(parsed)
        except UnicodeEncodeError:
            parsed = None
        except (ValueError, TypeError, RecursionError):
            parsed = None
    if isinstance(parsed, (dict, list)):
        return {"format": "json", "data": parsed, "output_bytes": total,
                "returned_bytes": returned, "truncated": False}
    return {"format": "text", "output": text, "output_bytes": total,
            "returned_bytes": returned, "truncated": truncated}


def _run_one(check, state_path, timeout, capture_bytes, output_limit):
    result = {"name": check["name"], "purpose": check["purpose"]}
    environment = dict(os.environ, LC_ALL="C", HOST_STEWARD_STATE=str(state_path),
                       HOST_STEWARD_CHECK_NAME=check["name"])
    started = time.monotonic()
    try:
        text = command(check["command"], max_bytes=capture_bytes, timeout=timeout, env=environment)
    except CommandFailedError as exc:
        result.update({"status": "failed", "exit_code": exc.returncode, "reason": "命令退出码非零"})
        result.update(_shape_output(exc.output, output_limit))
    except CommandOutputError as exc:
        result.update({"status": "output_limited", "output_bytes": exc.output_bytes,
                       "reason": f"输出超过 command_bytes={exc.max_bytes}"})
    except TimeoutError as exc:
        result.update({"status": "timeout", "output_bytes": getattr(exc, "output_bytes", 0),
                       "reason": f"超过 {timeout:g} 秒"})
    except UnicodeDecodeError:
        result.update({"status": "failed", "reason": "输出不是 UTF-8"})
    except OSError as exc:
        result.update({"status": "failed", "reason": f"无法执行：{exc}"})
    else:
        result.update({"status": "ok", "exit_code": 0})
        result.update(_shape_output(text, output_limit))
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def check_report(policy, state_path, limits, name=None, run_all=False):
    """列出配置，或按本机预算运行指定检查；不读写状态数据。"""
    configured = custom_checks(policy)
    if name is not None:
        selected = [check for check in configured if check["name"] == name]
        if not selected:
            raise StewardError(f"未配置自定义检查：{name}")
    elif run_all:
        selected = configured
    else:
        return {
            "status": "custom_checks",
            "checks": [_definition(check) for check in configured],
            "count": len(configured),
            "budget": {"timeout_seconds": limits["scan_seconds"],
                       "command_bytes": limits["command_bytes"],
                       "output_bytes": limits["output_bytes"]},
            "note": "未运行脚本；使用 --name NAME 运行单项，或 --all 在 scan_seconds 总预算内运行全部",
        }
    output_budget = limits["output_bytes"]
    capture_bytes = limits["command_bytes"]
    timeout = limits["scan_seconds"]
    count = max(1, len(selected))
    output_limit = max(256, min(capture_bytes, (output_budget - 1024 - 256 * count) // count))
    started = time.monotonic()
    results = []
    skipped = 0
    for index, check in enumerate(selected):
        if run_all:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                for pending in selected[index:]:
                    results.append({"name": pending["name"], "purpose": pending["purpose"],
                                    "status": "skipped_budget",
                                    "reason": f"总预算 {timeout:g} 秒已用完"})
                    skipped += 1
                break
            per_timeout = min(timeout, remaining)
        else:
            per_timeout = timeout
        results.append(_run_one(check, state_path, per_timeout, capture_bytes, output_limit))
    failed = sum(1 for result in results if result["status"] not in ("ok", "skipped_budget"))
    return {
        "status": "custom_check_results",
        "checks": results,
        "count": len(results),
        "executed": len(results) - skipped,
        "failed": failed,
        "skipped": skipped,
        "complete": failed == 0 and skipped == 0,
        "budget": {"timeout_seconds": timeout, "command_bytes": capture_bytes,
                   "output_bytes": output_budget},
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
