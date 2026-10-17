"""Read-only OS observations, with bounded subprocess output."""

import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import subprocess
import time


def command(arguments, max_bytes=262144, timeout=3, input_bytes=None):
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    except OSError as exc:
        return {"ok": False, "reason": str(exc)[:200], "text": "", "bytes_read": 0}
    if input_bytes is not None:
        process.stdin.write(input_bytes)
        process.stdin.close()
    output, reason = bytearray(), None
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "command_timeout"
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, min(65536, max_bytes - len(output) + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > max_bytes:
                    reason = "command_output_limit"
                    break
            if reason:
                break
        if reason:
            os.killpg(process.pid, 9)
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except (ProcessLookupError, subprocess.TimeoutExpired):
        reason = reason or "command_timeout"
        try:
            os.killpg(process.pid, 9)
        except ProcessLookupError:
            pass
        process.wait()
    finally:
        selector.close()
        process.stdout.close()
    return {"ok": reason is None and process.returncode == 0,
            "reason": reason or (None if process.returncode == 0 else "command_failed"),
            "bytes_read": len(output),
            "text": bytes(output[:max_bytes]).decode("utf-8", "replace")}


def parse_processes(text, residents):
    rows = []
    for line in text.splitlines():
        parts = line.split(None, 9)
        if len(parts) != 10:
            continue
        try:
            pid, parent = int(parts[0]), int(parts[1])
            cpu, rss = float(parts[7]), int(parts[8]) * 1024
        except ValueError:
            continue
        executable = parts[9]
        matched = next((rule for rule in residents if rule["executable"] in [executable, Path(executable).name]), None)
        rows.append({"pid": pid, "parent_pid": parent, "started": " ".join(parts[2:7]),
                     "executable": executable, "cpu_percent": cpu, "rss_bytes": rss,
                     "identity": f"{pid}:{' '.join(parts[2:7])}:{executable}",
                     "protection": matched["reason"] if matched else "unknown; observation only"})
    return rows


def observe(policy):
    system, limits = platform.system(), policy["limits"]
    result = {"system": system, "architecture": platform.machine(), "hostname": platform.node(),
              "cpu": {"cores": os.cpu_count(), "load_average": list(os.getloadavg())},
              "gpu": {"available": False, "reason": "未取得当前平台 GPU 利用率，未尝试提权采样"},
              "model_usage": {"available": False, "reason": "未配置模型用量来源"}}
    ps = command(["ps", "-axo", "pid=,ppid=,lstart=,pcpu=,rss=,comm="], limits["command_bytes"])
    rows = parse_processes(ps["text"], policy["residents"]) if ps["ok"] else []
    rows.sort(key=lambda row: (row["protection"] == "unknown; observation only", -row["rss_bytes"]))
    result["processes"] = {"available": ps["ok"], "reason": ps["reason"], "observed": len(rows),
                           "truncated": len(rows) > limits["processes"], "items": rows[:limits["processes"]],
                           "cpu_semantics": "ps process CPU percentage; not instantaneous whole-machine utilization"}
    if system == "Darwin":
        memory = command(["vm_stat"], limits["command_bytes"])
        capacity = command(["sysctl", "-n", "hw.memsize"])
        page = re.search(r"page size of (\d+) bytes", memory["text"])
        counters = dict(re.findall(r"^(Pages [^:]+):\s+(\d+)\.", memory["text"], re.M))
        capacity_text = capacity["text"].strip()
        total_bytes = int(capacity_text) if capacity["ok"] and capacity_text.isdigit() else None
        page_size = int(page[1]) if page else None
        reason = None
        if not memory["ok"]:
            reason = "vm_stat: " + str(memory["reason"])
        elif not capacity["ok"]:
            reason = "sysctl hw.memsize: " + str(capacity["reason"])
        elif not page_size or not total_bytes:
            reason = "内存统计缺少有效页大小或物理内存容量"
        result["memory"] = {"available": reason is None,
                            "total_bytes": total_bytes, "page_size": page_size,
                            "pages": {key: int(value) for key, value in counters.items()},
                            "reason": reason}
        service = command(["launchctl", "list"], limits["command_bytes"])
        service_scope = "current launchd domain"
        services = [line.split()[-1] for line in service["text"].splitlines()[1:] if line.strip()] if service["ok"] else []
    elif system == "Linux":
        try:
            info = dict(re.findall(r"^(\w+):\s+(\d+)", Path("/proc/meminfo").read_text(), re.M))
            result["memory"] = {"available": True, "total_bytes": int(info["MemTotal"]) * 1024,
                                "available_bytes": int(info["MemAvailable"]) * 1024}
        except (OSError, KeyError, ValueError):
            result["memory"] = {"available": False, "reason": "无法读取 /proc/meminfo"}
        service = command(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain", "--no-legend"], limits["command_bytes"])
        service_scope = "system systemd manager"
        services = [line.split()[0] for line in service["text"].splitlines() if line.strip()] if service["ok"] else []
    else:
        result["memory"] = {"available": False, "reason": "当前平台未实现"}
        service, services = {"ok": False, "reason": "当前平台未实现"}, []
        service_scope = None
    result["services"] = {"available": service["ok"], "reason": service["reason"],
                          "scope": service_scope, "observed": len(services),
                          "items": services[:128], "truncated": len(services) > 128,
                          "semantics": "observed labels/units; no service health or cleanup authorization inferred"}
    storage = []
    for root in policy["roots"]:
        try:
            usage = shutil.disk_usage(root)
            storage.append({"path": root, "device": os.stat(root).st_dev,
                            "total_bytes": usage.total, "free_bytes": usage.free})
        except OSError as exc:
            storage.append({"path": root, "reason": str(exc)[:160]})
    result["storage"] = storage
    return result
