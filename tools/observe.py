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


SIZE_UNITS = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4, "P": 1024 ** 5}


def parse_size(text):
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([KMGTPE]?)(?:B)?", text.strip())
    if not match:
        return None
    return int(float(match.group(1)) * SIZE_UNITS[match.group(2)])


def parse_vm_counters(text):
    counter = re.compile(r'^"?([^:"=]+?)"?\s*:\s+(\d+)\.')
    rows = {}
    for line in text.splitlines():
        match = counter.match(line.strip())
        if match:
            rows[match.group(1).strip()] = int(match.group(2))
    return rows


def parse_swapusage(text):
    values = dict(re.findall(r"(total|used|free)\s*=\s*([0-9.]+[KMGTPE]?(?:B)?)", text))
    if set(values) != {"total", "used", "free"}:
        return None
    parsed = {key: parse_size(value) for key, value in values.items()}
    if any(value is None for value in parsed.values()):
        return None
    return {"total_bytes": parsed["total"], "used_bytes": parsed["used"], "free_bytes": parsed["free"]}


def parse_boottime(text):
    match = re.search(r"sec\s*=\s*(\d+)", text)
    return int(match.group(1)) if match else None


def parse_battery(text):
    source = re.search(r"Now drawing from '([^']+)'", text)
    if not source:
        return None
    batteries = []
    for match in re.finditer(r"(\d+)%;\s*([^;]+);(?:\s*(\d+):(\d+)\s+remaining)?", text):
        batteries.append({"percent": int(match.group(1)), "status": match.group(2).strip(),
                          "remaining_minutes": int(match.group(3)) * 60 + int(match.group(4)) if match.group(3) else None})
    return {"source": source.group(1), "batteries": batteries}


def parse_thermal(text):
    details = [line.strip() for line in text.splitlines()
               if line.strip() and not line.strip().startswith("Note:")]
    return {"recorded": bool(details), "details": details[:8]}


def parse_gpu_statistics(text):
    match = re.search(r'"PerformanceStatistics"\s*=\s*\{([^}]*)\}', text)
    if not match:
        return None
    body = match.group(1)

    def number(key):
        found = re.search('"' + re.escape(key) + r'"=(\d+)', body)
        return int(found.group(1)) if found else None

    result = {"device_utilization_percent": number("Device Utilization %"),
              "renderer_utilization_percent": number("Renderer Utilization %"),
              "tiler_utilization_percent": number("Tiler Utilization %"),
              "allocated_bytes": number("Alloc system memory"),
              "in_use_bytes": number("In use system memory")}
    return result if any(value is not None for value in result.values()) else None


def parse_netstat_interfaces(text):
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9 or not parts[2].startswith("<Link#"):
            continue
        tail = []
        for token in reversed(parts[3:]):
            if not re.fullmatch(r"\d+", token):
                break
            tail.append(token)
        tail.reverse()
        if len(tail) < 6:
            continue
        counters = tail[-7:]
        try:
            rows.append({"name": parts[0].rstrip("*"),
                         "ipackets": int(counters[0]), "ierrs": int(counters[1]), "ibytes": int(counters[2]),
                         "opackets": int(counters[3]), "oerrs": int(counters[4]), "obytes": int(counters[5])})
        except (ValueError, IndexError):
            continue
    return rows


def parse_tcp_states(text):
    states = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[0] in ("tcp4", "tcp6") and re.fullmatch(r"[A-Z_]+", parts[-1]):
            states[parts[-1]] = states.get(parts[-1], 0) + 1
    return states


def parse_iostat(text):
    lines = [line for line in text.splitlines() if line.strip()]
    header = next((line for line in lines if "cpu" in line.split() and "load" in line.split()), None)
    if header is None:
        return None
    tokens = header.split()
    names = tokens[:tokens.index("cpu")]
    data = None
    for line in reversed(lines):
        try:
            data = [float(part) for part in line.split()]
        except ValueError:
            continue
        break
    if data is None or len(data) != 3 * len(names) + 6 or not names:
        return None
    disks = [{"name": names[index], "kb_per_transfer": data[3 * index],
              "transfers_per_second": data[3 * index + 1], "mb_per_second": data[3 * index + 2]}
             for index in range(len(names))]
    offset = 3 * len(names)
    cpu = {"user_percent": data[offset], "system_percent": data[offset + 1], "idle_percent": data[offset + 2]}
    return {"cpu": cpu, "disks": disks, "load_average": data[offset + 3:offset + 6]}


LINUX_TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
                    "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0a": "LISTEN", "0b": "CLOSING"}


def parse_proc_tcp_states(text):
    states = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[3].lower() not in LINUX_TCP_STATES:
            continue
        name = LINUX_TCP_STATES[parts[3].lower()]
        states[name] = states.get(name, 0) + 1
    return states


def parse_proc_net_dev(text):
    rows = []
    for line in text.splitlines()[2:]:
        name, separator, rest = line.partition(":")
        parts = rest.split()
        if not separator or len(parts) < 14:
            continue
        try:
            rows.append({"name": name.strip(),
                         "ibytes": int(parts[0]), "ipackets": int(parts[1]), "ierrs": int(parts[2]),
                         "obytes": int(parts[8]), "opackets": int(parts[9]), "oerrs": int(parts[10])})
        except ValueError:
            continue
    return rows


def parse_proc_stat(text):
    boot, cpu = None, None
    for line in text.splitlines():
        if line.startswith("btime "):
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit():
                boot = int(parts[1])
        elif line.startswith("cpu "):
            try:
                values = [int(value) for value in line.split()[1:9]]
            except ValueError:
                continue
            cpu = dict(zip(["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"], values))
    return boot, cpu


def trim_interfaces(rows, limit=64):
    if len(rows) <= limit:
        return rows, False
    ranked = sorted(rows, key=lambda row: row["ibytes"] + row["obytes"], reverse=True)[:limit]
    return sorted(ranked, key=lambda row: row["name"]), True


def observe_boot(system, limits):
    if system == "Darwin":
        response = command(["sysctl", "-n", "kern.boottime"], limits["command_bytes"])
        if not response["ok"]:
            return {"available": False, "reason": "sysctl kern.boottime: " + str(response["reason"])}
        boot = parse_boottime(response["text"])
        return {"available": boot is not None, "unix_time": boot,
                "reason": None if boot is not None else "kern.boottime 输出无法解析"}
    if system == "Linux":
        try:
            boot, _ = parse_proc_stat(Path("/proc/stat").read_text())
        except OSError:
            return {"available": False, "reason": "无法读取 /proc/stat"}
        return {"available": boot is not None, "unix_time": boot,
                "reason": None if boot is not None else "/proc/stat 缺少有效 btime"}
    return {"available": False, "reason": "当前平台未实现"}


def observe_darwin_memory(limits):
    memory = command(["vm_stat"], limits["command_bytes"])
    capacity = command(["sysctl", "-n", "hw.memsize"])
    swap = command(["sysctl", "-n", "vm.swapusage"], limits["command_bytes"])
    page = re.search(r"page size of (\d+) bytes", memory["text"])
    counters = parse_vm_counters(memory["text"])
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
    swap_result = {"available": False, "reason": None}
    if swap["ok"]:
        parsed = parse_swapusage(swap["text"])
        if parsed:
            swap_result.update({"available": True}, **parsed,
                               semantics="used 是累计高水位，当前压力看 vm_stat 的 Swapins/Swapouts 差分")
        else:
            swap_result["reason"] = "vm.swapusage 输出无法解析"
    else:
        swap_result["reason"] = "sysctl vm.swapusage: " + str(swap["reason"])
    return {"available": reason is None,
            "total_bytes": total_bytes, "page_size": page_size,
            "counters": counters if reason is None else {},
            "swap": swap_result, "reason": reason,
            "semantics": "counters 为 vm_stat 自开机原始计数：Pages* 键是页数（字节 = 页数 × page_size），"
                         "Pageins/Swapins/Compressions 等键是累计事件次数"}


def observe_linux_memory():
    try:
        info = dict(re.findall(r"^(\w+):\s+(\d+)", Path("/proc/meminfo").read_text(), re.M))
        total, available = int(info["MemTotal"]) * 1024, int(info["MemAvailable"]) * 1024
    except (OSError, KeyError, ValueError):
        return {"available": False, "reason": "无法读取 /proc/meminfo"}
    memory = {"available": True, "total_bytes": total, "available_bytes": available,
              "counters": {key: int(value) * 1024 for key, value in info.items()},
              "semantics": "counters 为 /proc/meminfo 全部键值（kB 换算字节）；Cached+SReclaimable 是可回收缓存，"
                           "AnonPages 是匿名占用，MemAvailable 已扣除可回收部分"}
    if "SwapTotal" in info and "SwapFree" in info:
        swap_total, swap_free = int(info["SwapTotal"]) * 1024, int(info["SwapFree"]) * 1024
        memory["swap"] = {"available": True, "total_bytes": swap_total,
                          "used_bytes": swap_total - swap_free, "free_bytes": swap_free,
                          "semantics": "used 是累计高水位，当前压力看换入换出差分"}
    return memory


def observe_linux_cpu():
    try:
        _, cpu = parse_proc_stat(Path("/proc/stat").read_text())
    except OSError:
        return {}
    if not cpu:
        return {}
    try:
        hz = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError):
        hz = None
    result = {"counters": cpu, "counters_semantics": "自开机累计 jiffies，跨轮差分 ÷ hz = 秒"}
    if hz:
        result["hz"] = hz
    return result


def observe_gpu(limits):
    reason = None
    for klass in ["IOGPU", "IOAccelerator"]:
        response = command(["ioreg", "-r", "-d", "1", "-w", "0", "-c", klass], limits["command_bytes"])
        reason = response["reason"]
        if not response["ok"]:
            continue
        parsed = parse_gpu_statistics(response["text"])
        if parsed:
            return dict({"available": True, "source_class": klass}, **parsed,
                        semantics="免提权 ioreg 瞬时采样；Alloc/In use system memory 是统一内存中的 GPU 占用")
    return {"available": False, "reason": "ioreg 未返回可解析的 GPU 性能统计（{}）".format(reason or "无匹配设备类")}


def observe_iostat(limits):
    response = command(["iostat", "-c", "2"], limits["command_bytes"])
    parsed = parse_iostat(response["text"]) if response["ok"] else None
    if parsed:
        utilization = dict({"available": True, "interval_seconds": 1}, **parsed["cpu"], reason=None)
        diskio = {"available": True, "interval_seconds": 1, "disks": parsed["disks"],
                  "semantics": "iostat 1 秒间隔采样速率，非累计计数器", "reason": None}
    else:
        detail = response["reason"] if not response["ok"] else "输出无法解析"
        utilization = {"available": False, "reason": "iostat: " + str(detail)}
        diskio = {"available": False, "reason": "iostat: " + str(detail)}
    return utilization, diskio


def observe_network(system, limits):
    interfaces = {"available": False, "reason": None, "items": [], "truncated": False}
    tcp_states = {"available": False, "reason": None, "states": {}, "connections": 0}
    if system == "Darwin":
        response = command(["netstat", "-ib"], limits["command_bytes"])
        rows = parse_netstat_interfaces(response["text"]) if response["ok"] else []
        if response["ok"] and rows:
            items, truncated = trim_interfaces(rows)
            interfaces.update({"available": True, "items": items, "truncated": truncated})
        elif response["ok"]:
            interfaces["reason"] = "netstat -ib 未返回可解析的接口行"
        else:
            interfaces["reason"] = "netstat -ib: " + str(response["reason"])
        connections = command(["netstat", "-an"], limits["command_bytes"])
        if connections["ok"]:
            states = parse_tcp_states(connections["text"])
            tcp_states.update({"available": True, "states": states, "connections": sum(states.values())})
        else:
            tcp_states["reason"] = "netstat -an: " + str(connections["reason"])
    elif system == "Linux":
        try:
            rows = parse_proc_net_dev(Path("/proc/net/dev").read_text())
        except OSError:
            rows = None
        if rows:
            items, truncated = trim_interfaces(rows)
            interfaces.update({"available": True, "items": items, "truncated": truncated})
        elif rows is not None:
            interfaces["reason"] = "/proc/net/dev 未返回可解析的接口行"
        else:
            interfaces["reason"] = "无法读取 /proc/net/dev"
        states = {}
        for path in ["/proc/net/tcp", "/proc/net/tcp6"]:
            try:
                states.update(parse_proc_tcp_states(Path(path).read_text()))
            except OSError:
                pass
        if states or Path("/proc/net/tcp").exists():
            tcp_states.update({"available": True, "states": states, "connections": sum(states.values())})
        else:
            tcp_states["reason"] = "无法读取 /proc/net/tcp"
    else:
        interfaces["reason"] = tcp_states["reason"] = "当前平台未实现"
    return {"available": interfaces["available"] or tcp_states["available"],
            "reason": None if (interfaces["available"] or tcp_states["available"]) else
            "；".join(str(part["reason"]) for part in (interfaces, tcp_states) if part["reason"]),
            "interfaces": interfaces, "tcp_states": tcp_states,
            "semantics": "接口计数器为自开机累计值，跨轮差分得到轮间流量；tcp 状态为采样时点直方图"}


def observe_power(system, limits):
    if system == "Darwin":
        battery = command(["pmset", "-g", "batt"], limits["command_bytes"])
        thermal = command(["pmset", "-g", "therm"], limits["command_bytes"])
        result = {"available": False, "reason": None, "source": None, "batteries": [], "thermal": None,
                  "semantics": "台式机通常只有 AC 电源、batteries 为空，属正常差异"}
        if battery["ok"]:
            parsed = parse_battery(battery["text"])
            if parsed:
                result.update({"available": True, "source": parsed["source"], "batteries": parsed["batteries"]})
            else:
                result["reason"] = "pmset -g batt 输出无法解析"
        else:
            result["reason"] = "pmset -g batt: " + str(battery["reason"])
        if thermal["ok"]:
            result["thermal"] = dict({"available": True}, **parse_thermal(thermal["text"]))
        return result
    if system == "Linux":
        try:
            entries = sorted(Path("/sys/class/power_supply").iterdir())
        except OSError:
            return {"available": False, "reason": "无法读取 /sys/class/power_supply（台式机或虚拟机常见）"}
        batteries, ac_online = [], None
        for entry in entries:
            try:
                kind = (entry / "type").read_text().strip()
            except OSError:
                continue
            if kind == "Mains":
                try:
                    ac_online = bool(int((entry / "online").read_text().strip()))
                except (OSError, ValueError):
                    pass
            elif kind == "Battery":
                battery = {}
                try:
                    battery["capacity_percent"] = int((entry / "capacity").read_text().strip())
                except (OSError, ValueError):
                    pass
                try:
                    battery["status"] = (entry / "status").read_text().strip()
                except OSError:
                    pass
                if battery:
                    batteries.append(battery)
        if not batteries and ac_online is None:
            return {"available": False, "reason": "未发现电源供应信息（台式机常见）",
                    "source": None, "batteries": [],
                    "semantics": "台式机通常没有电源供应信息，属正常差异"}
        source = "Battery" if (batteries and not ac_online) else "AC" if (ac_online or not batteries) else "AC+Battery"
        return {"available": True, "source": source, "batteries": batteries,
                "semantics": "source 由 /sys/class/power_supply 的 Mains/Battery 条目归纳"}
    return {"available": False, "reason": "当前平台未实现"}


def observe(policy):
    system, limits = platform.system(), policy["limits"]
    result = {"system": system, "architecture": platform.machine(), "hostname": platform.node(),
              "cpu": {"cores": os.cpu_count(), "load_average": list(os.getloadavg())},
              "gpu": {"available": False, "reason": "未取得当前平台 GPU 统计"},
              "model_usage": {"available": False, "reason": "未配置模型用量来源"}}
    ps = command(["ps", "-axo", "pid=,ppid=,lstart=,pcpu=,rss=,comm="], limits["command_bytes"])
    rows = parse_processes(ps["text"], policy["residents"]) if ps["ok"] else []
    rows.sort(key=lambda row: (row["protection"] == "unknown; observation only", -row["rss_bytes"]))
    result["processes"] = {"available": ps["ok"], "reason": ps["reason"], "observed": len(rows),
                           "truncated": len(rows) > limits["processes"], "items": rows[:limits["processes"]],
                           "cpu_semantics": "ps process CPU percentage; not instantaneous whole-machine utilization"}
    result["boot"] = observe_boot(system, limits)
    if system == "Darwin":
        result["memory"] = observe_darwin_memory(limits)
        service = command(["launchctl", "list"], limits["command_bytes"])
        service_scope = "current launchd domain"
        services = [line.split()[-1] for line in service["text"].splitlines()[1:] if line.strip()] if service["ok"] else []
        result["cpu"]["utilization"], result["diskio"] = observe_iostat(limits)
        result["gpu"] = observe_gpu(limits)
    elif system == "Linux":
        result["memory"] = observe_linux_memory()
        result["cpu"].update(observe_linux_cpu())
        result["gpu"]["reason"] = "Linux 无通用免提权 GPU 统计来源"
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
    result["network"] = observe_network(system, limits)
    result["power"] = observe_power(system, limits)
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


def sample_facts(host):
    facts = {}
    boot = host.get("boot") or {}
    if boot.get("available"):
        facts["boot_time"] = boot["unix_time"]
    memory = host.get("memory") or {}
    if memory.get("available"):
        memory_facts = {}
        if memory.get("counters"):
            memory_facts["counters"] = memory["counters"]
        swap = memory.get("swap") or {}
        if swap.get("available"):
            memory_facts["swap"] = {key: swap[key] for key in ("total_bytes", "used_bytes", "free_bytes")}
        if memory_facts:
            facts["memory"] = memory_facts
    cpu = host.get("cpu") or {}
    cpu_facts = {}
    if isinstance(cpu.get("counters"), dict):
        cpu_facts["counters"] = cpu["counters"]
    utilization = cpu.get("utilization") or {}
    if utilization.get("available"):
        cpu_facts["utilization"] = {key: utilization[key]
                                    for key in ("user_percent", "system_percent", "idle_percent")}
    if cpu.get("load_average") is not None:
        cpu_facts["load_average"] = cpu["load_average"]
    if cpu_facts:
        facts["cpu"] = cpu_facts
    diskio = host.get("diskio") or {}
    if diskio.get("available"):
        facts["diskio"] = diskio.get("disks", [])
    network = host.get("network") or {}
    network_facts = {}
    interfaces = network.get("interfaces") or {}
    if interfaces.get("available"):
        items = interfaces.get("items", [])
        kept = sorted(items, key=lambda row: row.get("ibytes", 0) + row.get("obytes", 0), reverse=True)[:8]
        network_facts["interfaces"] = sorted(kept, key=lambda row: row["name"])
    tcp_states = network.get("tcp_states") or {}
    if tcp_states.get("available") and tcp_states.get("states"):
        network_facts["tcp_states"] = tcp_states["states"]
    if network_facts:
        facts["network"] = network_facts
    gpu = host.get("gpu") or {}
    if gpu.get("available"):
        facts["gpu"] = {key: gpu[key] for key in
                        ("device_utilization_percent", "renderer_utilization_percent", "tiler_utilization_percent",
                         "allocated_bytes", "in_use_bytes") if key in gpu}
    power = host.get("power") or {}
    if power.get("available"):
        power_facts = {"source": power.get("source")}
        if power.get("batteries"):
            power_facts["batteries"] = power["batteries"]
        facts["power"] = power_facts
    return facts or None
