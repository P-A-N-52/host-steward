"""有预算的只读系统采集；采集和解析失败直接抛出异常。"""

import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import stat
import subprocess
import time
from collections import Counter

from state_io import StewardError
from policy import root_paths


class CommandFailedError(StewardError):
    def __init__(self, returncode, name, output, output_bytes=None):
        self.returncode = returncode
        self.name = name
        self.output = output
        self.output_bytes = (len(output.encode("utf-8"))
                             if output_bytes is None else output_bytes)
        super().__init__(f"命令退出码 {returncode}：{name}\n{output.rstrip()}")


def command(arguments, max_bytes=262144, timeout=3, input_bytes=None, metadata=None):
    if metadata is not None and not isinstance(metadata, dict):
        raise TypeError("metadata 必须是字典或 None")
    name = " ".join(arguments)
    deadline = time.monotonic() + timeout
    output = bytearray()
    if metadata is not None:
        metadata["output_bytes"] = 0
    with subprocess.Popen(arguments, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
                          env=dict(os.environ, LC_ALL="C")) as process:
        try:
            if input_bytes is not None:
                process.stdin.write(input_bytes)
                process.stdin.close()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError(f"命令超过 {timeout:g} 秒：{name}")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, min(65536, max_bytes - len(output) + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        output.extend(chunk)
                        if metadata is not None:
                            metadata["output_bytes"] = len(output)
                        if len(output) > max_bytes:
                            raise StewardError(f"命令输出超过 {max_bytes} 字节：{name}")
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            text = output.decode("utf-8")
            if metadata is not None:
                metadata["output_bytes"] = len(output)
            if process.returncode:
                raise CommandFailedError(process.returncode, name, text,
                                         output_bytes=len(output))
            return text
        except BaseException as exc:
            read_bytes = len(output)
            if metadata is not None:
                metadata["output_bytes"] = read_bytes
            try:
                exc.output_bytes = read_bytes
            except Exception:
                pass
            try:
                os.killpg(process.pid, 9)
            except ProcessLookupError:
                pass  # 进程组已自行退出。
            raise
        finally:
            process.wait()


def parse_processes(text, residents):
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 9)
        if len(parts) != 10:
            raise ValueError(f"ps 进程行字段不完整：{line}")
        pid, parent = int(parts[0]), int(parts[1])
        cpu, rss = float(parts[7]), int(parts[8]) * 1024
        executable = parts[9]
        matched = next((rule for rule in residents if rule["executable"] in [executable, Path(executable).name]), None)
        rows.append({"pid": pid, "parent_pid": parent, "started": " ".join(parts[2:7]),
                     "executable": executable, "cpu_percent": cpu, "rss_bytes": rss,
                     "identity": f"{pid}:{' '.join(parts[2:7])}:{executable}",
                     "protection": matched["reason"] if matched else "unknown; observation only"})
    if not rows:
        raise ValueError("ps 未返回进程行")
    return rows


SIZE_UNITS = {unit: 1024 ** index for index, unit in enumerate(["", "K", "M", "G", "T", "P", "E"])}


def parse_size(text):
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([KMGTPE]?)(?:B)?", text.strip())
    if not match:
        raise ValueError(f"容量值无法解析：{text}")
    return int(float(match.group(1)) * SIZE_UNITS[match.group(2)])


def parse_vm_counters(text):
    counter = re.compile(r'^"?([^:"=]+?)"?\s*:\s+(\d+)\.')
    rows = {}
    for line in text.splitlines()[1:]:
        if not line.strip():
            continue
        match = counter.match(line.strip())
        if not match:
            raise ValueError(f"vm_stat 计数器无法解析：{line}")
        rows[match.group(1).strip()] = int(match.group(2))
    if not rows:
        raise ValueError("vm_stat 没有计数器")
    return rows


def parse_swapusage(text):
    values = dict(re.findall(r"(total|used|free)\s*=\s*([0-9.]+[KMGTPE]?(?:B)?)", text))
    if set(values) != {"total", "used", "free"}:
        raise ValueError(f"vm.swapusage 缺少容量字段：{text}")
    parsed = {key: parse_size(value) for key, value in values.items()}
    return {"total_bytes": parsed["total"], "used_bytes": parsed["used"], "free_bytes": parsed["free"]}


def parse_boottime(text):
    match = re.search(r"sec\s*=\s*(\d+)", text)
    if not match:
        raise ValueError(f"kern.boottime 无法解析：{text}")
    return int(match.group(1))


def parse_battery(text):
    source = re.search(r"Now drawing from '([^']+)'", text)
    if not source:
        raise ValueError(f"pmset 电源来源无法解析：{text}")
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
    if '"PerformanceStatistics"' not in text:
        return None
    match = re.search(r'"PerformanceStatistics"\s*=\s*\{([^}]*)\}', text)
    if not match:
        raise ValueError("ioreg GPU PerformanceStatistics 结构无法解析")
    body = match.group(1)

    def number(key):
        found = re.search('"' + re.escape(key) + r'"=(\d+)', body)
        return int(found.group(1)) if found else None

    result = {"device_utilization_percent": number("Device Utilization %"),
              "renderer_utilization_percent": number("Renderer Utilization %"),
              "tiler_utilization_percent": number("Tiler Utilization %"),
              "allocated_bytes": number("Alloc system memory"),
              "in_use_bytes": number("In use system memory")}
    if not any(value is not None for value in result.values()):
        raise ValueError("ioreg GPU PerformanceStatistics 没有已知指标")
    return result


def parse_netstat_interfaces(text):
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if not parts:
            continue
        if len(parts) < 3:
            raise ValueError(f"netstat 接口行字段不完整：{line}")
        if not parts[2].startswith("<Link#"):
            continue
        tail = []
        for token in reversed(parts[3:]):
            if not re.fullmatch(r"\d+", token):
                break
            tail.append(token)
        tail.reverse()
        if len(tail) < 6:
            raise ValueError(f"netstat 接口计数器不完整：{line}")
        counters = tail[-7:]
        rows.append({"name": parts[0].rstrip("*"),
                     "ipackets": int(counters[0]), "ierrs": int(counters[1]), "ibytes": int(counters[2]),
                     "opackets": int(counters[3]), "oerrs": int(counters[4]), "obytes": int(counters[5])})
    if not rows:
        raise ValueError("netstat 没有链路接口统计")
    return rows


def parse_tcp_states(text):
    states = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] not in ("tcp4", "tcp6"):
            continue
        if len(parts) < 6 or not re.fullmatch(r"[A-Z][A-Z0-9_]*", parts[-1]):
            raise ValueError(f"netstat TCP 状态无法解析：{line}")
        states[parts[-1]] = states.get(parts[-1], 0) + 1
    return states


def parse_iostat(text):
    lines = [line for line in text.splitlines() if line.strip()]
    header = next((line for line in lines if "cpu" in line.split() and "load" in line.split()), None)
    if header is None:
        raise ValueError("iostat 缺少磁盘、CPU 和负载表头")
    tokens = header.split()
    names = tokens[:tokens.index("cpu")]
    data = [float(part) for part in lines[-1].split()]
    if len(data) != 3 * len(names) + 6 or not names:
        raise ValueError(f"iostat 最新采样字段不完整：{lines[-1]}")
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
    lines = text.splitlines()
    if not lines or not lines[0].lstrip().startswith("sl "):
        raise ValueError("/proc/net/tcp 缺少表头")
    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue
        if len(parts) < 4 or parts[3].lower() not in LINUX_TCP_STATES:
            raise ValueError(f"/proc/net/tcp 状态无法解析：{line}")
        name = LINUX_TCP_STATES[parts[3].lower()]
        states[name] = states.get(name, 0) + 1
    return states


def parse_proc_net_dev(text):
    rows = []
    for line in text.splitlines()[2:]:
        if not line.strip():
            continue
        name, separator, rest = line.partition(":")
        parts = rest.split()
        if not separator or len(parts) != 16:
            raise ValueError(f"/proc/net/dev 接口计数器不完整：{line}")
        rows.append({"name": name.strip(),
                     "ibytes": int(parts[0]), "ipackets": int(parts[1]), "ierrs": int(parts[2]),
                     "obytes": int(parts[8]), "opackets": int(parts[9]), "oerrs": int(parts[10])})
    if not rows:
        raise ValueError("/proc/net/dev 没有接口统计")
    return rows


def parse_proc_stat(text):
    boot, cpu = None, None
    for line in text.splitlines():
        if line.startswith("btime "):
            boot = int(line.split()[1])
        elif line.startswith("cpu "):
            values = [int(value) for value in line.split()[1:9]]
            if len(values) != 8:
                raise ValueError(f"/proc/stat CPU 计数器不完整：{line}")
            cpu = dict(zip(["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"], values))
    if boot is None or cpu is None:
        raise ValueError("/proc/stat 缺少 btime 或 CPU 计数器")
    return boot, cpu


def trim_interfaces(rows, limit=64):
    if len(rows) <= limit:
        return rows, False
    ranked = sorted(rows, key=lambda row: row["ibytes"] + row["obytes"], reverse=True)[:limit]
    return sorted(ranked, key=lambda row: row["name"]), True


def observe_boot(system, limits):
    if system == "Darwin":
        boot = parse_boottime(command(["sysctl", "-n", "kern.boottime"], limits["command_bytes"]))
    elif system == "Linux":
        boot, _ = parse_proc_stat(Path("/proc/stat").read_text())
    else:
        raise StewardError(f"不支持的采集平台：{system}")
    return {"available": True, "unix_time": boot, "reason": None}


def observe_darwin_memory(limits):
    memory = command(["vm_stat"], limits["command_bytes"])
    capacity = command(["sysctl", "-n", "hw.memsize"], limits["command_bytes"])
    swap = command(["sysctl", "-n", "vm.swapusage"], limits["command_bytes"])
    page = re.search(r"page size of (\d+) bytes", memory)
    if not page:
        raise ValueError("vm_stat 缺少页大小")
    page_size, total_bytes = int(page[1]), int(capacity.strip())
    if page_size <= 0 or total_bytes <= 0:
        raise ValueError("内存页大小或物理容量不是正数")
    return {"available": True, "total_bytes": total_bytes, "page_size": page_size,
            "counters": parse_vm_counters(memory),
            "swap": dict(parse_swapusage(swap), available=True,
                         semantics="used 是累计高水位，当前压力看 vm_stat 的 Swapins/Swapouts 差分"),
            "reason": None,
            "semantics": "counters 为 vm_stat 自开机原始计数：Pages* 键是页数（字节 = 页数 × page_size），"
                         "Pageins/Swapins/Compressions 等键是累计事件次数"}


def observe_linux_memory():
    info = dict(re.findall(r"^(\w+):\s+(\d+)", Path("/proc/meminfo").read_text(), re.M))
    total, available = int(info["MemTotal"]) * 1024, int(info["MemAvailable"]) * 1024
    memory = {"available": True, "total_bytes": total, "available_bytes": available,
              "counters": {key: int(value) * 1024 for key, value in info.items()},
              "semantics": "counters 为 /proc/meminfo 全部键值（kB 换算字节）；Cached+SReclaimable 是可回收缓存，"
                           "AnonPages 是匿名占用，MemAvailable 已扣除可回收部分"}
    swap_total, swap_free = int(info["SwapTotal"]) * 1024, int(info["SwapFree"]) * 1024
    memory["swap"] = {"available": True, "total_bytes": swap_total,
                      "used_bytes": swap_total - swap_free, "free_bytes": swap_free,
                      "semantics": "used 是累计高水位，当前压力看换入换出差分"}
    return memory


def observe_linux_cpu():
    _, cpu = parse_proc_stat(Path("/proc/stat").read_text())
    return {"counters": cpu, "hz": os.sysconf("SC_CLK_TCK"),
            "counters_semantics": "自开机累计 jiffies，跨轮差分 ÷ hz = 秒"}


def observe_gpu(limits):
    klass = "IOGPU" if platform.machine() == "arm64" else "IOAccelerator"
    parsed = parse_gpu_statistics(command(["ioreg", "-r", "-d", "1", "-w", "0", "-c", klass], limits["command_bytes"]))
    if parsed is None:
        return {"available": False, "reason": f"{klass} 没有 PerformanceStatistics 属性"}
    return dict(parsed, available=True, source_class=klass,
                semantics="免提权 ioreg 瞬时采样；Alloc/In use system memory 是统一内存中的 GPU 占用")


def observe_iostat(limits):
    parsed = parse_iostat(command(["iostat", "-c", "2"], limits["command_bytes"]))
    utilization = dict(parsed["cpu"], available=True, interval_seconds=1, reason=None)
    diskio = {"available": True, "interval_seconds": 1, "disks": parsed["disks"],
              "semantics": "iostat 1 秒间隔采样速率，非累计计数器", "reason": None}
    return utilization, diskio


def observe_network(system, limits):
    if system == "Darwin":
        rows = parse_netstat_interfaces(command(["netstat", "-ib"], limits["command_bytes"]))
        states = parse_tcp_states(command(["netstat", "-an"], limits["command_bytes"]))
    elif system == "Linux":
        rows = parse_proc_net_dev(Path("/proc/net/dev").read_text())
        states = Counter(parse_proc_tcp_states(Path("/proc/net/tcp").read_text()))
        # 内核未启用 IPv6 时没有 tcp6 文件；其他读取错误直接抛出。
        try:
            tcp6 = Path("/proc/net/tcp6").read_text()
        except FileNotFoundError:
            tcp6 = None
        if tcp6 is not None:
            states.update(parse_proc_tcp_states(tcp6))
    else:
        raise StewardError(f"不支持的采集平台：{system}")
    items, truncated = trim_interfaces(rows)
    return {"available": True, "reason": None,
            "interfaces": {"available": True, "reason": None, "items": items, "truncated": truncated},
            "tcp_states": {"available": True, "reason": None, "states": dict(states), "connections": sum(states.values())},
            "semantics": "接口计数器为自开机累计值，跨轮差分得到轮间流量；tcp 状态为采样时点直方图"}


def observe_power(system, limits):
    if system == "Darwin":
        battery = command(["pmset", "-g", "batt"], limits["command_bytes"])
        thermal = command(["pmset", "-g", "therm"], limits["command_bytes"])
        return dict(parse_battery(battery), available=True, reason=None,
                    thermal=dict(parse_thermal(thermal), available=True),
                    semantics="台式机通常只有 AC 电源、batteries 为空，属正常差异")
    if system == "Linux":
        try:
            entries = sorted(Path("/sys/class/power_supply").iterdir())
        except FileNotFoundError:
            return {"available": False, "reason": "内核没有 power_supply 设备目录"}
        batteries, ac_online = [], None
        for entry in entries:
            kind = (entry / "type").read_text().strip()
            if kind == "Mains":
                ac_online = bool(int((entry / "online").read_text().strip()))
            elif kind == "Battery":
                batteries.append({"capacity_percent": int((entry / "capacity").read_text().strip()),
                                  "status": (entry / "status").read_text().strip()})
        if not batteries and ac_online is None:
            return {"available": False, "reason": "未发现电源供应信息（台式机常见）",
                    "source": None, "batteries": [],
                    "semantics": "台式机通常没有电源供应信息，属正常差异"}
        source = "Battery" if (batteries and not ac_online) else "AC" if (ac_online or not batteries) else "AC+Battery"
        return {"available": True, "source": source, "batteries": batteries,
                "semantics": "source 由 /sys/class/power_supply 的 Mains/Battery 条目归纳"}
    raise StewardError(f"不支持的采集平台：{system}")


def observe(policy):
    system, limits = platform.system(), policy["limits"]
    result = {"system": system, "architecture": platform.machine(), "hostname": platform.node(),
              "cpu": {"cores": os.cpu_count(), "load_average": list(os.getloadavg())},
              "gpu": {"available": False, "reason": "未取得当前平台 GPU 统计"},
              "model_usage": {"available": False, "reason": "未配置模型用量来源"}}
    ps = command(["ps", "-axo", "pid=,ppid=,lstart=,pcpu=,rss=,comm="], limits["command_bytes"])
    rows = parse_processes(ps, policy["residents"])
    rows.sort(key=lambda row: (row["protection"] == "unknown; observation only", -row["rss_bytes"]))
    result["processes"] = {"available": True, "reason": None, "observed": len(rows),
                           "truncated": len(rows) > limits["processes"], "items": rows[:limits["processes"]],
                           "cpu_semantics": "ps process CPU percentage; not instantaneous whole-machine utilization"}
    result["boot"] = observe_boot(system, limits)
    if system == "Darwin":
        result["memory"] = observe_darwin_memory(limits)
        service = command(["launchctl", "list"], limits["command_bytes"])
        service_scope = "current launchd domain"
        services = [line.split()[-1] for line in service.splitlines()[1:] if line.strip()]
        result["cpu"]["utilization"], result["diskio"] = observe_iostat(limits)
        result["gpu"] = observe_gpu(limits)
    elif system == "Linux":
        result["memory"] = observe_linux_memory()
        result["cpu"].update(observe_linux_cpu())
        result["gpu"]["reason"] = "Linux 无通用免提权 GPU 统计来源"
        service = command(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain", "--no-legend"], limits["command_bytes"])
        service_scope = "system systemd manager"
        services = [line.split()[0] for line in service.splitlines() if line.strip()]
    else:
        raise StewardError(f"不支持的采集平台：{system}")
    result["services"] = {"available": True, "reason": None,
                          "scope": service_scope, "observed": len(services),
                          "items": services[:128], "truncated": len(services) > 128,
                          "semantics": "observed labels/units; no service health or cleanup authorization inferred"}
    result["network"] = observe_network(system, limits)
    result["power"] = observe_power(system, limits)
    storage, volumes = [], {}
    for root in root_paths(policy):
        try:
            info = os.stat(root)
            if not stat.S_ISDIR(info.st_mode):
                storage.append({"path": root, "available": False, "reason": f"观察根不是目录：{root}"[:200]})
                continue
            device = info.st_dev
            if device not in volumes:
                volumes[device] = shutil.disk_usage(root)
        except FileNotFoundError as exc:
            storage.append({"path": root, "available": False, "reason": f"观察根暂不可见：{exc}"[:200]})
            continue
        except OSError as exc:
            storage.append({"path": root, "available": False, "reason": f"观察根无法取得容量：{exc}"[:200]})
            continue
        usage = volumes[device]
        storage.append({"path": root, "device": device, "available": True,
                        "total_bytes": usage.total, "free_bytes": usage.free})
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
