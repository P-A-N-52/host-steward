"""Linux /proc 资源采集：有界读取、明确来源与单位，真实 I/O 和解析失败直接抛出。

模块只读取调用方给定的 proc/sys 根目录，不根据运行平台切换来源，也不 sleep 或保存历史。
预算耗尽与单文件读取上限使用独立的 StewardError 子类，和权限等执行失败区分。
"""

import heapq
import math
import os
from pathlib import Path
import re
import time

from state_io import StewardError


DEFAULT_PROC_ROOT = "/proc"
DEFAULT_SYS_ROOT = "/sys"
SECTOR_BYTES = 512
DEFAULT_READ_BYTES = 1024 * 1024
CPU_STAT_BYTES = 64 * 1024
MEMINFO_BYTES = 256 * 1024
DISKSTATS_BYTES = 1024 * 1024
NET_DEV_BYTES = 1024 * 1024
PID_STAT_BYTES = 8192
SYSFS_VALUE_BYTES = 512

CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
NET_DEV_FIELDS = (
    "ibytes", "ipackets", "ierrs", "idrop", "ififo", "iframe", "icompressed", "imulticast",
    "obytes", "opackets", "oerrs", "odrop", "ofifo", "ocollisions", "ocarrier", "ocompressed",
)
PID_NAME = re.compile(r"^[0-9]+$")
CPU_NAME = re.compile(r"^cpu[0-9]+$")
MEMINFO_LINE = re.compile(r"^([^:\s]+):\s+(\d+)(?:\s+([A-Za-z]+))?\s*$")


class LinuxBudgetExceededError(StewardError):
    """累计命令字节或单调时间预算已耗尽；不是权限或 I/O 失败。"""

    def __init__(self, kind, source, *, limit=None, observed=None, detail=None):
        self.kind = kind
        self.source = os.fspath(source)
        self.limit = limit
        self.observed = observed
        if kind == "time":
            message = f"Linux 采集超过时间预算：{self.source}"
        elif kind == "command_bytes":
            message = f"Linux 采集超过字节预算：{self.source}"
        else:
            message = f"Linux 采集预算耗尽（{kind}）：{self.source}"
        if limit is not None:
            message += f"；上限 {limit}"
        if observed is not None:
            message += f"，已用或需要 {observed}"
        if detail:
            message += f"；{detail}"
        super().__init__(message)


class LinuxReadLimitError(StewardError):
    """单个来源超过本次读取上限；不会返回截断内容。"""

    def __init__(self, source, limit, observed=None):
        self.source = os.fspath(source)
        self.limit = limit
        self.observed = observed
        message = f"Linux 来源超过单次读取上限：{self.source}；上限 {limit}"
        if observed is not None:
            message += f"，实际或至少 {observed}"
        super().__init__(message)


class LinuxBudget:
    """一次采集共享的累计字节预算与单调时钟 deadline。"""

    def __init__(self, command_bytes, seconds, *, clock=None):
        if isinstance(command_bytes, bool) or not isinstance(command_bytes, int):
            raise TypeError("command_bytes 必须是整数")
        if command_bytes < 0:
            raise ValueError("command_bytes 不能为负数")
        try:
            seconds = float(seconds)
        except (TypeError, ValueError) as exc:
            raise TypeError("seconds 必须是有限非负数") from exc
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("seconds 必须是有限非负数")
        self.command_bytes = command_bytes
        self.seconds = seconds
        self._clock = clock or time.monotonic
        self.started_at = self._clock()
        self.deadline = self.started_at + seconds
        self.used_bytes = 0
        self.reads = 0

    @property
    def remaining_seconds(self):
        return max(0.0, self.deadline - self._clock())

    @property
    def remaining_bytes(self):
        return max(0, self.command_bytes - self.used_bytes)

    def check_time(self, source):
        remaining = self.deadline - self._clock()
        if remaining <= 0:
            raise LinuxBudgetExceededError(
                "time", source, limit=self.seconds,
                observed=self.seconds + max(0.0, -remaining),
                detail="单调时钟 deadline 已到")

    def consume(self, source, count):
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("预算计数必须是非负整数")
        remaining = self.remaining_bytes
        self.used_bytes += count
        self.reads += 1
        if count > remaining:
            raise LinuxBudgetExceededError(
                "command_bytes", source, limit=self.command_bytes,
                observed=self.used_bytes,
                detail=f"本次已读 {count} 字节，读取前剩余 {remaining} 字节")
        self.check_time(source)


class LinuxSource:
    """固定根目录的有界读取器；测试可用读函数替换实际文件访问。"""

    def __init__(self, proc_root=DEFAULT_PROC_ROOT, sys_root=DEFAULT_SYS_ROOT, *,
                 read_bytes=None, readlink=None, listdir=None, sysconf=None, loadavg=None):
        self.proc_root = Path(proc_root)
        self.sys_root = Path(sys_root)
        self._read_bytes = read_bytes
        self._readlink = readlink or os.readlink
        self._listdir = listdir
        self._sysconf = sysconf or os.sysconf
        self._loadavg = loadavg or os.getloadavg

    def proc_path(self, *parts):
        return self.proc_root.joinpath(*parts)

    def sys_path(self, *parts):
        return self.sys_root.joinpath(*parts)

    def read_bytes(self, path, budget, *, max_bytes=DEFAULT_READ_BYTES):
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("max_bytes 必须是正整数")
        path = os.fspath(path)
        budget.check_time(path)
        if budget.remaining_bytes <= 0:
            raise LinuxBudgetExceededError(
                "command_bytes", path, limit=budget.command_bytes,
                observed=budget.used_bytes, detail="没有剩余字节预算")
        if self._read_bytes is not None:
            allowed = min(max_bytes, budget.remaining_bytes)
            data = self._read_bytes(path, allowed)
            if not isinstance(data, (bytes, bytearray)):
                raise TypeError(f"注入的读取函数必须返回 bytes：{path}")
            data = bytes(data)
            budget.consume(path, len(data))
            if len(data) > max_bytes:
                raise LinuxReadLimitError(path, max_bytes, len(data))
            return data
        return self._read_real(path, budget, max_bytes)

    def _read_real(self, path, budget, max_bytes):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            limit = min(max_bytes, budget.remaining_bytes)
            if limit <= 0:
                raise LinuxBudgetExceededError(
                    "command_bytes", path, limit=budget.command_bytes,
                    observed=budget.used_bytes, detail="没有剩余字节预算")
            chunks = []
            total = 0
            while total < limit:
                budget.check_time(path)
                chunk = os.read(fd, min(65536, limit - total))
                budget.consume(path, len(chunk))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            data = b"".join(chunks)
            if total == limit:
                budget.check_time(path)
                probe = os.read(fd, 1)
                budget.consume(path, len(probe))
                if probe:
                    raise LinuxReadLimitError(path, max_bytes, total + 1)
            return data
        finally:
            os.close(fd)

    def read_text(self, path, budget, *, max_bytes=DEFAULT_READ_BYTES):
        return self.read_bytes(path, budget, max_bytes=max_bytes).decode("utf-8")

    def read_link(self, path):
        return os.fsdecode(self._readlink(os.fspath(path)))

    def iter_names(self, path):
        path = os.fspath(path)
        if self._listdir is not None:
            for name in self._listdir(path):
                yield os.fspath(getattr(name, "name", name))
            return
        with os.scandir(path) as entries:
            for entry in entries:
                yield entry.name

    def sysconf(self, name):
        return self._sysconf(name)

    def load_average(self):
        return list(self._loadavg())


def _selected_source(source, proc_root, sys_root):
    if source is not None:
        return source
    return LinuxSource(proc_root=proc_root, sys_root=sys_root)


def _nonnegative_int(value, label):
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} 不是整数：{value!r}") from exc
    if result < 0:
        raise ValueError(f"{label} 不能为负数：{result}")
    return result


def _bounded_int(value, label, minimum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} 必须是整数")
    if value < minimum:
        raise ValueError(f"{label} 不能小于 {minimum}")
    return value


def _positive_sysconf(source, name):
    try:
        value = source.sysconf(name)
    except (ValueError, OSError) as exc:
        raise ValueError(f"无法取得 sysconf {name}：{exc}") from exc
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"sysconf {name} 不是正整数：{value!r}")
    return value


def _read_btime(text):
    values = []
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] == "btime":
            if len(parts) != 2:
                raise ValueError(f"/proc/stat 的 btime 行无法解析：{line}")
            values.append(_nonnegative_int(parts[1], "btime"))
    if len(values) != 1:
        raise ValueError(f"/proc/stat 应恰好包含一个 btime，实际 {len(values)} 个")
    return values[0]


def _boot_facts(budget, source):
    btime = _read_btime(source.read_text(
        source.proc_path("stat"), budget, max_bytes=CPU_STAT_BYTES))
    boot_id_path = source.proc_path("sys", "kernel", "random", "boot_id")
    try:
        raw_boot_id = source.read_text(boot_id_path, budget, max_bytes=256)
    except FileNotFoundError:
        boot_id = None
        fallback = "btime"
        reason = "boot_id 不存在；使用 /proc/stat btime 作为开机时间，缺少跨重启稳定身份"
    else:
        boot_id = raw_boot_id.strip()
        if not boot_id or any(character.isspace() for character in boot_id):
            raise ValueError(f"boot_id 无法解析：{raw_boot_id!r}")
        fallback = None
        reason = None
    return {
        "available": True,
        "reason": reason,
        "source": "/proc/sys/kernel/random/boot_id + /proc/stat btime",
        "boot_id": boot_id,
        "identity": boot_id or f"btime:{btime}",
        "identity_kind": "boot_id" if boot_id else "btime",
        "fallback": fallback,
        "unix_time": btime,
        "btime": btime,
        "semantics": "boot_id 是本次开机身份；btime 是 /proc/stat 的开机 Unix 秒，始终保留",
    }


def observe_boot(budget, *, proc_root=DEFAULT_PROC_ROOT, sys_root=DEFAULT_SYS_ROOT, source=None):
    """读取 boot_id，并保留 /proc/stat btime；只有 boot_id 缺失时回退 btime。"""
    return _boot_facts(budget, _selected_source(source, proc_root, sys_root))


def _parse_cpu_stat(text):
    counters = None
    cores = 0
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "cpu":
            if counters is not None:
                raise ValueError("/proc/stat 出现重复的 cpu 聚合行")
            if len(parts) < len(CPU_FIELDS) + 1:
                raise ValueError(f"/proc/stat CPU 计数器不完整：{line}")
            values = [_nonnegative_int(value, "CPU 计数器") for value in parts[1:len(CPU_FIELDS) + 1]]
            counters = dict(zip(CPU_FIELDS, values))
        elif CPU_NAME.match(parts[0]):
            if len(parts) < len(CPU_FIELDS) + 1:
                raise ValueError(f"/proc/stat 逐 CPU 计数器不完整：{line}")
            for value in parts[1:len(CPU_FIELDS) + 1]:
                _nonnegative_int(value, "逐 CPU 计数器")
            cores += 1
    if counters is None:
        raise ValueError("/proc/stat 缺少 cpu 聚合行")
    if cores <= 0:
        raise ValueError("/proc/stat 缺少逐 CPU 行，cores 无法核对")
    return counters, cores


def observe_cpu(budget, *, proc_root=DEFAULT_PROC_ROOT, sys_root=DEFAULT_SYS_ROOT, source=None):
    """读取聚合 CPU 累计 jiffies、SC_CLK_TCK、负载与在线 CPU 行数。"""
    source = _selected_source(source, proc_root, sys_root)
    text = source.read_text(source.proc_path("stat"), budget, max_bytes=CPU_STAT_BYTES)
    counters, cores = _parse_cpu_stat(text)
    return {
        "available": True,
        "reason": None,
        "source": "/proc/stat",
        "counters": counters,
        "hz": _positive_sysconf(source, "SC_CLK_TCK"),
        "counters_unit": "jiffies",
        "cores": cores,
        "load_average": source.load_average(),
        "counters_semantics": "自开机累计 jiffies，跨轮差分除以 hz 才是时间；不是瞬时百分比。"
                              " guest 与 guest_nice 已分别包含在 user 与 nice 中，本结构不重复列出，"
                              "避免求和时再次叠加",
    }


def _parse_meminfo(text):
    counters = {}
    units = {}
    source_units = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        match = MEMINFO_LINE.match(line)
        if match is None:
            raise ValueError(f"/proc/meminfo 行无法解析：{line}")
        key, raw_value, unit = match.group(1), match.group(2), match.group(3)
        if key in counters:
            raise ValueError(f"/proc/meminfo 出现重复字段：{key}")
        value = _nonnegative_int(raw_value, f"/proc/meminfo {key}")
        if unit == "kB":
            counters[key] = value * 1024
            units[key] = "bytes"
        elif unit is None:
            counters[key] = value
            units[key] = "count"
        else:
            counters[key] = value
            units[key] = unit
        source_units[key] = unit
    return counters, units, source_units


def _require_meminfo_kb(key, counters, source_units):
    if key not in counters:
        raise ValueError(f"/proc/meminfo 缺少关键字段：{key}")
    if source_units[key] != "kB":
        raise ValueError(f"/proc/meminfo {key} 的单位应为 kB，实际为 {source_units[key]!r}")
    return counters[key]


def observe_memory(budget, *, proc_root=DEFAULT_PROC_ROOT, sys_root=DEFAULT_SYS_ROOT, source=None):
    """读取 /proc/meminfo；kB 换字节，无单位计数保持原值。"""
    source = _selected_source(source, proc_root, sys_root)
    text = source.read_text(source.proc_path("meminfo"), budget, max_bytes=MEMINFO_BYTES)
    counters, units, source_units = _parse_meminfo(text)
    total_bytes = _require_meminfo_kb("MemTotal", counters, source_units)
    if total_bytes <= 0:
        raise ValueError("/proc/meminfo MemTotal 必须大于零")
    swap_total = _require_meminfo_kb("SwapTotal", counters, source_units)
    swap_free = _require_meminfo_kb("SwapFree", counters, source_units)
    if swap_free > swap_total:
        raise ValueError("SwapFree 大于 SwapTotal，内存字段不一致")

    platform_gaps = []
    if "MemAvailable" in counters:
        if source_units["MemAvailable"] != "kB":
            raise ValueError(
                f"/proc/meminfo MemAvailable 的单位应为 kB，实际为 {source_units['MemAvailable']!r}")
        available_bytes = counters["MemAvailable"]
        available_reason = None
        if available_bytes > total_bytes:
            raise ValueError("MemAvailable 大于 MemTotal，内存字段不一致")
    else:
        available_bytes = None
        available_reason = "旧内核 /proc/meminfo 未提供 MemAvailable；不伪造推导值"
        platform_gaps.append({"field": "MemAvailable", "reason": available_reason})

    return {
        "available": True,
        "reason": None,
        "source": "/proc/meminfo",
        "total_bytes": total_bytes,
        "available_bytes": available_bytes,
        "available_reason": available_reason,
        "counters": counters,
        "units": units,
        "source_units": source_units,
        "platform_gaps": platform_gaps,
        "swap": {
            "available": True,
            "total_bytes": swap_total,
            "free_bytes": swap_free,
            "used_bytes": swap_total - swap_free,
            "semantics": "used_bytes 是采样时点 total-free 的当前值，不保证是历史高水位；本模块不保存历史，"
                          "历史峰值需由采集方自行记录，不能把当前值当峰值",
        },
        "units_semantics": "units=bytes 表示来源单位 kB 已乘 1024；units=count 表示来源无单位计数，"
                           "保持原值（例如 HugePages_Total/Free/Rsvd/Surp）；其他单位不换算，保持原数值",
    }


def _parse_diskstats(text):
    rows = []
    seen_keys = set()
    seen_names = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) < 14:
            raise ValueError(f"/proc/diskstats 行字段不完整：{line}")
        major = _nonnegative_int(parts[0], "diskstats major")
        minor = _nonnegative_int(parts[1], "diskstats minor")
        name = parts[2]
        if not name:
            raise ValueError(f"/proc/diskstats 缺少设备名：{line}")
        key = (major, minor)
        if key in seen_keys or name in seen_names:
            raise ValueError(f"/proc/diskstats 出现重复设备：{name} {major}:{minor}")
        seen_keys.add(key)
        seen_names.add(name)
        values = [_nonnegative_int(value, f"diskstats {name}") for value in parts[3:14]]
        row = {
            "major": major,
            "minor": minor,
            "name": name,
            "reads_completed": values[0],
            "reads_merged": values[1],
            "sectors_read": values[2],
            "read_time_ms": values[3],
            "writes_completed": values[4],
            "writes_merged": values[5],
            "sectors_written": values[6],
            "write_time_ms": values[7],
            "in_flight": values[8],
            "io_time_ms": values[9],
            "weighted_io_time_ms": values[10],
        }
        row["read_bytes"] = row["sectors_read"] * SECTOR_BYTES
        row["write_bytes"] = row["sectors_written"] * SECTOR_BYTES
        if len(parts) >= 18:
            discard_values = [_nonnegative_int(value, f"diskstats {name} discard")
                              for value in parts[14:18]]
            row.update({
                "discards_completed": discard_values[0],
                "discards_merged": discard_values[1],
                "sectors_discarded": discard_values[2],
                "discard_time_ms": discard_values[3],
            })
        if len(parts) >= 20:
            flush_values = [_nonnegative_int(value, f"diskstats {name} flush")
                            for value in parts[18:20]]
            row.update({
                "flushes_completed": flush_values[0],
                "flush_time_ms": flush_values[1],
            })
        if len(parts) > 20:
            row["unparsed_fields"] = parts[20:]
        rows.append(row)
    return rows


def _optional_sysfs_text(source, budget, path):
    try:
        return source.read_text(path, budget, max_bytes=SYSFS_VALUE_BYTES), None
    except (OSError, UnicodeError) as exc:
        return None, exc


def _partition_evidence(source, budget, major, minor):
    base = source.sys_path("dev", "block", f"{major}:{minor}")
    try:
        raw = source.read_text(base / "partition", budget, max_bytes=SYSFS_VALUE_BYTES)
    except FileNotFoundError:
        try:
            os.stat(base)
        except FileNotFoundError:
            return None, None, "sysfs 中没有该块设备条目"
        except OSError as exc:
            return None, None, f"sysfs 设备条目无法检查：{type(exc).__name__}: {exc}"
        return False, None, None
    except OSError as exc:
        return None, None, f"sysfs 分区标记不可读：{type(exc).__name__}: {exc}"
    try:
        index = int(raw.strip())
    except ValueError:
        return None, None, f"sysfs 分区标记无法解析：{raw!r}"
    if index <= 0:
        return None, None, f"sysfs 分区标记不是正整数：{raw!r}"
    return True, index, None


def _device_identity(source, budget, major, minor):
    base = source.sys_path("dev", "block", f"{major}:{minor}")
    candidates = (
        ("device/wwid", "device/wwid"),
        ("wwid", "wwid"),
        ("device/serial", "device/serial"),
        ("device/unique_id", "device/unique_id"),
    )
    errors = []
    for relative, label in candidates:
        raw, error = _optional_sysfs_text(source, budget, base / relative)
        if raw is not None:
            value = raw.strip()
            if value:
                return value, f"sysfs:{label}", None
            errors.append(f"{label} 为空")
        elif not isinstance(error, FileNotFoundError):
            errors.append(f"{label} 不可读（{type(error).__name__}: {error}）")
    reason = "sysfs 未提供 wwid/serial/unique_id"
    if errors:
        reason += "；" + "；".join(errors)
    return None, None, reason


def _device_class(source, major, minor, partition):
    if partition is True:
        return "partition"
    if partition is not False:
        return "unknown"
    base = source.sys_path("dev", "block", f"{major}:{minor}")
    for marker in ("dm", "md", "loop"):
        if os.path.isdir(base / marker):
            return "virtual:" + marker
    try:
        os.stat(base)
    except OSError:
        return "unknown"
    return "whole"


def observe_diskio(budget, *, proc_root=DEFAULT_PROC_ROOT, sys_root=DEFAULT_SYS_ROOT, source=None):
    """读取 /proc/diskstats 累计计数，固定 512 字节扇区，并标注不可相加。"""
    source = _selected_source(source, proc_root, sys_root)
    text = source.read_text(source.proc_path("diskstats"), budget, max_bytes=DISKSTATS_BYTES)
    rows = _parse_diskstats(text)
    if not rows:
        return {
            "available": False,
            "reason": "/proc/diskstats 没有块设备计数",
            "source": "/proc/diskstats",
            "devices": [],
            "disks": [],
            "observed": 0,
            "truncated": False,
            "non_additive": True,
            "aggregation": "non_additive",
            "sector_bytes": SECTOR_BYTES,
            "comparison_gaps": [],
            "lifecycle_evidence": {"stable_identity": 0, "without_identity": 0},
            "semantics": "没有设备是能力结果，不是解析失败",
        }

    comparison_gaps = []
    for row in rows:
        partition, partition_index, partition_reason = _partition_evidence(
            source, budget, row["major"], row["minor"])
        identity, identity_source, identity_reason = _device_identity(
            source, budget, row["major"], row["minor"])
        row.update({
            "partition": partition,
            "partition_index": partition_index,
            "device_type": _device_class(source, row["major"], row["minor"], partition),
            "identity": identity,
            "identity_source": identity_source,
            "identity_reason": identity_reason,
            "additive": False,
        })
        if partition_reason:
            row["partition_reason"] = partition_reason
        if identity is None:
            comparison_gaps.append({
                "device": row["name"],
                "major": row["major"],
                "minor": row["minor"],
                "partition": partition,
                "reason": identity_reason,
            })
    return {
        "available": True,
        "reason": None,
        "source": "/proc/diskstats",
        "devices": rows,
        "disks": rows,
        "observed": len(rows),
        "truncated": False,
        "non_additive": True,
        "aggregation": "non_additive",
        "sector_bytes": SECTOR_BYTES,
        "comparison_gaps": comparison_gaps,
        "lifecycle_evidence": {
            "stable_identity": len(rows) - len(comparison_gaps),
            "without_identity": len(comparison_gaps),
        },
        "semantics": "内核 diskstats 扇区固定为 512 字节，不用 hw_sector_size 改算；读写完成数、扇区、"
                     "累计字节、毫秒耗时、in_flight 与 io_time 均为内核原义。分区、dm、md、整盘之间"
                     "不可盲目求和；无稳定 identity 时比较缺口交给查询层断开旧生命周期",
    }


def _parse_net_dev(text):
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) >= 2 and "|" in lines[0] and "|" in lines[1]:
        lines = lines[2:]
    rows = []
    seen = set()
    for line in lines:
        fields = line.rsplit(":", 1)
        if len(fields) != 2:
            raise ValueError(f"/proc/net/dev 行无法解析：{line}")
        name, rest = fields
        name = name.strip()
        if not name:
            raise ValueError(f"/proc/net/dev 行无法解析：{line}")
        parts = rest.split()
        if len(parts) != len(NET_DEV_FIELDS):
            raise ValueError(f"/proc/net/dev 接口计数器不完整：{line}")
        if name in seen:
            raise ValueError(f"/proc/net/dev 出现重复接口：{name}")
        seen.add(name)
        values = [_nonnegative_int(value, f"/proc/net/dev {name}") for value in parts]
        row = {"name": name}
        row.update(zip(NET_DEV_FIELDS, values))
        row["total_bytes"] = row["ibytes"] + row["obytes"]
        rows.append(row)
    return rows


def _interface_ifindex(source, budget, name):
    path = source.sys_path("class", "net", name, "ifindex")
    try:
        raw = source.read_text(path, budget, max_bytes=32)
    except FileNotFoundError as exc:
        return None, None, f"sysfs ifindex 缺失：{exc}"
    value = raw.strip()
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise ValueError(f"sysfs ifindex 不是严格正整数：{name} {raw!r}")
    return int(value), f"sysfs:class/net/{name}/ifindex", None


def observe_network(budget, *, proc_root=DEFAULT_PROC_ROOT, sys_root=DEFAULT_SYS_ROOT,
                    source=None, limit=64):
    """读取 /proc/net/dev 累计接口计数，按流量保留有界条数。"""
    limit = _bounded_int(limit, "limit", 1)
    source = _selected_source(source, proc_root, sys_root)
    text = source.read_text(source.proc_path("net", "dev"), budget, max_bytes=NET_DEV_BYTES)
    rows = _parse_net_dev(text)
    observed = len(rows)
    truncated = observed > limit
    if truncated:
        ranked = sorted(rows, key=lambda row: (-row["total_bytes"], row["name"]))[:limit]
        items = sorted(ranked, key=lambda row: row["name"])
    else:
        items = rows
    comparison_gaps = []
    for row in items:
        ifindex, identity_source, identity_reason = _interface_ifindex(source, budget, row["name"])
        row.update({
            "ifindex": ifindex,
            "identity": f"ifindex:{ifindex}" if ifindex is not None else None,
            "identity_source": identity_source,
            "identity_reason": identity_reason,
        })
        if ifindex is None:
            comparison_gaps.append({
                "interface": row["name"],
                "reason": identity_reason,
            })
    available = bool(rows)
    reason = None if available else "/proc/net/dev 没有接口累计计数"
    return {
        "available": available,
        "reason": reason,
        "source": "/proc/net/dev",
        "interfaces": {
            "available": available,
            "reason": reason,
            "observed": observed,
            "returned": len(items),
            "omitted": observed - len(items),
            "limit": limit,
            "truncated": truncated,
            "items": items,
        },
        "comparison_gaps": comparison_gaps,
        "tcp_states": {
            "available": False,
            "reason": "本模块未启用 /proc/net/tcp 采集；接口累计计数不包含连接状态",
            "states": None,
            "connections": None,
        },
        "identity_semantics": "ifindex 是接口生命周期证据；name 可能被复用，不能仅凭 name 跨轮拼接速率",
        "semantics": "接口字节、包、错误等为自开机累计值；跨轮差分使用 ifindex 作为身份，"
                     "truncated 只表示展示条数受限，不代表未读取的接口为零",
    }


def _parse_pid_stat(payload, expected_pid=None):
    open_index = payload.find(b"(")
    close_index = payload.rfind(b")")
    if open_index < 0 or close_index <= open_index:
        raise ValueError("进程 stat 缺少 comm 括号")
    pid = _nonnegative_int(payload[:open_index].strip(), "进程 stat pid")
    if expected_pid is not None and pid != expected_pid:
        raise ValueError(f"进程 stat 的 pid {pid} 与目录 {expected_pid} 不一致")
    comm = payload[open_index + 1:close_index].decode("utf-8", "backslashreplace")
    parts = payload[close_index + 1:].split()
    if len(parts) < 22:
        raise ValueError(f"进程 {pid} stat 字段不完整")
    state = parts[0].decode("ascii", "replace")
    if len(state) != 1:
        raise ValueError(f"进程 {pid} stat 状态字段无法解析：{state!r}")
    ppid = _nonnegative_int(parts[1], f"进程 {pid} ppid")
    utime = _nonnegative_int(parts[11], f"进程 {pid} utime")
    stime = _nonnegative_int(parts[12], f"进程 {pid} stime")
    threads = _nonnegative_int(parts[17], f"进程 {pid} num_threads")
    start_ticks = _nonnegative_int(parts[19], f"进程 {pid} starttime")
    rss_pages = _nonnegative_int(parts[21], f"进程 {pid} rss")
    return {
        "pid": pid,
        "comm": comm,
        "state": state,
        "ppid": ppid,
        "utime_ticks": utime,
        "stime_ticks": stime,
        "threads": threads,
        "start_ticks": start_ticks,
        "rss_pages": rss_pages,
    }


def _normalize_residents(residents):
    rules = []
    for rule in residents:
        if not isinstance(rule, dict):
            raise ValueError("residents 规则必须是对象")
        executable = rule.get("executable")
        if not isinstance(executable, str) or not executable:
            raise ValueError("residents 规则缺少 executable")
        reason = rule.get("reason")
        if reason is None:
            reason = "resident rule matched"
        if not isinstance(reason, str):
            raise ValueError("residents 规则的 reason 必须是字符串")
        rules.append((executable, reason))
    return rules


def _resident_reason(executable, rules):
    if not executable:
        return None
    basename = Path(executable).name
    for target, reason in rules:
        if target in (executable, basename):
            return reason
    return None


def _executable_gap(error):
    return {
        "errno": error.errno,
        "strerror": error.strerror or str(error),
        "reason": "executable unavailable",
    }


def observe_processes(budget, *, residents=(), limit=20, entries_limit=4096,
                      proc_root=DEFAULT_PROC_ROOT, sys_root=DEFAULT_SYS_ROOT, source=None):
    """有界枚举 /proc 进程，读取 stat 与 exe，输出常驻优先的 top RSS 候选。"""
    limit = _bounded_int(limit, "limit", 0)
    entries_limit = _bounded_int(entries_limit, "entries_limit", 0)
    rules = _normalize_residents(residents)
    source = _selected_source(source, proc_root, sys_root)
    hz = _positive_sysconf(source, "SC_CLK_TCK")
    page_size = _positive_sysconf(source, "SC_PAGE_SIZE")
    boot = _boot_facts(budget, source)

    heap = []
    examined = 0
    observed = 0
    exit_races = 0
    identity_races = 0
    executable_unavailable = 0
    entries_truncated = False
    names = source.iter_names(source.proc_root)
    try:
        for name in names:
            budget.check_time(source.proc_root)
            if not PID_NAME.match(name):
                continue
            if examined >= entries_limit:
                entries_truncated = True
                break
            examined += 1
            pid = int(name)
            stat_path = source.proc_path(name, "stat")
            try:
                payload = source.read_bytes(stat_path, budget, max_bytes=PID_STAT_BYTES)
            except FileNotFoundError:
                exit_races += 1
                continue
            fields = _parse_pid_stat(payload, expected_pid=pid)

            exe_path = source.proc_path(name, "exe")
            executable = None
            executable_status = "available"
            executable_error = None
            try:
                executable = source.read_link(exe_path)
            except FileNotFoundError as exc:
                executable_status = "no_exe"
                executable_error = _executable_gap(exc)
                executable_error["reason"] = (
                    "executable unavailable (ENOENT)：stat 已读取；内核线程通常没有 exe")
            except PermissionError as exc:
                executable_status = "permission_denied"
                executable_error = _executable_gap(exc)
                executable_error["reason"] = "executable unavailable：读取 /proc/<pid>/exe 权限不足"

            try:
                verified_payload = source.read_bytes(stat_path, budget, max_bytes=PID_STAT_BYTES)
            except FileNotFoundError:
                exit_races += 1
                continue
            verified = _parse_pid_stat(verified_payload)
            if verified["pid"] != pid or verified["start_ticks"] != fields["start_ticks"]:
                identity_races += 1
                continue
            observed += 1
            if executable_status != "available":
                executable_unavailable += 1

            protection = _resident_reason(executable, rules)
            resident = protection is not None
            if protection is None:
                protection = "unknown; observation only"
            row = {
                "pid": pid,
                "comm": fields["comm"],
                "state": fields["state"],
                "parent_pid": fields["ppid"],
                "ppid": fields["ppid"],
                "started": boot["btime"] + fields["start_ticks"] / hz,
                "start_ticks": fields["start_ticks"],
                "started_semantics": "btime + start_ticks/hz",
                "boot_id": boot["boot_id"],
                "boot_time": boot["btime"],
                "boot_identity_kind": boot["identity_kind"],
                "identity": f"{pid}:{boot['identity']}:{fields['start_ticks']}",
                "identity_semantics": "pid + boot 身份 + start_ticks；跨重启和 PID 复用仍可区分",
                "utime_ticks": fields["utime_ticks"],
                "stime_ticks": fields["stime_ticks"],
                "cpu_ticks": {
                    "user": fields["utime_ticks"],
                    "system": fields["stime_ticks"],
                    "total": fields["utime_ticks"] + fields["stime_ticks"],
                },
                "hz": hz,
                "cpu_seconds": {
                    "user": fields["utime_ticks"] / hz,
                    "system": fields["stime_ticks"] / hz,
                    "total": (fields["utime_ticks"] + fields["stime_ticks"]) / hz,
                },
                "cpu_semantics": "utime/stime 为进程自启动累计 jiffies；不是瞬时 CPU 百分比，"
                                  "差分除以 hz 后还需除以采集方记录的 interval",
                "rss_pages": fields["rss_pages"],
                "rss_bytes": fields["rss_pages"] * page_size,
                "page_size": page_size,
                "threads": fields["threads"],
                "executable": executable,
                "executable_source": f"/proc/{pid}/exe",
                "executable_semantics": "readlink 瞬时值；pid/start_ticks 已二次核对",
                "executable_status": executable_status,
                "executable_error": executable_error,
                "resident": resident,
                "protection": protection,
            }
            if limit > 0:
                rank = 1 if resident else 0
                item = (rank, row["rss_bytes"], -pid, row)
                if len(heap) < limit:
                    heapq.heappush(heap, item)
                elif item[:3] > heap[0][:3]:
                    heapq.heapreplace(heap, item)
    finally:
        close = getattr(names, "close", None)
        if close is not None:
            close()

    items = [item[3] for item in heap]
    items.sort(key=lambda row: (not row["resident"], -row["rss_bytes"], row["pid"]))
    not_returned = observed - len(items)
    truncated = entries_truncated or not_returned > 0
    partial = entries_truncated or exit_races > 0 or identity_races > 0
    partial_reason = []
    if entries_truncated:
        partial_reason.append(
            f"达到 entries_limit={entries_limit}，后续 PID 条目未检查；"
            "not_examined 无法从有界遍历中确定")
    if exit_races:
        partial_reason.append(f"{exit_races} 个 PID 的 stat 在枚举或二次核对时已不存在（exit race）")
    if identity_races:
        partial_reason.append(
            f"{identity_races} 个 PID 的 stat 在 exe 读取前后 pid/start_ticks 变化（identity race）")
    partial_reason = "；".join(partial_reason) if partial_reason else None
    return {
        "available": True,
        "reason": None,
        "source": "/proc/<pid>/stat + /proc/<pid>/exe",
        "observed": observed,
        "counts_semantics": "observed 是 exe 后二次核对 pid/start_ticks 一致的进程数；"
                             "entries_examined 是有界枚举的 PID 条目数；"
                             "omitted.not_examined=None 表示达到条目上限后未继续计数",
        "returned": len(items),
        "limit": limit,
        "entries_examined": examined,
        "entries_limit": entries_limit,
        "entries_truncated": entries_truncated,
        "truncated": truncated,
        "partial": partial,
        "complete": not partial and not truncated,
        "partial_reason": partial_reason,
        "exit_races": exit_races,
        "identity_races": identity_races,
        "executable_unavailable": executable_unavailable,
        "omitted": {
            "not_examined": None if entries_truncated else 0,
            "not_examined_known": not entries_truncated,
            "not_returned": not_returned,
            "exit_races": exit_races,
            "identity_races": identity_races,
        },
        "boot": {
            "boot_id": boot["boot_id"],
            "btime": boot["btime"],
            "identity_kind": boot["identity_kind"],
            "fallback": boot["fallback"],
            "reason": boot["reason"],
        },
        "hz": hz,
        "page_size": page_size,
        "items": items,
        "semantics": "进程身份为 pid+boot_id/btime+start_ticks；cpu_ticks 是累计值，不是瞬时百分比；"
                     "items 只保留有界 top RSS，常驻规则优先；exe 后二次核对不一致的行被丢弃，"
                     "exit_races/identity_races 与未检查条目分别计数",
    }
