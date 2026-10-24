"""常驻资源批次采样：逐来源隔离、共享预算与可核对的时间口径。

本模块只读取 CPU、内存、磁盘 I/O、网络、进程和 observation root 所在卷容量。
GPU、服务、电源与 TCP 状态不在首个常驻里程碑内，结果中以 ``not_observed``
显式列出。Linux 复用 ``linux_observe`` 的真实 /proc、/sys 读取和共享
``LinuxBudget``；Darwin 复用 ``observe`` 的解析器，但每条命令共用剩余的
单调时钟 deadline 与命令字节预算。

来源失败不返回空列表或零值：host section 标 ``available=False``，sources
保留异常类型、字符串、原始 traceback 与尝试/成功时间。共享预算耗尽后，
尚未开始的来源标 ``budget_not_attempted``。所有来源都失败时不产生可用样本。
"""

import os
import platform
import inspect
import re
import shutil
import socket
import stat
import time
import traceback

import linux_observe
import observe
from policy import SAMPLING_FIELDS, root_paths
from state_io import StewardError


CORE_SOURCES = ("boot", "cpu", "memory", "diskio", "network", "storage")
RESOURCE_SOURCES = ("cpu", "memory", "diskio", "network", "storage")
NOT_OBSERVED = ("gpu", "services", "power", "tcp_states", "model_usage")
DEFAULT_NETWORK_LIMIT = 64
DEFAULT_PROCESS_ENTRIES_LIMIT = 4096
DEFAULT_COMMAND_BYTES = 262144


class DarwinBudgetExceeded(StewardError):
    """Darwin 命令共用的单调时钟或命令字节预算已耗尽。"""

    def __init__(self, kind, source, *, limit=None, observed=None, detail=None):
        self.kind = kind
        self.source = os.fspath(source)
        self.limit = limit
        self.observed = observed
        if kind == "time":
            message = f"Darwin 采集超过时间预算：{self.source}"
        elif kind == "command_bytes":
            message = f"Darwin 采集超过字节预算：{self.source}"
        else:
            message = f"Darwin 采集预算耗尽（{kind}）：{self.source}"
        if limit is not None:
            message += f"；上限 {limit}"
        if observed is not None:
            message += f"，已用或需要 {observed}"
        if detail:
            message += f"；{detail}"
        super().__init__(message)


def _clip_text(value, limit):
    """按 UTF-8 字节截断文本，返回 (文本, 是否截断)。"""
    if not isinstance(value, str):
        value = str(value)
    payload = value.encode("utf-8")
    if len(payload) <= limit:
        return value, False
    head_bytes = max(0, limit // 2)
    tail_bytes = max(0, limit - head_bytes)
    head = payload[:head_bytes].decode("utf-8", "ignore")
    tail = payload[-tail_bytes:].decode("utf-8", "ignore") if tail_bytes else ""
    omitted = len(payload) - len(head.encode("utf-8")) - len(tail.encode("utf-8"))
    return (head + f"\n... [省略 {omitted} 字节] ...\n" + tail,
            True)


def error_detail(exc, label, *, traceback_limit=8192):
    """保留异常类、字符串和原始 traceback；超过记录预算时明确标记。"""
    message, message_truncated = _clip_text(str(exc), 4096)
    text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    text, traceback_truncated = _clip_text(text, traceback_limit)
    return {
        "type": type(exc).__name__,
        "module": type(exc).__module__,
        "message": message,
        "message_truncated": message_truncated,
        "traceback": text,
        "traceback_truncated": traceback_truncated,
        "traceback_limit_bytes": traceback_limit,
        "source": label,
    }


def compact_error(detail):
    """从 error_detail 结果取用于状态明细的短记录。"""
    if not isinstance(detail, dict):
        return detail
    return {key: detail[key] for key in ("type", "message", "source")
            if key in detail}


def sampling_config(policy):
    """校验并返回 v2 sampling；v1 明确要求显式 upgrade，不自动转换。"""
    if not isinstance(policy, dict):
        raise StewardError("本机约定必须是对象")
    if policy.get("version") != 2:
        raise StewardError(
            "常驻 collect 需要 version 2 本机约定；请先显式 upgrade 到 v2，"
            "v1 仍只能用于旧 patrol")
    sampling = policy.get("sampling")
    if not isinstance(sampling, dict) or set(sampling) != SAMPLING_FIELDS:
        raise StewardError("v2 sampling 字段必须完整，且不能包含未知字段")
    for key in SAMPLING_FIELDS:
        if type(sampling[key]) is not int or sampling[key] <= 0:
            raise StewardError(f"sampling.{key} 必须是正整数，布尔值无效")
    if sampling["cycle_seconds"] > sampling["interval_seconds"]:
        raise StewardError("sampling.cycle_seconds 不能大于 interval_seconds")
    if sampling["process_interval_seconds"] < sampling["interval_seconds"]:
        raise StewardError("sampling.process_interval_seconds 不能小于 interval_seconds")
    return dict(sampling)


def _limits(policy):
    limits = policy.get("limits")
    if not isinstance(limits, dict):
        raise StewardError("本机约定缺少 limits")
    return limits


def _command_bytes(policy):
    value = _limits(policy).get("command_bytes", DEFAULT_COMMAND_BYTES)
    if type(value) is not int or value <= 0:
        raise StewardError("limits.command_bytes 必须是正整数")
    return value


def _traceback_limit(policy):
    value = _limits(policy).get("file_bytes", 65536)
    if type(value) is not int or value <= 0:
        value = 65536
    # 单个来源错误要能与其他来源、host 和进程数据一起进入一条样本记录。
    return min(8192, max(2048, value // 32))


def _status_for(section, attempted_at, finished_at):
    status = {
        "available": section.get("available"),
        "attempted_at": attempted_at,
    }
    # 只有真实可用的结果才刷新最后成功时间；失败、预算和“能力不可用”
    # 只保留尝试/错误时间，不能让最后成功时间跟随失败尝试前进。
    if section.get("available") is True:
        status["success_at"] = finished_at
    if isinstance(section.get("source"), str):
        status["source"] = section["source"]
    if section.get("reason") is not None:
        reason, _ = _clip_text(section["reason"], 512)
        status["reason"] = reason
    for key in ("observed", "returned", "truncated", "partial", "complete",
                "budget_exhausted", "entries_truncated", "available_count",
                "unavailable_count"):
        if key in section:
            status[key] = section[key]
    return status


def _host_error(section_label, detail):
    reason, _ = _clip_text(f"{detail['type']}: {detail['message']}", 512)
    return {
        "available": False,
        "reason": reason,
        "source": section_label,
        "error": compact_error(detail),
    }


def _budget_host(source, exc):
    return {
        "available": False,
        "reason": str(exc),
        "source": source,
        "budget_exhausted": True,
        "budget_kind": getattr(exc, "kind", None),
    }


def _not_attempted(source, after, reason):
    return {
        "available": False,
        "reason": f"budget_not_attempted：共享采集预算已在 {after} 耗尽（{reason}）",
        "source": source,
        "budget_not_attempted": True,
    }


def _observe_storage(policy, *, roots=None, disk_usage=None):
    """按 root 所在卷读取容量；不跟随 root 内对象，不求和不同卷。"""
    disk_usage = disk_usage or shutil.disk_usage
    configured = list(root_paths(policy)) if roots is None else list(roots)
    entries = []
    volumes = {}
    for configured_path in configured:
        path = os.fspath(configured_path)
        try:
            info = os.stat(path)
        except FileNotFoundError as exc:
            entries.append({"path": path, "available": False,
                            "reason": f"观察根暂不可见：{type(exc).__name__}: {exc}"})
            continue
        except OSError as exc:
            entries.append({"path": path, "available": False,
                            "reason": f"观察根无法检查：{type(exc).__name__}: {exc}"})
            continue
        if not stat.S_ISDIR(info.st_mode):
            entries.append({"path": path, "available": False,
                            "reason": "观察根不是目录"})
            continue
        try:
            if info.st_dev not in volumes:
                volumes[info.st_dev] = disk_usage(path)
            usage = volumes[info.st_dev]
        except OSError as exc:
            entries.append({"path": path, "device": info.st_dev, "available": False,
                            "reason": f"观察根无法取得容量：{type(exc).__name__}: {exc}"})
            continue
        entries.append({
            "path": path,
            "device": info.st_dev,
            "available": True,
            "total_bytes": usage.total,
            "free_bytes": usage.free,
            "used_bytes": usage.total - usage.free,
            "source": "root volume statvfs",
        })
    available_count = sum(1 for entry in entries if entry["available"])
    unavailable = [entry for entry in entries if not entry["available"]]
    complete = bool(entries) and not unavailable
    if not entries:
        reason = "未配置观察根"
    elif unavailable:
        detail = "；".join(f"{entry['path']}：{entry['reason']}" for entry in unavailable[:4])
        if len(unavailable) > 4:
            detail += f"；另有 {len(unavailable) - 4} 个 root 不可用"
        reason, _ = _clip_text("部分观察根不可用：" + detail, 1024)
    else:
        reason = None
    return {
        "available": complete,
        "reason": reason,
        "source": "observation root volume",
        "roots": entries,
        "observed": len(entries),
        "available_count": available_count,
        "unavailable_count": len(unavailable),
        "partial": bool(available_count and unavailable),
        "complete": complete,
        "semantics": "按 root 所在 st_dev 复用容量读取；不同卷不求和；"
                     "容量是采样时点值，不是累计计数器",
    }


class DarwinBudgetRunner:
    """把多条命令限制在同一个单调时钟 deadline 与累计命令字节内。"""

    def __init__(self, command_bytes, seconds, *, clock=None, command=None):
        if type(command_bytes) is not int or command_bytes <= 0:
            raise ValueError("command_bytes 必须是正整数")
        seconds = float(seconds)
        if seconds <= 0:
            raise ValueError("seconds 必须是正数")
        self.command_bytes = command_bytes
        self.seconds = seconds
        self._clock = clock or time.monotonic
        self._command = command or observe.command
        try:
            parameters = inspect.signature(self._command).parameters.values()
            self._accepts_metadata = any(
                parameter.kind is parameter.VAR_KEYWORD
                or parameter.name == "metadata"
                for parameter in parameters)
        except (TypeError, ValueError):
            self._accepts_metadata = False
        self.started_at = self._clock()
        self.deadline = self.started_at + seconds
        self.used_bytes = 0

    @property
    def remaining_seconds(self):
        return max(0.0, self.deadline - self._clock())

    @property
    def remaining_bytes(self):
        return max(0, self.command_bytes - self.used_bytes)

    def check(self, source):
        if self.remaining_seconds <= 0:
            raise DarwinBudgetExceeded(
                "time", source, limit=self.seconds, observed=self.seconds)
        if self.remaining_bytes <= 0:
            raise DarwinBudgetExceeded(
                "command_bytes", source, limit=self.command_bytes,
                observed=self.used_bytes)

    def run(self, arguments, *, source=None):
        source = source or " ".join(arguments)
        self.check(source)
        limit = self.remaining_bytes
        timeout = self.remaining_seconds
        metadata = {}
        try:
            if self._accepts_metadata:
                text = self._command(list(arguments), max_bytes=limit,
                                     timeout=timeout, metadata=metadata)
            else:
                text = self._command(list(arguments), max_bytes=limit,
                                     timeout=timeout)
        except BaseException as exc:
            read_bytes = metadata.get("output_bytes")
            if type(read_bytes) is not int or read_bytes < 0:
                read_bytes = getattr(exc, "output_bytes", None)
            if type(read_bytes) is not int or read_bytes < 0:
                output = getattr(exc, "output", None)
                if isinstance(output, str):
                    read_bytes = len(output.encode("utf-8"))
            if type(read_bytes) is not int or read_bytes < 0:
                read_bytes = 0
            self.used_bytes += read_bytes
            raise
        read_bytes = metadata.get("output_bytes")
        if type(read_bytes) is not int or read_bytes < 0:
            read_bytes = getattr(text, "output_bytes", None)
        if type(read_bytes) is not int or read_bytes < 0:
            read_bytes = len(text.encode("utf-8"))
        self.used_bytes += read_bytes
        return text


def _linux_sample(policy, sampling, *, process_due, wall, monotonic,
                  linux_source, budget, disk_usage, roots, network_limit,
                  process_entries_limit):
    if budget is None:
        budget = linux_observe.LinuxBudget(
            _command_bytes(policy), sampling["cycle_seconds"], clock=monotonic)
    source = linux_source or linux_observe.LinuxSource()
    traceback_limit = _traceback_limit(policy)
    host, sources = {}, {}
    blocked = {"source": None, "reason": None}

    def attempt(name, function, label):
        if blocked["source"] is not None:
            host[name] = _not_attempted(label, blocked["source"], blocked["reason"])
            sources[name] = _not_attempted(label, blocked["source"], blocked["reason"])
            return None
        attempted_at = wall()
        try:
            section = function()
        except linux_observe.LinuxBudgetExceededError as exc:
            finished_at = wall()
            detail = error_detail(exc, label, traceback_limit=traceback_limit)
            blocked["source"], blocked["reason"] = label, str(exc)
            host[name] = _budget_host(label, exc)
            sources[name] = dict(_status_for(host[name], attempted_at, finished_at),
                                 error_at=finished_at, error=detail,
                                 budget_exhausted=True,
                                 budget_kind=exc.kind)
            return None
        except Exception as exc:
            finished_at = wall()
            detail = error_detail(exc, label, traceback_limit=traceback_limit)
            host[name] = _host_error(label, detail)
            sources[name] = dict(_status_for(host[name], attempted_at, finished_at),
                                 error_at=finished_at, error=detail)
            return None
        finished_at = wall()
        host[name] = section
        sources[name] = _status_for(section, attempted_at, finished_at)
        return section

    attempt("boot", lambda: linux_observe.observe_boot(budget, source=source), "/proc boot facts")
    attempt("cpu", lambda: linux_observe.observe_cpu(budget, source=source), "/proc/stat cpu")
    attempt("memory", lambda: linux_observe.observe_memory(budget, source=source), "/proc/meminfo")
    attempt("diskio", lambda: linux_observe.observe_diskio(budget, source=source), "/proc/diskstats")
    attempt("network", lambda: linux_observe.observe_network(
        budget, source=source, limit=network_limit), "/proc/net/dev")
    attempt("storage", lambda: (
        budget.check_time("observation root volume")
        or _observe_storage(policy, roots=roots, disk_usage=disk_usage)),
        "observation root volume")
    processes = None
    if process_due:
        section = attempt("processes", lambda: linux_observe.observe_processes(
            budget, residents=policy.get("residents", ()),
            limit=sampling["processes"], entries_limit=process_entries_limit,
            source=source), "/proc/<pid>")
        host.pop("processes", None)
        status = sources.get("processes")
        if section is not None:
            processes = section
        elif status is not None and not status.get("budget_not_attempted"):
            processes = {
                "available": False,
                "reason": status.get("reason"),
                "attempted_at": status.get("attempted_at"),
                "budget_exhausted": bool(status.get("budget_exhausted")),
                "error": compact_error(status.get("error")),
            }
    diskio = host.get("diskio")
    if isinstance(diskio, dict) and isinstance(diskio.get("disks"), list):
        # linux_observe 为兼容同时返回 disks/devices 两个同引用数组；入库只留一份。
        diskio.pop("devices", None)
        diskio["array_field"] = "disks"
    return host, sources, processes


def _darwin_boot_section(text):
    unix_time = observe.parse_boottime(text)
    return {
        "available": True,
        "reason": None,
        "source": "sysctl -n kern.boottime",
        "unix_time": unix_time,
        "boot_id": None,
        "identity": f"btime:{unix_time}",
        "identity_kind": "btime",
        "fallback": "btime",
        "semantics": "macOS 没有 boot_id；使用 kern.boottime 作为本次开机身份",
    }


def _darwin_memory_section(runner):
    memory_text = runner.run(["vm_stat"], source="vm_stat")
    capacity_text = runner.run(["sysctl", "-n", "hw.memsize"],
                               source="sysctl hw.memsize")
    swap_text = runner.run(["sysctl", "-n", "vm.swapusage"],
                           source="sysctl vm.swapusage")
    page = re.search(r"page size of (\d+) bytes", memory_text)
    if not page:
        raise ValueError("vm_stat 缺少页大小")
    page_size, total_bytes = int(page.group(1)), int(capacity_text.strip())
    if page_size <= 0 or total_bytes <= 0:
        raise ValueError("内存页大小或物理容量不是正数")
    swap = observe.parse_swapusage(swap_text)
    return {
        "available": True,
        "reason": None,
        "source": "vm_stat + sysctl hw.memsize + sysctl vm.swapusage",
        "total_bytes": total_bytes,
        "page_size": page_size,
        "counters": observe.parse_vm_counters(memory_text),
        "swap": dict(swap, available=True,
                     semantics="used 是采样时点当前已分配/使用的 swap 量，"
                               "不是历史高水位；当前压力结合 vm_stat 的 "
                               "Swapins/Swapouts 差分判断"),
        "semantics": "counters 为 vm_stat 自开机原始计数：Pages* 键是页数"
                     "（字节 = 页数 × page_size），Pageins/Swapins/Compressions "
                     "等键是累计事件次数",
    }


def _darwin_network_section(runner, *, limit, if_nametoindex):
    rows = observe.parse_netstat_interfaces(
        runner.run(["netstat", "-ib"], source="netstat -ib"))
    items, truncated = observe.trim_interfaces(rows, limit=limit)
    comparison_gaps = []
    for row in items:
        try:
            ifindex = if_nametoindex(row["name"])
        except OSError as exc:
            ifindex = None
            reason = f"if_nametoindex 失败：{type(exc).__name__}: {exc}"
        else:
            if type(ifindex) is not int or ifindex <= 0:
                reason = f"if_nametoindex 返回无效身份：{ifindex!r}"
                ifindex = None
            else:
                reason = None
        row.update({
            "ifindex": ifindex,
            "identity": f"ifindex:{ifindex}" if ifindex is not None else None,
            "identity_source": "socket.if_nametoindex" if ifindex is not None else None,
            "identity_reason": reason,
        })
        if ifindex is None:
            comparison_gaps.append({"interface": row["name"], "reason": reason})
    return {
        "available": True,
        "reason": None,
        "source": "netstat -ib",
        "interfaces": {
            "available": True,
            "reason": None,
            "observed": len(rows),
            "returned": len(items),
            "omitted": len(rows) - len(items),
            "limit": limit,
            "truncated": truncated,
            "items": items,
        },
        "comparison_gaps": comparison_gaps,
        "tcp_states": {
            "available": False,
            "reason": "not_observed：首个常驻资源里程碑未启用 TCP 状态采集",
            "not_observed": True,
            "states": None,
            "connections": None,
        },
        "identity_semantics": "ifindex 是接口生命周期证据；name 可能被复用；"
                              "缺少 ifindex 时只报告，不伪造 0",
        "semantics": "接口字节/包/错误为自开机累计值；跨轮差分使用 ifindex 身份",
    }


def _darwin_process_section(text, policy, sampling):
    rows = observe.parse_processes(text, policy.get("residents", ()))
    rows.sort(key=lambda row: (row["protection"] == "unknown; observation only",
                              -row["rss_bytes"]))
    limit = sampling["processes"]
    return {
        "available": True,
        "reason": None,
        "source": "ps -axo pid=,ppid=,lstart=,pcpu=,rss=,comm=",
        "observed": len(rows),
        "returned": min(len(rows), limit),
        "limit": limit,
        "truncated": len(rows) > limit,
        "items": rows[:limit],
        "cpu_semantics": "ps 的 pcpu 是进程 CPU 统计口径，不是整机瞬时利用率；"
                         "items 只保留有界 top RSS，常驻规则优先",
    }


def _darwin_sample(policy, sampling, *, process_due, wall, monotonic,
                   command_runner, if_nametoindex, disk_usage, roots,
                   network_limit, process_entries_limit):
    runner = DarwinBudgetRunner(_command_bytes(policy), sampling["cycle_seconds"],
                                clock=monotonic, command=command_runner or observe.command)
    if_nametoindex = if_nametoindex or socket.if_nametoindex
    traceback_limit = _traceback_limit(policy)
    host, sources = {}, {}
    blocked = {"source": None, "reason": None}

    def attempt(name, function, label):
        if blocked["source"] is not None:
            host[name] = _not_attempted(label, blocked["source"], blocked["reason"])
            sources[name] = _not_attempted(label, blocked["source"], blocked["reason"])
            return None
        attempted_at = wall()
        try:
            section = function()
        except DarwinBudgetExceeded as exc:
            finished_at = wall()
            detail = error_detail(exc, label, traceback_limit=traceback_limit)
            blocked["source"], blocked["reason"] = label, str(exc)
            host[name] = _budget_host(label, exc)
            sources[name] = dict(_status_for(host[name], attempted_at, finished_at),
                                 error_at=finished_at, error=detail,
                                 budget_exhausted=True, budget_kind=exc.kind)
            return None
        except Exception as exc:
            finished_at = wall()
            detail = error_detail(exc, label, traceback_limit=traceback_limit)
            host[name] = _host_error(label, detail)
            sources[name] = dict(_status_for(host[name], attempted_at, finished_at),
                                 error_at=finished_at, error=detail)
            return None
        finished_at = wall()
        host[name] = section
        sources[name] = _status_for(section, attempted_at, finished_at)
        return section

    attempt("boot", lambda: _darwin_boot_section(
        runner.run(["sysctl", "-n", "kern.boottime"], source="sysctl kern.boottime")),
        "sysctl kern.boottime")

    # iostat -c 2 约 1 秒；一次结果同时供 CPU 利用率与磁盘速率使用。
    if blocked["source"] is None:
        attempted_at = wall()
        try:
            parsed = observe.parse_iostat(runner.run(["iostat", "-c", "2"],
                                                     source="iostat -c 2"))
        except DarwinBudgetExceeded as exc:
            finished_at = wall()
            detail = error_detail(exc, "iostat -c 2", traceback_limit=traceback_limit)
            blocked["source"], blocked["reason"] = "iostat -c 2", str(exc)
            for name in ("cpu", "diskio"):
                host[name] = _budget_host("iostat -c 2", exc)
                sources[name] = dict(_status_for(host[name], attempted_at, finished_at),
                                     error_at=finished_at, error=detail,
                                     budget_exhausted=True, budget_kind=exc.kind)
        except Exception as exc:
            finished_at = wall()
            detail = error_detail(exc, "iostat -c 2", traceback_limit=traceback_limit)
            for name in ("cpu", "diskio"):
                host[name] = _host_error("iostat -c 2", detail)
                sources[name] = dict(_status_for(host[name], attempted_at, finished_at),
                                     error_at=finished_at, error=detail)
        else:
            finished_at = wall()
            cpu = {
                "available": True,
                "reason": None,
                "source": "iostat -c 2",
                "utilization": dict(parsed["cpu"], available=True,
                                    interval_seconds=1, rate=True),
                "load_average": parsed["load_average"],
                "cores": os.cpu_count(),
                "interval_seconds": 1,
                "rate": True,
                "counters": None,
                "semantics": "iostat 1 秒间隔的瞬时 CPU 占比和负载；"
                             "不是自开机累计计数器",
            }
            diskio = {
                "available": True,
                "reason": None,
                "source": "iostat -c 2",
                "interval_seconds": 1,
                "rate": True,
                "disks": parsed["disks"],
                "semantics": "iostat 1 秒间隔采样的磁盘速率，非累计计数器；"
                             "不同磁盘不求和",
            }
            for name, section in (("cpu", cpu), ("diskio", diskio)):
                host[name] = section
                sources[name] = _status_for(section, attempted_at, finished_at)
    else:
        for name in ("cpu", "diskio"):
            host[name] = _not_attempted("iostat -c 2", blocked["source"],
                                             blocked["reason"])
            sources[name] = _not_attempted("iostat -c 2", blocked["source"],
                                                  blocked["reason"])

    attempt("memory", lambda: _darwin_memory_section(runner),
            "vm_stat + sysctl memory")
    attempt("network", lambda: _darwin_network_section(
        runner, limit=network_limit, if_nametoindex=if_nametoindex),
        "netstat -ib")
    attempt("storage", lambda: (
        runner.check("observation root volume")
        or _observe_storage(policy, roots=roots, disk_usage=disk_usage)),
        "observation root volume")
    processes = None
    if process_due:
        section = attempt("processes", lambda: _darwin_process_section(
            runner.run(["ps", "-axo", "pid=,ppid=,lstart=,pcpu=,rss=,comm="],
                       source="ps"), policy, sampling), "ps")
        host.pop("processes", None)
        status = sources.get("processes")
        if section is not None:
            processes = section
        elif status is not None and not status.get("budget_not_attempted"):
            processes = {
                "available": False,
                "reason": status.get("reason"),
                "attempted_at": status.get("attempted_at"),
                "budget_exhausted": bool(status.get("budget_exhausted")),
                "error": compact_error(status.get("error")),
            }
    return host, sources, processes


def boot_identity(value):
    if isinstance(value, dict):
        if value.get("available") is False:
            return None
        for key in ("boot_id", "identity", "unix_time", "boot_time"):
            if value.get(key) is not None:
                return key, value[key]
        return None
    return value


def boot_changed(before, after):
    """仅当两侧都有开机身份且不同才判定为重开机。"""
    old, new = boot_identity(before), boot_identity(after)
    return old is not None and new is not None and old != new


def boot_summary(section):
    """压缩开机事实，供运行记录与样本 boot 字段复用。"""
    if not isinstance(section, dict) or section.get("available") is not True:
        return None
    result = {"available": True}
    for key in ("boot_id", "unix_time", "btime", "identity", "identity_kind", "fallback"):
        if key in section:
            result[key] = section[key]
    return result


def sample_boot(policy, *, system=None, monotonic=None,
                linux_source=None, command_runner=None):
    """启动前轻量读取开机身份，成功时返回可入库的 boot 摘要。"""
    monotonic = monotonic or time.monotonic
    system = system or platform.system()
    sampling = sampling_config(policy)
    seconds = min(float(sampling["cycle_seconds"]), 2.0)
    if system == "Linux":
        budget = linux_observe.LinuxBudget(
            _command_bytes(policy), seconds, clock=monotonic)
        section = linux_observe.observe_boot(
            budget, source=linux_source or linux_observe.LinuxSource())
    elif system == "Darwin":
        runner = DarwinBudgetRunner(_command_bytes(policy), seconds,
                                    clock=monotonic, command=command_runner or observe.command)
        section = _darwin_boot_section(
            runner.run(["sysctl", "-n", "kern.boottime"], source="sysctl kern.boottime"))
    else:
        raise StewardError(f"不支持的采集平台：{system}")
    return boot_summary(section)


def sample_resources(policy, *, process_due=True, system=None,
                     wall_clock=None, monotonic=None,
                     linux_source=None, budget=None, command_runner=None,
                     if_nametoindex=None, disk_usage=None, roots=None,
                     network_limit=DEFAULT_NETWORK_LIMIT,
                     process_entries_limit=DEFAULT_PROCESS_ENTRIES_LIMIT):
    """采样一批资源事实。

    参数：
    - ``policy``：已校验的 v2 本机约定。
    - ``process_due``：是否本批尝试进程快照；False 时返回 ``processes=None``。
    - ``system``：默认 ``platform.system()``；测试可显式指定 Darwin/Linux。
    - 其余关键字仅用于测试注入：时钟、LinuxSource、LinuxBudget、命令 runner、
      ifindex 查询、root 容量读取和 root 列表。

    返回字段：``host``、``boot``、``sources``、``processes``、
    ``observed_at``、``monotonic_at``、``elapsed_seconds``、``complete``、
    ``usable``、``status``、``failed_sources``、``not_attempted_sources``、
    ``budget_exhausted``、``not_observed``。``status`` 为 ok/partial/failed；
    failed 时不应用空 host 伪造成成功样本。
    """
    wall_clock = wall_clock or time.time
    monotonic = monotonic or time.monotonic
    system = system or platform.system()
    sampling = sampling_config(policy)
    started_mono = monotonic()
    started_wall = wall_clock()
    common = dict(process_due=bool(process_due), wall=wall_clock, monotonic=monotonic)
    if system == "Linux":
        host, sources, processes = _linux_sample(
            policy, sampling, linux_source=linux_source, budget=budget,
            disk_usage=disk_usage, roots=roots, network_limit=network_limit,
            process_entries_limit=process_entries_limit, **common)
    elif system == "Darwin":
        host, sources, processes = _darwin_sample(
            policy, sampling, command_runner=command_runner,
            if_nametoindex=if_nametoindex, disk_usage=disk_usage, roots=roots,
            network_limit=network_limit,
            process_entries_limit=process_entries_limit, **common)
    else:
        raise StewardError(f"不支持的采集平台：{system}")
    observed_at = wall_clock()
    monotonic_at = monotonic()
    elapsed = max(0.0, monotonic_at - started_mono)

    required = list(CORE_SOURCES)
    complete = all(
        isinstance(host.get(name), dict) and host[name].get("available") is True
        for name in required)
    if process_due:
        complete = complete and isinstance(processes, dict) \
            and processes.get("available") is True
    storage = host.get("storage") if isinstance(host.get("storage"), dict) else {}
    usable = any(
        isinstance(host.get(name), dict) and host[name].get("available") is True
        for name in RESOURCE_SOURCES
        if name != "storage")
    usable = usable or (storage.get("available_count", 0) > 0)
    failed = sorted(name for name, status in sources.items()
                    if status.get("available") is False)
    not_attempted = sorted(name for name, status in sources.items()
                           if status.get("budget_not_attempted"))
    budget_exhausted = any(status.get("budget_exhausted") for status in sources.values())
    if complete:
        status = "ok"
    elif usable:
        status = "partial"
    else:
        status = "failed"
    return {
        "host": host,
        "boot": boot_summary(host.get("boot")) or {
            "available": False,
            "reason": (host.get("boot") or {}).get("reason")
            if isinstance(host.get("boot"), dict) else "boot not observed",
            "source": "boot facts",
        },
        "sources": sources,
        "processes": processes,
        "process_due": bool(process_due),
        "observed_at": observed_at,
        "monotonic_at": monotonic_at,
        "started_at": started_wall,
        "started_monotonic_at": started_mono,
        "elapsed_seconds": elapsed,
        "complete": complete,
        "usable": usable,
        "status": status,
        "failed_sources": failed,
        "not_attempted_sources": not_attempted,
        "budget_exhausted": budget_exhausted,
        "not_observed": list(NOT_OBSERVED),
        "platform": system,
        "sampling": sampling,
    }
