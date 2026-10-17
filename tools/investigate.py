"""Targeted read-only investigation, with shared traversal, I/O and time budgets."""

import hashlib
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import time

from files import identity, is_canonical_path, within
from inventory import knowledge, policy_links, read_inventory, record_inspection, service_parts
from observe import command, parse_processes
from state import StewardError, encode
from state_schema import read_current


TEXT_SUFFIXES = {".json", ".toml", ".yaml", ".yml", ".ini", ".conf", ".plist", ".service", ".socket",
                 ".timer", ".desktop", ".sh", ".zsh", ".bash", ".py", ".md", ".txt"}


class Budget:
    def __init__(self, limits):
        self.started = time.monotonic()
        self.seconds = limits["scan_seconds"]
        self.max_entries = limits["scan_entries"]
        self.max_files = 100
        self.per_file = min(limits["command_bytes"], 262144)
        self.max_bytes = min(limits["file_bytes"], 2097152)
        self.entries = self.files = self.bytes = self.omitted_gaps = 0
        self.gaps = []

    def gap(self, reason, target):
        if len(self.gaps) < 24:
            self.gaps.append({"reason": reason, "target": str(target)[:1024]})
        else:
            self.omitted_gaps += 1

    def active(self):
        return (time.monotonic() - self.started < self.seconds and self.entries < self.max_entries
                and self.files < self.max_files and self.bytes < self.max_bytes)

    def read(self, path):
        if not self.active():
            self.gap("investigation_budget", path)
            return None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    self.gap("not_regular_file", path)
                    return None
                allowance = min(self.per_file, self.max_bytes - self.bytes)
                if info.st_size > allowance:
                    self.gap("file_size_limit", path)
                    return None
                self.files += 1
                content = stream.read(allowance)
                self.bytes += len(content)
                after = os.fstat(stream.fileno())
                if len(content) != info.st_size or (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    self.gap("file_changed_during_read_or_limit", path)
                    return None
                return content
        except OSError as exc:
            self.gap(f"read_errno_{exc.errno}", path)
            return None

    def run(self, arguments, name):
        remaining = self.seconds - (time.monotonic() - self.started)
        if remaining <= 0 or self.bytes + 1 >= self.max_bytes:
            self.gap("investigation_budget", name)
            return None
        # command reads one extra byte to detect truncation; reserve it in the shared budget.
        result = command(arguments, max_bytes=min(self.per_file, self.max_bytes - self.bytes - 1), timeout=remaining)
        self.bytes += result.get("bytes_read", len(result["text"].encode()))
        if not result["ok"]:
            self.gap(result["reason"], name)
            return None
        return result["text"]

    def summary(self):
        return {"elapsed_seconds": round(time.monotonic() - self.started, 3), "entries": self.entries,
                "files_read": self.files, "bytes_read_and_command_output": self.bytes,
                "limits": {"seconds": self.seconds, "entries": self.max_entries, "files": self.max_files,
                           "per_file_bytes": self.per_file, "read_and_command_bytes": self.max_bytes},
                "gaps": self.gaps, "gaps_omitted": self.omitted_gaps}


def reference_search(target, policy, store, budget, self_paths=()):
    name = target.rsplit("/", 1)[-1]
    terms = [term for term in dict.fromkeys([target, name]) if len(term) >= 3]
    needles = [term.encode() for term in terms]
    items, matches, skipped, coverage = [], 0, 0, []

    def visit(directory, depth, device):
        nonlocal matches, skipped
        if not budget.active():
            budget.gap("investigation_budget", directory)
            return
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if not budget.active():
                        budget.gap("investigation_budget", directory)
                        break
                    budget.entries += 1
                    if entry.name in policy["exclude_names"] or within(entry.path, str(store.path)):
                        skipped += 1
                        continue
                    info = entry.stat(follow_symlinks=False)
                    if info.st_dev != device or stat.S_ISLNK(info.st_mode):
                        skipped += 1
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if depth >= policy["limits"]["scan_depth"]:
                            budget.gap("depth_limit", entry.path)
                        else:
                            visit(entry.path, depth + 1, device)
                    elif stat.S_ISREG(info.st_mode) and Path(entry.name).suffix.lower() in TEXT_SUFFIXES:
                        content = budget.read(entry.path)
                        if content is not None and b"\0" not in content and any(term in content for term in needles):
                            matches += 1
                            if len(items) < 20:
                                suffix = Path(entry.name).suffix.lower()
                                role = ("self_definition" if entry.path in self_paths else "documentation" if suffix in {".md", ".txt"}
                                        else "source" if suffix in {".py", ".sh", ".zsh", ".bash"} else "configuration")
                                items.append({"path": entry.path, "role": role})
        except OSError as exc:
            budget.gap(f"scan_errno_{exc.errno}", directory)

    for root in policy["roots"]:
        before = len(budget.gaps) + budget.omitted_gaps
        checked = False
        try:
            info = os.lstat(root)
            if stat.S_ISDIR(info.st_mode) and budget.active():
                checked = True
                visit(root, 0, info.st_dev)
            else:
                budget.gap("root_not_directory_or_budget_exhausted", root)
        except OSError as exc:
            budget.gap(f"root_errno_{exc.errno}", root)
        coverage.append({"path": root, "started": checked,
                         "complete_within_declared_filters": checked and len(budget.gaps) + budget.omitted_gaps == before})
    return {"root_coverage": coverage, "method": "literal bytes in selected text suffixes; no content returned",
            "terms": terms, "matches": matches, "items": items, "items_truncated": matches > len(items),
            "excluded_entries": skipped, "meaning": "引用线索；文档命中、无命中或自定义启动文件均不证明有无实际调用"}


def program_details(program, working_directory):
    program = program if isinstance(program, str) else None
    working_directory = working_directory if isinstance(working_directory, str) else None
    resolved = None
    if program and os.path.isabs(program):
        resolved = os.path.normpath(program)
    elif program and "/" in program and working_directory and os.path.isabs(working_directory):
        resolved = os.path.normpath(os.path.join(working_directory, program))
    result = {"program": program, "working_directory": working_directory, "resolved_program": resolved}
    if resolved:
        try:
            result["program_exists"] = stat.S_ISREG(os.stat(resolved).st_mode)
        except OSError as exc:
            result["program_exists"] = False if exc.errno == 2 else None
            result["program_stat_errno"] = exc.errno
    return result


def startup_directories(manager, scope):
    home = Path.home()
    if manager == "launchd":
        suffix = "LaunchAgents" if scope == "user" else "LaunchDaemons"
        return ([home / "Library/LaunchAgents"] if scope == "user" else []) + [Path("/Library") / suffix, Path("/System/Library") / suffix]
    suffix = "user" if scope == "user" else "system"
    roots = [Path(prefix) / "systemd" / suffix for prefix in ["/etc", "/run", "/usr/lib", "/usr/local/lib", "/lib"]]
    if scope == "user":
        roots += [home / ".config/systemd/user", home / ".local/share/systemd/user", Path(f"/run/user/{os.getuid()}/systemd/user")]
    return roots


def allowed_config(path, directories, budget):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not any(within(str(path.resolve()), str(root.resolve())) for root in directories):
        budget.gap("startup_config_outside_known_directories_or_symlink", path)
        return False
    return True


def startup_service(locator, budget):
    manager, scope, name = service_parts(locator)
    expected = "Darwin" if manager == "launchd" else "Linux"
    result = {"manager": manager, "scope": scope, "name": name, "pid": None, "configurations": []}
    if platform.system() != expected:
        budget.gap("service_manager_not_on_this_platform", locator)
        return result
    directories = startup_directories(manager, scope)
    if manager == "launchd":
        domain = f"gui/{os.getuid()}" if scope == "user" else "system"
        raw = budget.run(["launchctl", "print", f"{domain}/{name}"], "launchd runtime")
        fields = dict(re.findall(r"^\t(pid|state|path|last exit code) = (.+)$", raw or "", re.M))
        result.update(runtime_state=fields.get("state"), domain=domain,
                      pid=int(fields["pid"]) if fields.get("pid", "").isdigit() else None)
        candidates = ([Path(fields["path"])] if "path" in fields else []) + [root / (name + ".plist") for root in directories]
        for path in dict.fromkeys(candidates):
            if not path.exists() or not allowed_config(path, directories, budget):
                continue
            content = budget.read(path)
            if content is None:
                continue
            try:
                config = plistlib.loads(content)
                if config.get("Label") != name:
                    continue
                arguments = config.get("ProgramArguments", [])
                program = config.get("Program") or (arguments[0] if arguments else None)
                result.update(program_details(program, config.get("WorkingDirectory")))
                result.update(run_at_load=config.get("RunAtLoad") if type(config.get("RunAtLoad")) is bool else None,
                              start_interval=config.get("StartInterval") if type(config.get("StartInterval")) is int else None,
                              keep_alive=config.get("KeepAlive") if type(config.get("KeepAlive")) is bool else None)
                result["configurations"].append({"path": str(path), "sha256": hashlib.sha256(content).hexdigest()})
                break
            except (plistlib.InvalidFileException, ValueError, TypeError, AttributeError):
                budget.gap("invalid_startup_plist", path)
        result["configuration_coverage"] = "runtime path and exact label.plist candidates; other filenames and login items unchecked"
    else:
        properties = ["Id", "LoadState", "ActiveState", "SubState", "MainPID", "FragmentPath", "DropInPaths", "WorkingDirectory", "ExecStart"]
        raw = budget.run(["systemctl", "--user" if scope == "user" else "--system", "show", name, "--no-pager",
                          "--property=" + ",".join(properties)], "systemd runtime properties")
        fields = dict(line.split("=", 1) for line in (raw or "").splitlines() if "=" in line)
        result.update(runtime_state=fields.get("ActiveState"), load_state=fields.get("LoadState"),
                      sub_state=fields.get("SubState"), unit_id=fields.get("Id"),
                      pid=int(fields["MainPID"]) if fields.get("MainPID", "").isdigit() and int(fields["MainPID"]) > 0 else None)
        executable = re.search(r"\bpath=([^;]+);", fields.get("ExecStart", ""))
        program = executable[1].strip() if executable else None
        if program:
            program = re.sub(r"\\x([0-9a-fA-F]{2})", lambda match: chr(int(match[1], 16)), program)
        result.update(program_details(program, fields.get("WorkingDirectory")))
        paths = [fields["FragmentPath"]] if fields.get("FragmentPath") else []
        drop_ins = fields.get("DropInPaths", "").split()
        paths += drop_ins[:8]
        if len(drop_ins) > 8:
            budget.gap("drop_in_count_limit", locator)
        for item in paths:
            path = re.sub(r"\\x([0-9a-fA-F]{2})", lambda match: chr(int(match[1], 16)), item)
            if allowed_config(path, directories, budget):
                content = budget.read(path)
                if content is not None:
                    result["configurations"].append({"path": path, "sha256": hashlib.sha256(content).hexdigest()})
        result["configuration_coverage"] = "manager-reported fragment and first 8 drop-ins; custom paths outside known directories unchecked"
    if not result["configurations"]:
        budget.gap("startup_configuration_not_observed", locator)
    return result


def process_and_sockets(pid, budget):
    result = {"scope": "main PID only; children and historical callers unchecked", "process": None,
              "sockets": [], "socket_records_observed": 0}
    if not pid:
        result["reason"] = "no_current_main_pid; idle does not establish retirement"
        return result
    raw = budget.run(["ps", "-p", str(pid), "-o", "pid=,ppid=,lstart=,pcpu=,rss=,comm="], "main process metadata")
    processes = parse_processes(raw or "", [])
    result["process"] = processes[0] if processes else None
    if platform.system() == "Darwin":
        raw = budget.run(["lsof", "-nP", "-a", "-p", str(pid), "-i", "-FpfnPT"], "main process sockets")
        current = None
        for line in (raw or "").splitlines():
            if line.startswith("f"):
                current = {}
            elif line.startswith("P") and current is not None:
                current["protocol"] = line[1:]
            elif line.startswith("n") and current is not None:
                current["endpoint"] = line[1:]
                result["socket_records_observed"] += 1
                if len(result["sockets"]) < 32:
                    result["sockets"].append(current)
            elif line.startswith("TST=") and current is not None:
                current["state"] = line[4:]
    else:
        raw = budget.run(["ss", "-H", "-t", "-u", "-a", "-n", "-p"], "socket metadata; process attribution may be restricted")
        for line in (raw or "").splitlines():
            parts = line.split(None, 6)
            if len(parts) == 7 and str(pid) in re.findall(r"pid=(\d+)", parts[6]):
                result["socket_records_observed"] += 1
                if len(result["sockets"]) < 32:
                    result["sockets"].append({"protocol": parts[0], "state": parts[1], "local": parts[4], "peer": parts[5]})
    result["socket_query_available"] = raw is not None
    result["socket_records_truncated"] = result["socket_records_observed"] > len(result["sockets"])
    result["socket_scope"] = "visible main-PID TCP/UDP sockets at observation time; attribution may be incomplete"
    return result


def path_observation(path, policy, store, budget):
    result = {"path": path}
    if not any(within(path, root) for root in policy["roots"]) or not is_canonical_path(path):
        budget.gap("path_outside_roots_or_symlink", path)
        return result, None
    try:
        info = os.lstat(path)
        result.update(kind="directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "other",
                      id=identity(info), mtime_ns=info.st_mtime_ns,
                      size_bytes=info.st_size if stat.S_ISREG(info.st_mode) else None)
        current = read_current(store)
        result["directory_summary"] = next((row for row in current.get("directory_index", []) if row["path"] == path), None)
        directory = Path(path) if stat.S_ISDIR(info.st_mode) else Path(path).parent
        result["agents"] = []
        for parent in [directory, *directory.parents]:
            if not any(within(str(parent), root) for root in policy["roots"]):
                break
            note = parent / "AGENTS.md"
            if note.is_file() and not note.is_symlink():
                result["agents"].append(str(note))
        signature = f"{identity(info)}:{getattr(info, 'st_birthtime', '')}"
        return result, signature
    except OSError as exc:
        budget.gap(f"target_errno_{exc.errno}", path)
        return result, None


def inspect_target(store, policy, resource_id=None, path=None, service=None):
    data = read_inventory(store)
    entry = data["resources"].get(resource_id) if resource_id else None
    if resource_id and entry is None:
        raise StewardError("资源 id 未登记；不能将查询无匹配当作没有历史")
    target = entry["definition"]["locator"] if entry else service if service else os.path.abspath(path)
    kind = entry["definition"]["kind"] if entry else "service" if service else "file"
    budget = Budget(policy["limits"])
    report = {"status": "investigated", "target": target, "observed_at": time.time(),
              "knowledge": knowledge(entry) if entry else None, "identity": None,
              "unchecked": ["historical callers", "business dependency and health", "proxy/tunnel forwarding", "unconfigured reference roots"],
              "decision": "只读证据；不判断可以停止或删除。授权以 host.json 为准"}
    if entry and kind != "service" and not is_canonical_path(target):
        report["status"] = "migration_required"
        report["budget"] = budget.summary()
        report["recording"] = {"saved": False, "reason": "legacy_noncanonical_locator; explicit migration required"}
        return report
    if kind == "service":
        startup = startup_service(target, budget)
        report["startup"] = startup
        report["runtime"] = process_and_sockets(startup["pid"], budget)
        configurations = startup["configurations"]
        if configurations:
            report["identity"] = hashlib.sha256(encode(configurations)).hexdigest()
        self_paths = [row["path"] for row in configurations]
        report["policy"] = policy_links({"kind": kind, "locator": target}, policy, startup.get("resolved_program"))
    else:
        report["object"], report["identity"] = path_observation(target, policy, store, budget)
        self_paths = [target]
        report["policy"] = policy_links({"kind": kind, "locator": target}, policy)
    report["references"] = reference_search(target, policy, store, budget, self_paths)
    report["budget"] = budget.summary()
    report["recording"] = {"saved": bool(entry), "reason": "latest inspection replaces previous; knowledge does not expire with events" if entry else "unregistered target; output only"}
    if entry:
        if len(encode(report)) > min(32768, policy["limits"]["file_bytes"]):
            raise StewardError("调查摘要超过记录预算，原档案保留；请缩小引用范围")
        record_inspection(store, data, resource_id, report)
    return report
