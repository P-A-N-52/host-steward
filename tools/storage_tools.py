"""动态状态的显式迁移、导出与一致备份。调用方持有本机状态锁。"""

import hashlib
import math
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import stat
import tempfile
import time

from database import DATASET_NAMES, RESERVE_HEADROOM, SIDECAR_SUFFIXES, format_bytes
from files import is_canonical_path, within
from inventory import read_inventory
from state import Store, StewardError, decode, encode, read_regular_bytes
from state_schema import read_current, read_operations, tool_version as valid_tool_version


STAGING = ".sqlite-migrating"
RECEIPT = "sqlite-migration.json"
READERS = {"current.json": read_current, "inventory.json": read_inventory,
           "operations.json": read_operations}

BUNDLE_FORMAT = "host-steward-bundle"
BUNDLE_VERSION = 1
BUNDLE_MANIFEST = "bundle.json"
BUNDLE_INCOMPLETE = "bundle.incomplete.json"
RESTORE_INCOMPLETE = "restore.incomplete.json"
BUNDLE_MANIFEST_LIMIT = 1024 * 1024
# 清单最后原子发布；预检按读取上限预留空间，避免 manifest 自身写不下。
BUNDLE_MANIFEST_RESERVE = BUNDLE_MANIFEST_LIMIT
BUNDLE_MAX_FILES = 1024
BUNDLE_DATABASE = "steward.sqlite3"
BUNDLE_CONFIGURATION = "host.json"
BUNDLE_ADAPTATION = "adaptation.json"
BUNDLE_GUIDANCE = "guidance"
BUNDLE_ROLES = frozenset({"database", "configuration", "adaptation", "guidance"})
BUNDLE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
BUNDLE_EXCLUDED = [
    ".lock", ".collector.lock", "sqlite-migration.json", "current.json", "inventory.json",
    "operations.json", ".sqlite-migrating", ".writing-*", "steward.sqlite3-journal",
    "steward.sqlite3-wal", "steward.sqlite3-shm",
]
HISTORY_TABLES = ("resource_samples", "process_samples", "collector_runs",
                  "collector_gaps", "collector_sources")


class LegacyInput:
    """只读迁移输入；普通运行不使用此读取路径。"""

    def __init__(self, store):
        self.values, self.fingerprints = {}, {}
        for name in DATASET_NAMES:
            try:
                payload = read_regular_bytes(store.target(name), store.limits["file_bytes"])
            except FileNotFoundError:
                self.fingerprints[name] = None
                continue
            try:
                self.values[name] = decode(payload)
            except (ValueError, RecursionError) as exc:
                raise StewardError(f"旧状态不是有效 JSON，保留原文件：{name}") from exc
            self.fingerprints[name] = hashlib.sha256(payload).hexdigest()

    def read(self, name, default=None):
        return self.values.get(name, default)

    def validate(self):
        for name, reader in READERS.items():
            reader(self)
        return self.values


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _database_digest(path, limit):
    return hashlib.sha256(read_regular_bytes(path, limit)).hexdigest()


def _finish_publication(store, staging):
    if not staging.exists():
        return False
    if not staging.samefile(store.database_path):
        raise StewardError("正式库已存在，迁移临时库与它不是同一对象；保留现场供核对")
    # 正式名称持久化后才移除临时名称，两者指向同一数据库。
    _sync_directory(store.path)
    staging.unlink()
    _sync_directory(store.path)
    return True


def migrate_json(store, apply=False, policy_guard=None):
    staging = store.target(STAGING)
    if store.database_exists():
        store.check_database()
        pending = staging.exists()
        if pending and apply:
            if policy_guard:
                policy_guard()
            _finish_publication(store, staging)
        return {"status": "already_sqlite", "applied": pending and apply,
                "publication_cleanup_pending": pending and not apply,
                "storage": store.database_info(), "capacity": store.capacity()}
    source = LegacyInput(store)
    data = source.validate()
    if not data:
        raise StewardError("未找到旧 JSON 状态；已有主机请恢复数据库，不重新建立空库")
    receipt = store.read(RECEIPT)
    if receipt is not None:
        try:
            digest = _database_digest(staging, store.limits["total_bytes"])
        except (OSError, StewardError) as exc:
            raise StewardError("已有迁移凭据，但临时库无法核对；请恢复正式 SQLite 数据库，不重新导入旧 JSON") from exc
        if (not isinstance(receipt, dict) or receipt.get("sources") != source.fingerprints
                or receipt.get("version") != 1 or receipt.get("database_sha256") != digest):
            raise StewardError("迁移记录与临时库不符；请恢复 SQLite 数据库，不重新导入旧快照")
    elif staging.exists() or staging.is_symlink():
        raise StewardError(
            f"存在未发布的迁移临时库，请先核对残留：{staging}；"
            "确认旧数据与失败原因后可删除临时库重试")
    plan = {"source": str(store.path), "destination": str(store.database_path),
            "datasets": list(data), "sources": source.fingerprints,
            "capacity": {"total_bytes": store.limits["total_bytes"], "state_bytes": store.usage()},
            "legacy_files": "保留原字节，发布后仅作为迁移证据"}
    if not apply:
        return {"status": "migration_plan", "applied": False, "plan": plan}
    if receipt is None:
        staged_store = Store(store.path, store.limits)
        staged_store.initialize_database(staging)
        try:
            # 导入事务按实际数据核对容量；剩余预算不足时在发布前停止，旧数据保持原样。
            staged_store.import_data(data, metadata={"migration": {
                "migrated_at": time.time(), "sources": source.fingerprints}})
            staged_store.check_database()
            loaded = staged_store.export_data()
            if any(loaded[name] != value for name, value in data.items()):
                raise StewardError("迁移读回与旧状态不一致")
            receipt = {"version": 1, "sources": source.fingerprints,
                       "database_sha256": _database_digest(staging, store.limits["total_bytes"])}
        except (OSError, StewardError) as exc:
            raise StewardError(
                f"迁移尚未发布，旧数据保留；核对临时库 {staging}：{exc} 可删除临时库后重试。") from exc
    # 保留发布凭据，使正式库以后丢失时不能把过时 JSON 再导入为空白新世代。
    if LegacyInput(store).fingerprints != source.fingerprints:
        raise StewardError("迁移期间旧 JSON 已变化，保留原数据与临时库")
    if policy_guard:
        policy_guard()
    if not store.target(RECEIPT).exists():
        store.write_bytes(RECEIPT, encode(receipt), exclusive=True)
    try:
        os.link(staging, store.database_path)
        _finish_publication(store, staging)
    except OSError as exc:
        raise StewardError("迁移发布未能确认；保留旧数据、临时库与发布凭据，请核对正式数据库") from exc
    return {"status": "migrated", "applied": True, "storage": store.database_info(),
            "capacity": store.capacity(), "plan": plan}


def _output_path(store, destination):
    path = Path(destination).absolute()
    if not is_canonical_path(str(path)) or not path.parent.is_dir():
        raise StewardError("输出需为父目录已存在、无符号链接的规范路径")
    if within(str(path), str(store.path)):
        raise StewardError("导出与备份请放在状态目录之外，避免覆盖运行状态")
    return path


def _write_output(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(path.parent)


def export_dataset(store, dataset, output=None):
    name = dataset + ".json"
    if name not in READERS:
        raise StewardError("未知数据集")
    data = READERS[name](store)
    result = {"status": "exported", "dataset": dataset, "exported_at": time.time(),
              "source": str(store.database_path), "data": data}
    if output is None:
        return result
    path = _output_path(store, output)
    _write_output(path, encode(result))
    return {key: value for key, value in dict(result, output=str(path)).items() if key != "data"}


def backup_database(store, destination, *, deadline=None):
    store.database_info()
    store.check_database()
    path = _output_path(store, destination)
    for suffix in SIDECAR_SUFFIXES:
        companion = Path(str(path) + suffix)
        if companion.exists() or companion.is_symlink():
            raise StewardError("备份目标存在 SQLite 伴随文件，请使用全新的输出位置")
    database_bytes = store._database_bytes(store.database_path)
    required_bytes = database_bytes * 2 + RESERVE_HEADROOM
    try:
        free = shutil.disk_usage(path.parent).free
    except OSError as exc:
        raise StewardError("无法取得备份目标的空间信息") from exc
    if free < required_bytes:
        raise StewardError(f"备份目标空间不足：含伴随文件与目标日志预留约需 {format_bytes(required_bytes)}，"
                           f"可用 {format_bytes(free)}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    if deadline is None:
        deadline = time.monotonic() + store.limits["scan_seconds"]
    source = target = None

    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise StewardError("数据库备份达到本轮时间预算，保留未完成输出供核对")

    try:
        source = sqlite3.connect(store.database_path.as_uri() + "?mode=ro", uri=True, timeout=1)
        target = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=1)
        source.backup(target, pages=64, progress=progress, sleep=0.01)
        if target.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise StewardError("备份完整性校验失败，保留输出供核对")
        target.close()
        target = None
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
        _sync_directory(path.parent)
    except sqlite3.Error as exc:
        raise StewardError("数据库备份未完成，保留输出供核对") from exc
    finally:
        if source is not None:
            source.close()
        if target is not None:
            target.close()
    return {"status": "backed_up", "output": str(path), "bytes": path.stat().st_size,
            "verified": True, "scope": "SQLite 一致快照；host.json 与本机指导需分别保存"}


def upgrade_state(store, policy, backup=None, apply=False, policy_guard=None):
    """调用方持有状态锁和采集生命周期锁，备份核对后升级结构与配置。"""
    from database import Database
    from policy import convert_v1_policy, policy_digest, read_policy_with_evidence, validate

    validate(policy)
    actual_policy, _ = read_policy_with_evidence(store.path)
    if dict(actual_policy) != dict(policy):
        raise StewardError("升级前本机约定已变化，请重新读取后预览")
    source_bytes = read_regular_bytes(store.target("host.json"), min(32768, store.limits["file_bytes"]))
    if decode(source_bytes) != dict(policy):
        raise StewardError("升级前本机约定已变化，请重新读取后预览")
    target_policy = convert_v1_policy(policy) if policy["version"] == 1 else dict(policy)
    target_bytes = encode(target_policy)
    if len(target_bytes) > min(32768, store.limits["file_bytes"]):
        raise StewardError("转换后的本机约定超过读取预算，原配置保留；不能省略观察根或授权")
    database = store._database()
    schema_plan = database.upgrade_schema()
    config_change = policy["version"] != target_policy["version"]
    needs_upgrade = config_change or not schema_plan["already_current"]
    plan = {
        "source": str(store.path), "database": schema_plan,
        "configuration": {"from_version": policy["version"], "to_version": target_policy["version"],
                          "changed": config_change, "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                          "target_policy_digest": policy_digest(target_policy)},
        "backup": None if backup is None else os.fspath(backup),
        "scope_change": "v1 深度预算转为逐 root 声明范围，下一轮重建受影响基线，不据此推断删除" if config_change else None,
        "rollback": "旧工具不能读取 schema 2；回退须核对切换后新记录，不能直接重新启用旧快照",
    }
    if not needs_upgrade:
        return {"status": "already_current", "applied": False, "plan": plan,
                "storage": store.database_info()}
    if not apply:
        return {"status": "upgrade_plan", "applied": False, "plan": plan}
    if backup is None or not Path(backup).is_absolute():
        raise StewardError("执行升级必须用 --backup 指定状态区外全新的绝对路径备份目录")
    destination = _output_path(store, backup)
    store.check_database()
    original_data = store.export_data()
    if policy_guard:
        policy_guard()
    destination.mkdir(mode=0o700)
    _sync_directory(destination.parent)
    host_backup = destination / "host.json"
    _write_output(host_backup, source_bytes)
    sqlite_backup = destination / "steward.sqlite3"
    backup_result = backup_database(store, sqlite_backup)
    backed = Database(sqlite_backup, store.limits["file_bytes"], store.limits["total_bytes"])
    if backed.export_data() != original_data or read_regular_bytes(host_backup, len(source_bytes)) != source_bytes:
        raise StewardError("升级备份独立读回与原状态不一致，原状态未切换，保留备份供核对")
    manifest = {"version": 1, "created_at": time.time(), "plan": plan,
                "backup": {"host": str(host_backup), "database": backup_result,
                           "database_sha256": _database_digest(sqlite_backup, store.limits["total_bytes"])},
                "recovery": "先读回当前配置与数据库版本；结构升级与配置发布分步提交，中断后可能为 schema 2 配置 v1，仍可读取并重新预览"}
    _write_output(destination / "upgrade.json", encode(manifest))
    if policy_guard:
        policy_guard()
    if read_regular_bytes(store.target("host.json"), min(32768, store.limits["file_bytes"])) != source_bytes:
        raise StewardError("备份期间本机约定已变化，原状态未切换，请重新预览；已生成备份保留")
    if store.export_data() != original_data:
        raise StewardError("备份期间动态状态已变化，原状态未切换，请重新预览；已生成备份保留")
    phase, schema_confirmed, config_publication = "schema_upgrade", False, "not_attempted"
    try:
        schema_result = database.upgrade_schema(
            apply=True, total_bytes=store.limits["total_bytes"], outside_bytes=store._database_outside(database))
        schema_confirmed = True
        phase = "schema_readback"
        store.check_database()
        if store.export_data() != original_data:
            raise StewardError("结构升级后数据集读回不一致，停止发布配置；保留数据库和外部备份供恢复")
        if config_change:
            phase = "configuration_guard"
            if policy_guard:
                policy_guard()
            phase, config_publication = "configuration_publish", "unverified"
            store.write_bytes("host.json", target_bytes)
        phase = "configuration_readback"
        loaded_policy, evidence = read_policy_with_evidence(store.path)
        if dict(loaded_policy) != target_policy:
            raise StewardError("升级后配置读回不一致，保留当前状态与外部备份供核对")
    except BaseException as error:
        import sys
        sys.stderr.write(encode({
            "status": "upgrade_incomplete", "phase": phase,
            "schema_2_confirmed": schema_confirmed,
            "configuration_publication": config_publication,
            "backup": str(destination), "original_error_type": type(error).__name__,
            "message": "升级可能已部分提交；保留当前状态，先核对配置与数据库版本及 upgrade.json，再决定续接；原始异常继续抛出",
        }).decode("utf-8"))
        raise
    return {"status": "upgraded", "applied": True, "plan": plan,
            "backup": str(destination), "database": schema_result,
            "policy_version": loaded_policy["version"], "policy_evidence": evidence,
            "storage": store.database_info(), "capacity": store.capacity()}


def _check_deadline(deadline, message):
    if deadline is not None and time.monotonic() > deadline:
        raise StewardError(message)


def _file_sha256(path, limit=None):
    """流式读取普通文件并核对读取期间未变化；不整份载入内存。"""
    fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise StewardError("读取目标必须是普通文件")
        digest, size = hashlib.sha256(), 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if limit is not None and size > limit:
                    raise StewardError("文件超过读取上限")
                digest.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise StewardError("文件在读取期间发生变化")
        if size != before.st_size:
            raise StewardError("文件未能在预算内完整读取")
        return size, digest.hexdigest()
    finally:
        os.close(fd)


def _bundle_relative_path(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise StewardError("bundle 文件路径必须是非空相对路径")
    if len(value.encode("utf-8")) > 4096:
        raise StewardError("bundle 文件路径超过 4096 字节")
    if value.startswith("/") or Path(value).is_absolute() or "\\" in value:
        raise StewardError(f"bundle 文件路径必须是 POSIX 相对路径：{value}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts) or os.path.normpath(value) != value:
        raise StewardError(f"bundle 文件路径必须是规范的 POSIX 相对路径：{value}")
    return parts


def _guidance_fingerprints(store):
    """枚举本机指导普通文件，返回相对路径到大小与摘要的有界映射。"""
    root = store.path / BUNDLE_GUIDANCE
    try:
        info = os.lstat(root)
    except FileNotFoundError as exc:
        raise StewardError("状态缺少 guidance 目录，不能创建完整备份") from exc
    except OSError as exc:
        raise StewardError("本机指导目录无法检查") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise StewardError("本机指导 guidance 必须是普通目录，不能是符号链接")
    result, count, pending = {}, 0, [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(directory) as entries:
                items = sorted(entries, key=lambda item: item.name)
        except OSError as exc:
            raise StewardError(f"本机指导目录无法读取：{directory}") from exc
        for item in items:
            count += 1
            if count > BUNDLE_MAX_FILES:
                raise StewardError(f"本机指导对象超过 {BUNDLE_MAX_FILES} 项上限，不能创建完整备份")
            relative = item.name if not prefix else prefix + "/" + item.name
            try:
                child = item.stat(follow_symlinks=False)
            except OSError as exc:
                raise StewardError(f"本机指导对象无法检查：{relative}") from exc
            if stat.S_ISLNK(child.st_mode):
                raise StewardError(f"本机指导不能包含符号链接：{relative}")
            if stat.S_ISDIR(child.st_mode):
                pending.append((Path(item.path), relative))
            elif stat.S_ISREG(child.st_mode):
                try:
                    size, digest = _file_sha256(item.path, store.limits["file_bytes"])
                except (OSError, StewardError) as exc:
                    raise StewardError(f"本机指导文件无法读取或超过单文件预算：{relative}") from exc
                result[BUNDLE_GUIDANCE + "/" + relative] = {
                    "path": os.fspath(item.path), "bytes": size, "sha256": digest}
            else:
                raise StewardError(f"本机指导只能是普通文件或目录：{relative}")
    if not result:
        raise StewardError("本机指导目录为空，不能创建完整备份")
    return result


def _state_other_entries(store):
    known = {".lock", ".collector.lock", BUNDLE_DATABASE, BUNDLE_CONFIGURATION,
             BUNDLE_ADAPTATION, BUNDLE_GUIDANCE, "sqlite-migration.json", "current.json",
             "inventory.json", "operations.json", ".sqlite-migrating"}
    known |= {BUNDLE_DATABASE + suffix for suffix in SIDECAR_SUFFIXES}
    try:
        with os.scandir(store.path) as entries:
            names = sorted(entry.name for entry in entries)
    except OSError as exc:
        raise StewardError("无法枚举状态目录，停止创建完整备份") from exc
    return [name for name in names if name not in known and not name.startswith(".writing-")]


def _copy_verified(source, destination, expected_bytes, expected_sha256):
    """分块复制并同时核对来源稳定与摘要；目标独占创建。"""
    source_fd = os.open(os.fspath(source), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    target_fd = None
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise StewardError(f"复制来源必须是普通文件：{source}")
        if before.st_size != expected_bytes:
            raise StewardError(f"复制来源大小已变化：{source}")
        target_fd = os.open(os.fspath(destination),
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        digest, size = hashlib.sha256(), 0
        with os.fdopen(source_fd, "rb", closefd=False) as reader, \
                os.fdopen(target_fd, "wb", closefd=False) as writer:
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        after = os.fstat(source_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise StewardError(f"复制期间来源发生变化：{source}")
        if size != expected_bytes or digest.hexdigest() != expected_sha256:
            raise StewardError(f"文件摘要与清单不符：{source}")
    except OSError as exc:
        raise StewardError(f"文件复制失败：{source}") from exc
    finally:
        os.close(source_fd)
        if target_fd is not None:
            os.close(target_fd)
    _sync_directory(Path(destination).parent)


def _database_evidence(path, file_limit, total_limit, label):
    """read-only 连接核对完整性与日志模式，再用独立 Database 读回数据集。"""
    from database import Database

    connection = None
    try:
        connection = sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True, timeout=1)
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise StewardError(f"{label}完整性检查失败，拒绝使用")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
        if str(journal).lower() != "delete":
            raise StewardError(f"{label}不是 DELETE 日志模式（{journal}），拒绝使用")
        if version not in {1, 2}:
            raise StewardError(f"{label}版本不受支持：{version}")
        history = {}
        if version == 2:
            for table in HISTORY_TABLES:
                history[table] = connection.execute(
                    f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except sqlite3.Error as exc:
        raise StewardError(f"{label}损坏或无法读取") from exc
    finally:
        if connection is not None:
            connection.close()
    try:
        database = Database(path, file_limit, total_limit)
        info = database.info()
        data = database.export_data()
    except StewardError as exc:
        raise StewardError(f"{label}无法独立读回：{exc}") from exc
    return {"schema_version": info["schema_version"], "journal_mode": str(journal).lower(),
            "integrity_check": "ok", "datasets": info["datasets"],
            "export_sha256": hashlib.sha256(encode(data)).hexdigest(),
            "history": history, "data": data}


def _database_report(database):
    return {key: database[key] for key in
            ("schema_version", "journal_mode", "integrity_check", "datasets",
             "export_sha256", "history")}


def _write_manifest(directory, manifest):
    payload = encode(manifest)
    if len(payload) > BUNDLE_MANIFEST_LIMIT:
        raise StewardError("完整备份清单超过 1 MiB 上限，备份未完成（标记保留）")
    fd, temporary = tempfile.mkstemp(prefix=".bundle-manifest-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, Path(directory) / BUNDLE_MANIFEST)
        _sync_directory(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def backup_bundle(store, policy, destination, policy_guard=None):
    """在状态锁内创建完整 bundle；清单最后原子发布，中断时保留未完成标记。"""
    from policy import policy_digest, validate
    from steward import TOOL_VERSION

    started = time.monotonic()
    deadline = started + store.limits["scan_seconds"]
    source = store.database_info()
    store.check_database()
    host_bytes = read_regular_bytes(store.target(BUNDLE_CONFIGURATION),
                                   min(32768, store.limits["file_bytes"]))
    try:
        host_policy = validate(decode(host_bytes))
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise StewardError("本机约定格式错误，不能创建完整备份") from exc
    if dict(host_policy) != dict(policy):
        raise StewardError("备份前本机约定已变化，请重新读取后再创建完整备份")
    if host_policy.get("host") != {"system": platform.system(), "hostname": platform.node()}:
        raise StewardError("本机约定的主机标识与当前环境不符，停止创建完整备份")
    adaptation_bytes = read_regular_bytes(store.target(BUNDLE_ADAPTATION),
                                          store.limits["file_bytes"])
    try:
        adaptation = decode(adaptation_bytes)
    except (ValueError, RecursionError) as exc:
        raise StewardError("裁剪记录 adaptation.json 不是有效 JSON") from exc
    if not isinstance(adaptation, dict):
        raise StewardError("裁剪记录 adaptation.json 必须是 JSON 对象")
    guidance = _guidance_fingerprints(store)
    other_entries = _state_other_entries(store)
    _check_deadline(deadline, "源预检超过本轮时间预算，未创建完整备份目录")
    try:
        requested = Path(os.fspath(destination))
    except (TypeError, ValueError) as exc:
        raise StewardError("完整备份目标必须是路径") from exc
    if not requested.is_absolute():
        raise StewardError("完整备份目标必须是绝对路径")
    path = _output_path(store, requested)
    if path.exists() or path.is_symlink():
        raise StewardError("完整备份目标必须尚不存在，请使用新的输出目录，不覆盖已有文件")
    database_bytes = store._database_bytes(store.database_path)
    other_bytes = len(host_bytes) + len(adaptation_bytes) + sum(
        item["bytes"] for item in guidance.values())
    required = database_bytes * 2 + other_bytes + RESERVE_HEADROOM + BUNDLE_MANIFEST_RESERVE
    try:
        free = shutil.disk_usage(path.parent).free
    except OSError as exc:
        raise StewardError("无法取得完整备份目标的空间信息") from exc
    if free < required:
        raise StewardError(f"完整备份目标空间不足：约需 {format_bytes(required)}，可用 {format_bytes(free)}")
    _check_deadline(deadline, "目标预检超过本轮时间预算，未创建完整备份目录")
    scope = {"included": [BUNDLE_DATABASE, BUNDLE_CONFIGURATION, BUNDLE_ADAPTATION,
                          BUNDLE_GUIDANCE + "/"],
             "guidance_file_count": len(guidance),
             "guidance_bytes": sum(item["bytes"] for item in guidance.values()),
             "excluded": list(BUNDLE_EXCLUDED), "other_entries": other_entries}
    path.mkdir(mode=0o700)
    _sync_directory(path.parent)
    _write_output(path / BUNDLE_INCOMPLETE, encode({
        "status": "incomplete", "created_at": time.time(), "tool_version": TOOL_VERSION,
        "destination": str(path), "scope": scope}))
    _write_output(path / BUNDLE_CONFIGURATION, host_bytes)
    _write_output(path / BUNDLE_ADAPTATION, adaptation_bytes)
    for relative in sorted(guidance):
        item = guidance[relative]
        target = path / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _copy_verified(Path(item["path"]), target, item["bytes"], item["sha256"])
    _sync_directory(path / BUNDLE_GUIDANCE)
    backup_database(store, path / BUNDLE_DATABASE, deadline=deadline)
    _check_deadline(deadline, "写入阶段超过本轮时间预算，完整备份未完成（标记保留）")
    database_size, database_digest = _file_sha256(path / BUNDLE_DATABASE)
    database = _database_evidence(path / BUNDLE_DATABASE, store.limits["file_bytes"],
                                  store.limits["total_bytes"], "完整备份数据库")
    if database["schema_version"] != source["schema_version"] or database["datasets"] != source["datasets"]:
        raise StewardError("完整备份数据库结构与源库不一致，备份未完成（标记保留）")
    files = [{"path": BUNDLE_DATABASE, "role": "database",
              "bytes": database_size, "sha256": database_digest}]
    for name, role, expected in ((BUNDLE_CONFIGURATION, "configuration", host_bytes),
                                 (BUNDLE_ADAPTATION, "adaptation", adaptation_bytes)):
        size, digest = _file_sha256(path / name)
        if size != len(expected) or digest != hashlib.sha256(expected).hexdigest():
            raise StewardError(f"完整备份读回的 {name} 与源字节不一致，备份未完成（标记保留）")
        files.append({"path": name, "role": role, "bytes": size, "sha256": digest})
    for relative in sorted(guidance):
        size, digest = _file_sha256(path / relative)
        item = guidance[relative]
        if size != item["bytes"] or digest != item["sha256"]:
            raise StewardError(f"完整备份读回的指导与原文件不一致：{relative}；备份未完成（标记保留）")
        files.append({"path": relative, "role": "guidance", "bytes": size, "sha256": digest})
    if policy_guard:
        policy_guard()
    if read_regular_bytes(store.target(BUNDLE_CONFIGURATION),
                          min(32768, store.limits["file_bytes"])) != host_bytes:
        raise StewardError("备份期间本机约定已变化，完整备份未完成（标记保留）")
    if read_regular_bytes(store.target(BUNDLE_ADAPTATION), store.limits["file_bytes"]) != adaptation_bytes:
        raise StewardError("备份期间裁剪记录已变化，完整备份未完成（标记保留）")
    if _guidance_fingerprints(store) != guidance:
        raise StewardError("备份期间本机指导已变化，完整备份未完成（标记保留）")
    after = store.database_info()
    if after["schema_version"] != source["schema_version"] or after["datasets"] != source["datasets"]:
        raise StewardError("备份期间源库结构已变化，完整备份未完成（标记保留）")
    _check_deadline(deadline, "复核阶段超过本轮时间预算，完整备份未完成（标记保留）")
    created_at = time.time()
    manifest = {
        "format": BUNDLE_FORMAT, "version": BUNDLE_VERSION, "status": "complete",
        "created_at": created_at, "tool_version": TOOL_VERSION,
        "schema_version": database["schema_version"],
        "source": {"state": str(store.path), "host": dict(host_policy["host"]),
                   "policy_version": host_policy["version"],
                   "policy_digest": policy_digest(host_policy),
                   "policy_source_digest": hashlib.sha256(host_bytes).hexdigest()},
        "scope": scope, "files": files,
        "database": _database_report(database),
        "verification": {"files_sha256": "all", "database_readback": True,
                         "policy_validated": True, "adaptation_decoded": True,
                         "guidance_sha256": "all", "source_stable": True},
        "recovery": "先备份现有状态；用 restore-bundle 预览，再 --apply 恢复到全新绝对路径；"
                    "恢复后独立读回配置、数据库与指导，不直接覆盖正在使用的状态。",
    }
    _write_manifest(path, manifest)
    (path / BUNDLE_INCOMPLETE).unlink()
    _sync_directory(path)
    return {"status": "bundle_created", "output": str(path),
            "manifest": str(path / BUNDLE_MANIFEST),
            "bytes": sum(entry["bytes"] for entry in files), "files": files,
            "tool_version": TOOL_VERSION, "schema_version": database["schema_version"],
            "created_at": created_at, "database": manifest["database"], "scope": scope}


def _bundle_root(bundle):
    try:
        path = Path(os.fspath(bundle))
    except (TypeError, ValueError) as exc:
        raise StewardError("bundle 必须是目录路径") from exc
    if not path.is_absolute():
        raise StewardError("bundle 必须是绝对路径")
    path = path.absolute()
    if not is_canonical_path(str(path)):
        raise StewardError("bundle 必须是父目录已存在、无符号链接的规范绝对路径")
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise StewardError("bundle 目录不存在") from exc
    except OSError as exc:
        raise StewardError("bundle 目录无法检查") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise StewardError("bundle 必须是普通目录，不能是符号链接")
    return path


def _read_manifest(root):
    marker = root / BUNDLE_INCOMPLETE
    if marker.exists() or marker.is_symlink():
        raise StewardError("bundle 存在未完成标记 bundle.incomplete.json，不能恢复；请重新创建完整备份")
    path = root / BUNDLE_MANIFEST
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise StewardError("bundle 缺少清单 bundle.json，不能恢复") from exc
    except OSError as exc:
        raise StewardError("bundle.json 无法检查") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise StewardError("bundle.json 必须是普通文件")
    if info.st_size > BUNDLE_MANIFEST_LIMIT:
        raise StewardError(f"bundle.json 超过 {format_bytes(BUNDLE_MANIFEST_LIMIT)} 读取上限")
    try:
        manifest = decode(read_regular_bytes(path, BUNDLE_MANIFEST_LIMIT))
    except (ValueError, RecursionError) as exc:
        raise StewardError("bundle.json 不是有效 JSON") from exc
    if not isinstance(manifest, dict):
        raise StewardError("bundle.json 顶层必须是对象")
    return manifest


def _validate_manifest_source(source):
    if not isinstance(source, dict):
        raise StewardError("bundle.json 的 source 必须是对象")
    state = source.get("state")
    if not isinstance(state, str) or not state or "\x00" in state \
            or not Path(state).is_absolute() or os.path.normpath(state) != state:
        raise StewardError("bundle.json 的 source.state 必须是规范的绝对路径")
    host = source.get("host")
    if not isinstance(host, dict) or set(host) != {"system", "hostname"} or not all(
            isinstance(value, str) and value for value in host.values()):
        raise StewardError("bundle.json 的 source.host 必须包含字符串 system 与 hostname")
    version = source.get("policy_version")
    if type(version) is not int or version not in {1, 2}:
        raise StewardError("bundle.json 的 source.policy_version 仅支持 1 或 2")
    for key in ("policy_digest", "policy_source_digest"):
        value = source.get(key)
        if not isinstance(value, str) or BUNDLE_SHA256.fullmatch(value) is None:
            raise StewardError(f"bundle.json 的 source.{key} 必须是 64 位小写十六进制摘要")


def _validate_manifest_scope(scope):
    if not isinstance(scope, dict):
        raise StewardError("bundle.json 的 scope 必须是对象")
    for key in ("included", "excluded", "other_entries"):
        value = scope.get(key)
        if not isinstance(value, list) or any(
                not isinstance(item, str) or not item or len(item.encode("utf-8")) > 4096
                for item in value):
            raise StewardError(f"bundle.json 的 scope.{key} 必须是非空字符串数组")
    for key in ("guidance_file_count", "guidance_bytes"):
        if type(scope.get(key)) is not int or scope[key] < 0:
            raise StewardError(f"bundle.json 的 scope.{key} 必须是非负整数")


def _validate_manifest_database(database):
    if not isinstance(database, dict):
        raise StewardError("bundle.json 的 database 必须是对象")
    version = database.get("schema_version")
    if type(version) is not int or version not in {1, 2}:
        raise StewardError("bundle.json 的 database.schema_version 仅支持 1 或 2")
    if database.get("journal_mode") != "delete":
        raise StewardError("bundle.json 的 database.journal_mode 必须是 delete")
    if database.get("integrity_check") != "ok":
        raise StewardError("bundle.json 的 database.integrity_check 必须是 ok")
    datasets = database.get("datasets")
    if not isinstance(datasets, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in datasets.items()):
        raise StewardError("bundle.json 的 database.datasets 必须是从数据集到根类型的对象")
    digest = database.get("export_sha256")
    if not isinstance(digest, str) or BUNDLE_SHA256.fullmatch(digest) is None:
        raise StewardError("bundle.json 的 database.export_sha256 必须是 64 位小写十六进制摘要")
    history = database.get("history")
    if not isinstance(history, dict) or any(
            not isinstance(key, str) or type(value) is not int or value < 0
            for key, value in history.items()):
        raise StewardError("bundle.json 的 database.history 必须是非负整数计数")


def _validate_manifest_fields(manifest):
    for key in ("format", "version", "status", "created_at", "tool_version", "schema_version",
                "source", "scope", "files", "database", "verification", "recovery"):
        if key not in manifest:
            raise StewardError(f"bundle.json 缺少字段：{key}")
    if manifest["format"] != BUNDLE_FORMAT:
        raise StewardError(f"bundle 格式不受支持：{manifest['format']}")
    if type(manifest["version"]) is not int or manifest["version"] != BUNDLE_VERSION:
        raise StewardError(f"bundle 版本不受支持：{manifest['version']}")
    if manifest["status"] != "complete":
        raise StewardError(f"bundle 状态不是 complete：{manifest['status']}")
    created = manifest["created_at"]
    if type(created) not in (int, float) or not math.isfinite(float(created)):
        raise StewardError("bundle.json 的 created_at 必须是有限数值")
    if not valid_tool_version(manifest["tool_version"]):
        raise StewardError("bundle.json 的 tool_version 必须是三段式版本号")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] not in {1, 2}:
        raise StewardError("bundle.json 的 schema_version 仅支持 1 或 2")
    _validate_manifest_source(manifest["source"])
    _validate_manifest_scope(manifest["scope"])
    _validate_manifest_database(manifest["database"])
    if not isinstance(manifest["verification"], dict):
        raise StewardError("bundle.json 的 verification 必须是对象")
    if not isinstance(manifest["recovery"], str) or not manifest["recovery"].strip():
        raise StewardError("bundle.json 的 recovery 必须是非空文本")


def _require_bundle_parent(root, relative):
    current = root
    for part in relative.split("/")[:-1]:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError as exc:
            raise StewardError(f"bundle 文件父目录不存在：{relative}") from exc
        except OSError as exc:
            raise StewardError(f"bundle 文件父目录无法检查：{relative}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise StewardError(f"bundle 文件父路径必须是普通目录：{relative}")


def _validate_bundle_files(root, manifest):
    entries = manifest.get("files")
    if not isinstance(entries, list) or not 1 <= len(entries) <= BUNDLE_MAX_FILES:
        raise StewardError(f"bundle 文件集必须是 1–{BUNDLE_MAX_FILES} 项的数组")
    files, paths, folded = [], set(), {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "role", "bytes", "sha256"}:
            raise StewardError("bundle 文件条目必须且仅包含 path、role、bytes、sha256")
        relative = entry["path"]
        _bundle_relative_path(relative)
        if relative in paths:
            raise StewardError(f"bundle 文件路径重复：{relative}")
        if relative.casefold() in folded:
            raise StewardError(f"bundle 文件路径大小写冲突：{relative} 与 {folded[relative.casefold()]}")
        paths.add(relative)
        folded[relative.casefold()] = relative
        if entry["role"] not in BUNDLE_ROLES:
            raise StewardError(f"bundle 文件角色无效：{entry['role']}")
        if type(entry["bytes"]) is not int or entry["bytes"] < 0:
            raise StewardError(f"bundle 文件大小无效：{relative}")
        if not isinstance(entry["sha256"], str) or BUNDLE_SHA256.fullmatch(entry["sha256"]) is None:
            raise StewardError(f"bundle 文件摘要无效：{relative}")
        files.append({"path": relative, "role": entry["role"],
                      "bytes": entry["bytes"], "sha256": entry["sha256"]})
    ordered = sorted(paths)
    for index, relative in enumerate(ordered[:-1]):
        if ordered[index + 1].startswith(relative + "/"):
            raise StewardError(f"bundle 文件路径存在前缀冲突：{relative}")
    by_role = {}
    for entry in files:
        by_role.setdefault(entry["role"], []).append(entry)
    for role, name in (("database", BUNDLE_DATABASE), ("configuration", BUNDLE_CONFIGURATION),
                       ("adaptation", BUNDLE_ADAPTATION)):
        matches = by_role.get(role, [])
        if len(matches) != 1 or matches[0]["path"] != name:
            raise StewardError(f"bundle 必须且只能有一个 {role} 文件 {name}")
    guidance = by_role.get("guidance", [])
    if not guidance:
        raise StewardError("bundle 缺少 guidance/ 本机指导文件")
    if any(not entry["path"].startswith(BUNDLE_GUIDANCE + "/") for entry in guidance):
        raise StewardError("guidance 角色的文件必须位于 guidance/ 目录下")
    scope = manifest["scope"]
    if scope["guidance_file_count"] != len(guidance) or scope["guidance_bytes"] != sum(
            entry["bytes"] for entry in guidance):
        raise StewardError("bundle 的 guidance 数量或字节数与清单 scope 不一致")
    for entry in files:
        _require_bundle_parent(root, entry["path"])
        path = root / entry["path"]
        try:
            info = os.lstat(path)
        except FileNotFoundError as exc:
            raise StewardError(f"bundle 缺少清单列出的文件：{entry['path']}") from exc
        except OSError as exc:
            raise StewardError(f"bundle 文件无法检查：{entry['path']}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise StewardError(f"bundle 清单文件必须是普通文件：{entry['path']}")
        if info.st_size != entry["bytes"]:
            raise StewardError(f"bundle 文件大小与清单不符：{entry['path']}")
        size, digest = _file_sha256(path)
        if size != entry["bytes"] or digest != entry["sha256"]:
            raise StewardError(f"bundle 文件摘要与清单不符：{entry['path']}")
    for suffix in SIDECAR_SUFFIXES:
        companion = root / (BUNDLE_DATABASE + suffix)
        if companion.exists() or companion.is_symlink():
            raise StewardError("bundle 数据库存在 SQLite 伴随文件，拒绝恢复")
    return files


def _bundle_unlisted_files(root, files):
    listed = {entry["path"] for entry in files}
    pending, result, count = [(root, "")], [], 0
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(directory) as entries:
                items = sorted(entries, key=lambda item: item.name)
        except OSError as exc:
            raise StewardError("bundle 目录无法完整枚举") from exc
        for item in items:
            relative = item.name if not prefix else prefix + "/" + item.name
            if relative in {BUNDLE_MANIFEST, BUNDLE_INCOMPLETE, RESTORE_INCOMPLETE}:
                continue
            count += 1
            if count > BUNDLE_MAX_FILES * 2:
                raise StewardError("bundle 目录对象数超过上限，拒绝恢复")
            try:
                info = item.stat(follow_symlinks=False)
            except OSError as exc:
                raise StewardError(f"bundle 对象无法检查：{relative}") from exc
            if stat.S_ISDIR(info.st_mode):
                pending.append((Path(item.path), relative))
            elif stat.S_ISREG(info.st_mode) and relative not in listed:
                result.append(relative)
    return sorted(result)


def _inspect_bundle(bundle, allow_foreign_host):
    from policy import policy_digest, validate

    root = _bundle_root(bundle)
    manifest = _read_manifest(root)
    _validate_manifest_fields(manifest)
    files = _validate_bundle_files(root, manifest)
    host_bytes = read_regular_bytes(root / BUNDLE_CONFIGURATION, 32768)
    try:
        policy = validate(decode(host_bytes))
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise StewardError("bundle 的 host.json 格式错误") from exc
    evidence = {"policy_version": policy["version"],
                "policy_digest": policy_digest(policy),
                "policy_source_digest": hashlib.sha256(host_bytes).hexdigest()}
    source = manifest["source"]
    if source["policy_version"] != policy["version"] \
            or source["policy_digest"] != evidence["policy_digest"] \
            or source["policy_source_digest"] != evidence["policy_source_digest"]:
        raise StewardError("bundle 的 host.json 与清单来源摘要不一致，拒绝恢复")
    stored_host = policy.get("host")
    if not isinstance(stored_host, dict) or stored_host != source["host"]:
        raise StewardError("bundle 的 host.json 主机标识与清单不一致，拒绝恢复")
    current_host = {"system": platform.system(), "hostname": platform.node()}
    host_identity_match = stored_host == current_host
    if not host_identity_match and not allow_foreign_host:
        raise StewardError(
            f"bundle 来自其他主机（{stored_host.get('hostname')} / {stored_host.get('system')}），"
            "默认拒绝恢复；确需跨主机恢复请加 --allow-foreign-host，并在恢复后人工核对 "
            "host.json 的主机标识与 roots")
    database = _database_evidence(root / BUNDLE_DATABASE, policy["limits"]["file_bytes"],
                                  policy["limits"]["total_bytes"], "bundle 数据库")
    recorded = manifest["database"]
    if manifest["schema_version"] != database["schema_version"] \
            or recorded["schema_version"] != database["schema_version"] \
            or recorded["datasets"] != database["datasets"]:
        raise StewardError("bundle 数据库结构与清单不一致，拒绝恢复")
    if recorded["export_sha256"] != database["export_sha256"]:
        raise StewardError("bundle 数据库数据摘要与清单不一致，拒绝恢复")
    if recorded["history"] != database["history"]:
        raise StewardError("bundle 资源历史行数与清单不一致，拒绝恢复")
    return {"root": root, "manifest": manifest, "files": files, "policy": policy,
            "policy_evidence": evidence, "raw_host": host_bytes,
            "host_identity_match": host_identity_match, "database": database,
            "unlisted_files": _bundle_unlisted_files(root, files),
            "limits": dict(policy["limits"])}


def _restore_destination(inspection, destination):
    try:
        path = Path(os.fspath(destination))
    except (TypeError, ValueError) as exc:
        raise StewardError("恢复目标必须是路径") from exc
    if not path.is_absolute():
        raise StewardError("恢复目标必须是绝对路径")
    path = path.absolute()
    if not is_canonical_path(str(path)):
        raise StewardError("恢复目标必须是父目录已存在、无符号链接的规范绝对路径")
    if not path.parent.is_dir():
        raise StewardError("恢复目标的父目录必须已存在")
    try:
        os.lstat(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise StewardError("恢复目标无法检查") from exc
    else:
        raise StewardError("恢复目标必须尚不存在；不覆盖现有状态（含空目录），请使用全新路径")
    if within(str(path), str(inspection["root"])):
        raise StewardError("恢复目标不能位于 bundle 目录内")
    if within(str(path), inspection["manifest"]["source"]["state"]):
        raise StewardError("恢复目标不能位于 bundle 来源状态目录内")
    roots = [root["path"] if isinstance(root, dict) else root
             for root in inspection["policy"].get("roots", [])]
    if any(within(root, str(path)) for root in roots):
        raise StewardError("恢复目标不能包含观察根目录；运行时将拒绝该状态")
    required = sum(entry["bytes"] for entry in inspection["files"]) + RESERVE_HEADROOM
    try:
        free = shutil.disk_usage(path.parent).free
    except OSError as exc:
        raise StewardError("无法取得恢复目标的空间信息") from exc
    if free < required:
        raise StewardError(f"恢复目标空间不足：约需 {format_bytes(required)}，可用 {format_bytes(free)}")
    return path


def _verify_file_set(root, files):
    for entry in files:
        path = root / entry["path"]
        try:
            info = os.lstat(path)
        except FileNotFoundError as exc:
            raise StewardError(f"缺少文件：{entry['path']}") from exc
        except OSError as exc:
            raise StewardError(f"文件无法检查：{entry['path']}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise StewardError(f"文件必须是普通文件：{entry['path']}")
        if info.st_size != entry["bytes"]:
            raise StewardError(f"文件大小与清单不符：{entry['path']}")
        size, digest = _file_sha256(path)
        if size != entry["bytes"] or digest != entry["sha256"]:
            raise StewardError(f"文件摘要与清单不符：{entry['path']}")


def _compare_database(expected, actual, label):
    for key in ("schema_version", "journal_mode", "integrity_check", "datasets",
                "export_sha256", "history"):
        if expected[key] != actual[key]:
            raise StewardError(f"{label}与 bundle 清单不一致：{key}")


def _verify_staged(staging, inspection):
    limits = inspection["limits"]
    _verify_file_set(staging, inspection["files"])
    host_bytes = read_regular_bytes(staging / BUNDLE_CONFIGURATION,
                                    min(32768, limits["file_bytes"]))
    if host_bytes != inspection["raw_host"]:
        raise StewardError("staging 中的 host.json 与校验时字节不一致")
    database = _database_evidence(staging / BUNDLE_DATABASE, limits["file_bytes"],
                                  limits["total_bytes"], "staging 数据库")
    _compare_database(inspection["database"], database, "staging 数据库")


def _verify_published(destination, inspection):
    import sys

    from policy import policy_digest, validate

    limits = inspection["limits"]
    phase = {"value": "file_readback"}
    try:
        _verify_file_set(destination, inspection["files"])
        phase["value"] = "policy_readback"
        host_bytes = read_regular_bytes(destination / BUNDLE_CONFIGURATION,
                                        min(32768, limits["file_bytes"]))
        if host_bytes != inspection["raw_host"]:
            raise StewardError("恢复后 host.json 与 bundle 原字节不一致")
        policy = validate(decode(host_bytes))
        evidence = {"policy_version": policy["version"],
                    "policy_digest": policy_digest(policy),
                    "policy_source_digest": hashlib.sha256(host_bytes).hexdigest()}
        if evidence != inspection["policy_evidence"]:
            raise StewardError("恢复后本机约定摘要与 bundle 不一致")
        roots = [root["path"] if isinstance(root, dict) else root
                 for root in policy.get("roots", [])]
        if any(within(root, str(destination.resolve())) for root in roots):
            raise StewardError("恢复后的状态目录包含观察根目录，运行时将拒绝该状态")
        phase["value"] = "database_readback"
        database = _database_evidence(destination / BUNDLE_DATABASE, limits["file_bytes"],
                                      limits["total_bytes"], "恢复后的数据库")
        _compare_database(inspection["database"], database, "恢复后的数据库")
        phase["value"] = "datasets_readback"
        store = Store(destination, limits)
        store.check_database()
        data = store.export_data()
        if data != inspection["database"]["data"]:
            raise StewardError("恢复后数据集与 bundle 独立读回不一致")
        current = read_current(store)
        operations = read_operations(store)
    except BaseException as error:
        sys.stderr.write(encode({
            "status": "restore_incomplete", "phase": phase["value"],
            "bundle": str(inspection["root"]), "destination": str(destination),
            "original_error_type": type(error).__name__,
            "message": "恢复已发布但最终独立读回失败；保留目标现场，先核对配置、数据库与指导，"
                       "不要覆盖或删除；原始异常继续抛出",
        }).decode("utf-8"))
        raise
    return {"files_sha256": "all", "policy_digest": evidence["policy_digest"],
            "database_readback": True,
            "datasets": sorted(name for name, value in data.items() if value is not None),
            "operations_count": len(operations), "current_version": current.get("version")}


def restore_bundle(bundle, destination, apply=False, allow_foreign_host=False):
    """校验 bundle 并恢复到全新目录；默认只预览，--apply 才写入。"""
    started = time.monotonic()
    inspection = _inspect_bundle(bundle, allow_foreign_host)
    limits = inspection["limits"]
    deadline = started + limits["scan_seconds"]
    target = _restore_destination(inspection, destination)
    _check_deadline(deadline, "恢复校验超过 host.json 的时间预算，未写入任何文件")
    report = {
        "bundle": str(inspection["root"]), "destination": str(target),
        "host_identity_match": inspection["host_identity_match"],
        "files": inspection["files"], "file_count": len(inspection["files"]),
        "unlisted_files": inspection["unlisted_files"],
        "schema_version": inspection["database"]["schema_version"],
        "policy_version": inspection["policy"]["version"],
        "policy_evidence": inspection["policy_evidence"],
        "database": _database_report(inspection["database"]),
        "scope": inspection["manifest"]["scope"],
        "limits": {"scan_seconds": limits["scan_seconds"]},
    }
    if not apply:
        report.update(status="restore_plan", applied=False, verified=True,
                      message="预览只读取并校验 bundle，未写入任何文件；加 --apply 恢复到全新状态目录")
        return report
    staging, published = None, False
    try:
        prefix = f".{target.name[:64]}.restoring-"
        staging = Path(tempfile.mkdtemp(prefix=prefix, dir=str(target.parent)))
        _sync_directory(target.parent)
        _write_output(staging / RESTORE_INCOMPLETE, encode({
            "status": "incomplete", "created_at": time.time(),
            "bundle": str(inspection["root"]), "destination": str(target)}))
        for entry in inspection["files"]:
            staged = staging / entry["path"]
            staged.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _copy_verified(inspection["root"] / entry["path"], staged,
                           entry["bytes"], entry["sha256"])
        _sync_directory(staging)
        _check_deadline(deadline, "复制阶段超过 host.json 的时间预算，目标未发布")
        _verify_staged(staging, inspection)
        _check_deadline(deadline, "校验阶段超过 host.json 的时间预算，目标未发布")
        if target.exists() or target.is_symlink():
            raise StewardError("恢复目标在准备期间已出现，停止发布；现有内容未改动")
        (staging / RESTORE_INCOMPLETE).unlink()
        _sync_directory(staging)
        os.rename(staging, target)
        staging = None
        published = True
        _sync_directory(target.parent)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        if published:
            raise StewardError(
                f"恢复已发布到 {target}，但目录持久化确认失败；保留目标现场核对：{error}") from error
        if staging is not None and staging.exists():
            raise StewardError(
                f"恢复未发布，目标不存在；staging 保留供核对：{staging}；{error}") from error
        raise
    readback = _verify_published(target, inspection)
    report.update(status="restored", applied=True, verified=True, readback=readback)
    return report
