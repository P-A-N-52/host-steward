"""动态状态的显式迁移、导出与一致备份。调用方持有本机状态锁。"""

import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import time

from database import DATASET_NAMES, RESERVE_HEADROOM, SIDECAR_SUFFIXES, format_bytes
from files import is_canonical_path, within
from inventory import read_inventory
from state import Store, StewardError, decode, encode, read_regular_bytes
from state_schema import read_current, read_operations


STAGING = ".sqlite-migrating"
RECEIPT = "sqlite-migration.json"
READERS = {"current.json": read_current, "inventory.json": read_inventory,
           "operations.json": read_operations}


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


def backup_database(store, destination):
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
    started = time.monotonic()
    source = target = None

    def progress(status, remaining, total):
        if time.monotonic() - started > store.limits["scan_seconds"]:
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
