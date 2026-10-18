"""动态状态的显式迁移、导出与一致备份。调用方持有本机状态锁。"""

import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import time

from database import DATASET_NAMES, SIDECAR_SUFFIXES, format_bytes
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
    store.check_database()
    path = _output_path(store, destination)
    for suffix in SIDECAR_SUFFIXES:
        companion = Path(str(path) + suffix)
        if companion.exists() or companion.is_symlink():
            raise StewardError("备份目标存在 SQLite 伴随文件，请使用全新的输出位置")
    database_bytes = store.database_path.stat().st_size
    try:
        free = shutil.disk_usage(path.parent).free
    except OSError as exc:
        raise StewardError("无法取得备份目标的空间信息") from exc
    if free < database_bytes:
        raise StewardError(f"备份目标空间不足：需要约 {format_bytes(database_bytes)}，"
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
