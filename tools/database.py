"""SQLite 动态状态存储。"""

import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import tempfile


_MISSING = object()


SCHEMA_VERSION = 1
DATASET_NAMES = ("current.json", "inventory.json", "operations.json")
SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")
# 提交时回滚日志保存旧页；为日志头与校验字节单独留出的余量。
RESERVE_HEADROOM = 65536


class DatabaseError(Exception):
    """状态库无法使用。"""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("重复 JSON 字段")
        result[key] = value
    return result


def _finite_float(value):
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("非有限 JSON 数字")
    return value


def _invalid_constant(value):
    raise ValueError("非有限 JSON 数字")


def _json(value):
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise DatabaseError("动态状态不能编码为有限 JSON") from exc


def _decode(payload):
    try:
        return json.loads(payload, object_pairs_hook=_unique_object,
                          parse_float=_finite_float, parse_constant=_invalid_constant)
    except (TypeError, ValueError, RecursionError) as exc:
        raise DatabaseError("SQLite 状态库包含损坏的 JSON 条目") from exc


def _path_json(path):
    return json.dumps(list(path), ensure_ascii=False, separators=(",", ":"))


def _path_decode(value):
    path = _decode(value)
    if not isinstance(path, list) or not all(isinstance(item, str) for item in path):
        raise DatabaseError("SQLite 状态库 section 路径损坏")
    return tuple(path)


def _validate_regular(path, missing_ok=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return False
        raise DatabaseError("SQLite 状态库不存在")
    except OSError as exc:
        raise DatabaseError("SQLite 状态库无法检查") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise DatabaseError("SQLite 状态库及其日志必须是普通文件")
    return True


def format_bytes(value):
    if value is None:
        return "未知"
    if value >= 1024 ** 2:
        return f"{value / 1024 ** 2:.2f} MiB"
    if value >= 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value} B"


def writable_database_bytes(total_bytes, outside_bytes):
    """按写入后的回滚日志预留，算出数据库可以长期写入的字节上限。"""
    if total_bytes is None:
        return None
    available = total_bytes - outside_bytes - RESERVE_HEADROOM
    return max(0, available * 32 // 65)


def _capacity_text(total_bytes, outside_bytes, limit, current_bytes):
    return (f"状态预算 {format_bytes(total_bytes)}，库外占用 {format_bytes(outside_bytes)}，"
            f"数据库可长期写入上限 {format_bytes(limit)}（当前 {format_bytes(current_bytes)}）")


def _is_full_error(exc):
    code = getattr(exc, "sqlite_errorcode", None)
    if code is not None:
        return code % 256 == 13
    return "full" in str(exc).lower()


class Database:
    """一个已存在的 SQLite 状态库，连接按操作短时打开。"""

    def __init__(self, path, file_limit=None, total_limit=None):
        self.path = Path(path)
        self.file_limit = file_limit
        self.total_limit = total_limit

    def _validate_files(self):
        _validate_regular(self.path)
        for suffix in SIDECAR_SUFFIXES:
            _validate_regular(Path(str(self.path) + suffix), missing_ok=True)

    def _connect(self):
        self._validate_files()
        connection = None
        try:
            connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=5.0)
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                raise DatabaseError(f"SQLite 状态库版本不受支持：{version}")
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"datasets", "metadata", "sections", "rows"} <= tables:
                raise DatabaseError("SQLite 状态库结构不完整")
            return connection
        except DatabaseError:
            if connection is not None:
                connection.close()
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            raise DatabaseError("SQLite 状态库损坏或无法打开") from exc

    @staticmethod
    def initialize(path):
        """创建空状态库，目标已存在时拒绝覆盖。"""
        path = Path(path)
        _validate_regular(path, missing_ok=True)
        for suffix in SIDECAR_SUFFIXES:
            if _validate_regular(Path(str(path) + suffix), missing_ok=True):
                raise DatabaseError("SQLite 伴随文件已存在，保留现场并停止初始化")
        try:
            fd = os.open(os.fspath(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise DatabaseError("SQLite 状态库已存在，拒绝覆盖") from exc
        except OSError as exc:
            raise DatabaseError("SQLite 状态库无法创建") from exc
        os.close(fd)
        connection = None
        try:
            connection = sqlite3.connect(os.fspath(path), timeout=5.0)
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.executescript(
                """
                CREATE TABLE datasets (
                    dataset TEXT PRIMARY KEY,
                    root_kind TEXT NOT NULL CHECK (root_kind IN ('object', 'array'))
                ) WITHOUT ROWID;
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE sections (
                    dataset TEXT NOT NULL REFERENCES datasets(dataset) ON DELETE CASCADE,
                    section TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind IN ('scalar', 'object', 'array')),
                    ordinal INTEGER NOT NULL,
                    PRIMARY KEY (dataset, section)
                ) WITHOUT ROWID;
                CREATE TABLE rows (
                    dataset TEXT NOT NULL,
                    section TEXT NOT NULL,
                    item_key TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    value_json TEXT NOT NULL,
                    PRIMARY KEY (dataset, section, position, item_key),
                    FOREIGN KEY (dataset, section) REFERENCES sections(dataset, section)
                        ON DELETE CASCADE
                ) WITHOUT ROWID;
                PRAGMA user_version = 1;
                """)
            connection.commit()
            connection.close()
            connection = None
            directory_fd = os.open(os.fspath(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            try:
                path.unlink()
            except OSError:
                pass
            raise DatabaseError("SQLite 状态库初始化失败") from exc

    @staticmethod
    def empty_database_bytes():
        with tempfile.TemporaryDirectory(prefix="host-steward-db-") as directory:
            path = Path(directory) / "steward.sqlite3"
            Database.initialize(path)
            try:
                return path.read_bytes()
            except OSError as exc:
                raise DatabaseError("SQLite 空状态库无法读取") from exc

    def check(self):
        connection = self._connect()
        try:
            result = connection.execute("PRAGMA integrity_check").fetchone()
            if not result or result[0] != "ok":
                raise DatabaseError("SQLite 状态库完整性检查失败")
        except sqlite3.Error as exc:
            raise DatabaseError("SQLite 状态库完整性检查失败") from exc
        finally:
            connection.close()

    def info(self):
        connection = self._connect()
        try:
            datasets = connection.execute(
                "SELECT dataset, root_kind FROM datasets ORDER BY dataset").fetchall()
            return {"path": str(self.path), "schema_version": SCHEMA_VERSION,
                    "datasets": {name: kind for name, kind in datasets},
                    "size": self.path.stat().st_size}
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError("SQLite 状态库信息读取失败") from exc
        finally:
            connection.close()

    @staticmethod
    def _array_key(section, value):
        if not isinstance(value, dict):
            return ""
        if section in {"pending", "pending_overflow", "pending_history"}:
            value = value.get("key")
        elif section == "changes":
            value = value.get("path")
        elif section == "__root__":
            value = value.get("id")
        elif section == "directory_index":
            value = [value.get("root"), value.get("path")]
        else:
            value = None
        return "" if value is None else _json(value)

    @classmethod
    def _sections(cls, dataset, data):
        if isinstance(data, list):
            return "array", [(_path_json(()), (), "array", [
                (cls._array_key("__root__", item), position, item)
                for position, item in enumerate(data)])]
        if not isinstance(data, dict):
            raise DatabaseError("动态状态顶层必须是对象或数组")
        sections = []
        for name, value in data.items():
            if not isinstance(name, str):
                raise DatabaseError("动态状态字段名必须是字符串")
            if dataset == "current.json" and name == "baselines" and isinstance(value, dict):
                if not value:
                    sections.append((_path_json((name,)), (name,), "object", []))
                    continue
                for root, snapshot in value.items():
                    root = str(root)
                    if not isinstance(snapshot, dict):
                        raise DatabaseError("baseline 条目必须是对象")
                    base = dict(snapshot)
                    records = base.pop("records", _MISSING)
                    directories = base.pop("directories", _MISSING)
                    if records is not _MISSING and not isinstance(records, dict):
                        raise DatabaseError("baseline.records 必须是对象")
                    if directories is not _MISSING and not isinstance(directories, dict):
                        raise DatabaseError("baseline.directories 必须是对象")
                    sections.append((_path_json((name, root, "snapshot")),
                                     (name, root, "snapshot"), "object",
                                     [(str(key), 0, item) for key, item in base.items()]))
                    if isinstance(records, dict):
                        sections.append((_path_json((name, root, "records")),
                                         (name, root, "records"), "object",
                                         [(str(key), 0, item) for key, item in records.items()]))
                    if isinstance(directories, dict):
                        sections.append((_path_json((name, root, "directories")),
                                         (name, root, "directories"), "object",
                                         [(str(key), 0, item) for key, item in directories.items()]))
                continue
            path = (name,)
            if isinstance(value, dict):
                entries, kind = [(str(key), 0, item) for key, item in value.items()], "object"
            elif isinstance(value, list):
                entries, kind = [(cls._array_key(name, item), position, item)
                                 for position, item in enumerate(value)], "array"
            else:
                entries, kind = [("", 0, value)], "scalar"
            sections.append((_path_json(path), path, kind, entries))
        return "object", sections

    @staticmethod
    def _row_map(connection, dataset, section):
        return {(key, position): value for key, position, value in connection.execute(
            "SELECT item_key, position, value_json FROM rows WHERE dataset=? AND section=?",
            (dataset, section)).fetchall()}

    def _entry_json(self, value):
        payload = _json(value)
        if self.file_limit is not None and len(payload.encode("utf-8")) > self.file_limit:
            raise DatabaseError("SQLite 单条状态记录超过容量上限")
        return payload

    def _replace_dataset(self, connection, dataset, data):
        encoded = _json(data)
        if self.total_limit is not None and len(encoded.encode("utf-8")) > self.total_limit:
            raise DatabaseError("动态状态数据集超过总容量预算")
        root_kind, desired = self._sections(dataset, data)
        connection.execute("INSERT OR IGNORE INTO datasets(dataset, root_kind) VALUES (?, ?)",
                           (dataset, root_kind))
        connection.execute("UPDATE datasets SET root_kind=? WHERE dataset=?", (root_kind, dataset))
        old_sections = {section: (kind, ordinal) for section, kind, ordinal in connection.execute(
            "SELECT section, kind, ordinal FROM sections WHERE dataset=?", (dataset,))}
        desired_ids = {section for section, _, _, _ in desired}
        for section in set(old_sections) - desired_ids:
            connection.execute("DELETE FROM sections WHERE dataset=? AND section=?", (dataset, section))
        for ordinal, (section, _, kind, entries) in enumerate(desired):
            if section in old_sections:
                if old_sections[section] != (kind, ordinal):
                    connection.execute("UPDATE sections SET kind=?, ordinal=? WHERE dataset=? AND section=?",
                                       (kind, ordinal, dataset, section))
            else:
                connection.execute("INSERT INTO sections(dataset, section, kind, ordinal) VALUES (?, ?, ?, ?)",
                                   (dataset, section, kind, ordinal))
            old_rows = self._row_map(connection, dataset, section)
            new_rows = {(key, position): self._entry_json(value) for key, position, value in entries}
            for key, position in set(old_rows) - set(new_rows):
                connection.execute("DELETE FROM rows WHERE dataset=? AND section=? AND item_key=? AND position=?",
                                   (dataset, section, key, position))
            for (key, position), value_json in new_rows.items():
                if old_rows.get((key, position)) == value_json:
                    continue
                if (key, position) in old_rows:
                    connection.execute(
                        "UPDATE rows SET value_json=? WHERE dataset=? AND section=? AND item_key=? AND position=?",
                        (value_json, dataset, section, key, position))
                else:
                    connection.execute(
                        "INSERT INTO rows(dataset, section, item_key, position, value_json) VALUES (?, ?, ?, ?, ?)",
                        (dataset, section, key, position, value_json))
        return len(encoded.encode("utf-8"))

    @staticmethod
    def _section_value(kind, rows):
        if kind == "scalar":
            first = next(rows, None)
            if first is None or first[:2] != ("", 0) or next(rows, None) is not None:
                raise DatabaseError("SQLite 状态库标量条目损坏")
            return _decode(first[2])
        if kind == "array":
            result = []
            for _, position, value_json in rows:
                if position != len(result):
                    raise DatabaseError("SQLite 状态库数组顺序损坏")
                result.append(_decode(value_json))
            return result
        if kind == "object":
            result = {}
            for key, position, value_json in rows:
                if position != 0 or key in result:
                    raise DatabaseError("SQLite 状态库对象条目损坏")
                result[key] = _decode(value_json)
            return result
        raise DatabaseError("SQLite 状态库字段类型损坏")

    def _read_dataset(self, connection, dataset, default):
        root_row = connection.execute(
            "SELECT root_kind FROM datasets WHERE dataset=?", (dataset,)).fetchone()
        if not root_row:
            return default
        if self.file_limit is not None or self.total_limit is not None:
            payload_bytes, largest_entry = connection.execute(
                "SELECT COALESCE(SUM(length(CAST(value_json AS BLOB))), 0), "
                "COALESCE(MAX(length(CAST(value_json AS BLOB))), 0) "
                "FROM rows WHERE dataset=?", (dataset,)).fetchone()
            if self.file_limit is not None and largest_entry > self.file_limit:
                raise DatabaseError("SQLite 单条状态记录超过读取上限")
            if self.total_limit is not None and payload_bytes > self.total_limit:
                raise DatabaseError("动态状态超过读取上限")
        result = [] if root_row[0] == "array" else {}
        section_rows = connection.execute(
            "SELECT section, kind FROM sections WHERE dataset=? ORDER BY ordinal", (dataset,))
        seen_sections = 0
        for section_id, kind in section_rows:
            seen_sections += 1
            path = _path_decode(section_id)
            values = connection.execute(
                "SELECT item_key, position, value_json FROM rows WHERE dataset=? AND section=? "
                "ORDER BY position, item_key", (dataset, section_id))
            if root_row[0] == "array":
                if path != () or kind != "array" or seen_sections != 1:
                    raise DatabaseError("SQLite 状态库根数组 section 损坏")
                result = self._section_value(kind, values)
                continue
            if len(path) == 1:
                name = path[0]
                if name in result:
                    raise DatabaseError("SQLite 状态库字段路径冲突")
                result[name] = self._section_value(kind, values)
                continue
            if dataset != "current.json" or len(path) != 3 or path[0] != "baselines" or kind != "object":
                raise DatabaseError("SQLite 状态库 section 路径损坏")
            _, root, child = path
            baselines = result.setdefault("baselines", {})
            if not isinstance(baselines, dict):
                raise DatabaseError("SQLite 状态库基线路径冲突")
            baseline = baselines.setdefault(root, {})
            if not isinstance(baseline, dict):
                raise DatabaseError("SQLite 状态库基线条目损坏")
            value = self._section_value(kind, values)
            if child == "snapshot":
                if set(baseline) & set(value):
                    raise DatabaseError("SQLite 状态库基线字段冲突")
                baseline.update(value)
            elif child in {"records", "directories"}:
                if child in baseline:
                    raise DatabaseError("SQLite 状态库基线字段冲突")
                baseline[child] = value
            else:
                raise DatabaseError("SQLite 状态库 baseline section 损坏")
        if root_row[0] == "array" and seen_sections != 1:
            raise DatabaseError("SQLite 状态库根数组 section 缺失")
        payload_size = len(_json(result).encode("utf-8"))
        if self.total_limit is not None and payload_size > self.total_limit:
            raise DatabaseError("动态状态超过读取上限")
        return result

    def read(self, dataset, default=None):
        if dataset not in DATASET_NAMES:
            raise DatabaseError(f"未知动态状态数据集：{dataset}")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            result = self._read_dataset(connection, dataset, default)
            connection.commit()
            return result
        except sqlite3.Error as exc:
            connection.rollback()
            raise DatabaseError("SQLite 状态库读取失败") from exc
        except DatabaseError:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _capacity_failure(self, total_bytes, outside_bytes, action):
        limit = writable_database_bytes(total_bytes, outside_bytes)
        try:
            current_bytes = self.path.stat().st_size
        except OSError:
            current_bytes = 0
        return ("状态总容量不足，" + action + "；"
                + _capacity_text(total_bytes, outside_bytes, limit, current_bytes)
                + "。上次已提交状态保留；可核对采集范围、记录保留或本机 total_bytes 约定。")

    def _capacity(self, connection, total_bytes, outside_bytes):
        if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            raise DatabaseError("状态写入要求 DELETE 日志模式；请先核对数据库配置与恢复方案")
        # 整个状态有容量上限，保留脏页到提交前，避免提前写盘与多段日志。
        connection.execute("PRAGMA cache_spill=OFF")
        if total_bytes is None:
            return
        limit = writable_database_bytes(total_bytes, outside_bytes)
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        current_pages = connection.execute("PRAGMA page_count").fetchone()[0]
        try:
            current_bytes = max(self.path.stat().st_size, current_pages * page_size)
        except OSError as exc:
            raise DatabaseError("SQLite 状态库无法检查") from exc
        max_pages = limit // page_size
        if current_bytes > limit or max_pages < current_pages:
            raise DatabaseError(self._capacity_failure(total_bytes, outside_bytes, "尚未开始写入"))
        connection.execute(f"PRAGMA max_page_count={max(max_pages, 1)}")

    def _capacity_check(self, connection, total_bytes, outside_bytes):
        if total_bytes is None:
            return
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        page_bytes = (connection.execute("PRAGMA page_count").fetchone()[0] * page_size)
        try:
            current_bytes = max(self.path.stat().st_size, page_bytes)
        except OSError as exc:
            raise DatabaseError("SQLite 状态库无法检查") from exc
        limit = writable_database_bytes(total_bytes, outside_bytes)
        if current_bytes > limit:
            raise DatabaseError(self._capacity_failure(total_bytes, outside_bytes, "本次写入已回滚"))

    def write(self, dataset, data, *, total_bytes=None, outside_bytes=0):
        if dataset not in DATASET_NAMES:
            raise DatabaseError(f"未知动态状态数据集：{dataset}")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._capacity(connection, total_bytes, outside_bytes)
            size = self._replace_dataset(connection, dataset, data)
            self._capacity_check(connection, total_bytes, outside_bytes)
            connection.commit()
            return size
        except DatabaseError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            if _is_full_error(exc):
                raise DatabaseError(self._capacity_failure(total_bytes, outside_bytes, "本次写入已回滚")) from exc
            raise DatabaseError("SQLite 状态库写入失败，事务已回滚") from exc
        finally:
            connection.close()

    def import_data(self, data, metadata=None, *, total_bytes=None, outside_bytes=0):
        if not isinstance(data, dict) or any(name not in DATASET_NAMES for name in data):
            raise DatabaseError("导入数据集名称无效")
        if metadata is not None and not isinstance(metadata, dict):
            raise DatabaseError("导入元数据必须是对象")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._capacity(connection, total_bytes, outside_bytes)
            sizes = {name: self._replace_dataset(connection, name, value)
                     for name, value in data.items()}
            if metadata is not None:
                for key, value in metadata.items():
                    if not isinstance(key, str) or not key:
                        raise DatabaseError("导入元数据键必须是非空字符串")
                    connection.execute(
                        "INSERT INTO metadata(key, value_json) VALUES (?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                        (key, self._entry_json(value)))
            self._capacity_check(connection, total_bytes, outside_bytes)
            connection.commit()
            return sizes
        except DatabaseError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            if _is_full_error(exc):
                raise DatabaseError(self._capacity_failure(total_bytes, outside_bytes, "本次写入已回滚")) from exc
            raise DatabaseError("SQLite 状态库导入失败，事务已回滚") from exc
        finally:
            connection.close()

    def export_data(self, defaults=None):
        defaults = defaults or {}
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            result = {name: self._read_dataset(connection, name, defaults.get(name))
                      for name in DATASET_NAMES}
            connection.commit()
            return result
        except sqlite3.Error as exc:
            connection.rollback()
            raise DatabaseError("SQLite 状态库导出失败") from exc
        except DatabaseError:
            connection.rollback()
            raise
        finally:
            connection.close()
