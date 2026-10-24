"""SQLite 动态状态存储。

schema 2 在 current/inventory/operations 数据集之外保存资源历史；v1 仍按原数据集
读写，资源历史与结构升级必须显式调用 ``upgrade_schema``，连接时不会自动升级。
"""

from collections import defaultdict
from contextlib import contextmanager
from itertools import groupby
import os
from pathlib import Path
import sqlite3
import stat
import tempfile

from state_io import DatabaseError, decode, dumps


_MISSING = object()


SCHEMA_VERSION = 2
DATASET_NAMES = ("current.json", "inventory.json", "operations.json")
SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")
# 提交时回滚日志保存旧页；为日志头与校验字节单独留出的余量。
RESERVE_HEADROOM = 65536


def _compact_sql(statement):
    """SQLite 会把建表原文写入 schema；压缩空白以控制空库页数。"""
    return " ".join(line.strip() for line in statement.strip().splitlines())


SCHEMA_1_TABLES = frozenset({"datasets", "metadata", "sections", "rows"})
SCHEMA_2_TABLES = SCHEMA_1_TABLES | frozenset({
    "resource_samples", "process_samples", "collector_runs",
    "collector_state", "collector_gaps", "collector_sources",
})
SCHEMA_1_TABLE_STATEMENTS = (
    """
    CREATE TABLE datasets (
        dataset TEXT PRIMARY KEY,
        root_kind TEXT NOT NULL CHECK (root_kind IN ('object', 'array'))
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE metadata (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE sections (
        dataset TEXT NOT NULL REFERENCES datasets(dataset) ON DELETE CASCADE,
        section TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('scalar', 'object', 'array')),
        ordinal INTEGER NOT NULL,
        PRIMARY KEY (dataset, section)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE rows (
        dataset TEXT NOT NULL,
        section TEXT NOT NULL,
        item_key TEXT NOT NULL,
        position INTEGER NOT NULL,
        value_json TEXT NOT NULL,
        PRIMARY KEY (dataset, section, position, item_key),
        FOREIGN KEY (dataset, section) REFERENCES sections(dataset, section)
            ON DELETE CASCADE
    ) WITHOUT ROWID
    """,
)
SCHEMA_2_TABLE_STATEMENTS = (
    """
    CREATE TABLE collector_runs (
        run_id TEXT PRIMARY KEY,
        mode TEXT NOT NULL,
        started_at REAL NOT NULL,
        stopped_at REAL,
        stop_reason TEXT,
        boot_json TEXT,
        pid INTEGER CHECK (pid IS NULL OR pid >= 1),
        policy_json TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        CHECK (stopped_at IS NULL OR stopped_at >= started_at)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE collector_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        run_id TEXT,
        heartbeat_at REAL,
        last_complete_at REAL,
        stopped_at REAL,
        detail_json TEXT
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE collector_gaps (
        gap_id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT REFERENCES collector_runs(run_id) ON DELETE RESTRICT,
        start_at REAL NOT NULL,
        end_at REAL,
        reason TEXT NOT NULL,
        detail_json TEXT,
        recorded_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        CHECK (end_at IS NULL OR end_at >= start_at)
    )
    """,
    """
    CREATE TABLE collector_sources (
        source TEXT PRIMARY KEY,
        available INTEGER CHECK (available IS NULL OR available IN (0, 1)),
        attempted_at REAL,
        success_at REAL,
        error_at REAL,
        error_json TEXT,
        detail_json TEXT NOT NULL,
        updated_at REAL NOT NULL
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE resource_samples (
        sample_id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES collector_runs(run_id) ON DELETE RESTRICT,
        observed_at REAL NOT NULL,
        monotonic_at REAL,
        boot_json TEXT,
        host_json TEXT NOT NULL,
        sources_json TEXT NOT NULL,
        sampling_json TEXT NOT NULL,
        process_observed INTEGER NOT NULL CHECK (process_observed IN (0, 1)),
        process_truncated INTEGER NOT NULL CHECK (process_truncated IN (0, 1)),
        process_observed_at REAL,
        process_count INTEGER NOT NULL CHECK (process_count >= 0),
        process_meta_json TEXT,
        created_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE process_samples (
        sample_id INTEGER NOT NULL REFERENCES resource_samples(sample_id) ON DELETE CASCADE,
        position INTEGER NOT NULL,
        identity TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        PRIMARY KEY (sample_id, position)
    ) WITHOUT ROWID
    """,
)
SCHEMA_2_INDEX_STATEMENTS = (
    "CREATE INDEX resource_samples_observed_idx ON resource_samples(observed_at, sample_id)",
    "CREATE INDEX process_samples_identity_idx ON process_samples(identity, sample_id)",
)
SCHEMA_2_INDEXES = frozenset({
    "resource_samples_observed_idx", "process_samples_identity_idx",
})
SCHEMA_1_TABLE_STATEMENTS = tuple(_compact_sql(item) for item in SCHEMA_1_TABLE_STATEMENTS)
SCHEMA_2_TABLE_STATEMENTS = tuple(_compact_sql(item) for item in SCHEMA_2_TABLE_STATEMENTS)
_SCHEMA_2_SQL = ";\n".join(
    SCHEMA_1_TABLE_STATEMENTS + SCHEMA_2_TABLE_STATEMENTS
    + SCHEMA_2_INDEX_STATEMENTS) + ";\nPRAGMA user_version = 2;"


def _json(value):
    try:
        return dumps(value)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise DatabaseError("动态状态不能编码为有限 JSON") from exc


def _decode(payload):
    try:
        return decode(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise DatabaseError("SQLite 状态库包含损坏的 JSON 条目") from exc


def _path_json(path):
    return dumps(list(path))


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
            if version == 1:
                required_tables, required_indexes = SCHEMA_1_TABLES, frozenset()
            elif version == 2:
                required_tables, required_indexes = SCHEMA_2_TABLES, SCHEMA_2_INDEXES
            else:
                raise DatabaseError(f"SQLite 状态库版本不受支持：{version}；保留现场，核对备份与版本")
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            missing_tables = sorted(required_tables - tables)
            if missing_tables:
                raise DatabaseError("SQLite 状态库结构不完整，缺少表：" + "、".join(missing_tables))
            if required_indexes:
                indexes = {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'")}
                missing_indexes = sorted(required_indexes - indexes)
                if missing_indexes:
                    raise DatabaseError("SQLite 状态库结构不完整，缺少资源历史索引："
                                        + "、".join(missing_indexes))
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
            connection.executescript(_SCHEMA_2_SQL)
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
            path.unlink(missing_ok=True)
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
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            datasets = connection.execute(
                "SELECT dataset, root_kind FROM datasets ORDER BY dataset").fetchall()
            return {"path": str(self.path), "schema_version": version,
                    "datasets": {name: kind for name, kind in datasets},
                    "size": self.path.stat().st_size}
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError("SQLite 状态库信息读取失败") from exc
        finally:
            connection.close()

    @staticmethod
    def _schema_objects(connection):
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        return tables, indexes

    def upgrade_schema(self, apply=False, *, total_bytes=None, outside_bytes=0):
        """预览或显式升级到资源历史 schema；不自动调用，也不代替备份。"""
        connection = self._connect()
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            tables, indexes = self._schema_objects(connection)
        except sqlite3.Error as exc:
            raise DatabaseError("SQLite 状态库版本读取失败") from exc
        finally:
            connection.close()
        steps = [f"table:{name}" for name in sorted(SCHEMA_2_TABLES - SCHEMA_1_TABLES)] \
            + [f"index:{name}" for name in sorted(SCHEMA_2_INDEXES)] + ["user_version=2"]
        preview = {"from_version": version, "to_version": SCHEMA_VERSION,
                   "applied": False, "already_current": version == SCHEMA_VERSION,
                   "steps": steps}
        if version == SCHEMA_VERSION:
            return preview
        if version != 1:
            raise DatabaseError(f"SQLite 状态库版本不受支持：{version}；不执行结构升级")
        conflicts = sorted(
            ((SCHEMA_2_TABLES - SCHEMA_1_TABLES) | SCHEMA_2_INDEXES)
            & (tables | indexes))
        if conflicts:
            raise DatabaseError("SQLite 状态库已存在部分资源历史结构，保留现场并停止升级："
                                + "、".join(conflicts))
        if not apply:
            return preview
        with self._transaction(write=True, total_bytes=total_bytes,
                               outside_bytes=outside_bytes) as connection:
            # 预览与写入之间可能被其他写者升级；锁内重新核对版本。
            locked_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if locked_version == SCHEMA_VERSION:
                preview.update(applied=False, already_current=True)
                return preview
            if locked_version != 1:
                raise DatabaseError(
                    f"SQLite 状态库版本不受支持：{locked_version}；不执行结构升级")
            # DDL 必须逐条执行；executescript 会隐式提交，无法与版本号一起回滚。
            for statement in SCHEMA_2_TABLE_STATEMENTS + SCHEMA_2_INDEX_STATEMENTS:
                connection.execute(statement)
            connection.execute("PRAGMA user_version=2")
            tables, indexes = self._schema_objects(connection)
            missing = sorted((SCHEMA_2_TABLES | SCHEMA_2_INDEXES)
                             - (tables | indexes))
            if missing:
                raise DatabaseError("SQLite 状态库升级后结构校验失败："
                                    + "、".join(missing))
        # 新连接按 v2 校验表、索引和版本；失败时正式库仍保留升级结果供核对。
        self._connect().close()
        preview["applied"] = True
        preview["schema_version"] = SCHEMA_VERSION
        return preview

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
            if dataset == "current.json" and name == "scan_progress" and isinstance(value, dict):
                # 续扫进度按 root 分节：候选记录、分配字节与按目录排除计数逐条成行；
                # 队列、边界、游标等相对文件数较小的字段留在 snapshot 行内（queue 随
                # 目录数增长），避免候选记录随文件数挤进单条记录。
                sections.append((_path_json((name,)), (name,), "object",
                                 [("next_index", 0, value["next_index"])]
                                 if "next_index" in value else []))
                for root, entry in value.items():
                    if root == "next_index":
                        continue
                    root = str(root)
                    if not isinstance(entry, dict):
                        raise DatabaseError("scan_progress 条目必须是对象")
                    base = dict(entry)
                    children = {}
                    for child in ("records", "allocated", "excluded_by_dir"):
                        item = base.pop(child, _MISSING)
                        if item is _MISSING:
                            continue
                        if not isinstance(item, dict):
                            raise DatabaseError(f"scan_progress.{child} 必须是对象")
                        children[child] = item
                    sections.append((_path_json((name, root, "snapshot")),
                                     (name, root, "snapshot"), "object",
                                     [(str(key), 0, item) for key, item in base.items()]))
                    for child, item in children.items():
                        sections.append((_path_json((name, root, child)),
                                         (name, root, child), "object",
                                         [(str(key), 0, entry_value) for key, entry_value in item.items()]))
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

    def _entry_json_with_size(self, value):
        payload = _json(value)
        size = len(payload.encode("utf-8"))
        if self.file_limit is not None and size > self.file_limit:
            raise DatabaseError("SQLite 单条状态记录超过容量上限")
        return payload, size

    def _entry_json(self, value):
        return self._entry_json_with_size(value)[0]

    def _replace_dataset(self, connection, dataset, data):
        root_kind, desired = self._sections(dataset, data)
        prepared = []
        encoded_size = 0
        for section, _, kind, entries in desired:
            new_rows = {}
            for key, position, value in entries:
                payload, size = self._entry_json_with_size(value)
                new_rows[(key, position)] = payload
                encoded_size += size
            prepared.append((section, kind, new_rows))
        if self.total_limit is not None:
            if encoded_size > self.total_limit:
                raise DatabaseError("动态状态数据集超过总容量预算")
            if encoded_size > self.total_limit * 0.9:
                # 行级累计不含节名与结构开销；接近上限时回退整份编码精确判定。
                if len(_json(data).encode("utf-8")) > self.total_limit:
                    raise DatabaseError("动态状态数据集超过总容量预算")
        connection.execute(
            "INSERT INTO datasets(dataset, root_kind) VALUES (?, ?) "
            "ON CONFLICT(dataset) DO UPDATE SET root_kind=excluded.root_kind "
            "WHERE datasets.root_kind != excluded.root_kind", (dataset, root_kind))
        old_sections = {section: (kind, ordinal) for section, kind, ordinal in connection.execute(
            "SELECT section, kind, ordinal FROM sections WHERE dataset=?", (dataset,))}
        desired_ids = {section for section, _, _, _ in desired}
        for section in set(old_sections) - desired_ids:
            connection.execute("DELETE FROM sections WHERE dataset=? AND section=?", (dataset, section))
        existing = defaultdict(dict)
        for section, key, position, value in connection.execute(
                "SELECT section, item_key, position, value_json FROM rows WHERE dataset=?", (dataset,)):
            existing[section][key, position] = value
        for ordinal, (section, kind, new_rows) in enumerate(prepared):
            if section in old_sections:
                if old_sections[section] != (kind, ordinal):
                    connection.execute("UPDATE sections SET kind=?, ordinal=? WHERE dataset=? AND section=?",
                                       (kind, ordinal, dataset, section))
            else:
                connection.execute("INSERT INTO sections(dataset, section, kind, ordinal) VALUES (?, ?, ?, ?)",
                                   (dataset, section, kind, ordinal))
            old_rows = existing[section]
            connection.executemany(
                "DELETE FROM rows WHERE dataset=? AND section=? AND item_key=? AND position=?",
                [(dataset, section, key, position) for key, position in old_rows.keys() - new_rows.keys()])
            connection.executemany(
                "INSERT INTO rows(dataset, section, item_key, position, value_json) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(dataset, section, position, item_key) DO UPDATE SET value_json=excluded.value_json",
                [(dataset, section, key, position, value_json)
                 for (key, position), value_json in new_rows.items()
                 if old_rows.get((key, position)) != value_json])
        return encoded_size

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

    def _read_dataset(self, connection, dataset, default, fields=None):
        root_row = connection.execute(
            "SELECT root_kind FROM datasets WHERE dataset=?", (dataset,)).fetchone()
        if not root_row:
            return default
        parameters = [dataset]
        selection = ""
        if fields is not None:
            if root_row[0] != "object":
                raise DatabaseError("只有对象数据集支持按字段读取")
            clauses = []
            for field in fields:
                exact = _path_json((field,))
                prefix = exact[:-1] + ","
                clauses.append("(s.section=? OR substr(s.section, 1, ?)=?)")
                parameters.extend((exact, len(prefix), prefix))
            selection = " AND (" + " OR ".join(clauses) + ")" if clauses else " AND 0"
        if self.file_limit is not None or self.total_limit is not None:
            payload_bytes, largest_entry = connection.execute(
                "SELECT COALESCE(SUM(length(CAST(r.value_json AS BLOB))), 0), "
                "COALESCE(MAX(length(CAST(r.value_json AS BLOB))), 0) "
                "FROM rows r JOIN sections s ON s.dataset=r.dataset AND s.section=r.section "
                "WHERE s.dataset=?" + selection, parameters).fetchone()
            if self.file_limit is not None and largest_entry > self.file_limit:
                raise DatabaseError("SQLite 单条状态记录超过读取上限")
            if self.total_limit is not None and payload_bytes > self.total_limit:
                raise DatabaseError("动态状态超过读取上限")
        result = [] if root_row[0] == "array" else {}
        rows = connection.execute(
            "SELECT s.section, s.kind, r.item_key, r.position, r.value_json "
            "FROM sections s LEFT JOIN rows r ON r.dataset=s.dataset AND r.section=s.section "
            "WHERE s.dataset=?" + selection + " ORDER BY s.ordinal, s.section, r.position, r.item_key", parameters)
        seen_sections = 0
        for (section_id, kind), entries in groupby(rows, key=lambda row: row[:2]):
            seen_sections += 1
            path = _path_decode(section_id)
            values = ((key, position, value) for _, _, key, position, value in entries if position is not None)
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
            if dataset != "current.json" or len(path) != 3 or kind != "object":
                raise DatabaseError("SQLite 状态库 section 路径损坏")
            _, root, child = path
            if path[0] == "baselines":
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
                continue
            if path[0] == "scan_progress":
                progress = result.setdefault("scan_progress", {})
                if not isinstance(progress, dict):
                    raise DatabaseError("SQLite 状态库续扫进度路径冲突")
                entry = progress.setdefault(root, {})
                if not isinstance(entry, dict):
                    raise DatabaseError("SQLite 状态库续扫进度条目损坏")
                value = self._section_value(kind, values)
                if child == "snapshot":
                    if set(entry) & set(value):
                        raise DatabaseError("SQLite 状态库续扫进度字段冲突")
                    entry.update(value)
                elif child in {"records", "allocated", "excluded_by_dir"}:
                    if child in entry:
                        raise DatabaseError("SQLite 状态库续扫进度字段冲突")
                    entry[child] = value
                else:
                    raise DatabaseError("SQLite 状态库 scan_progress section 损坏")
                continue
            raise DatabaseError("SQLite 状态库 section 路径损坏")
        if root_row[0] == "array" and seen_sections != 1:
            raise DatabaseError("SQLite 状态库根数组 section 缺失")
        payload_size = len(_json(result).encode("utf-8"))
        if self.total_limit is not None and payload_size > self.total_limit:
            raise DatabaseError("动态状态超过读取上限")
        return result

    @contextmanager
    def _transaction(self, *, write=False, total_bytes=None, outside_bytes=0,
                     require_version=None):
        connection = self._connect()
        try:
            if require_version is not None:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version != require_version:
                    raise DatabaseError(
                        f"该操作要求 SQLite 状态库版本 {require_version}，当前为 {version}；"
                        "请先核对备份并显式执行 upgrade_schema，不会自动升级")
            with connection:
                connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                if write:
                    self._capacity(connection, total_bytes, outside_bytes)
                yield connection
        except sqlite3.Error as exc:
            if write and _is_full_error(exc):
                raise DatabaseError(self._capacity_failure(total_bytes, outside_bytes, "本次写入已回滚")) from exc
            action = "写入" if write else "读取"
            raise DatabaseError(f"SQLite 状态库{action}失败，事务已回滚") from exc
        finally:
            connection.close()

    def read(self, dataset, default=None, fields=None):
        if dataset not in DATASET_NAMES:
            raise DatabaseError(f"未知动态状态数据集：{dataset}")
        with self._transaction() as connection:
            return self._read_dataset(connection, dataset, default, fields)

    def _capacity_failure(self, total_bytes, outside_bytes, action):
        limit = writable_database_bytes(total_bytes, outside_bytes)
        current_bytes = self.path.stat().st_size
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

    def write(self, dataset, data, *, total_bytes=None, outside_bytes=0):
        if dataset not in DATASET_NAMES:
            raise DatabaseError(f"未知动态状态数据集：{dataset}")
        with self._transaction(write=True, total_bytes=total_bytes, outside_bytes=outside_bytes) as connection:
            return self._replace_dataset(connection, dataset, data)

    def import_data(self, data, metadata=None, *, total_bytes=None, outside_bytes=0):
        if not isinstance(data, dict) or any(name not in DATASET_NAMES for name in data):
            raise DatabaseError("导入数据集名称无效")
        if metadata is not None and not isinstance(metadata, dict):
            raise DatabaseError("导入元数据必须是对象")
        with self._transaction(write=True, total_bytes=total_bytes, outside_bytes=outside_bytes) as connection:
            sizes = {name: self._replace_dataset(connection, name, value) for name, value in data.items()}
            for key, value in (metadata or {}).items():
                if not isinstance(key, str) or not key:
                    raise DatabaseError("导入元数据键必须是非空字符串")
                connection.execute(
                    "INSERT INTO metadata(key, value_json) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                    (key, self._entry_json(value)))
            return sizes

    def export_data(self, defaults=None):
        defaults = defaults or {}
        with self._transaction() as connection:
            return {name: self._read_dataset(connection, name, defaults.get(name)) for name in DATASET_NAMES}
