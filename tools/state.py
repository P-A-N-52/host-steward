"""状态文件、SQLite 动态状态与单机巡检锁。"""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import tempfile

from database import DATASET_NAMES, SIDECAR_SUFFIXES, Database, writable_database_bytes
from state_io import PolicyChangedError, StewardError, _metadata, decode, encode, read_regular_bytes


class Store:
    def __init__(self, directory, limits):
        self.path = Path(directory).absolute()
        if self.path.is_symlink():
            raise StewardError("状态目录不能是符号链接")
        self.path = self.path.resolve()
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.limits = limits
        self.policy_evidence = None
        self._database_path = self.path / "steward.sqlite3"

    @property
    def database_path(self):
        return self._database_path

    def database_exists(self):
        try:
            info = self._database_path.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise StewardError("SQLite 状态库无法检查") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise StewardError("SQLite 状态库必须是普通文件")
        return True

    @staticmethod
    def empty_database_bytes():
        return Database.empty_database_bytes()

    def database_info(self):
        return self._database().info()

    def check_database(self):
        self._database().check()

    def initialize_database(self, path=None):
        target = self._database_path if path is None else Path(path)
        if not target.is_absolute():
            target = self.target(target)
        if target.parent != self.path:
            raise StewardError("SQLite 状态库必须位于状态目录内")
        Database.initialize(target)
        self._database_path = target

    def _database(self):
        if not self.database_exists():
            raise StewardError("SQLite 状态库不存在，请先迁移旧状态；不会自动读取旧 JSON")
        return Database(self._database_path, self.limits["file_bytes"], self.limits["total_bytes"])

    @staticmethod
    def _database_bytes(path):
        total = path.stat().st_size
        for suffix in SIDECAR_SUFFIXES:
            sidecar = Path(str(path) + suffix)
            try:
                total += sidecar.stat().st_size
            except FileNotFoundError:
                pass
        return total

    def _database_outside(self, database):
        return max(0, self.usage() - self._database_bytes(database.path))

    def capacity(self):
        """返回数据库可长期写入的上限与当前余量，供 agent 判断是否继续写入。"""
        database = self._database()
        database_bytes = self._database_bytes(database.path)
        state_bytes = self.usage()
        outside = max(0, state_bytes - database_bytes)
        total = self.limits["total_bytes"]
        limit = writable_database_bytes(total, outside)
        return {"total_bytes": total, "state_bytes": state_bytes,
                "database_bytes": database_bytes, "outside_bytes": outside,
                "database_limit_bytes": limit,
                "database_headroom_bytes": max(0, limit - database_bytes),
                "writable": database_bytes <= limit}

    def target(self, name):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise StewardError("状态路径必须位于状态目录内")
        target = self.path / relative
        for parent in [target, *target.parents]:
            if parent == self.path.parent:
                break
            if parent.is_symlink():
                raise StewardError("状态目录内不能包含符号链接")
        return target

    @contextmanager
    def lock(self, name=".lock"):
        try:
            fd = os.open(self.target(name),
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        except OSError as exc:
            raise StewardError("锁文件无法打开，必须是普通文件") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise StewardError("锁文件必须是普通文件")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                message = "已有常驻采集运行，停止采集后再执行升级" if name == ".collector.lock" else "已有巡检或操作运行，本轮退出"
                raise StewardError(message) from exc
            yield
        finally:
            os.close(fd)

    def read(self, name, default=None, fields=None):
        if name in DATASET_NAMES:
            return self._database().read(name, default, fields=fields)
        path = self.target(name)
        try:
            payload = read_regular_bytes(path, self.limits["file_bytes"])
        except FileNotFoundError:
            return default
        except OSError as exc:
            raise StewardError(f"状态损坏或无法读取，保留原文件：{name}") from exc
        try:
            return decode(payload)
        except (ValueError, RecursionError) as exc:
            raise StewardError(f"状态损坏或无法读取，保留原文件：{name}") from exc

    def usage(self):
        total = count = 0
        pending = [self.path]
        while pending:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    count += 1
                    if stat.S_ISLNK(info.st_mode) or count > 1024:
                        raise StewardError("状态区存在链接或对象数超限，停止写入")
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(entry.path)
                    elif stat.S_ISREG(info.st_mode):
                        total += info.st_size
        return total

    def check_capacity(self, new_bytes):
        if self.usage() + new_bytes > self.limits["total_bytes"]:
            raise StewardError("状态总容量不足，未开始新变更；请检查既有记录与预算")

    def write_bytes(self, name, payload, *, exclusive=False, created=None):
        if name in DATASET_NAMES:
            raise StewardError("动态状态必须写入 SQLite 状态库，不能写 JSON")
        if name != "steward.sqlite3" and len(payload) > self.limits["file_bytes"]:
            raise StewardError(f"单文件容量不足，保留上次状态：{name}")
        self.check_capacity(len(payload) * (2 if exclusive else 1))
        target = self.target(name)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".writing-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
                if exclusive:
                    published = _metadata(os.fstat(stream.fileno()))
                    os.link(temporary, target)
                    if isinstance(created, dict):
                        created[name] = published
                else:
                    os.replace(temporary, target)
            directory_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def write(self, name, value):
        if name in DATASET_NAMES:
            database = self._database()
            database.write(name, value, total_bytes=self.limits["total_bytes"],
                           outside_bytes=self._database_outside(database))
            return
        self.write_bytes(name, encode(value))

    def import_data(self, data, metadata=None):
        database = self._database()
        return database.import_data(data, metadata=metadata,
                                    total_bytes=self.limits["total_bytes"],
                                    outside_bytes=self._database_outside(database))

    def export_data(self, defaults=None):
        return self._database().export_data(defaults)
