"""状态文件、SQLite 动态状态与单机巡检锁。"""

from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import stat
import tempfile

from database import (DATASET_NAMES, SIDECAR_SUFFIXES, Database, DatabaseError,
                      writable_database_bytes)


class StewardError(Exception):
    pass


class PolicyChangedError(StewardError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def invalid_constant(value):
    raise ValueError("non-finite JSON number")


def decode(payload):
    return json.loads(payload, object_pairs_hook=unique_object,
                      parse_float=finite_float, parse_constant=invalid_constant)


def encode(value):
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def _metadata(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def read_regular_bytes(path, limit):
    if type(limit) is not int or limit < 0:
        raise StewardError("普通文件读取上限无效")
    fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise StewardError("读取目标必须是普通文件")
        if before.st_size > limit:
            raise StewardError("文件超过读取上限")
        remaining = limit + 1
        chunks = []
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        payload = b"".join(chunks)
        if _metadata(before) != _metadata(after):
            raise StewardError("文件在读取期间发生变化")
        if len(payload) != after.st_size:
            raise StewardError("文件未能完整读取")
        if len(payload) > limit:
            raise StewardError("文件超过读取上限")
        return payload
    finally:
        os.close(fd)


class Store:
    def __init__(self, directory, limits):
        self.path = Path(directory).absolute()
        if self.path.is_symlink():
            raise StewardError("状态目录不能是符号链接")
        self.path = self.path.resolve()
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.limits = limits
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
        try:
            return Database.empty_database_bytes()
        except DatabaseError as exc:
            raise StewardError(str(exc)) from exc

    def database_info(self):
        try:
            return self._database().info()
        except DatabaseError as exc:
            raise StewardError(str(exc)) from exc

    def check_database(self):
        try:
            self._database().check()
        except DatabaseError as exc:
            raise StewardError(str(exc)) from exc

    def initialize_database(self, path=None):
        target = self._database_path if path is None else Path(path)
        if not target.is_absolute():
            target = self.target(target)
        if target.parent != self.path:
            raise StewardError("SQLite 状态库必须位于状态目录内")
        try:
            Database.initialize(target)
        except DatabaseError as exc:
            raise StewardError(str(exc)) from exc
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
            if sidecar.exists():
                total += sidecar.stat().st_size
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
    def lock(self):
        try:
            fd = os.open(self.target(".lock"),
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
                raise StewardError("已有巡检或操作运行，本轮退出") from exc
            yield
        finally:
            os.close(fd)

    def read(self, name, default=None):
        if name in DATASET_NAMES:
            try:
                return self._database().read(name, default)
            except DatabaseError as exc:
                raise StewardError(str(exc)) from exc
        path = self.target(name)
        try:
            payload = read_regular_bytes(path, self.limits["file_bytes"])
        except FileNotFoundError:
            return default
        except StewardError:
            raise
        except OSError as exc:
            raise StewardError(f"状态损坏或无法读取，保留原文件：{name}") from exc
        try:
            return decode(payload)
        except (ValueError, RecursionError) as exc:
            raise StewardError(f"状态损坏或无法读取，保留原文件：{name}") from exc

    def usage(self):
        total = count = 0
        for parent, directories, files in os.walk(self.path, followlinks=False):
            for name in directories + files:
                path = Path(parent) / name
                if path.is_symlink():
                    raise StewardError("状态区存在符号链接，停止写入")
                count += 1
                if count > 1024:
                    raise StewardError("状态区对象数异常，停止写入")
                if path.is_file():
                    total += path.stat().st_size
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
            payload_size = len(encode(value))
            if payload_size > self.limits["total_bytes"]:
                raise StewardError(f"动态状态超过总容量预算，保留上次状态：{name}")
            try:
                database = self._database()
                outside = self._database_outside(database)
                database.write(name, value, total_bytes=self.limits["total_bytes"],
                               outside_bytes=outside)
            except DatabaseError as exc:
                raise StewardError(str(exc)) from exc
            return
        self.write_bytes(name, encode(value))

    def import_data(self, data, metadata=None):
        if not isinstance(data, dict):
            raise StewardError("导入数据必须是对象")
        sizes = {name: len(encode(value)) for name, value in data.items()}
        for name, size in sizes.items():
            if name not in DATASET_NAMES:
                raise StewardError(f"未知动态状态数据集：{name}")
            if size > self.limits["total_bytes"]:
                raise StewardError(f"动态状态超过总容量预算，保留上次状态：{name}")
        try:
            database = self._database()
            outside = self._database_outside(database)
            return database.import_data(data, metadata=metadata,
                                        total_bytes=self.limits["total_bytes"],
                                        outside_bytes=outside)
        except DatabaseError as exc:
            raise StewardError(str(exc)) from exc

    def export_data(self, defaults=None):
        try:
            return self._database().export_data(defaults)
        except DatabaseError as exc:
            raise StewardError(str(exc)) from exc
