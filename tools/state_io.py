"""状态共用的 JSON 编码、普通文件读取与异常。"""

import json
import math
import os
import stat


class StewardError(Exception):
    pass


class PolicyChangedError(StewardError):
    pass


class DatabaseError(StewardError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("重复 JSON 字段")
        result[key] = value
    return result


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("非有限 JSON 数字")
    return result


def invalid_constant(value):
    raise ValueError("非有限 JSON 数字")


def decode(payload):
    return json.loads(payload, object_pairs_hook=unique_object,
                      parse_float=finite_float, parse_constant=invalid_constant)


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def encode(value):
    return (dumps(value) + "\n").encode()


def _metadata(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def read_regular_bytes(path, limit):
    fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise StewardError("读取目标必须是普通文件")
        if before.st_size > limit:
            raise StewardError("文件超过读取上限")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            payload = stream.read(before.st_size + 1)
        after = os.fstat(fd)
        if _metadata(before) != _metadata(after):
            raise StewardError("文件在读取期间发生变化")
        if len(payload) != after.st_size or len(payload) > limit:
            raise StewardError("文件未能在预算内完整读取")
        return payload
    finally:
        os.close(fd)
