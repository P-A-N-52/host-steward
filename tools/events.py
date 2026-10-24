"""短时读取 macOS FSEvents；系统接口失败时直接抛出异常。"""

import ctypes as C
import json
import sys
import time


MAX_EVENT_PATHS = 64
MAX_EVENT_PATH_BYTES = 8192
MAX_EVENT_PATH_LENGTH = 4096


def collect_clue(result, seen, budget, path, event_id=None):
    """记录有界的路径线索；超出条数或字节预算时只标记截断，不静默假装完整。"""
    if not isinstance(path, str) or not path:
        return
    ids = result.setdefault("path_ids", [])
    if path in seen:
        if isinstance(seen, dict) and event_id is not None:
            index = seen[path]
            ids[index] = max(ids[index], event_id)
        return
    encoded = len(path.encode("utf-8"))
    if encoded > MAX_EVENT_PATH_LENGTH or len(result["paths"]) >= MAX_EVENT_PATHS \
            or budget["bytes"] + encoded > MAX_EVENT_PATH_BYTES:
        result["paths_truncated"] = True
        return
    if isinstance(seen, dict):
        seen[path] = len(result["paths"])
    else:
        seen.add(path)
    result["paths"].append(path)
    ids.append(event_id if event_id is not None else 0)
    budget["bytes"] += encoded


def apply_event_flag(result, flag):
    if flag & 0x10:
        result["history_complete"] = True
    if flag & (0x1 | 0x2 | 0x4 | 0x8 | 0x20):
        result["rescan_required"] = True
    if flag & (0x2 | 0x4 | 0x8):
        result["history_invalid"] = True


def read_events(roots, since=None):
    if sys.platform != "darwin":
        return {"source": "metadata_snapshot", "available": False,
                "reason": "当前平台使用元数据快照比较"}
    cf = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    fs = C.CDLL("/System/Library/Frameworks/CoreServices.framework/CoreServices")
    pointer = C.c_void_p
    callback_type = C.CFUNCTYPE(None, pointer, pointer, C.c_size_t, pointer,
                               C.POINTER(C.c_uint32), C.POINTER(C.c_uint64))
    cf.CFStringCreateWithCString.argtypes = [pointer, C.c_char_p, C.c_uint32]
    cf.CFStringCreateWithCString.restype = pointer
    cf.CFArrayCreate.argtypes = [pointer, C.POINTER(pointer), C.c_long, pointer]
    cf.CFArrayCreate.restype = pointer
    cf.CFRunLoopGetCurrent.restype = pointer
    cf.CFRunLoopRunInMode.argtypes = [pointer, C.c_double, C.c_bool]
    cf.CFRelease.argtypes = [pointer]
    fs.FSEventsGetCurrentEventId.restype = C.c_uint64
    fs.FSEventStreamCreate.argtypes = [pointer, callback_type, pointer, pointer, C.c_uint64, C.c_double, C.c_uint32]
    fs.FSEventStreamCreate.restype = pointer
    fs.FSEventStreamScheduleWithRunLoop.argtypes = [pointer, pointer, pointer]
    fs.FSEventStreamStart.argtypes = [pointer]
    fs.FSEventStreamStart.restype = C.c_bool
    for name in ["FSEventStreamStop", "FSEventStreamInvalidate", "FSEventStreamRelease"]:
        getattr(fs, name).argtypes = [pointer]
    head = fs.FSEventsGetCurrentEventId()
    if head == 0:
        raise RuntimeError("FSEventsGetCurrentEventId 返回 0，无法取得系统事件位置")
    result = {"source": "macos_fsevents", "available": True, "cursor": head,
              "history_complete": False, "history_invalid": False, "baseline": False,
              "dirty_roots": [], "rescan_required": False,
              "paths": [], "path_ids": [], "paths_truncated": False}
    if since is None:
        result.update(baseline=True, reason="首次记录事件位置；目录基线由元数据盘点建立")
        return result
    if since > head:
        result.update(rescan_required=True, history_invalid=True, reason="事件位置失效")
        return result
    dirty, seen, budget = set(), {}, {"bytes": 0}

    @callback_type
    def callback(stream, context, count, paths, flags, ids):
        names = C.cast(paths, C.POINTER(C.c_char_p))
        for index in range(count):
            flag = flags[index]
            apply_event_flag(result, flag)
            if ids[index] > head or flag & 0x10:
                continue
            name = names[index].decode("utf-8", "replace").rstrip("/") or "/"
            for root in roots:
                if name == root or name.startswith(root + "/"):
                    dirty.add(root)
                    collect_clue(result, seen, budget, name, ids[index])
                    break
                if root.startswith(name + "/"):
                    # 事件发生在 root 的上级；把 root 自身作为复核线索。
                    dirty.add(root)
                    collect_clue(result, seen, budget, root, ids[index])
                    break

    strings = [cf.CFStringCreateWithCString(None, path.encode(), 0x08000100) for path in roots]
    array = cf.CFArrayCreate(None, (pointer * len(strings))(*strings), len(strings), None)
    stream = fs.FSEventStreamCreate(None, callback, None, array, since, 0.05, 0x4)
    if not stream:
        raise RuntimeError("FSEventStreamCreate 创建失败")
    try:
        mode = pointer.in_dll(cf, "kCFRunLoopDefaultMode")
        fs.FSEventStreamScheduleWithRunLoop(stream, cf.CFRunLoopGetCurrent(), mode)
        if not fs.FSEventStreamStart(stream):
            raise RuntimeError("FSEventStreamStart 启动失败")
        deadline = time.monotonic() + 1.5
        while not result["history_complete"] and time.monotonic() < deadline:
            cf.CFRunLoopRunInMode(mode, 0.1, False)
        fs.FSEventStreamStop(stream)
    finally:
        fs.FSEventStreamInvalidate(stream)
        fs.FSEventStreamRelease(stream)
        cf.CFRelease(array)
        for value in strings:
            cf.CFRelease(value)
    result["dirty_roots"] = sorted(dirty)
    if not result["history_complete"]:
        raise TimeoutError("FSEvents 历史读取超过 1.5 秒，未提交新游标")
    return result


if __name__ == "__main__":
    request = json.loads(sys.stdin.buffer.read(16384))
    print(json.dumps(read_events(request["roots"], request.get("since"))))
