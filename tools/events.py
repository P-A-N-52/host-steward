"""Short-lived macOS FSEvents reader; output contains hints, not a full audit."""

import ctypes as C
import json
import sys
import time


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
                "reason": "此 demo 尚未实现当前平台的原生变化采集"}
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
        return {"source": "macos_fsevents", "available": False,
                "reason": "未取得系统事件位置，可能受沙箱或系统权限限制；使用快照核验"}
    result = {"source": "macos_fsevents", "available": True, "cursor": head,
              "history_complete": False, "history_invalid": False, "baseline": False,
              "dirty_roots": [], "rescan_required": False}
    if since is None:
        result.update(baseline=True, reason="首次记录事件位置；目录基线由元数据盘点建立")
        return result
    if since > head:
        result.update(rescan_required=True, history_invalid=True, reason="事件位置失效")
        return result
    dirty = set()

    @callback_type
    def callback(stream, context, count, paths, flags, ids):
        names = C.cast(paths, C.POINTER(C.c_char_p))
        for index in range(count):
            flag = flags[index]
            apply_event_flag(result, flag)
            if ids[index] > head or flag & 0x10:
                continue
            name = names[index].decode("utf-8", "replace").rstrip("/")
            for root in roots:
                if name == root or name.startswith(root + "/") or root.startswith(name + "/"):
                    dirty.add(root)

    strings = [cf.CFStringCreateWithCString(None, path.encode(), 0x08000100) for path in roots]
    array = cf.CFArrayCreate(None, (pointer * len(strings))(*strings), len(strings), None)
    stream = fs.FSEventStreamCreate(None, callback, None, array, since, 0.05, 0x4)
    if not stream:
        raise RuntimeError("FSEventStreamCreate failed")
    try:
        mode = pointer.in_dll(cf, "kCFRunLoopDefaultMode")
        fs.FSEventStreamScheduleWithRunLoop(stream, cf.CFRunLoopGetCurrent(), mode)
        if not fs.FSEventStreamStart(stream):
            raise RuntimeError("FSEventStreamStart failed")
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
        result["rescan_required"] = True
        result["reason"] = "历史读取未在时间预算内完成；本轮仍核对目录快照"
    return result


if __name__ == "__main__":
    try:
        request = json.loads(sys.stdin.buffer.read(16384))
        print(json.dumps(read_events(request["roots"], request.get("since"))))
    except Exception as error:
        print(json.dumps({"source": "macos_fsevents", "available": False, "reason": str(error)[:200]}))
