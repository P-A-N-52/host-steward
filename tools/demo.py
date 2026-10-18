"""A small, real filesystem exercise; all changes stay inside a new workspace."""

import json
import os
from pathlib import Path
import platform
import sys
import time
import subprocess

from files import compare, identity, scan
from maintain import annotate, quarantine, restore
from inventory import register
from investigate import inspect_target
from state import Store, StewardError, decode
from state_schema import read_current
from steward import ensure_policy_locked, initialize, patrol, refresh_policy_locked


def run_demo(workspace):
    workspace = Path(workspace)
    if workspace.is_symlink():
        raise StewardError("演示工作目录不能是符号链接")
    workspace = workspace.resolve()
    if workspace.exists() and not workspace.is_dir():
        raise StewardError("演示工作目录需为目录")
    if workspace.exists() and any(workspace.iterdir()):
        manifest, report = workspace / "demo.json", workspace / "report.md"
        if manifest.is_symlink() or report.is_symlink():
            raise StewardError("已有演示的清单和报告不能是符号链接")
        if manifest.is_file() and manifest.stat().st_size < 16384 and report.is_file():
            try:
                saved = decode(manifest.read_bytes())
            except (ValueError, RecursionError) as exc:
                raise StewardError("已有演示清单损坏，未重新验证或覆盖") from exc
            if not isinstance(saved, dict):
                raise StewardError("已有演示清单需为对象，未重新验证或覆盖")
            if "checks" in saved and (not isinstance(saved["checks"], dict) or
                                       any(type(value) is not bool for value in saved["checks"].values())):
                raise StewardError("已有演示 checks 格式无效")
            if "changes" in saved and (not isinstance(saved["changes"], list) or
                                        any(not isinstance(row, dict) for row in saved["changes"])):
                raise StewardError("已有演示 changes 格式无效")
            if "demo_version" in saved and (type(saved["demo_version"]) is not int or saved["demo_version"] < 1):
                raise StewardError("已有演示版本无效")
            if "verified" in saved and type(saved["verified"]) is not bool:
                raise StewardError("已有演示 verified 格式无效")
            if saved.get("status") == "demo_verified" and saved.get("workspace") == str(workspace):
                return {"status": "existing_demo", "verified": False, "workspace": str(workspace), "report": str(report),
                        "message": "仅保留历史产物供查看，本轮未重新执行或验证；指定新的空目录可重新运行"}
        raise StewardError(f"演示目录已有内容，未覆盖：{workspace}；可查看历史 report.md，或指定新的空目录重新验证")
    workspace.mkdir(parents=True, exist_ok=True)
    root = workspace / "sample-host"
    for name in ["cold", "working", "logs", "inbox", "gone"]:
        (root / name).mkdir(parents=True)
    cold = root / "cold/original.txt"
    cold.write_text("重要原始资料：即使长期未用也保留。\n")
    (root / "cold/AGENTS.md").write_text("# 用户原有说明\n\n此处保存重要资料。\n")
    temporary = root / "working/task.tmp"
    temporary.write_text("已结束演示任务的可回收产物\n")
    old = time.time() - 90 * 86400
    os.utime(cold, (old, old))
    os.utime(temporary, (old, old))
    (root / "logs/app.log").write_text("demo log\n")
    (root / "inbox/item.txt").write_text("待收纳的样例\n")
    (root / "gone/old.txt").write_text("目录删除样例\n")
    store, policy = initialize(workspace / "state", [root], "隔离样例：演示整机观测与目录维护，文件仅覆盖 sample-host")
    policy["residents"] = [{"executable": Path(sys.executable).name, "reason": "演示工具自身，只观察、不终止"}]
    policy["directory_rules"] = [
        {"path": str(root / "cold"), "purpose": "重要冷资料", "kind": "cold", "allow_notes": True,
         "directory_id": identity((root / "cold").stat())},
        {"path": str(root / "working"), "purpose": "演示任务临时产物", "kind": "temporary", "allow_notes": True,
         "allow_quarantine": True, "retention_days": 1, "recycle_bytes": 1048576,
         "directory_id": identity((root / "working").stat())},
        {"path": str(root / "logs"), "purpose": "演示程序日志", "kind": "service",
         "directory_id": identity((root / "logs").stat())}]
    with store.lock():
        store.write("host.json", policy)
    first = patrol(store, policy)
    (root / "inbox").rename(root / "received")
    (root / "gone/old.txt").unlink()
    (root / "gone").rmdir()
    (root / "new-batch").mkdir()
    for index in range(128):
        (root / "new-batch" / f"item-{index}.txt").write_text("sample\n")
    with (root / "logs/app.log").open("a") as stream:
        stream.write("x" * 1024**2)
    second = patrol(store, policy)
    with store.lock():
        policy = refresh_policy_locked(store)

        def policy_guard():
            ensure_policy_locked(store, policy)

        note = annotate(store, policy, root / "cold", True, policy_guard)
        annotate(store, policy, root / "working", True, policy_guard)
        try:
            quarantine(store, policy, cold, True, policy_guard)
            cold_rejected = False
        except StewardError:
            cold_rejected = True
        moved = quarantine(store, policy, temporary, True, policy_guard)
        move_verified = not temporary.exists() and Path(moved["operation"]["target"]).is_file()
        restored = restore(store, policy, moved["operation"]["id"], True, policy_guard)
    final = patrol(store, policy)
    with store.lock():
        policy = refresh_policy_locked(store)
        register(store, {"id": "demo.cold", "kind": "directory", "locator": str(root / "cold"),
                         "purpose": "重要原始资料", "owner": "隔离样例", "dependencies": ["演示中的长期项目"],
                         "retention": "长期保留，不按年龄回收", "maintenance": "原位检查；操作引用 host.json",
                         "basis": "reported", "source": "样例用户说明，未独立确认实际业务用途",
                         "evidence_at": old, "review_after_hours": 720})
        investigation = inspect_target(store, policy, "demo.cold")
    reader = subprocess.run([sys.executable, str(Path(__file__).resolve().with_name("steward.py")), "inventory", "--state", str(store.path),
                             "--id", "demo.cold"], cwd="/", capture_output=True, timeout=5, check=True)
    readback = decode(reader.stdout)["resources"][0]
    current = read_current(store)
    small_limits = dict(policy["limits"], scan_entries=2)
    incomplete = scan(policy["roots"], small_limits, policy["exclude_names"], str(store.path))
    limited_delta = compare(current["baselines"], incomplete, policy["limits"]["change_records"])
    before = store.read("current.json")
    limited_store = Store(store.path, dict(policy["limits"], total_bytes=store.usage() + 1))
    try:
        limited_store.write("current.json", {"would_replace": True})
        quota_rejected = False
    except StewardError:
        quota_rejected = True
    by_path = {row["path"]: row for row in second["changes"]}
    root_change, log_change = by_path.get(str(root), {}), by_path.get(str(root / "logs"), {})
    samples = root_change.get("samples", [])
    created = {row["directory_created"] for row in samples if isinstance(row, dict) and "directory_created" in row}
    removed = {row["directory_removed"] for row in samples if isinstance(row, dict) and "directory_removed" in row}
    source, destination = str(root / "inbox"), str(root / "received")
    reliable_move = any(isinstance(row, dict) and row.get("from") == source and row.get("to") == destination
                        and row.get("kind") == "directory" for row in samples)
    uncertain_move = any(f"identity: move uncertain {source} -> {destination}" in row["reasons"] for row in second["gaps"])
    reliable_changes = (root_change.get("added"), root_change.get("removed"), root_change.get("moved")) == (1, 1, 1) \
        and reliable_move and created == {str(root / "new-batch")} and removed == {str(root / "gone")}
    uncertain_changes = (root_change.get("added"), root_change.get("removed"), root_change.get("moved")) == (2, 2, 0) \
        and uncertain_move and bool(created) and created <= {str(root / "new-batch"), destination} \
        and bool(removed) and removed <= {str(root / "gone"), source}
    checks = {
        "complete_baseline_created": first["last_run"]["coverage_complete"] and not first["changes"]
                                     and first["new_baselines"] == [str(root)] and not first["gaps"],
        "change_snapshot_complete": second["last_run"]["coverage_complete"] and not second["new_baselines"],
        "directory_changes_observed": reliable_changes or uncertain_changes,
        "log_growth_detected": log_change.get("modified") == 1 and log_change.get("byte_delta") == 1024**2,
        "cold_file_protected": cold_rejected and cold.read_text().startswith("重要原始资料"),
        "user_agents_preserved": note["applied"] and (root / "cold/AGENTS.md").read_text().startswith("# 用户原有说明"),
        "quarantine_verified": move_verified,
        "restore_verified": restored["applied"] and temporary.read_text().startswith("已结束"),
        "partial_scan_does_not_report_deletion": bool(limited_delta["gaps"]) and not limited_delta["changes"],
        "quota_preserves_last_state": quota_rejected and store.read("current.json") == before,
        "independent_process_reads_durable_knowledge": readback["definition"]["retention"] == "长期保留，不按年龄回收",
        "inspection_does_not_refresh_old_knowledge": readback["review_due"] and readback["definition"]["evidence_at"] == old,
        "inspection_evidence_is_saved": readback["inspection"]["observed_at"] == investigation["observed_at"],
    }
    if not all(checks.values()):
        raise StewardError("演示验证未全部通过：" + json.dumps(checks, ensure_ascii=False))
    observed_at = time.time()
    observations = {}
    for kind in ["processes", "services"]:
        observation = current["host"][kind]
        observations[kind] = {key: observation.get(key) for key in ["available", "observed", "truncated", "reason", "scope"]}
        observations[kind].update(retained=len(observation["items"]), shown=len(final[kind]["items"]))
    coverage = {"baseline": first["last_run"]["coverage_complete"], "changes": second["last_run"]["coverage_complete"],
                "final": final["last_run"]["coverage_complete"]}
    summary = {"status": "demo_verified", "verified": True, "demo_version": 2, "observed_at": observed_at,
               "platform": platform.system(), "workspace": str(workspace), "checks": checks,
               "state_bytes": store.usage(), "capacity": store.capacity(), "events": final["events"],
               "sample_limits": policy["limits"],
               "file_coverage": coverage, "observations": observations, "observation_gaps": final["observation_gaps"],
               "gaps": second["gaps"], "changes": second["changes"], "report": str(workspace / "report.md")}
    lines = ["# Host Steward 0.2 Demo", "", "已完成真实样例文件的巡检、变化对比、目录说明、回收与恢复，以及资源档案、只读调查和独立进程读回。",
             "本机资源来自只读系统观测；文件覆盖仅限 sample-host，未清理真实主机资源。", "",
             f"- 本轮时间：{time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(observed_at))}；平台：{summary['platform']}。",
             f"- 样例预算（非真实主机授权或预算）：`{json.dumps(policy['limits'], ensure_ascii=False)}`。",
             f"- 状态区：{store.usage():,} 字节 / {policy['limits']['total_bytes']:,} 字节预算。",
             f"- 元数据快照覆盖：{json.dumps(coverage)}；不代表完整事件审计。",
             f"- 原生变化来源：{final['events'].get('source', 'unavailable')}；available={final['events']['available']}。"]
    for kind, label in [("processes", "进程"), ("services", "服务")]:
        row = observations[kind]
        lines.append(f"- {label}观测：available={row['available']}；observed={row['observed']}；retained={row['retained']}；shown={row['shown']}；truncated={row['truncated']}；scope={row['scope']}。")
    lines += [f"- 覆盖与身份缺口：{json.dumps(second['gaps'], ensure_ascii=False)}。",
              f"- 整机观测缺口：{json.dumps(final['observation_gaps'], ensure_ascii=False)}。",
              "- GPU 与模型费用：当前 demo 无来源，标为未知。", "", "## 演示验证", ""]
    lines += [f"- **通过** `{key}`" for key in checks]
    lines += ["", "## 目录变化", "", "端点样本每组最多 3 条；缺 birth 时，以预期聚合计数、精确 move uncertain 缺口和允许端点样本核验，不声称逐端点完整审计。", "",
              "| 目录 | 新增 | 删除 | 修改 | 移动 | 子树体积差 |",
              "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for row in second["changes"]:
        lines.append(f"| {Path(row['path']).relative_to(root) or '.'} | {row['added']} | {row['removed']} | {row['modified']} | {row['moved']} | {row['byte_delta']:+,} B |")
    lines += ["", "父子目录体积重叠，不能相加；同卷回收已明确记录释放空间为 0。", "",
              "## 查看结果", "", "- `state/host.json`：示例约定、常驻规则与预算。",
              "- `state/steward.sqlite3`：本机观测、目录索引、近期变化、待办、长期知识与操作恢复证据。",
              "- 使用 status / inventory 查询，export --dataset current、inventory 或 operations 导出逻辑数据。",
              "- `sample-host/cold/AGENTS.md`：用户原文与新增 Steward 说明。", "",
              "## 当前范围", "", "macOS FSEvents 仅提供线索，仍对配置 roots 做有界快照核验；Linux 当前只做快照对比。",
              "尚未实现自动全机分批续扫、Linux 实时监听、GPU 采样、服务功能探测、自动日志修复与最终删除。"]
    report = "\n".join(lines) + "\n"
    if len(report.encode()) > 16384:
        raise StewardError("演示报告超过 16 KiB")
    with (workspace / "report.md").open("x") as stream:
        stream.write(report)
    with (workspace / "demo.json").open("x") as stream:
        stream.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    return summary
