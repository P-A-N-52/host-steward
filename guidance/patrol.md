# 日常巡检

使用接管时记录的 skill 与本机状态绝对路径。按宿主任务指定的模式和时间安排本轮工作，仍以当前 `host.json` 核对权限和预算；需调整频率、维护时段或通知安排时，进入[接管与配置](setup.md#建立并验证定时任务)。

## 一轮工作

1. 根据本轮任务确认是只读调查还是维护，读取 `host.json` 核对范围和预算；用 `status` 查看待核验事项，用 `export --dataset operations` 查看操作证据。按 [inventory](inventory.md) 读相关长期知识，状态或恢复问题进入 [recovery](situations/recovery.md)。
2. 运行 `python3 /skill目录/tools/steward.py patrol --state /本机状态`，采集有限的整机与进程事实，并把内存计数器、swap、网络接口计数、GPU 与电源等主机级样本随轮存入 samples，供跨轮差分判断趋势。macOS 读取 FSEvents 线索并核对 roots 内的元数据快照，Linux 比较快照。
3. 先检查 gaps、coverage_scope、观测可用性和扫描完整性，再判断占用与变化。预算耗尽的范围留作后续检查；scope 变化按 [files-storage](situations/files-storage.md) 重建可比基线。目录大小包含子树，比较时选择互不重叠的统计范围。
4. 由 agent 结合主机用途、任务进展、依赖、可恢复性与成本判断本轮工作。工具提供变化与采样事实，是否异常、怎样整理及优先级由 agent 决定。按需 `inspect --id` 补查，并进入对应专项指导。`status` 返回的 directory_index 中，agents 字段定位目录说明，维护相关对象前按需读取。
5. 将本轮候选工作按下述[维护流程](#维护流程)处理。只读模式完成调查、建议与计划；维护模式完成本轮已授权的动作。
6. 核对本轮状态是否保存、`capacity` 的数据库可写余量与自身开销，以及覆盖缺口和待核验事项是否完整。无后续工作时结束；有严重故障、维护异常、目标持续受阻、异常成本、重要成果或需要用户取舍时通知，同类问题合并报告。

自身观测、知识和待核验事项的状态更新属于巡检收尾。

## 维护流程

1. **计划**：列出目标身份、动作、预期收益、影响、约定条目、判断证据、验证方法和恢复办法。达到本机评审门槛的计划在执行前送审。
2. **核验**：执行前重新核对实际目标、当前约定和前置条件；情况变化时重新形成计划并核验。需要用户决定的事项说明具体选择，确认后继续。
3. **执行**：按核验后的计划使用维护工具；执行中出现的新情况重新判断。
4. **验证**：检查实际目标、功能和预期收益，独立确认动作结果。
5. **记录**：关联保存计划、结果与验证，注明完成、部分完成或失败及后续安排。Steward 维护命令使用工具提供的操作编号；宿主工具的维护按本机既有方式保存可追踪记录，Steward 的 operations 数据集仅由其维护工具写入。未完成操作转入 [recovery](situations/recovery.md)。

## 查询与输出

用 `python3 /skill目录/tools/steward.py status --state /本机状态 --path /相关目录 --limit 10` 查询相关对象，`--offset` 可分页。过期观测标为 stale；`capacity` 显示数据库可长期写入的上限与当前余量。需要 host、events、samples 等完整观测或输出带 `output_limited: true` 时，用 `export --dataset current --output /外部目录/current-export.json` 导出后按字段读取，命令与输出约定见[接管指导](setup.md#旧状态迁移与导出)。

定时调用 `patrol` 可加 `--quiet`，工具仅在本轮 `observations_changed` 为真时输出，表示文件变化、新基线或覆盖缺口变化。是否值得维护和通知由 agent 判断；即使命令静默，也要查看既有待核验事项及按任务需要查询 samples 等观测。

## 待核验事项与记录收尾

普通变化按 `host.json.limits` 的窗口和条数滚动保留，淘汰数量可见。agent 用 `track` 登记需要跨轮跟进的事项，说明判断依据、未知项和下一步；相同 key 更新说明并保留首次登记时间。确认已处理或无需跟进后用 `resolve` 关闭：

```sh
python3 /skill目录/tools/steward.py track --state /本机状态 --key 事项键 --reason '判断依据、待查问题和下一步'
python3 /skill目录/tools/steward.py resolve --state /本机状态 --key 事项键 --reason '已核验的处理结果或无需跟进的理由'
```

两条命令只更新状态，不执行维护或增加授权。待核验事项保存在单一 `pending` 列表，受单条记录与状态总容量预算控制；容量不足时拒绝本次写入并保留原状态。旧版 `pending_overflow` 查询时一并展示，下次巡检、登记或关闭时合并保存到 `pending`，保留原事项内容。事项键和说明各最多 512 字节，长调查保存在资源档案或来源材料中，通过说明定位。

解决历史保留最近 32 条，淘汰数量单独记录。未完成维护的恢复证据由 operations 数据集保存，其处理见 [recovery](situations/recovery.md)。
