# 日常巡检

## 一轮工作

1. 根据本轮任务确认是只读调查还是维护，读取 `host.json` 核对范围和预算；查看 `current.json` 的待核验事项及 `operations.json` 的未完成操作。按 [inventory](inventory.md) 读相关长期知识，状态或恢复问题进入 [recovery](situations/recovery.md)。
2. 运行 `/skill目录/steward patrol --state /本机状态`，采集有限的整机与进程事实。macOS 读取 FSEvents 线索并核对 roots 内的元数据快照，Linux 比较快照。
3. 先检查 gaps、coverage_scope、观测可用性和扫描完整性，再判断占用与变化。预算耗尽的范围留作后续检查；scope 变化按 [files-storage](situations/files-storage.md) 重建可比基线。目录大小包含子树，比较时选择互不重叠的统计范围。
4. 对照主机用途、任务进展、已知依赖和保护规则筛选值得处理的事项。优先复核到期知识和身份变化，按需 `inspect --id` 补查，并进入对应专项指导。`current.json.directory_index` 的 agents 字段定位目录说明，维护相关对象前按需读取。
5. 将本轮候选工作按下述[维护流程](#维护流程)处理。只读模式完成调查、建议与计划；维护模式完成本轮已授权的动作。
6. 核对本轮状态是否保存、覆盖缺口和待核验事项是否完整，检查状态容量与自身开销。无后续工作时结束；有严重故障、维护异常、目标持续受阻、异常成本、重要成果或需要用户取舍时通知，同类问题合并报告。

自身观测、知识和待核验事项的状态更新属于巡检收尾。

## 维护流程

1. **计划**：列出目标身份、动作、预期收益、影响、约定条目、判断证据、验证方法和恢复办法。达到本机评审门槛的计划在执行前送审。
2. **核验**：执行前重新核对实际目标、当前约定和前置条件；情况变化时重新形成计划并核验。需要用户决定的事项说明具体选择，确认后继续。
3. **执行**：按核验后的计划使用维护工具；执行中出现的新情况重新判断。
4. **验证**：检查实际目标、功能和预期收益，独立确认动作结果。
5. **记录**：关联保存计划、结果与验证，注明完成、部分完成或失败及后续安排。Steward 维护命令使用工具提供的操作编号；宿主工具的维护按本机既有方式保存可追踪记录，Steward 的 `operations.json` 仅由其维护工具写入。未完成操作转入 [recovery](situations/recovery.md)。

## 查询与输出

用 `/skill目录/steward status --state /本机状态 --path /相关目录 --limit 10` 查询相关对象，`--offset` 可分页。过期观测标为 stale。输出带 `output_limited: true` 时，直接读取 `current.json` 中所需的 host、events、directory_index 或 changes 字段。

定时调用 `patrol` 可加 `--quiet`，工具仅在本轮 `actionable` 为真时输出。agent 仍需查看既有待核验事项；命令静默与用户通知由各自的触发条件决定。

## 待核验事项与记录收尾

普通变化按 `host.json.limits` 的窗口和条数滚动保留，淘汰数量可见。待核验事项持续保留，确认已处理或无需跟进后关闭：

```sh
/skill目录/steward resolve --state /本机状态 --key 事项键 --reason '已核验的处理结果或无需跟进的理由'
```

`resolve` 只更新状态并留下解决记录。活动队列最多 64 条，满后新事项进入最多 64 条的 overflow；关闭事项后，overflow 按首次发现时间补位。两队列都无法容纳本轮发现时，工具报告未保存事项的样例与省略计数，整轮 `current.json` 不提交，基线、观测与事件游标保持原值；先核验并关闭已解决事项，再重跑巡检。

解决历史保留最近 32 条，淘汰数量单独记录。未完成维护的恢复证据由 `operations.json` 保存，其处理见 [recovery](situations/recovery.md)。
