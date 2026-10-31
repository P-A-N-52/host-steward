# 日常巡检

使用接管时记录的 skill 与本机状态绝对路径。按宿主任务指定的模式和时间安排本轮工作，仍以当前 `host.json` 核对权限和预算；需调整频率、维护时段或通知安排时，进入[接管与配置](setup.md#建立并验证定时任务)。

## 一轮工作

1. 根据本轮任务确认是只读调查还是维护，读取 `host.json` 核对范围和预算；用 `status` 查看待核验事项，用 `export --dataset operations` 查看操作证据。按 [inventory](inventory.md) 读相关长期知识，状态或恢复问题进入 [recovery](situations/recovery.md)。
2. 运行 `python3 /skill目录/tools/steward.py patrol --state /本机状态`，采集有限的整机与进程事实，并把内存计数器、swap、网络接口计数、GPU 与电源等主机级样本随轮存入 samples，供跨轮差分判断趋势。macOS 读取 FSEvents 线索并核对 roots 内的元数据快照，Linux 比较快照。
3. 先检查扫描覆盖 gaps（状态中的 coverage_gaps）、comparison_gaps、coverage_scope、观测可用性和扫描完整性，再判断占用与变化。扫描缺口表示本轮未能扫全，比较缺口表示跨轮比较的范围或身份不连续，按 [files-storage](situations/files-storage.md#先看变化覆盖了哪里) 分别解释。`coverage_scope` 中未完成的 root 带有 `resumable`（已用轮数、已处理条目、待扫目录数），表示后续轮次会继续该范围；只有完整且没有覆盖缺口的 pass 才更新基线并参与删除判断。同一目录 mtime 持续变化会让本 pass 记为覆盖不完整：本轮只记缺口、不更新基线，下一轮从头复核。平台事件线索形成的待复核目录见 `status.event_recheck`（首次/最近时间、次数与 `degraded` 原因）及 `coverage_scope.*.event_recheck` 摘要；它们只缩小下一轮复核范围，变化仍以完整扫描比较为准。目录大小包含子树，比较时选择互不重叠的统计范围。
4. 由 agent 结合主机用途、任务进展、依赖、可恢复性与成本判断本轮工作。工具提供变化与采样事实，是否异常、怎样整理及优先级由 agent 决定。按需 `inspect --id` 补查，并进入对应专项指导。`status` 返回的 directory_index 中，agents 字段定位目录说明，维护相关对象前按需读取。
5. 将本轮候选工作按下述[维护流程](#维护流程)处理。只读模式完成调查、建议与计划；维护模式完成本轮已授权的动作。
6. 核对本轮状态是否保存、`capacity` 的数据库可写余量与自身开销，以及覆盖缺口和待核验事项是否完整。无后续工作时结束；有严重故障、维护异常、目标持续受阻、异常成本、重要成果或需要用户取舍时通知，同类问题合并报告。

自身观测、知识和待核验事项的状态更新属于巡检收尾。

命令失败时先读 stderr 的 traceback，定位原始命令、文件或解析错误，修正原因后重新运行。失败巡检不会提交新的 current；`status.last_run` 仍表示上次成功巡检，不能证明失败这轮已经完成。平台能力缺失与预算截断仍在正式结果中分别说明。

## 维护流程

1. **计划**：列出目标身份、动作、预期收益、影响、约定条目、判断证据、验证方法和恢复办法。达到本机评审门槛的计划在执行前送审。
2. **核验**：执行前重新核对实际目标、当前约定和前置条件；情况变化时重新形成计划并核验。需要用户决定的事项说明具体选择，确认后继续。
3. **执行**：按核验后的计划使用维护工具；执行中出现的新情况重新判断。
4. **验证**：检查实际目标、功能和预期收益，独立确认动作结果。
5. **记录**：关联保存计划、结果与验证，注明完成、部分完成或失败及后续安排。Steward 维护命令使用工具提供的操作编号；宿主工具的维护按本机既有方式保存可追踪记录，Steward 的 operations 数据集仅由其维护工具写入。未完成操作转入 [recovery](situations/recovery.md)。

## 查询与输出

用 `python3 /skill目录/tools/steward.py status --state /本机状态 --path /相关目录 --limit 10` 查询相关对象，`--offset` 可分页。过期观测标为 stale；`capacity` 显示数据库可长期写入的上限与当前余量；`collector` 段报告常驻采集的运行/停止状态、心跳年龄、缺口与来源最后成功时间，没有运行记录时明确报 `not_started`，不冒充运行中。需要 host、events、samples 等完整观测或输出带 `output_limited: true` 时，用 `export --dataset current --output /外部目录/current-export.json` 导出后按字段读取，命令与输出约定见[接管指导](setup.md#旧状态迁移与导出)。

常驻资源历史用 `samples` 查询，它不等待巡检锁，采集运行中也可即时读取：

```sh
python3 /skill目录/tools/steward.py samples --state /本机状态                 # 最近十分钟摘要
python3 /skill目录/tools/steward.py samples --state /本机状态 --process 完整identity  # 单进程序列
python3 /skill目录/tools/steward.py samples --state /本机状态 --since A --until B --before 上一页最老sample_id  # 固定窗口分页
python3 /skill目录/tools/steward.py samples --state /本机状态 --raw --output /外部目录/本页.json              # 本页完整原始事实
```

返回按时间倒序，并带 `contract: {name: "host-steward.resource_history", version: 1}`：新增字段不升版本，只有破坏性变更才升版本。`--limit` 默认 41、最大 200；非法值或超过 200 直接报错，不静默截断，更早历史用 `--before` 沿固定窗口分页。`summary` 只统计本页样本，`boundary` 用窗外前驱说明页首变化的可比性；进程、网卡、磁盘的 top-N 截断视野用 `entered/left_bounded_snapshot` 表达，不称启动或消失。默认未载入进程历史时标 `process_changes_not_loaded`。

默认摘要的 memory 段保留常用字节字段与 components，并补充 Linux 的单位与平台差异：其余单位/计数见 `non_byte_units`、`non_byte_counters`（各最多 16 项，超出带 `*_omitted`），`available_reason` 说明缺 MemAvailable 等平台原因，`platform_gaps`（最多 8 项，超出带 `platform_gaps_omitted`）列出平台缺口。Linux 的 components 均为已换算的 bytes 口径，HugePages_* 等无单位计数不能按字节相加；macOS 的 components 是 vm_stat 页数（字节 = 页数 × page_size）。macOS 没有 units 等字段，摘要不输出空占位。

`retention.history` 报告 runs/gaps 的生效值与声明值、`retention_source`（`latest_run_policy`/`defaults`）、`over_target` 和硬上限；`gap_history.retention_hours`/`count_limit` 是生效值，`declared_retention_hours`/`declared_count_limit` 是当前配置的声明值，`pruned_through` 是已淘汰缺口的最大结束时间水位。`gap_history.complete_since` 是缺口记录可能完整的起点；早于该点的相邻样本不判连续，`continuity.reasons` 会带 `gap_history_incomplete`，不能把“没有缺口记录”当作连续。缺口按时间与条数淘汰，查询窗口越界时以该字段为准。`--output` 导出不受终端输出预算裁剪；预算裁剪到无样本时报告 `pagination_blocked_by_output` 并以非零退出，不把空结果当作查询成功。

定时调用 `patrol` 可加 `--quiet`，工具仅在本轮 `observations_changed` 为真时输出，表示文件变化、新基线，或扫描、比较、整机观测缺口的出现与消失。是否值得维护和通知由 agent 判断；即使命令静默，也要查看既有待核验事项及按任务需要查询 samples 等观测。

### 宿主脚本传递巡检事实

宿主脚本将采样、变化和缺口原因交给 agent，保留观察时间、范围、来源、可用性和截断信息。缺口需带 root、kind 及 reason/reasons 等原有字段；汇总只展示部分原因时，附上省略数量与完整输出或状态的读取入口。输出带 `output_limited` 时，先按上面的导出方式补读，再作结论。

阈值可以筛选需要调查的候选；是否异常、是否通知由 agent 结合用途、任务进展和持续影响判断。宿主确需候选筛选阈值时，放在其可审阅的本机配置中，写明用途与采样口径；应用名称排除表会隐藏相关观测，应由 agent 根据上下文辨认正常工作。进程上下文的调查方法见[资源指导](situations/resources.md#核对资源来自哪里)。

## 自定义检查

`patrol` 不会自动运行 `host.json.custom_checks`。只有主机已配置检查、且本轮任务需要核对相应健康状态时，才在完成常规巡检后显式运行；配置、脚本契约和授权边界见[自定义检查](situations/custom-checks.md)。

```sh
python3 /skill目录/tools/steward.py check --state /本机状态 --all
python3 /skill目录/tools/steward.py check --state /本机状态 --name backup-freshness
```

先运行 `--all` 做批量检查；某项失败、超时、输出超限或总预算跳过时，再用 `--name` 复跑该项并读取完整结果。读取 `complete`、`failed`、`skipped` 和每项 `status`：`ok` 只表示脚本按约定退出 0，检查结论仍要看 `data`/`output`；`failed` 要区分非零退出与无法执行；`timeout`、`output_limited` 和 `skipped_budget` 表示没有取得结果，不能当作正常。CLI 退出 2 表示至少一项未成功或终端输出被裁剪，本轮报告要如实说明。

处理失败时先核对脚本、命令绝对路径、运行用户和预算，判断是脚本结论还是执行问题；脚本损坏或需要调整时，向用户说明并取得确认后再改 `host.json`。`output_limited` 用 `--name` 缩小返回范围；超时先实测耗时，再决定拆分检查或请用户确认调整 `scan_seconds`。发现的长期事项用 `track`，目录说明用 `note`；检查结果本身不落状态，需要运行证据时保存在宿主调度日志或当轮汇总中。

需要例行运行时，在宿主调度中显式调用 `check`，使用绝对路径并保存输出与退出码；可与巡检合并为同一轮，也可单独安排，但不要让两个任务并发运行同一组有副作用的脚本。`custom_checks` 配置本身不会创建任务，也不会让 `patrol` 自动执行脚本。

## 待核验事项与记录收尾

普通变化按 `host.json.limits.retention_hours` 与 `change_records` 两个上限滚动保留：先移除到期记录，再按条数保留最近写入的记录。时间上限表示最长保留年龄，实际保留范围同时受条数限制。`patrol` 与 `status` 的 `change_retention` 描述最近一次成功巡检保存的全局历史，独立于查询路径与分页：

| 字段 | 含义 |
| --- | --- |
| `retention_hours`、`record_limit` | 本轮采用的时间与条数上限。 |
| `expired_by_age` | 本轮因超过时间上限淘汰的条数。 |
| `evicted_by_count` | 时间筛选后，本轮因条数上限淘汰的条数。非零属正常滚动淘汰；与 `span_hours` 联读判断窗口是否被挤短。 |
| `oldest_observed_at`、`newest_observed_at` | 现存变化记录最早、最晚的观察时间；空历史为 null。 |
| `span_hours` | 上述两端的小时差；单条为 0，空历史为 null。条数上限生效时会小于 `retention_hours`；它描述记录跨度，完整观察范围仍需结合巡检与缺口证据判断。 |

两个淘汰数都只统计本轮：`expired_by_age` 是到期淘汰，`evicted_by_count` 是条数上限挤掉的、仍在保留期内的记录。稳态下只要持续有新增，`evicted_by_count` 每轮都会等于新增超出条数上限的部分，长期非零是正常的滚动淘汰，不累计、不表示数据丢失，也不能仅凭它非零判定异常；`change_records_dropped` 兼容旧调用，值等于 `evicted_by_count`，同样不含到期淘汰。判断实际窗口以 `span_hours`（或 `oldest_observed_at`/`newest_observed_at`）为准：`evicted_by_count>0` 且 `span_hours<retention_hours` 表示条数上限先于时间上限生效，声明窗口未达到；记录稀疏时跨度也会偏短，完整观察范围仍需结合巡检与缺口证据。需要单独核对的是状态写入失败、`capacity.writable` 与覆盖缺口，而不是淘汰数量本身；agent 结合历史是否足够支持当前工作决定下一步。旧状态尚无 `change_retention` 时，`status` 返回 null，下一次成功巡检生成该摘要。

agent 用 `track` 登记需要跨轮跟进的事项，说明判断依据、未知项和下一步；相同 key 更新说明并保留首次登记时间。确认已处理或无需跟进后用 `resolve` 关闭：

```sh
python3 /skill目录/tools/steward.py track --state /本机状态 --key 事项键 --reason '判断依据、待查问题和下一步'
python3 /skill目录/tools/steward.py resolve --state /本机状态 --key 事项键 --reason '已核验的处理结果或无需跟进的理由'
```

两条命令只更新状态，不执行维护或增加授权。待核验事项保存在单一 `pending` 列表，受单条记录与状态总容量预算控制；容量不足时拒绝本次写入并保留原状态。旧版 `pending_overflow` 查询时一并展示，下次巡检、登记或关闭时合并保存到 `pending`，保留原事项内容。事项键和说明各最多 512 字节，长调查保存在资源档案或来源材料中，通过说明定位。

解决历史保留最近 32 条，淘汰数量单独记录。未完成维护的恢复证据由 operations 数据集保存，其处理见 [recovery](situations/recovery.md)。
