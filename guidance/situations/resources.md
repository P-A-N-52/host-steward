# 常驻程序与资源异常

资源异常先从主机正在做什么查起：读常驻约定，确认程序身份、任务进展和主要工作的影响，再与同一口径的历史样本比较。

## 让样本保持可比

进程以 `pid + started + executable` 识别。启动时间改变后，重新建立趋势，旧进程样本保留各自的生命周期。

CPU 结合持续时间、任务进展和前台体验判断。`ps` 百分比采用进程 CPU 统计口径；整机当前负载用 `cpu.utilization`（iostat 采样）或 `cpu.counters` 差分解释。

内存结合实际压力和同一进程的多次样本判断。常驻历史用 `samples` 读取主机级样本（内存计数器、swap、网络接口计数、磁盘速率）与进程 RSS/CPU 序列，采集口径与分页见[查询与输出](../patrol.md#查询与输出)；`patrol` 仍按单轮保存 GPU、电源等额外观测。相邻样本是否可比先看 `continuity.reasons`：`gap_history_incomplete` 表示查询区间早于缺口记录的完整起点，不能用“没有缺口记录”推断连续。agent 根据任务、缓存行为、持续时间和内存口径分析趋势，决定是否继续调查。需要跨轮跟进时按 [巡检指导](../patrol.md#待核验事项与记录收尾)登记事项。

## 保留窗口与历史配置

资源库的运行记录与缺口保留设置来自 host.json 顶层 `history`，默认各 256 条、168 小时：

```json
"history": {
  "runs": {"records": 256, "retention_hours": 168},
  "gaps": {"records": 256, "retention_hours": 168}
}
```

采集器每批重新读取 host.json，修改 `history` 无需重启：批次边界会结束旧 run、按新设置启动新 run，因此“只调整保留”也会形成一次 run 边界，运行记录随之增加。collector 停止时修改配置，要等下一次 `collect` 写批次才实际裁剪；只读 `samples` 不触发裁剪。运行记录与缺口都按“先时间、再条数”淘汰，被保留样本或缺口引用的 run、未关闭的缺口永远不会为了条数被删除。

`records` 是目标值而不是硬上限：引用保护或 open 缺口导致无法压回目标时，实际条数允许超过目标，`retention.history.over_target` 与 `gap_history.over_target` 会标出。运行记录只有在达到固定绝对硬上限（1024 条）时才拒绝新增并报错，错误给出目标值、硬上限、引用原因和调整建议。缺口达到绝对硬上限（4096 条）且没有可淘汰的已关闭缺口时不阻断采集：该缺口不写入，`gap_history.gap_history_degraded` 记录 `reason/since/dropped`，下一轮继续尝试。

`retention.history` 同时报告 `effective` 与 `declared`：前者是最新 run 实际使用的设置（`retention_source` 为 `latest_run_policy`，没有 run 时为 `defaults`），后者是当前 host.json 的声明值；两者不一致说明配置已改但还没有形成新 run。`gap_history.complete_since` 是缺口记录完整的起点，取参考时间（`until` 或当前）减生效保留期、已淘汰缺口的最大结束时间（`pruned_through`）与条数受限时最老缺口起点三者中的最大值；早于它的区间可能已淘汰，不能因为查不到缺口就判断连续。进程历史跟随资源样本窗口级联删除，不单独配置。

每项指标保留来源、单位、时间口径和可用性。单位不明或与任务明显矛盾时，先标为待验证，补查后再用于计算或处置。

Linux 的内存计数器逐字段单位见 `memory.units`：`bytes` 表示来源 kB 已乘 1024；`count` 表示来源无单位计数（例如 `HugePages_Total/Free/Rsvd/Surp`），保持原值；其他单位（例如 `Odd: 7 MB`）不换算，保留来源数值与单位。`memory.source_units` 保留原始单位文本，`memory.platform_gaps` 记录旧内核缺少 `MemAvailable` 等平台缺口，`patrol` 会把它们并入 `observation_gaps`。`patrol` 与常驻采集共用 `tools/linux_observe.py` 的同一 meminfo/swap 口径，同一字段在两条链路中的数值、单位与缺口解释一致。

## 看清怎么涨的

主机级样本分两类，判断方法不同：

- **自开机累计计数器**：vm_stat 事件（Pageins/Swapins/Compressions 等）、网络接口字节与包计数、Linux 的 cpu jiffies。跨轮差分得到轮间速率；`boot_time` 变化说明计数器随重启重置，趋势重新开始。
- **瞬时采样**：iostat 的 CPU 占比与磁盘速率、GPU 利用率、tcp 状态直方图、电池状态。只代表采样时点，单点不作结论，结合任务进展与多轮样本看。

内存看成分不看表面：Pages free 少是缓存占位的正常形态，压力看匿名页（Anonymous pages / AnonPages）与 file-backed 的比例变化、压缩器页数和换入换出差分，Linux 用 `MemAvailable`（已扣除可回收缓存）。缓存增长不需要处置，只有不可回收的匿名占用持续增长才进调查。swap 已用量是采样时点的当前占用（macOS `vm.swapusage` 的 used 即当前值），持续压力看 Swapins/Swapouts 差分。常驻采集不含 GPU、电源、TCP 状态与模型占用，这些在结果中以 `not_observed` 列出，需要时用 `patrol` 单轮观测补齐。

疑似泄漏盯同一身份进程的 RSS 序列：台阶式只涨不跌是候选，锯齿式涨跌多是缓存或池的正常行为；idle 时仍单调增长、且匿名页同步上涨才有嫌疑。ps 的 RSS 会把 fork 后的共享页在父子进程间重复计入。Apple 芯片上 GPU 是统一内存的租户（`gpu.allocated_bytes` / `in_use_bytes`），内存账单要把它计入。

## 机器之间的差异

不同主机可采指标不同：台式机没有电池条目、Linux 无通用免提权 GPU 统计、磁盘 IO 采样当前仅 macOS 实现。这些能力差异以 `available/reason` 报告；命令、读取和解析错误直接抛出，停止本轮采集。跨主机比较前先核对指标口径一致。

## 核对资源来自哪里

采样命令和短时前台任务单独辨认，避免将观察自身的消耗计作待清理负载。按可执行文件、启动时间和任务关系识别具体进程；解释器名称只能说明运行方式。

巡检进程条目提供 `pid`、`parent_pid`、`started`、`executable`、CPU 与 RSS。保留数量受预算限制，父进程可能不在返回列表中；需要解释某个候选时，按 PID 和启动时间核对身份，再在预算内补查父进程链、必要启动参数及端口归属，关联已知服务与当前任务。服务的主进程和可见端点可用 `inspect --service` 调查。完整进程树、命令行和所有端口按需要下钻，避免每轮重复全量采集。

远程串流、编译、渲染、转码等正常任务都可能持续占用较多 CPU。agent 结合任务进展、持续时间、硬件容量和其他工作的影响判断；宿主脚本保留采样事实与调查入口，让后续轮次能继续核对。

存储同时看目录增量和卷可用空间，父子目录的占用选择同一层级汇总，详细口径见 [文件与存储指导](files-storage.md)。模型费用当前仍无来源，标为未知；工具不做提权功耗采样。

需要定位到具体进程时，用宿主命令按需下钻：`nettop -l 1`（进程网络）、`footprint`（含压缩与换出的内存账单）、`lsof -i -nP`（连接归属）、`top` / `ps`（CPU）。巡检只保留便宜的聚合事实，一次性深挖由 agent 在证据需要时发起，不做成常驻工具。

## 先给主机让出资源

资源紧张时，先减少 Steward 自己的扫描、采样、并发和非必要分析。结合 CPU 核心数、内存余量、存储读写、电源状态与前台负载调整检查范围，在本机预算内优先保留关键检查和未完成操作的看护。

调整其他程序前，按 [巡检流程](../patrol.md) 核对允许动作、维护窗口和验证方法。工具没有停止进程的命令。原因暂时查不清时，保存有限证据和下一步待查项，结束本轮调查。
