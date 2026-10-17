# 日常巡检

1. 读取 `host.json`、`current.json` 的 pending 与 `operations.json` 的非完成操作，按 [inventory](inventory.md) 查询相关资源的长期知识与最新调查。未解决的授权冲突、状态损坏或恢复问题先进入 recovery。
2. 运行 `./steward patrol --state <本机状态目录>`。它采集有限整机与程序事实，读取 macOS FSEvents 线索，并核对明确 roots 内的元数据快照。Linux 当前使用快照比较。
3. 看 gaps、coverage_scope、进程观测是否可用、GPU/费用缺口和扫描完整性，再看占用与变化。scope 改变只表示观察范围不可直接比较，不能把退出范围当删除；当前快照完整不代表排除卷或中间事件完整。扫描达到预算表示尚未覆盖；不宣称整机正常。目录大小含子树，父子项不能相加。
4. 对照主机用途、已知归属与依赖、常驻保护规则及任务进展筛选工作。先看档案来源、复核期限和身份变化，必要时 `inspect --id` 补查；新的观测不能刷新旧用途陈述。未知用途不自动归为垃圾。异常进入对应专项说明；没有值得处理的事项结束，定时调用可用 `--quiet` 隐藏无事输出。
5. 目录索引在 `current.json.directory_index`；查看相关目录的 agents 字段，按需读取其 `AGENTS.md`。说明来源不明时不能当作授权。
6. 只读轮次停留在调查、建议与计划。具体维护先预览计划，再核验目标和既有约定；需要用户确认的动作等确认后执行。demo 的 note/quarantine/restore 默认预览；`--apply` 仅执行已配置允许的动作。完成后用状态与目标文件重新验证。
7. 查看状态区容量与 pending，按实际结果报告。普通变化按 `host.json.limits` 的窗口与条数上限保留；被淘汰的记录数量可见。未解决事项和待恢复对象不随窗口消失。确认事项已处理或无需跟进后，用 `./steward resolve --state <本机状态目录> --key <事项键> --reason '<解决理由>'` 关闭并留痕；这不修改托管文件。active 满时新事项进入有界 overflow，resolve 释放位置后自动晋升；overflow 也满时整轮 current 不提交，包括新基线、观测与事件游标，新 finding 不会静默丢弃或覆盖旧证据。先用 status 查看已有 pending/overflow 并 resolve 释放位置，再重跑 patrol；不按年龄静默淘汰。

本轮读写状态属于巡检收尾；不得将工具退出成功、已入回收区或已见过变化等同于维护目标达成。
