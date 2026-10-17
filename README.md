# Host Steward 0.2 Demo

一份面向 macOS/Linux 的整机保护与维护 skill，附带可运行工具。bash 和 zsh 共用入口，工具只依赖 Python 3.9+ 标准库。

## 直接看演示

```sh
./steward demo
```

在项目 `.demo/` 中建立一个隔离样例，运行真实目录盘点、增长检测、目录说明、临时文件回收与恢复，生成 `.demo/report.md`。它还执行本机只读资源观测，但文件维护只作用于样例。已有演示不会被覆盖，返回 `existing_demo, verified=false` 仅供查看历史产物，不代表本轮或当前版本验收；重新验证必须指定新的空目录。

需要重新演示时指定新的空目录：

```sh
./steward demo --workspace /tmp/host-steward-demo
```

样例包含：已有日志增加 1 MiB；新增带 128 个文件的目录；一个目录消失；目录重命名；90 天前的重要冷资料保持原位；已有 AGENTS.md 用户内容保留；一个明确允许回收的临时文件移入待回收区后恢复。

0.2 还登记冷资料的长期用途、保存最新只读调查，并从不同工作目录的独立进程读回；旧来源的复核到期状态仍保留。旧演示结果保持原样，要运行新版本可指定 `.demo/v0.2` 等新的空目录，让演示产物继续留在既有排除范围中。

## 对指定目录做只读巡检

```sh
./steward init --state .local-state --root . --purpose '开发工作站的只读试运行，具体维护授权待确认'
./steward patrol --state .local-state
./steward status --state .local-state
./steward status --state .local-state --path . --limit 10
```

`init` 只接受新建或空状态目录（普通 `.lock` 除外），不会覆盖已有档案或本机指导；host 缺失但其他状态仍在时，应先恢复约定而非重新初始化。它预检完整内容与容量、最后提交 host；失败仅尝试回滚本次创建且身份与内容仍匹配的文件，不能安全清理时报告残留，详见 [recovery](guidance/situations/recovery.md)。初始化默认没有托管目录写入、回收或进程处置授权。

`patrol` 观察整机资源、有限进程和服务标签，文件盘点仅覆盖显式 roots 的当前声明范围，排除状态目录、配置排除项和其他卷。`coverage_scope` 展示扫描语义、排除计数及有界跨卷样例；过滤、设备边界或状态排除路径改变时报告 scope 缺口并重建基线，不把退出范围的对象记成删除或增长。旧基线缺少 scope 时首次显式重建，部分扫描仍保留旧完整基线；退役 root 不再保留活动基线，待办不因此自动关闭。

`status` 支持按目录查询和 `--offset` 分页，范围摘要也按 limit/offset 分页；索引中的过期数据明确标为 stale，近期变化仍是带观察时间的历史。体积增量附带前后测量时间和平均变化速率，不将观察时刻误认为每次写入发生的时间。定时调用可加 `--quiet`，无新变化、基线或覆盖问题时不输出。

待核验事项不会因一轮未出现而自动关闭。确认处理或无需继续跟进后，运行 `./steward resolve --state /本机状态 --key 事项键 --reason '解决理由'`；命令只更新 Steward 状态并记录理由，不修改托管文件。未关闭事项最多 64 条，更多精确证据进入最多 64 条的 overflow；resolve 后自动晋升。溢出队列也满时整轮 current 不提交，包括新基线、观测与事件游标；先用 status 核对已有事项并 resolve 释放位置，再重跑 patrol，不静默丢弃新 finding。

macOS 原生事件使用 FSEvents；事件位置不可读、历史失效或读取未完成时如实报告，仍用有界快照核验。只有事件历史有效且本轮所有 roots 快照完整才推进已提交游标；暂时失败保留旧游标，连续 3 次无法提交后显式失效并重建基线，失效位置不会复用。`coverage_complete` 只表示元数据快照覆盖，不代表快照之间的每个中间事件都可追溯。Linux 继续使用预期的 snapshot-only 模式，不把该能力边界当作每轮异常。受限环境可能禁止读取进程或原生事件，工具返回缺口，不自行提权。

## 本机档案与针对性调查

按 [资源定义模板](state/resource.example.json) 填写实际用途、归属、依赖、保留与维护方法、来源时间和复核期限，再登记到明确的本机状态。模板本身不是本机事实或授权。

```sh
./steward inventory --state /本机状态 --record /资源定义.json
./steward inventory --state /本机状态 --id 资源编号
./steward inventory --state /本机状态 --path /相关目录 --limit 10
./steward inspect --state /本机状态 --id 资源编号
./steward inspect --state /本机状态 --service launchd:user/com.example.job
./steward inspect --state /本机状态 --service systemd:user/example.service
```

档案最多 128 项，每份定义最多 8 KiB；用途不随普通变化窗口删除。新文件资源定义需使用无符号链接的规范绝对路径；旧别名档案保持可读并标为 `legacy_noncanonical`，调查返回 `migration_required`，不覆盖旧证据。路径查询可临时归一过滤条件，但不改写档案或授予权限；显式迁移需另行核对并保存旧证据，重新登记不是无损迁移。

`inspect --id` 替换规范资源的最新调查，保留来源时间并核对稳定对象身份；size/mtime 等可变观测以 `metadata_continuity` 单独报告，普通原位追加不锁存身份复核，路径身份／类型或服务启动配置换代才锁存。已发现的复核要求不会因暂时不可见或回到原身份自动清除；真实复核后登记更新来源或证据时间的新定义可重建基准，相同定义的 unchanged 不解除提示。其他未登记目标只返回输出。档案中的维护建议和依据类型不能授予权限，`host.json` 保持唯一授权来源。

引用调查只读取 roots 内选定文本文件，返回位置及配置/源码/文档类型，不输出配置正文、完整启动参数或环境变量；开销同时受本机预算与固定工具上限约束，截断和覆盖缺口可见，详细约定见 [inventory](guidance/inventory.md)。

## 三部分

```text
SKILL.md                       agent 入口
guidance/                      日常巡检、接管和问题专项说明
tools/                         观测、文件、原生事件、状态与维护工具
state/host.example.json        空白本机约定模板
```

每台主机的实际状态由 `--state` 指定，部署时放在 skill 可更新内容之外：

```text
host.json                      唯一的本机用途、授权、保护与预算约定
inventory.json                 长期资源知识、来源、复核期限与最新调查
guidance/ + adaptation.json    本机指导与版本/裁剪记录
current.json                   当前事实、目录索引、近期变化、采样与待核验事项
operations.json                维护计划、结果和恢复证据
```

## 预算和维护

初始默认值唯一来源是 [本机约定模板](state/host.example.json)，实际运行以状态目录中的 `host.json.limits` 为准。扫描条目与时间、状态单文件与总容量、输出、变化窗口及记录条数分别受限；替换临时文件也计入总容量。达到预算时报告精度下降或停止写入，保持上次状态和恢复证据。目录说明另有固定 8 KiB 上限。

`note`、`quarantine`、`restore` 默认展示计划，只有 `--apply` 才执行；状态目录及其后代在预览和执行中都不能作为普通维护目标，包括派生回收／恢复路径。目录规则要求规范路径唯一，完全相同或冲突的重复项均拒绝；不同路径嵌套仍取最具体规则。

所有命令在锁内重新读取当前 `host.json` 并刷新 Store 预算；patrol 在提交 current 前复核策略，维护动作在托管文件副作用前复核。策略在执行期间发生语义变化时，旧计划不提交，已写入的 planned/restoring 证据保留且不使用旧预算二次写状态。它们还要求本机目录规则明确允许并匹配已确认的规则目录身份。cold 类别不能回收；temporary 需配置期限和回收区容量。没有最终删除命令。非合作编辑在最后复核之后的影响仍不具备原子撤销保证。

```sh
./steward note --state /本机状态 --path /已约定目录
./steward quarantine --state /本机状态 --path /已约定临时文件
./steward restore --state /本机状态 --operation 操作编号
```

回收以同卷移动保存恢复依据，释放空间记为 0。`note/quarantine --path` 保留相对路径按当前工作目录转绝对路径的输入行为，建议执行者始终传明确绝对路径；归一后的目标仍需通过规范路径、规则和身份检查，不跟随符号链接。持久授权路径和恢复证据不会在执行时自动迁移。恢复使用不覆盖目标的创建方式；原位置已有新文件时停止。规则目录或目标文件身份变化、记录损坏或预算不足会阻止维护。

状态、约定、资源定义和说明均以有界普通文件读取，拒绝 FIFO、目录、设备及符号链接，并校验读前后元数据；非阻塞打开不等于普通磁盘 I/O 的硬超时。当前仍依赖可信状态目录，未新增既有目录 owner/权限审计；恢复未保存源父目录的完整身份链，note 原子替换也不保证保留 mode/ACL/硬链接元数据。这些边界不应被解释为本轮六项修复已提供的保证。

## 已实现与边界

- macOS/Linux 共用 CLI、元数据盘点、目录变化与体积差、状态容量限制和巡检锁。
- `current.json` 与 `operations.json` 使用统一结构 reader；错误结构、重复键/ID 和非有限数字在动作前阻断并保留原文件。参与时间计算的 Unix 秒字段限定在 ±10¹² 秒，避免超大整数溢出；此限制不作用于精确整数文件大小或纳秒 mtime。旧 v1 缺字段可兼容，未知 current 顶层会保留，未知 operation kind 不执行也不淘汰。
- 资源档案按 id 或目录直接读回；有预算的文件引用调查和指定 launchd/systemd 服务调查。服务只观察当前用户/系统管理器及主 PID，不证明业务健康、完整依赖或孤儿状态。
- macOS FSEvents 历史线索已接入；Linux 当前使用快照对比，未实现 inotify 常驻采集。快照间的中间事件不保证还原。
- 同路径身份或类型换代记录为带身份缺口的修改，不作为确定新增/删除/移动。只有 birth 可取得且相同时才确认移动；birth 缺失的候选只报告端点变化和不确定性。换代体积差不用于普通增长速率或增长待办。可靠迁移影响的目录及祖先标为 `migration_delta`，不把迁入字节当普通增长；包含两端的共同祖先仍可报告真实净增长，预算合并时按实际汇总范围计算体积。
- macOS 读取 vm_stat、ps、launchctl；Linux 读取 /proc/meminfo、ps、systemctl。服务标签存在不证明服务功能健康。
- 内存趋势只是有限 RSS 样本的调查线索，不确认泄漏。GPU 利用率、模型费用、网络性能、自动日志修复和全机分批续扫尚未实现。
- 全机保护是 skill 的目标；demo 不默认递归扫描 `/`，不安装后台进程，不自动停止服务或清理真实主机。

当前实机验证在 macOS 完成，bash 与 zsh 入口均已运行；Linux 分支有离线测试，尚未在 Linux 实机执行。跨进程读回与新 agent 上下文试用需分别记录，不能将工具读回通过写成宿主会自动注入状态。

## 验证

```sh
python3 -m unittest discover -s tests -v
```

测试覆盖目录聚合与迁移边界、日志增长、扫描缺口、硬链接、符号链接、身份变化、状态容量与损坏、秒时间及速率溢出、重叠巡检、执行中策略不可读、pending 生命周期、长期资料保护、说明保留、回收与恢复，以及 bash/zsh 入口。演示回归还覆盖旧产物只读查看、错误清单、缺 birth 与故意篡改变化证据；上游快照有独立的离线完整性回归。

设计背景见 [agent.md](agent.md) 与 [design.md](design.md)，上游参考保存在 [references/upstream-skills](references/upstream-skills/README.md)。

2026-10-17 的现场验证（独立进程知识读回、启动项反例、受限观测修正、Linux 主机上的检索与引用检查）因包含真实主机与网络细节，作为私有材料保存，不随仓库公开；其结论已并入指导、设计文档与测试。
