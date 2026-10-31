# 首次接管

## 初始化时确认什么

先在只读范围内查看主机现状和已有部署，用下表整理待确认项；已有明确约定直接沿用，只向用户补问缺失或需要取舍的内容。管理范围和调度安排确认后再落地，结果保存在表中对应位置，后续轮次能直接读回。

| 项目 | 需要确定的内容 | 保存位置 |
| --- | --- | --- |
| 主机用途 | 主要工作、需要保障的程序与数据、维护优先级 | `host.json.purpose`、`residents` 与资源档案 |
| 管理范围 | 观察目录与排除项；可变更的目录、服务和动作；共享区域及其他用户的边界 | `host.json` 的观察范围、保护与授权条目 |
| 保护与保留 | 重要冷资料、活跃任务、依赖和恢复材料；临时内容的保留起点、期限与回收额度 | `host.json.directory_rules` 与资源档案；档案只保存依据和授权位置 |
| 工作预算 | 扫描、采样、记录和输出上限；agent 单轮时长、模型开销、电源和负载下的工作条件 | 工具预算在 `host.json.limits`；agent 执行限制在宿主配置 |
| 自定义检查 | 需要工具代跑的本机健康脚本；用途、完整命令、运行用户、超时与输出预算、副作用和结果去向 | `host.json.custom_checks`（[说明](situations/custom-checks.md)）；脚本与运行日志按本机既有位置保存 |
| 调用入口 | 本机 skill、独立状态目录和 Python 解释器的绝对路径；以哪个用户运行 | 本地 agent 的既有持久记录与任务配置 |
| 定时安排 | 使用哪个调度机制、时区、具体时刻或间隔、允许维护的时间段，以及暂停和恢复办法 | 宿主任务配置，记录任务标识供后续查询 |
| 通知方式 | 正常结果是否汇总、汇总时间与渠道；异常和需要用户取舍时如何通知 | 宿主通知配置与本机巡检指导 |

`host.json` 是本机授权与观察范围的唯一来源。当前模板使用 v2：每个 root 是独立对象，采样设置写在 `sampling`；旧 v1 配置仍可读取，但顶层 `exclude_names` 与 `limits.scan_depth` 只属于 v1，不会与 v2 规则同时生效。观察范围不等于变更权限，定时触发也不增加权限；宿主任务和指导引用已确认的约定。当前工具直接识别的字段见下文，调度由宿主执行，不能只在 `host.json` 中填写时间便视为任务已建立。

## 取得运行内容

首次从项目地址接入时，由本地 agent 按自己的工作方式取得以下内容，保留相对路径，放在本机使用的 skill 目录中：

```text
host-steward/
├── SKILL.md
├── guidance/
├── tools/
└── state/
```

仓库的介绍、开发约定、设计文档、测试和上游参考留在开发侧。运行时从 `SKILL.md` 进入，按任务读取指导和所需工具。每台主机使用独立的部署副本，以便完成接管后移除该副本的首次引导。

确认本机为 macOS/Linux 且有 Python 3.9+，工具只依赖标准库。用 `python3 /skill目录/tools/steward.py --help` 核对命令入口，任务配置使用已验证的 Python 绝对路径。macOS 与 Linux（K6）已实测巡检、文件变化、缺口、历史轮转、状态读写、备份、常驻采集与完整备份/恢复，以及自建临时文件的说明写入、回收与恢复；工具版本见状态与巡检结果中的 `tool_version`，平台可用观测与缺口在部署时按本机核对。维护命令的预览、执行和恢复约定按[文件与存储](situations/files-storage.md)及[恢复指导](situations/recovery.md)读取，其他维护动作由本地 agent 在对应授权内使用已有工具完成。

## 确定范围与部署位置

确认主机主要用途、观察目录、常驻程序和保护对象，分别约定桌面、共享缓存、模型及其他用户或 agent 工作区的观察与变更范围。首次接管按只读模式建立空间地图，登记用途、归属、依赖、可重建条件和保留理由；重要资源的长期知识按 [inventory](inventory.md) 保存。

每台主机的状态独立保存在 skill 目录之外。本地 agent 用自己的现有记录方式保存 skill 目录和 `--state` 的绝对路径，后续轮次沿用；已有状态先核对并继续使用，确认为尚未接管的新主机再初始化。已有部署的路径丢失、状态缺失或损坏按 [recovery](situations/recovery.md) 处理。

```sh
python3 /skill目录/tools/steward.py init --state /绝对路径/本机状态 --root /绝对路径/观察目录 --max-depth 3 --purpose '主机主要用途'
python3 /skill目录/tools/steward.py patrol --state /绝对路径/本机状态
```

观察目录用 `--root` 逐个指定，选择不包含 skill 内容的范围；`--max-depth` 为该次初始化的所有 root 指定非负深度，省略时默认 32。整机资源观测与目录覆盖分别报告。`init` 的 `--state` 与 `--root` 都只接受已确认的绝对路径，不展开 `~`、相对路径或服务账户 home；符号链接与路径别名按实际目标解析，并把输入与实际目标一起写入 `root_resolution`。状态目录不能包含观察 root；状态目录位于 root 内时由扫描排除。运行期 root 暂不可见、未挂载或不再是目录时记录缺口，不会自动改用其他目录，也不会据此推断删除。

## 初始化与状态布局

`init` 接受新建或空状态目录，普通 `.lock` 文件可以保留。初始化成功后有以下内容：

```text
host.json                      本机用途、观察范围、授权、保护与预算约定
steward.sqlite3                 动态状态：资源档案、观测、基线、事项与操作证据
guidance/                      本机指导副本
adaptation.json                指导来源版本与裁剪记录
```

初始化建立空数据库。首轮 `patrol` 写入 current 数据集，保存当前事实、目录索引、近期变化、采样与待核验事项；资源登记写入 inventory，实际维护写入 operations，保存计划、结果和恢复证据，预览仅返回计划。数据库内尚无对应数据集时按空记录查询。已有状态的数据库缺失、损坏或初始化残留按 [recovery](situations/recovery.md) 处理。

接管时用独立进程验证能按上述路径读回规则与知识，并确认本地 agent 的后续会话能找到这两个入口。后续调用方式沿用 agent 的现有能力。查询时区分检索失败、尚未覆盖和没有匹配。

## 旧状态迁移与导出

已接管主机仍使用 `current.json`、`inventory.json`、`operations.json` 时，先核对原状态路径和本机约定，再预览迁移：

```sh
python3 /skill目录/tools/steward.py migrate --state /本机状态
python3 /skill目录/tools/steward.py migrate --state /本机状态 --apply
```

迁移在锁内校验旧输入，在临时数据库中按实际数据核对容量并读回，再独占发布正式库。旧 JSON 保留原字节，之后普通命令只使用 SQLite。`sqlite-migration.json` 保存发布凭据；它和旧文件一同计入容量。容量不足时迁移在发布前停止并保留旧数据；只有临时库残留时，核对失败原因后删除该临时库可重试。核对迁移结果并取得备份后，旧 JSON 与凭据可一同清理，释放的容量由 agent 判断。本机约定与已经裁剪的指导继续沿用，升级时按指导差异复核。发布中断的核对方法见 [recovery](situations/recovery.md#迁移中断与数据库恢复)。

平时使用 `status`、`inventory` 查询需要的内容；完整 current、inventory 或 operations 可导出为 JSON。外部输出路径的父目录需已存在，目标文件需尚不存在：

```sh
python3 /skill目录/tools/steward.py export --state /本机状态 --dataset current --output /外部目录/current-export.json
python3 /skill目录/tools/steward.py export --state /本机状态 --dataset operations
python3 /skill目录/tools/steward.py backup --state /本机状态 --output /外部目录/steward-backup.sqlite3
```

导出包含数据集名称、来源、导出时间与 data；省略 `--output` 时结果受工具输出预算限制。`backup` 使用 SQLite 备份接口并校验数据库，生成动态状态的一致快照；备份写在状态区外，按主库、伴随文件与目标日志预留核对可用空间，时间使用本轮时间预算。`host.json`、`adaptation.json` 与本机指导另行保存；备份的长期保留由本机既有安排管理。

需要连同本机约定与指导一起保全时，用 `backup-bundle` 在状态区外新建完整备份目录：

```sh
python3 /skill目录/tools/steward.py backup-bundle --state /本机状态 --output /外部目录/完整备份-日期
```

目录包含 SQLite 一致快照、`host.json`、`adaptation.json`、`guidance/` 和 `bundle.json` 清单（逐文件 SHA-256、工具与 schema 版本、创建时间、来源主机与范围）。目标必须尚不存在；先写 `bundle.incomplete.json`，清单最后原子发布，标记存在或清单缺失即不可恢复。恢复用 `restore-bundle --bundle /外部目录/完整备份-日期 --state /全新状态目录`：默认只校验预览，`--apply` 才写入尚不存在的新目录，不覆盖现有状态；跨主机默认拒绝，`--allow-foreign-host` 只放行、不改写 `host.json`。完整语义、独立读回、首轮巡检变化与外部对象核对见[完整备份与恢复到全新目录](situations/recovery.md#完整备份与恢复到全新目录)。

## 配置与结构显式升级

新初始化使用配置 v2 与数据库 schema 2。已有 v1 配置和 schema 1 数据集仍可读写，不在连接时自动改版。JSON 状态先按上节 `migrate` 导入，再预览配置与结构升级：

```sh
python3 /skill目录/tools/steward.py upgrade --state /本机状态
python3 /skill目录/tools/steward.py upgrade --state /本机状态 --apply --backup /外部目录/本次升级备份
```

预览不改配置或数据库。执行时 `--backup` 必须是状态区外的绝对路径，父目录已存在、备份目录尚不存在；工具先保存原字节 `host.json`、SQLite 一致快照与 `upgrade.json`，独立读回核对后才升级。目录规则、授权、用途、未知扩展和原预算保留，不自动提高容量。v1 深度与排除项转为逐 root 配置，下一轮重建不可比的基线，范围变化不算删除。

执行升级取得状态锁与 `.collector.lock` 生命周期锁；采集运行时拒绝应用。schema 与配置分别提交，中断后可能出现 schema 2 配置 v1，先按[升级中断](situations/recovery.md#配置与结构升级中断)读回版本再续接。旧工具不能读取 schema 2；回退须核对切换后的新记录，不能直接启用旧备份丢弃新证据。本机指导、裁剪清单和运行代码版本另行保全，升级命令不覆盖它们。

## 配置本机约定

初始常驻清单与目录规则为空，按接管结果在 `host.json` 中填写。v2 的每个 root 包含 `path`、`max_depth`、`exclude_names` 和 `exclude_paths`：`max_depth` 为非负整数，0 表示只检查 root 的直属条目；`exclude_names` 按单层名称匹配，`exclude_paths` 相对于该 root、按路径分量匹配指定文件或子树，不能越出 root。root 与规则路径使用无符号链接的规范绝对路径，保留原有大小写、Unicode 与空格；root 之间不能重叠或指向同一 `samefile` 对象。目录规则包含 `path`、`purpose` 和 `kind`。类别由 agent 按本机用途命名，为最多 64 字节的非空短文本；可沿用 cold / temporary / active / service。每个规范路径配置一条，嵌套目录采用最具体的规则。类别本身不增加权限，`allow_notes`、`allow_quarantine` 缺省为不允许，按接管时确认的动作填写；当前回收工具只接受明确授权的 `temporary` 文件。

`sampling` 只在 v2 使用，包含主机采样间隔、单轮时间预算、进程采样间隔、每页进程数、样本条数与保留小时；字段必须是完整正整数，单轮时间预算不得大于主机采样间隔，`process_interval_seconds` 不得小于 `interval_seconds`。`cycle_seconds` 是单批命令的真实耗时预算：macOS 的 `iostat -c 2` 自身约需 1 秒，周期低于实际命令下限（如 1 秒）时整批按预算失败并记录缺口，不会伪造样本；调整周期前先用 `collect --once` 核对本机实际耗时。旧 v1 主机继续按字符串 root、顶层排除项与 `limits.scan_depth` 读取和巡检；使用上节 `upgrade` 显式转换后再启用 v2 设置，不能把两套规则同时当作活动来源。

顶层 `history` 控制采集运行与缺口的保留，省略整段即全部使用默认值（`runs`、`gaps` 各 256 条、168 小时）；提供时必须完整包含 `runs` 与 `gaps`，每组同时给出 `records`、`retention_hours`。`records` 是目标条数，范围 runs 8–1024、gaps 8–4096；`retention_hours` 范围 1–8760；字段只接受正整数，布尔值无效。v1 配置不接受 `history`，先按上节 `upgrade` 显式转换。采集每批重新读取配置，修改后无需重启：批次边界结束旧 run 并按新设置开新 run，只调整保留也会形成一次 run 边界；采集停止时修改，在下一次 `collect` 写批次时才生效。`records` 因被样本/缺口引用或 open 缺口保护而无法压回目标时允许超过目标，`samples` 的 `retention.history.over_target` 标出；仅达到固定绝对硬上限才拒绝新增，缺口满且无已关闭缺口可淘汰时降级记账并继续采集。`sampling.records`/`retention_hours` 管样本本身，`history.runs`/`gaps` 管运行与缺口记录，不要混用；字段语义与查询见[保留窗口与历史配置](situations/resources.md#保留窗口与历史配置)。

`custom_checks` 是顶层可选数组，省略等价于空数组；`init` 模板写入空数组。每项必须有且仅有 `name`、`command`、`purpose`：名称在同一配置内唯一；`command` 是 1–16 个非空参数，首项为绝对路径，工具直接执行、不经过 shell、不按 PATH 查找；用途为不超过 512 字节的非空短文本。只登记用户确认过用途、命令、运行用户、预算和副作用的脚本。脚本以当前用户权限运行，工具只能限制时间和输出，不能保证只读；新增或修改是有副作用的授权变更，先说明影响并保存 `host.json` 副本。结果不写入状态，`patrol` 也不会自动运行，运行时机、失败语义和调度方式见[自定义检查](situations/custom-checks.md)。

```sh
python3 /skill目录/tools/steward.py check --state /绝对路径/本机状态
python3 /skill目录/tools/steward.py check --state /绝对路径/本机状态 --name backup-freshness
python3 /skill目录/tools/steward.py check --state /绝对路径/本机状态 --all
```

列出模式只展示配置与 `executable_available`，不运行脚本；`--name` 与 `--all` 互斥，运行受 `limits.scan_seconds`、`command_bytes` 和 `output_bytes` 约束。任一执行项失败、超时、输出超限或预算跳过，或整份终端输出被裁剪时退出 2。

v2 主机可用 `collect` 前台常驻采集，由宿主管理进程生命周期（本工具不安装开机服务、不派生后台进程）：

```sh
python3 /skill目录/tools/steward.py collect --state /本机状态            # 持续采集，SIGTERM 在批次边界停止
python3 /skill目录/tools/steward.py collect --state /本机状态 --once     # 只采一批，验证配置与本机耗时
python3 /skill目录/tools/steward.py samples --state /本机状态            # 最近十分钟有界历史
python3 /skill目录/tools/steward.py changes --state /本机状态            # 最近 60 分钟变化聚合
```

采集按批次读取 `host.json`，配置变化在批次边界切换并新开运行记录；配置无效时暂停采集、显式记录缺口与心跳，历史仍可用 `samples`/`changes`/`status` 读取（报告标明 `policy_source=last_valid_collector_run` 与当前配置错误，该归档预算只供读取，不授予采集、维护或升级授权）。`samples`、`changes` 与 `status` 不等待巡检锁；分页用 `--since/--until` 固定窗口加 `--before`，`--output` 把本页完整原始事实导出到状态区外。来源失败保留原始异常；GPU、电源、TCP 状态与模型占用不在常驻来源内，以 `not_observed` 报告，需要时用 `patrol` 的单轮观测补齐。变化聚合与两点差分见[查询与输出](patrol.md#查询与输出)。

允许写说明或回收的目录还需配置 `directory_id`：运行 `python3 /skill目录/tools/steward.py status --state /本机状态 --path /约定目录`，在 `directory_index` 中找到 path 完全相同的行，取其 `id`（`dev:ino`）。缺少精确行时先补观测。临时内容回收还需 `retention_days` 和 `recycle_bytes`；工具按修改时间判断期限，任务是否结束、依赖是否解除由执行者现场核对。

用途不明的自定义目录先调查，确认用途后登记规则，并按 [files-storage](situations/files-storage.md) 预览目录说明。目录说明保留已有用户原文，只更新 Steward 标记区。

编辑约定前在状态目录外保存副本，编辑后运行 `python3 /skill目录/tools/steward.py status --state /本机状态` 验证。约定校验失败时按 [recovery](situations/recovery.md) 恢复副本。

## 预算与指导更新

初始预算来自 skill 目录的 `state/host.example.json`，仅 `init` 读取；运行时使用本机 `host.json.limits`。v2 的逐 root 深度不在 `limits` 中，扫描的条目与时间预算、进程采样与命令读取、状态容量、工具输出，以及变化、采样和操作记录的条数与保留窗口仍由 `limits` 限制；`sampling` 单独描述后续连续采样的节奏与历史条数。`file_bytes` 限制普通状态文件和数据库单条 JSON 记录，例如一项资源、一份文件元数据或一项操作。完整 current、inventory、operations 的读取与编码使用 `total_bytes` 上限，整份 baseline 不再受旧单文件上限约束。

整个状态区受 `total_bytes` 限制，包含数据库、事务日志、迁移临时库和保留的旧 JSON。数据库可长期写入的上限还要为回滚日志留空间，因此会小于 `total_bytes`；`status` 与 `patrol` 的 `capacity` 给出上限与当前余量，判断是否继续写入或调整采集范围时读它。容量不足时写入被拒绝并保留上次已提交状态，`migrate` 会在发布前按实际数据停下。数据库有页和索引开销，体积未必小于 JSON；观察后续轮次时，结合记录条数、覆盖范围与实际状态占用判断增长原因。

续扫进度的候选记录、分配字节与基线记录都按单个对象逐条保存，`file_bytes` 只约束单条记录，不随文件数增长；队列、边界等字段仍留在单个 snapshot 行内，queue 随目录数增长，超大目录树要把目录数计入估算。容量估算要把两份记录一起算：文件数 × 每文件记录体积（路径、id、size、mtime 与 birth，通常约 150–250 字节）× 2（未完成 pass 的候选进度与上一份基线并存），再加目录摘要、变化与采样记录，以及约为 JSON 1.5–2 倍的 SQLite 页和索引开销与回滚日志余量。例如 9000 个文件、路径约 100 字节时，两份记录约 3–4 MiB，默认 `total_bytes` 的 4 MiB 在完成写入时容易不足；按本机约定核对后可提高 `total_bytes`，或缩小观察范围、减少保留记录，工具不会自动提高预算。巡检写入因容量被拒时事务整体回滚，上次基线与续扫进度保留，下一轮从同一进度重试并报告同一容量原因，直到调整预算或范围。

结合硬件容量、磁盘读写、前台负载和实际巡检开销调整预算；`total_bytes` 属于本机约定，达到限制时先看 `capacity` 与采集范围，再决定是否请用户确认新的预算。

`init` 将全部通用指导复制到状态区。按本机情况裁剪后，在 `adaptation.json` 记录版本、删减内容和原因。skill 更新时对照差异复核本机指导，保留已确认的本机约定。模板与公共入口 `SKILL.md` 从已记录的 skill 目录读取，状态区副本中的专项链接用于本机指导之间跳转。

更新若重新带入首次引导，核对已有接管结果后按下述收尾步骤移除，继续使用原状态；新主机部署使用保留引导的分发模板。

## 建立并验证定时任务

先查看宿主已有的任务，沿用其调度能力。根据主机用途、在线时间、CPU 核心数、内存、存储、电源和前台负载提出安排，结合首轮实测开销确定频率。写清时区，以及具体执行时刻或间隔；需要空闲维护时，同时确定允许时段和负载条件。只读巡检、维护与结果汇总可使用不同频率，是否拆分按本机需要决定。

将确认后的任务配置到宿主，保存任务标识。每次触发应让本地 agent 从已部署的 `SKILL.md` 进入，使用相同的本机状态路径，按本机巡检指导完成一轮工作；只有执行 `patrol` 命令时，完成的是事实采集。调度机制不支持的休眠补跑、超时或重叠控制要明确记录，并说明下一轮怎样接续。

核对实际任务的时区、下一次运行时间、运行用户、调用路径和启用状态；用相同入口试跑，检查状态、错误输出和通知去向。记录如何查询、暂停、恢复和调整任务。创建成功与定时触发成功分别报告，未观察到实际定时触发时注明待验证；调度能力缺失或用户选择手动运行时，记录该限制或选择。

## 接管完成后移除入口引导

本机约定已确认、首轮只读巡检结果与覆盖缺口已保存、路径记录和独立读回验证完成，且调度与通知安排已落地核对或明确记录为未启用后，由本地 agent 编辑已记录的本机 skill 目录中的 `SKILL.md`，删除 `<!-- 首次引导开始 -->` 到 `<!-- 首次引导结束 -->` 的整个区段，包含两个标记。接管或验证尚未完成时保留该段，供下一轮继续；待观察的实际定时触发留在本机后续核验事项中。

修改前说明本次收尾范围并保留可恢复的原文；修改后核对差异，确认只移除了标记区段，YAML 元数据、通用规则和任务导航完整。保留本文件及状态区中的本机副本，后续配置、升级和重新部署仍可查阅。开发仓库中的分发模板保留首次引导。
