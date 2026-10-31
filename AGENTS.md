# AGENTS.md

本文件供开发 agent 维护 Host Steward 仓库时使用。运行时入口是 [SKILL.md](SKILL.md)，项目目标见 [charter.md](charter.md)，设计取舍见 [design.md](design.md)。

## 设计原则

本项目的目的是在用户约定的范围内放手让 agent 长期整理与维护主机。LLM 负责理解用途和上下文、发现工作、补充调查、选择整理方式并判断结果；开发时应为它提供充分的事实、长期知识和可靠工具。文件分类、冷热状态、归档方式及可恢复性与恢复成本等判断，优先由 agent 结合具体情况完成。

固定规则用于明确授权、保护、预算和执行可靠性，工具落实路径、对象身份、容量与状态写入等可核验约束。新增配置、类型白名单或分支前，先判断该问题是否适合交给 agent；只有明确的用户约定、通用约束或经验证的工具需求才固化为规则。已有授权内的常规决定由 agent 自主完成，证据不足时按需调查，新增权限或需要用户取舍时再请求确认。

## 开发方式

每次修改前先进入规划阶段，说明要解决的问题、涉及的文件和验证方法，再开始编辑。根据问题选择完整、清楚的改法，让组件各有职责、逻辑自然衔接。文档、指导、代码注释和报错信息使用中文。

命令、读取与解析失败直接抛出异常，保留原始原因和调用位置。平台能力缺失与预算截断按明确语义报告；清理、回滚和操作记账完成后继续抛出原始错误。

只使用 Python 3.9+ 标准库。模块平铺在 `tools/`，测试通过 `sys.path.insert(0, tools/)` 导入。实现时结合 CPU 核心数、内存、存储、电源和当前负载选择采集方式与并发规模。

## 常用命令

```sh
python3 tools/steward.py --help                         # CLI 命令列表
python3 tools/steward.py status --state /本机状态         # 状态读回
python3 tools/steward.py patrol --state /本机状态         # 实机巡检
python3 tools/steward.py collect --state /本机状态 --once # 常驻采集验证一批
python3 tools/steward.py samples --state /本机状态        # 资源历史查询；history 段控制运行与缺口保留
python3 tools/steward.py changes --state /本机状态        # 资源变化聚合（episode/断点）
python3 tools/steward.py backup-bundle --state /本机状态 --output /外部目录/完整备份-日期
python3 tools/steward.py restore-bundle --bundle /外部目录/完整备份-日期 --state /全新状态目录
python3 tools/steward.py check --state /本机状态          # 自定义检查列表；--name NAME 或 --all 运行
```

`restore-bundle` 默认只预览，`--apply` 才写入尚不存在的新状态目录；`backup-bundle` 与恢复的完整语义见[恢复指导](guidance/situations/recovery.md#完整备份与恢复到全新目录)。

验证直接使用实机与正式 CLI，记录实际操作、原始返回、耗时和独立读回结果。历史测试代码用于查阅案例，验收依据实操证据。`.demo/` 与 `.local-state/` 中的已有运行资料继续保留。

## 模块职责

| 模块 | 职责 |
| --- | --- |
| `tools/steward.py` | 本地 agent 调用的 Python 命令入口（patrol、collect、samples、changes、upgrade、backup-bundle、restore-bundle 等） |
| `policy.py` | 本机约定 v1/v2 校验、规范路径、逐 root 范围规则、版本证据、显式转换与坏配置时的归档只读预算 |
| `files.py`、`baseline.py`、`events.py` | 有界扫描、对象身份与 scope、跨轮续扫（持久进度、目录游标、多 root 公平轮转）、变化聚合与原生事件 |
| `recheck.py` | 事件路径线索的待复核队列：路径归一、去重合并、父目录聚合、有界截断与退化记录 |
| `observe.py`、`linux_observe.py` | 有预算的系统命令与 Linux proc/sysfs 来源采集；Linux meminfo 解析只在 `linux_observe`，`observe.py` 的 patrol 内存入口是薄适配器 |
| `resource_sampler.py`、`collector.py` | 跨平台常驻批次采样（逐来源隔离、共享预算）与批次边界调度、热重载（含 `history`）、缺口记账 |
| `state_io.py`、`state.py`、`database.py`、`state_schema.py` | 共用编码与异常、状态文件、独立锁与 SQLite 存储、容量控制与结构校验 |
| `sample_store.py` | 独立资源样本、来源、运行与缺口的增量存储、保留目标与绝对硬上限、缺口水位与有限查询 |
| `resource_changes.py`、`resource_query.py` | 资源连续性、差分口径、episode 聚合、samples/changes 查询摘要与输出预算裁剪 |
| `history_config.py` | host.json `history` 段的默认值、字段契约、范围校验与解析 |
| `storage_tools.py` | 旧 JSON 显式迁移、配置与结构升级、数据导出、数据库备份与完整 bundle 创建/恢复 |
| `custom_checks.py` | 显式授权的自定义检查：配置读取、无 shell 有界执行、JSON/文本结果整形与失败语义 |
| `inventory.py`、`investigate.py` | 长期档案、文件引用与服务调查 |
| `maintain.py` | 维护动作与恢复 |

工具返回可核对的事实、执行结果与失败原因，guidance 和 agent 据此决策。每台主机的真实状态经 `--state` 指定，与可更新的 skill 内容分开保存；文件布局见[首次接管](guidance/setup.md)。

## 修改时核对什么

涉及工具、状态语义或安全边界时，先读章程和设计，再读对应指导。运行规则在 [SKILL.md](SKILL.md)，具体工具约定集中在以下位置，修改行为时同步核对相关测试：

- [首次接管](guidance/setup.md)：初始化输入、目录规则、`history` 保留配置和预算来源。`LIMIT_FIELDS`（v2）与 `LEGACY_LIMIT_FIELDS`（v1）是工具内的预算键集契约，模板只在初始化时提供默认值；v2 的深度与排除项属于各 root，`sampling` 与 `history` 分别校验，修改时同步核对 `SAMPLING_FIELDS`、`history_config.py` 与 `tests/test_policy.py`。
- [自定义检查](guidance/situations/custom-checks.md)：`custom_checks` 字段与预算契约、无 shell 直接 exec、结果整形、退出码和“不落状态”边界；修改行为时同步核对 `CUSTOM_CHECK_*` 常量与 `tests/test_custom_checks.py`。
- [文件与存储](guidance/situations/files-storage.md)：对象身份、覆盖与变化判定，目录说明、冷资料保护、回收方式与容量收益。
- [中断与恢复](guidance/situations/recovery.md)：状态结构校验、初始化回滚、维护中断与恢复证据。完整备份/恢复条目同时核对 `BUNDLE_*` 常量、未完成标记与清单语义、预览不覆盖、跨主机身份和首轮 `state_path` 范围变化；修改行为时同步核对 `tests/test_storage_tools.py`。
- [常驻程序与资源异常](guidance/situations/resources.md)：`history` 保留目标/绝对硬上限、热切换与 run 边界、缺口 `pruned_through`/`complete_since` 水位、samples 契约与 changes episode 口径；修改行为时同步核对 `history_config.py`、`sample_store.py`、`resource_changes.py`、`resource_query.py` 及对应测试。

通用规则在入口维护，专项方法在对应指导维护，设计文档解释理由。把新增案例先用于验证，再判断现有指导需要怎样调整。

## 验证与资料

macOS 与 Linux（K6）已有实机验证，覆盖正式 CLI 的有界巡检、文件变化、缺口、历史轮转、状态读写、备份，以及自建临时文件的说明写入、回收与恢复。完整备份/恢复已在 macOS 15.7.9（Python 3.9.6）与 K6（Linux 7.0 / Python 3.14.4）实机演练：创建、预览零写入、`--apply` 恢复、独立读回、篡改拒绝与首轮 `patrol` 的 `state_path` 范围重建；`history` 热切换、`over_target`、缺口 `pruned_through`/`complete_since` 水位与坏配置只读回退在 macOS 验证，K6 复核了热切换与坏配置回退。精简前后代码已核对同一真实状态的读取结果和双向读写兼容。报告结果时注明平台、观察范围和未执行的检查。

实操中的维护只作用于明确授权的对象。现场材料位于 `references/` 中已忽略的路径，包含真实主机与网络细节，保持本地保存；上游参考在 `references/upstream-skills/`。
