# AGENTS.md

本文件供开发 agent 维护 Host Steward 仓库时使用。运行时入口是 [SKILL.md](SKILL.md)，项目目标见 [charter.md](charter.md)，设计取舍见 [design.md](design.md)。

## 设计原则

本项目的目的是在用户约定的范围内放手让 agent 长期整理与维护主机。LLM 负责理解用途和上下文、发现工作、补充调查、选择整理方式并判断结果；开发时应为它提供充分的事实、长期知识和可靠工具。文件分类、冷热状态、归档方式及可恢复性与恢复成本等判断，优先由 agent 结合具体情况完成。

固定规则用于明确授权、保护、预算和执行可靠性，工具落实路径、对象身份、容量与状态写入等可核验约束。新增配置、类型白名单或分支前，先判断该问题是否适合交给 agent；只有明确的用户约定、通用约束或经验证的工具需求才固化为规则。已有授权内的常规决定由 agent 自主完成，证据不足时按需调查，新增权限或需要用户取舍时再请求确认。

## 开发方式

每次修改前先进入规划阶段，说明要解决的问题、涉及的文件和验证方法，再开始编辑。根据问题选择完整、清楚的改法，让组件各有职责、逻辑自然衔接。文档、指导、代码注释和报错信息使用中文。

只使用 Python 3.9+ 标准库。模块平铺在 `tools/`，测试通过 `sys.path.insert(0, tools/)` 导入。实现时结合 CPU 核心数、内存、存储、电源和当前负载选择采集方式与并发规模。

## 常用命令

```sh
python3 -m unittest discover -s tests -v   # 统一测试入口
python3 tools/steward.py --help                         # CLI 命令列表
python3 tools/steward.py demo --workspace /tmp/新空目录  # 演示回归
```

演示保留已有 workspace，并返回 `existing_demo, verified=false`；重新验证须换用新空目录。`.demo/` 与 `.local-state/` 是已忽略的运行产物。

## 模块职责

| 模块 | 职责 |
| --- | --- |
| `tools/steward.py` | 本地 agent 调用的 Python 命令入口 |
| `files.py`、`events.py` | 扫描、对象身份、变化聚合与原生事件 |
| `observe.py` | 有预算的子进程观测 |
| `state.py`、`database.py`、`state_schema.py` | 状态文件与 SQLite 存储、容量控制与结构校验 |
| `storage_tools.py` | 旧 JSON 显式迁移、数据导出与数据库备份 |
| `inventory.py`、`investigate.py` | 长期档案、文件引用与服务调查 |
| `maintain.py`、`demo.py` | 维护动作与隔离演示 |

工具返回可核对的事实、执行结果与失败原因，guidance 和 agent 据此决策。每台主机的真实状态经 `--state` 指定，与可更新的 skill 内容分开保存；文件布局见[首次接管](guidance/setup.md)。

## 修改时核对什么

涉及工具、状态语义或安全边界时，先读章程和设计，再读对应指导。运行规则在 [SKILL.md](SKILL.md)，具体工具约定集中在以下位置，修改行为时同步核对相关测试：

- [首次接管](guidance/setup.md)：初始化输入、目录规则和预算来源。`LIMIT_FIELDS` 是工具内的预算键集契约，模板只在初始化时提供默认值。
- [文件与存储](guidance/situations/files-storage.md)：对象身份、覆盖与变化判定，目录说明、冷资料保护、回收方式与容量收益。
- [中断与恢复](guidance/situations/recovery.md)：状态结构校验、初始化回滚、维护中断与恢复证据。

通用规则在入口维护，专项方法在对应指导维护，设计文档解释理由。把新增案例先用于验证，再判断现有指导需要怎样调整。

## 验证与资料

当前 macOS 分支已有实机验证；Linux 分支仅有离线测试。报告验证结果时注明平台、观察范围和未执行的检查。

演示的文件维护仅作用于样例。现场材料位于 `references/` 中已忽略的路径，包含真实主机与网络细节，保持本地保存；上游参考在 `references/upstream-skills/`。
