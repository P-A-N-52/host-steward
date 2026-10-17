# Host Steward 工作区改进讨论纪要 · 2026-10-17

本文归档本轮多视角子代理讨论的收敛结果。每个议题均经过独立分析、交叉反驳和主代理裁决；复杂议题另做修复后红队复核。为避免 k3 成本，子代理统一使用 `gpt-5.6-luna`。本文是决策纪要，不是逐字转录；未完成的议题明确标为讨论中。

## 1. 回收与恢复状态收敛

**参与视角**：故障与恢复、CLI/持久格式兼容、最小实现与测试、安全与并发红队，共 4 路，另做 1 路修复后复核。

**主要分歧**：

- 是否让普通 `restore` 接受 `planned/failed`，还是只处理 `quarantined/restoring`。
- `restoring` 且源、回收目标都为预期身份时，应删除精确回收目标以完成恢复，还是永久保留以避免 TOCTOU。
- 操作目录清理失败是否需要新的持久状态，重复恢复应幂等返回还是继续拒绝。

**裁决与理由**：

- 不做全局 reconcile，也不把 `planned/failed` 直接纳入普通恢复；旧 inode 身份不足以安全自动重放。
- 允许 `restoring` 按源/目标实际身份续作。两侧身份都匹配时，二次核验后删除精确目标；这与正常恢复流程的本机受管目录威胁模型一致。
- 先验证文件恢复并持久化 `restored`，再 best-effort 删除操作目录；清理结果单独返回，不递归删除额外内容，不新增 `cleanup_pending` 终态。
- 已完成的 `restored` 再次恢复继续拒绝，保持 CLI 兼容。

**实际结果**：修改 `tools/maintain.py`、`guidance/situations/recovery.md` 和测试；覆盖非空操作目录、源/target 同时存在、target 已删除、源抢占后重试及旧状态阻断。修复后复核又发现绝对 `operation_id` 可造成路径逃逸，随后增加 32 位十六进制编号校验和外部目标保护测试。最终相关阶段为 **52/52 测试通过**。外部恶意写者在二次核验与 `unlink` 间的 TOCTOU 被明确记录为边界，不宣称原子条件删除。

## 2. pending 生命周期与容量

**参与视角**：证据生命周期、CLI 与旧状态兼容、最小实现、容量与对抗红队，共 4 路，另做 1 路修复后复核。

**主要分歧**：

- finding 消失、进程退出或目录停止增长能否自动标为 resolved。
- 应新增显式 `resolve`，还是只依赖类型特定的自动收敛。
- 容量满后使用摘要 overflow、精确 overflow，还是直接安全阻断。

**裁决与理由**：

- 一轮未出现不等于解决，不实现自动 `quiet/resolved` 或 TTL 淘汰。
- 新增 `resolve --key --reason`，只修改 Steward 状态并保留有界关闭历史；不修改托管文件。
- `pending` 只保存 active；使用最多 64 条的精确 overflow，resolve 后按首次发现顺序晋升。overflow 也满时保留旧状态并安全阻断，不用无法逐项处理的摘要冒充完整证据。
- 同 key 合并并保留首次发现时间；resolved 后同 key 复发重新告警。

**实际结果**：修改 `tools/steward.py`、README 和巡检指导，增加 resolve CLI、精确 overflow、32 条关闭历史及淘汰计数。修复后复核发现一轮多个当前 key 可能只报告最后一个、长 key 无法 resolve、status 输出可能被整体截断；随后改为整轮容量预检、统一 512 字节 key 上限、错误中保留完整 key 样例与未显示数量，并为 pending/overflow 增加分页。最终相关阶段为 **58/58 测试通过**，真实 CLI `resolve + status` 端到端通过。

## 3. 原生事件缺口与游标

**参与视角**：FSEvents 正确性、巡检/quiet 契约、最小实现与测试、平台故障红队，共 4 路，另做 1 路修复后复核。

**主要分歧**：

- 游标只依赖 `HistoryDone`，还是必须等待所有 roots 快照完整后提交。
- `rescan_required` 是否一律阻止推进；Linux snapshot-only 是否属于异常缺口。
- 持续超时或扫描长期不完整时，是否允许无限重试旧位置。

**裁决与理由**：

- 采用候选 cursor 与 patrol 提交屏障：事件历史有效且所有 roots 快照完整时才提交，避免未核对区间被静默跳过。
- 拆分普通 `MustScanSubDirs/RootChanged` 与真正的 `UserDropped/KernelDropped/EventIdsWrapped`；前者不必然阻塞，后者标记 `history_invalid`。
- `coverage_complete` 继续只表示元数据快照覆盖；Linux snapshot-only 是预期能力边界，不作为每轮异常。macOS 缺口按出现、持续、恢复去重通知，status 可读取 events。
- 暂时失败保留旧 cursor；连续 3 次无法提交后显式失效并重建，避免无限重试。

**实际结果**：修改 `tools/events.py`、`tools/steward.py`、README 和文件指导；增加标志分类、旧游标复用、完整快照提交、失效恢复及 macOS/Linux 跨轮测试。修复后复核指出非对象 JSON 和持续失败恢复不足，随后增加非对象结果降级、旧 events 结构防御和 3 次重建路径。最终相关阶段为 **65/65 测试通过**。历史重建仍不承诺还原快照间的短生命周期事件。

## 4. 同路径目录与对象类型换代

**参与视角**：比较算法与不变量、覆盖与公开契约、最小实现与红队测试，共 3 路，另做 1 路修复后复核。

**主要分歧**：

- 新增 `replaced` 计数，还是复用 `modified` 并增加结构化样本。
- 身份 gap 是否应让完整快照的 `coverage_complete=false`。
- birth 缺失时是否停止可靠移动配对，以及 Linux 信息损失如何保留。
- 换代后的净 `byte_delta` 应省略，还是保留但禁止作为普通增长证据。

**裁决与理由**：

- 复用 `modified`，附 `identity_changed` 样本与 identity gap；不新增计数，不伪装成确定 added/removed/moved。
- `coverage_complete` 改由实际快照完整性决定；身份 gap 表示连续性不确定，不等于扫描未覆盖。
- 仅两侧 birth 可取得且相同才确认 moved；缺 birth 的候选保留端点 added/removed 和 `move uncertain`，不强行配对。
- 只发射最外层目录 replacement，抑制其子树事件；合法 swap 不重复报修改，可靠跨边界移动保留。
- 净 `byte_delta` 保留并标 `continuity_gap`，但不计算普通增长速率、不生成 growth pending；含 moved 的迁移增量同样不按普通增长处理。

**实际结果**：修改 `tools/files.py`、`tools/steward.py`、README 和文件指导；新增目录空/非空换代、嵌套换代、两种类型互换、swap、缺 birth 候选、根换代和迁移增长测试。修复后复核发现可靠移动仍可能触发目标目录增长、嵌套 replacement 泄漏，随后分别补排除条件和最外层过滤。最终相关阶段为 **74/74 测试通过**。Linux 缺 birth 时不汇总确定 moved；同路径同 inode、同类型、birth 缺失且元数据完全相同的复用仍是元数据观测边界。

## 5. 持久状态结构校验

**参与视角**：current 不变量、operations 维护安全、兼容与最小实现、恶意状态红队，共 4 路，另做 1 路修复后复核。

**主要分歧**：

- 在 Store 统一硬编码完整 schema，还是按文件提供 typed reader。
- 深检所有观测载荷，还是只校验生产代码会直接索引及影响安全的状态。
- 未知 current 顶层、operation kind/字段应拒绝，还是作为 opaque 保留；数量超限是否属于读取损坏。

**裁决与理由**：

- 新增独立 `state_schema.py`；Store 负责通用 JSON/IO 卫生，`read_current/read_operations` 负责文件语义，并接入 patrol/status/resolve/inspect/demo/maintain 全部生产读取路径。
- 旧 v1 缺字段兼容、错类型阻断；深检 baselines/events/changes/samples/pending 等直接使用结构，不递归限制 host 等平台观测载荷。
- 未知 current 顶层允许且 patrol 写回保留；未知 operation kind 可展示但不可执行、不可淘汰。已知 quarantine 的路径、身份和状态严格校验，重复 ID/key 一律拒绝。
- 策略数量超限留给 patrol/resolve 等现有恢复路径，不用 schema 把修复入口一并卡死。
- Store/host/资源定义统一拒绝重复 JSON 键和非有限数字；patrol 以旧状态为基础更新，避免静默删除扩展字段。

**实际结果**：新增 `tools/state_schema.py`，修改 Store、steward、maintain、investigate、demo 和 inventory；补错误 baseline、嵌套字段、重复 ID/key、operations 副作用、未知 kind 淘汰、外部 target 和 CLI 错误形态测试。修复后复核发现超大整数 `OverflowError` 与负 mtime 兼容问题，随后修正整数有限性判断、允许 epoch 前 mtime，并同步收口 host 版本和资源定义解析。最终相关阶段为 **85/85 测试通过**。

## 6. 执行前授权复核

**参与视角**：并发与锁不变量、授权与 CLI 契约、最小实现与测试、安全红队，共 4 路，另做 1 路修复后复核。

**主要分歧**：

- 锁内直接采用 fresh policy，还是启动 raw hash 不一致就拒绝本次命令。
- 替换 fresh Store，还是复用同一 Store 并更新 limits。
- 是否还需要提交前 guard，以及应覆盖所有命令还是只覆盖 patrol 与托管文件 apply。

**裁决与理由**：

- 不做启动 raw hash：当前 CLI 没有锁前授权 token，格式化变化不应导致失败；获锁后重新读取并按当前授权重新计算即可避免沿用撤权前快照。
- 复用同一 Store 并在锁内更新 limits，避免旧对象持锁、新对象写入的生命周期混乱和嵌套锁。
- 保留提交前语义 guard：patrol 写 current 前复核，note/quarantine/restore 在实际托管文件副作用前复核。preview 不作为后续执行授权。
- 所有 CLI 命令和 demo 的直接 patrol/维护路径都刷新；输出也使用刷新后的预算。非合作编辑在最后复核后的影响不具备原子撤销保证。

**实际结果**：修改 `tools/steward.py`、`tools/maintain.py`、`tools/demo.py` 和测试；补锁内 fresh roots/limits、提交前变化不提交、CLI 撤权、quarantine/restore 两阶段 guard 测试，临时目录 demo 11/11 通过。修复后复核发现 guard 失败仍可能用旧 limits 写 failed，随后增加 `PolicyChangedError`，保留 planned/restoring 证据而不再二次写旧预算状态。最终相关阶段为 **91/91 测试通过**。

## 7. 路径、预算与文档契约归一

**参与视角**：路径与迁移、文档与预算、最小实现、跨契约红队，共 4 路，两轮讨论后由原红队修复后复核（agent-37–40）。

**主要分歧**：新输入与旧证据是否统一严格 canonical；init 是否还能显式归一输入；旧别名查询是否回写；compare 内部 64 是否改为另一个硬编码；目录索引是否承载长期知识；旧 managed 标记是否迁移覆盖。

**裁决与理由**：

- 新资源定义及 host roots/directory_rules 严格规范绝对路径，无符号链接；`init --root` 保留显式输入归一。维护 CLI 保留相对输入按 cwd 转绝对路径的兼容行为，但执行目标仍需通过路径、规则与身份检查，文档建议始终传绝对路径。
- 旧 inventory/operations 证据保持可读，不在 reader 中隐式迁移。只读 query/status 临时归一双方过滤路径，输出保留原值；旧资源标为 `legacy_noncanonical`，inspect 返回 `migration_required` 且不覆盖旧调查。重新登记会重建身份基准，不作为无损迁移。
- legacy 别名不绑定当前链接目标的目录规则，避免 symlink 改指后把旧知识与新授权对象混淆；restore 的旧别名 preview/apply 均拒绝且不改证据。
- compare 的低层 fallback 64 保留，所有 policy-aware 调用显式传 `change_records`；不换成另一个硬编码。默认数值引用 `state/host.example.json`，实际运行只以状态区 `host.json.limits` 为准；调查固定安全上限在专项指导中单独说明。
- design 使用实现的 begin/end 成对标记、`current.json.directory_index` 当前/stale 观测索引，以及规则派生的 purpose；长期用途与依赖在 inventory。旧 managed/未知标记当原文保留。已有本机指导不会因源更新自动覆盖，升级需复核。

**实际结果**：修改 files、inventory、investigate、steward、maintain、demo 与 README/setup/inventory/design；新增规范/别名注册、legacy 调查与恢复、65 个精确变化组测试，并强化旧标记保留。初轮 **96/96** 通过；红队无阻断，补修 legacy policy link 来源和 status 双方只读归一，增加 retarget/status 回归后 **98/98 测试通过**。96/97 分组上限的更细颗粒边界测试未单独新增，现有 65 组测试证明生产不再提前收缩为 64；历史设计章节的 48 小时是原需求语境，落地预算引用当前 host 字段。

## 8. 演示证据与参考资料验证

**参与视角**：行为证据与回归、安全与可验证性、最小实现与文档契约，3 路 Luna（agent-41–43）独立分析并交叉反驳，由 agent-42 复核实际修复；agent-44/45 分别执行快照与演示测试。执行代理因不必要命令审批停顿后，取消该等待并恢复同一 agent-45 的上下文，仅补测试，没有丢弃任务或由主代理重做其文件。

**主要分歧**：旧 demo 是否可直接当当前验收；是否加版本/schema、报告哈希或签名；精确 moved 断言是否误伤 Linux；manifest 应新增运行时 CLI 还是只做离线测试；历史附件是否需要改写或重新索引。

**裁决与理由**：

- 新演示返回 `demo_verified, verified=true, demo_version=2`，分别验证完整首轮、变化轮、目录样例语义、日志精确增长及原有保护/回收/恢复/知识读回。旧产物不覆盖，一律 `existing_demo, verified=false`，只供历史查看；缺少新字段或历史 checks=false 不冒充本轮通过，错误 JSON/字段类型仍阻断。
- 复用严格 JSON decode；拒绝最终 workspace、manifest/report 符号链接。保留 `/tmp` 等祖先系统别名兼容；新报告和清单使用独占创建，不覆盖已出现的同名产物。不引入签名或报告哈希认证，因为同目录联合伪造不能靠自存哈希解决。
- 可靠目录移动验证精确新增/删除/移动与样本；缺 birth 则验证 `(added=2, removed=2, moved=0)`、精确 move uncertain 缺口及允许端点集合。每组样本最多 3 条，报告明确不是逐端点完整审计；不提高全局 sample 上限、不强行假定 Linux 有 birth。
- 报告增加本轮时间、平台、样例 limits、快照覆盖、整机缺口，以及进程/服务 observed、retained、shown、truncated 与 scope。不将主机观测不可用误当文件样例失败，也不将样例预算写成真实本机授权。
- 上游 manifest 只新增标准库离线回归，不联网、不安装或执行快照，不新增生产 CLI。核对来源声明与实际文件的双向集合、规范相对路径、无链接普通文件、字节数、Git blob SHA-1、SHA-256 与模式；复用一次项目遍历，删除重复 walk/路径包装。哈希仅证明内部一致性，不是来源认证。
- 历史访谈和实验原文不改。结论入口增加历史版本注记并指向纠正段；主代理重算实验附件得到 14,837 字节与记录中的 SHA-256 完全相同，因此未采纳“附件缺失”的红队判断，也没有伪造证据索引。

**实际结果**：新增 `tests/test_demo.py` 的 7 项方法（含多子场景）和 `tests/test_references.py` 的 10 项方法；真实快照全部匹配，篡改/缺失/未列文件/模式/链接/越界/重复及错误字段均有负例。演示错误证据注入、缺 birth、旧结果与坏清单均通过回归。最终整体验证包含下一节补修，为 **120/120 测试通过**；新的隔离 CLI demo **13/13 checks 通过**，报告约 3 KiB，历史重读 verified=false 且字节不变。

## 9. 最终安全红队与交付验证

**参与视角**：数值与故障注入、兼容与最小修复，两路 Luna（agent-46/47）实证并交叉复核；随后对迁移祖先问题再次双视角核验，由主代理裁决和执行。

**新增实证及裁决**：

1. **秒时间与派生速率溢出**：无界整数 observed_at 可通过 reader，却在 patrol 浮点减法抛 OverflowError；baseline.measured_at 还缺类型校验。新增共享 `timestamp_seconds`，将参与时间计算的秒字段约束为有限且位于 ±10¹² 秒，补 baseline 时间并复用到 inventory，birth 同为秒字段也受限。文件大小、inode 与纳秒 mtime 仍保持精确整数及负 mtime 兼容。进一步发现巨大 byte_delta 除以浮点 duration 可溢出或得到 Infinity：局部降为 rate=null 并标 `growth_rate_gap=numeric_range`，保留精确体积差，禁止把 Infinity 写入状态。回归既覆盖观测前阻断/CLI 无 traceback，也覆盖匹配真实 root_id 后的巨大整数与非有限派生速率。
2. **执行期间策略不可读**：guard 读取损坏、缺失或 I/O 失败的 host 时，普通异常曾落入按旧 limits 写 failed。仅在 `ensure_policy_locked` 包装为 `PolicyChangedError`，初始 read/load 行为不变；note/quarantine 保留 planned，restore 保留 restoring 与实际两侧对象，不做旧预算二次写。损坏、缺失、I/O 与恢复第二阶段均有回归。
3. **迁移祖先误报与预算汇总**：可靠 move 只在目标父目录有 moved，但其上级可能仅见正 byte_delta，从而被误当增长。compare 对实际统计范围包含移动恰一端的目录标 `migration_delta`，速率与增长 finding 排除此项而非笼统排除 moved。共同祖先两端均包含时仍保留真实净增长。预算合并到根目录时按实际汇总路径重新计算净值，不让子树 delta 覆盖根值；用文件与目录一起嵌套迁移、同时真实增长及 `change_records=1` 验证。

**保留的边界**：不新增 retention duration 上限或“永久” sentinel：当前消费是纯整数乘法及安全比较，没有同类 Overflow 实证，新增期限语义不属于本轮最小修复。输出型扩展观测字段仍不当作完整事实认证。迁移与真实增长混在同一受影响子树时保守不归因为普通增长；共同祖先的净增长单独保留。非合作外部写者的最后核验后 TOCTOU、Linux 实机、新 agent 自动加载、完整依赖与业务恢复仍未据此证明。

**最终验证**：

- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`：**120/120 通过**。
- 全部 tools/tests Python 源文件 AST 解析；`bash -n steward` 与 `zsh -n steward` 均通过。
- 从 cwd `/` 经 bash/zsh 运行真实临时目录的 init、patrol、status、inventory、inspect、resolve、幂等 note、quarantine preview/apply、restore apply；全部通过。
- 最后重跑当前交付的 zsh demo，13/13 checks 与三轮元数据覆盖通过；再经 bash 读取历史结果 verified=false，清单与实际输出一致。所有维护只作用于临时样例，未修改真实主机授权或清理真实资源。
- Git 审计发现当前仓库文件尚未跟踪（`git ls-files` 为空），因此没有可用于逐行原始差异审计的已提交基线；未擅自 add/commit/reset。现存 `.demo` 与 `.local-state` 不做覆盖或清理。

## 10. 再次总体逻辑复审：已确认问题，尚未修复

**范围与状态**：用户再次要求从整体检查逻辑自洽。本节是只读审查及隔离复现，不是新一轮修复完成声明；生产代码与测试未改，仅追加本纪要。复查时现有 **120/120 测试仍通过**，以下说明测试覆盖之外仍存在真实漏洞。

**参与方式**：3 路 GPT Luna（agent-48：状态机与活性；agent-49：安全与故障；agent-50：产品契约与可解释性）独立审查整个工作流，再恢复各自上下文交叉反驳。候选由多个视角复核，主代理亲自用公开 CLI 与临时目录验证关键链路。后续对扫描范围问题又由 agent-48/50 短轮交叉确认。未使用 K3，未修改实际 `.local-state`、`.demo` 或真实主机授权，未执行上游脚本。

### 10.1 总体判断

指导／工具／状态分层、知识与授权分离、默认只读的方向是自洽的；问题主要集中在全局不变量未贯通各模块：**控制面状态不能成为普通托管对象、初始化不能隐式重置既有知识、不同扫描范围不能直接比较成删除、不可观测不能等于已复核**。普通成功路径与此前 120 项测试未覆盖这些组合。

### 10.2 六类已确认、建议修复的问题

1. **高：维护可以回收自身状态，破坏授权和恢复入口。**
   - 位置：`tools/maintain.py:18-30,116-165`；`tools/steward.py:115-122`；README 的正常示例允许状态目录嵌套在 root 内。
   - 前提：观察根含 state，给该根配置合法 temporary、allow_quarantine、retention_days=0 与正确 directory_id。扫描排除 state，但维护没有同样的控制面保护。
   - 主流程公开 CLI 实测：回收 `state/current.json` 返回 exit 0、applied=true，原位文件消失；回收 `state/host.json` 也成功，后续 restore 在读取授权阶段返回 exit 2。不同代理均独立复现。`.lock` 也未被统一排除，存在锁文件路径与已持有 inode 分裂的风险；主流程未额外演示并发攻击。
   - 最小方向：所有 note/quarantine/restore 的目标核验统一排除 state 本身及后代，不能仅依靠扫描 exclude 或用户不选择它。

2. **高：host 缺失时重新 init 会静默清空已有长期档案。**
   - 位置：`tools/steward.py:118-126`。
   - 主流程先通过 inventory CLI 登记合法资源，再移除隔离 host，重新 init 返回成功；`inventory.json.resources` 从 `[evidence]` 变为 `[]`，没有覆盖确认。初始化只防覆盖 host，不保护其余已有状态／本机指导。
   - **连锁实测**：在同一份嵌套状态里登记 1 项知识 → CLI 回收自身 host 成功 → status 提示“请先 init” → 照提示 init 成功 → 资源数 1→0。故第 1、2 项不只是两个独立边界，而会形成具有破坏性的恢复建议链。
   - 最小方向：发现既有状态产物时区分新建／恢复／重置，默认拒绝覆盖；给缺失 host 提供非破坏性修复说明。跨文件初始化的预检与中断恢复也需补充。

3. **高可用性：特殊文件可使只读／预览命令无限等待并持锁。**
   - 位置：`tools/state.py:82-91`；`tools/maintain.py:66-70,89-90`。
   - Store.read 仅 exists/stat 后 read_bytes，note 对 AGENTS.md 直接 read_text，均未先要求普通文件。FIFO 的 size=0 不能靠字节预算阻止阻塞。
   - 主流程公开 status CLI 在隔离 `current.json` FIFO 上 1.5 秒仍等待；此时第二个 status 因“已有巡检或操作运行”被锁阻断。源代码该读调用没有期限且无 writer，非正常启动延迟。测试 harness 显式终止进程、删除临时 FIFO 后 status 恢复，未留后台进程。agent-49 也独立复现 note 的 FIFO 预览阻塞。
   - 最小方向：统一有界普通文件读取，以 no-follow/nonblocking open 配合 fstat 校验类型；状态与说明使用一致的读取边界。

4. **中：扫描范围改变，被误报为实际对象删除及体积减少。**
   - 位置：`tools/files.py:81-91,121-144,216-237`；`tools/steward.py:286-309`。
   - **普通 CLI 实测，无真实挂载或 mock**：首次巡检 `root/cache/keep`（10 B）；只把 cache 加入 host.exclude_names，不删除文件；第二次报告 `directory_removed=cache, removed=1, byte_delta=-10, gaps=[]`，文件仍存在。旧 baseline 与新扫描语义不同，却被当作可比端点。
   - 另以 DirEntry 设备号 mock 模拟跨卷：scan 的 `other_volume=1`、complete=true，compare 同样给 removed=1、-10 B、无 gap。没有执行真实 Linux／macOS 挂载实验。
   - 分歧裁决：**complete=true 本身不必错误**，它可表示当前声明范围／根设备已扫完；错误是无标签地把“退出观察范围”写成 `directory_removed`。不能把该计数描述成工具真的删除了文件。
   - 最小方向：记录可比较的扫描语义／范围指纹与设备边界；变化时 rebaseline，或输出 out_of_scope 并抑制相应 removed 与体积差。排除信息需进入可见输出，不只存在 raw snapshot 计数。

5. **中：同路径冲突规则被接受，授权结果依赖数组顺序。**
   - 位置：`tools/steward.py:56-70`；`tools/maintain.py:24-29`；巡检的规则选取也采用首个匹配项。
   - 主流程公开 CLI 实测：同 canonical path 的 `[allow=true, allow=false]` 可回收，交换为 `[false,true]` 后被拒绝（exit 0 对 exit 2）。最长路径策略对同长度没有明确冲突语义。
   - 这是**配置歧义及禁止项被遮蔽**，不是外部攻击者凭空获得权限。正常的不同路径嵌套规则不应因此被禁用。
   - 最小方向：validate 要求规范路径唯一，重复即拒绝；若要采用顺序优先级，则需明确契约并在计划中显示选中规则，不可默默依赖列表顺序。

6. **中：不可观测会清除尚未解决的身份复核提示。**
   - 位置：`tools/inventory.py:105-112,159-168`；`tools/investigate.py:351-360`。
   - 主流程通过 CLI 登记、建立身份基准、改变文件得到 changed，`identity_review_required=true`；删除文件后再 inspect，得到 not_observed，但该摘要标志变为 false。
   - 最新报告仍显示 not_observed，长期用途与 anchor 也没有全丢，因此不能声称“调查证明对象恢复正常”或“全部知识被删除”。确定的问题是 required 摘要由 true→false，缺失／权限不足不应解除尚未确认的复核要求。
   - “只保留最新调查”本身是既定设计，不单独算漏洞。最小方向：复核要求独立锁存或使用明确的 unknown 状态，只有显式确认／重建基准才清除；是否另存 last-good evidence 可再权衡容量。

### 10.3 行为已证实，但影响需按契约／环境裁决

- **恢复到新父目录**：主流程 CLI 回收 nested/temporary 后，将整个 nested 改名保留、创建不同 inode 的新 nested，restore 仍成功恢复到新目录。`maintain.py:180-211` 只核对规则根 directory_id。它不是末次核验后的 TOCTOU；但规则根未换代、目标仍在授权路径内，**不自动等于路径越权**。需明确恢复承诺是“同一目录对象”还是“当前授权路径”；若要求对象连续性，应记录并复核必要父目录链。agent-49 从高危降为中／待产品裁决，agent-48/50 更严格，此分歧保留。
- **note 元数据副作用**：主流程 CLI 实测既有 0644 AGENTS.md 成功更新后变成 0600（mkstemp + replace）。正文保留不等于共享访问权限保留；共享目录中有实际影响。ACL/xattr 的丢失仅是可能性，本轮没有据此声称已逐项实测。建议保留 mode 或在不支持的元数据条件下阻断／说明。
- **既有状态目录信任**：agent-49 实测 Store 接受既有 0777 目录而不修正；是否能被其他用户替换 host 取决于父目录可达性、owner 与 ACL。未做真实跨用户攻击，列为多用户环境条件风险，不当作当前单用户必然提权。应明确或校验私有可信目录前提。
- **初始化半成品与退役 baseline**：代理分别验证容量失败后的部分初始化、A→B→A 遗留 baseline；缺少显式收敛入口及范围世代，值得补齐。长期端点差已有 measurement_from/to，旧 changes 作为历史保留可合理；不能仅凭 coverage_complete=true 或跨 48 小时平均速率就断言造假。确定的范围误删已由第 4 项单独证明。

### 10.4 未采纳为新安全漏洞的说法

- planned/failed 不被普通 restore 接受，是已裁决的禁止盲目重放边界；不建议靠放开重放修复。副作用后停在 planned、失败记录占满且无显式关闭入口属于可操作性／收敛缺口，应单独设计核验后 reconcile。
- 字节预算满时 resolve 也写不进去，符合当前“无法安全记录则停止”的 fail-closed 契约；控制面缺预留空间是运维问题，不称高危永久死锁。
- 挂载／过滤后的当前快照完成，不表示历史事件完整；审查不再混淆这两种 coverage。

**建议执行顺序**：先切断第 1＋2 项连锁风险，再修第 3 项有界读取；第 4、5、6 项分别补扫描范围世代、规则唯一性、复核状态单调性。父目录身份和状态目录权限先明确承诺及威胁模型，再选择兼容迁移方案。以上均为待实施建议，本节未修改生产代码或测试。

## 11. 六项逻辑漏洞修复、交叉复核与验收

### 11.1 参与方式与裁决过程

用户随后授权按交叉讨论结果执行修复。本节记录实际交付；第 10 节保留为修复前的历史证据，不把当时的“待实施”回写成已完成。

- 全部子代理使用 **GPT Luna，未使用 K3**。恢复 agent-48、agent-49、agent-50 的原审查上下文和任务，从状态机／活性、安全／故障、产品契约／可解释性三个角度继续交叉讨论；六类问题均经过多个视角复核，而不是由单个执行代理自行裁决。
- 实施由 agent-51（普通文件读取与状态区保护）、agent-52（扫描范围）、agent-53（档案复核锁存）、agent-54（初始化故障回归）分工，主代理完成初始化／规则整合、接口衔接、文档与实际 CLI 验收。
- 修复后恢复原三路再次只读复核实际代码和回归；代理没有把主代理报告的全量测试冒充自己运行的结果。三路均未发现本轮六项仍有阻断缺口；邻接候选及不采纳项如下明确保留。

### 11.2 六项实际修复与取舍

1. **控制面不能成为普通维护对象。** `tools/maintain.py` 统一 `protect_path(store, path)`，在规则选择前拒绝状态目录本身及全部后代。note 的实际说明文件、quarantine 的源与派生回收目标、restore 的两侧均复用保护，preview/apply 一致；host、current、inventory、operations 和 `.lock` 不再因上层目录合法授权而成为可回收对象。普通授权回收与恢复保持可用。

2. **初始化不覆盖已有知识，并显式处理失败残留。** `initialize` 在锁内只接受空目录，普通 `.lock` 除外；任意既有档案、指导或其他文件均拒绝。完整 payload、对象数、单文件及总容量先预检，host 另受 32 KiB 上限，最后发布。没有另设 staging 状态协议：初始化采用独占 hard-link 发布，记录本次创建对象身份，发布身份在 link 成功后、目录 fsync 前进入回滚跟踪。回滚只移除身份及内容仍匹配的本次文件，并对本次空目录做 rmdir；不递归删除，不覆盖或删除外来同名文件。若 host 无法安全移除，保留其他完整 payload 并报告残留，绝不返回 initialized。物理 I/O 故障下不承诺绝对零残留；缺失 host 的提示改为先恢复原约定，不再建议对旧状态直接 init。

3. **读取边界统一，特殊文件不再等待 writer。** `tools/state.py` 新增 `read_regular_bytes`，以 no-follow/nonblocking 打开，fstat 要求普通文件，最多读取 limit+1，并校验读前后 dev/inode/size/mtime 与长度。状态、host、资源定义和 note 首读／复读／写后验证复用它；锁文件也要求普通文件。真正缺失仍保留 Store.read 的默认值语义，其他损坏或物理错误按上层契约阻断。调查模块原有共享预算读取不被无差别替换。非阻塞打开不是普通磁盘 I/O 硬超时。

4. **扫描范围换代不再伪造删除。** 每个 root 记录版本化 scope：root、根设备、规范化排除项、状态排除路径、扫描深度、同卷策略，以及完整跨卷边界集合的稳定 digest／数量／最多 8 个样例／truncated。集合暂存受扫描预算约束，持久样例有界；不复制授权、全部 host 或无关预算，也不把普通 excluded 计数纳入比较身份。双方完整但 scope 不同时只报告 scope gap 并建立新基线，不产出普通删除／体积差／增长证据。旧基线首次升级可见，partial 保留旧完整基线；退役 root 清除活动 baseline，A→B→A 重新建基线，历史 changes 和未关闭待办不因此清空。`coverage_scope` 在 patrol/status 可见并按原分页约定输出，reader 严格校验结构。scope gap 可与 `coverage_complete=true` 共存：后者仍只指当前声明范围的快照。

5. **同路径规则不再依赖列表顺序。** validate 拒绝同一规范路径的全部重复规则，包括完全相同的重复项；合法的不同路径嵌套仍选择最长匹配。排除项同时收紧为非空单层文件名，拒绝非法类型、`.`、`..`、斜线和 NUL，避免范围摘要进入不可排序或无效状态。

6. **身份复核要求单调锁存。** 最新 inspection 增加可选布尔 `identity_review_required`，不扩张资源 entry 的四字段结构，不增加历史表或 last-good 副本。新值为旧 latch 与当前 changed 的 OR，兼容旧 `identity_continuity=changed`；not_observed、后续 same 及相同定义的 unchanged 均不能清除。实际更新且经复核的新定义仍沿用登记流程重建 anchor/inspection，才解除旧提示；来源时间不会因巡检刷新，知识仍不授予维护权限。

### 11.3 修复后交叉反驳与补修

- agent-48 提出资源定义解码异常的 API 一致性候选。主代理进一步用 4,000 字节深嵌套 JSON 实测，发现它还能导致 CLI `RecursionError`、exit 1 和 traceback，并非仅内部异常风格差异。agent-48/49 短轮共同确认后，`read_definition` 将 decode 的 `ValueError/RecursionError` 转为 `StewardError`，保留共享低层 reader 的原始 OSError 契约。新增直接 API＋真实 CLI 回归覆盖坏 JSON、重复键、NaN、1e309、非法 UTF-8、深嵌套：统一 blocked／exit 2／无 traceback，inventory 字节不变。
- agent-50 要求冻结两个易误读契约：当前快照完整不等于历史范围可比；初始化精确回滚不等于物理故障下绝对原子。两者已同步至 README、SKILL、design 及相应 setup/patrol/inventory/recovery/files-storage 指导。
- agent-49 提出独立 **P2 邻接残余**：普通非 exclusive `Store.write_bytes` 先 os.replace，再做目录 fsync；后者失败时调用方收到错误，但目标可能已经是新内容。初始化 exclusive 路径有专门回滚，本轮六项不受该残余阻断；未借本轮扩张为普通状态提交协议重构，也不声称“所有 I/O 失败都保留旧文件”。

### 11.4 最终交付验证

- 首轮集成为 166 项；补资源定义格式异常回归后，在最终代码上重新运行 `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`：**167/167 通过**。相对上一轮 120 项增加 47 项，包含 4 份专项回归与 inventory 扩展；不是只导入或编译。
- 故障注入覆盖 guidance 中途失败、host 发布后的目录 fsync 失败、同名外来文件、外部改写、host 清理 PermissionError、32 KiB host 预检、容量不足及特殊文件。不能安全回滚时测试要求报告残留，不要求通过破坏外来内容获得“干净目录”。
- 主代理从 cwd `/` 经 bash/zsh 在临时目录验证六项链路：嵌套 state 的 preview/apply 阻断且字节不变；合法资源档案在 host 缺失后拒绝重 init 并保持；FIFO 快速拒绝且锁可再用；仅增加排除项不报删除；重复允许／禁止规则阻断；changed→not_observed→same 始终要求复核，相同登记不清，真正更新定义才清。正常 note 幂等、quarantine/restore、patrol/resolve 也通过。
- 最终补修后再次从 cwd `/` 经 zsh 新建独立 demo：**13/13 checks 通过**，baseline/changes/final 三轮快照覆盖通过；再经 bash 读历史返回 `existing_demo, verified=false`，demo.json 与 report.md 的 SHA256 均不变。
- bash/zsh 入口语法检查通过；tools/tests 共 18 份 Python 源文件 AST 解析通过。未把离线跨卷模拟或 Linux 分支回归描述为 Linux 实机挂载验收。
- 所有维护和故障注入均限于临时目录，未覆盖既有 `.local-state`／`.demo`，未清理真实资源、修改真实授权或执行上游脚本。未增加依赖，未 add/commit/reset；当前项目文件仍未跟踪，没有可用的已提交原始 diff 基线。

### 11.5 保留边界与结论

本轮六类已确认漏洞已修复并经三路交叉复核，但不据此声称整个项目再无漏洞。以下仍是独立边界：恢复没有保存源父目录的完整身份链；既有状态目录未新增 owner/mode/world-writable 审计，仍要求可信私有目录；note 原子替换不保证 mode/ACL/硬链接元数据保持；普通 I/O 没有硬超时，非合作外部写者没有原子隔离；普通替换后目录 fsync 失败的提交不确定性仍在。planned/failed 不由普通 restore 盲目重放、字节预算满时 resolve fail-closed，均未擅自改变。未证明 Linux 实机、新 agent 自动注入、完整依赖或业务恢复。

## 12. 对“绝对圆满”和过度绝对化的反思

**范围**：用户指出不能预设 100% 预知，灵活处理才是核心，并要求回看此前文本是否也犯了这类问题。本轮恢复原 agent-48／49 的 GPT Luna 上下文，分别从运行活性与风险比例进行两轮交叉核对；主代理补做一项公开 CLI 实证。只追加本纪要，未修改生产代码、测试或操作指导，因此以下是纠偏结论，不是新一轮修复完成声明。

### 12.1 确实存在的三处问题

1. **把普通内容变化过度提升为身份复核。** `tools/investigate.py:315-318` 对普通文件把 size/mtime 一并放入 identity，`tools/inventory.py:166-180` 因此将原位追加、编辑或触碰时间标成 `changed` 并锁存复核。主代理在临时目录用真实 init→inventory→inspect 流程复现：同一 dev/ino 的日志只正常追加一行，即得到 `identity_continuity=changed`、`identity_review_required=true`；再次登记完全相同的 definition 返回 unchanged，之后提示仍为 true。这会使正常日志与长期资料频繁积累提示，降低提示的可信度。纠偏方向是区分稳定对象身份与可变内容指纹，保留两类证据，而不是简单删除 size/mtime 或把一切变化都视为无风险。该标志当前只是复核提示，不直接撤销 host 授权，不能夸大为“所有维护都被禁止”。

2. **把当前 demo 的完整流程写成永久且无例外的原则。** `design.md:254-266` 的“所有改变状态的操作……没有例外通道”没有清楚区分托管对象／授权／恢复关键变更与自身轻量记录；`agent.md:40` 也容易产生同样理解。实际 pending、inventory 和派生 current 更新并未全部建立 maintenance operation，说明代码已有合理分层，文案却更绝对。完整计划—核验—执行—验证—记录仍适用于托管对象和恢复关键动作；低风险内部派生记录应允许锁、校验、原子写和必要复读的轻量路径。这里是默认分层需要写准，不是给高影响操作开例外。

3. **安全停止之后的人工收敛路径偏弱。** `guidance/situations/recovery.md` 与 `tools/state_schema.py` 对损坏 current 保留原文并 fail-closed 是合理的，但 patrol/status/resolve 会一起无法继续，现有文本主要停留在备份、恢复可信约定和不要重放。planned/failed/restoring 同样强调先观察，却缺少足够清楚的人工核对、局部只读诊断与结束／放弃记录路径。纠偏方向是补足可解释的人工恢复说明，再按真实需要决定是否加最小工具入口；不自动拼接损坏状态、不盲目重放，也不先建通用恢复框架。

### 12.2 不应借此放宽的边界

局部 root 或观测缺口当前已经能降级并保留 stale／gap，GPU 等信息缺失也没有让整个 patrol 停机，不能把现状概括为“任何未知都会全局停止”。init 不自动覆盖旧状态、状态区不作为普通维护对象、FIFO 不等待 writer、未知档案不扩权、损坏状态不静默重建、未完成操作不盲目重放，仍是合理硬边界。灵活性应体现在**按影响分级、保留证据、提供人工复核与恢复出口、允许延期和局部继续**，而不是把不确定自动解释成安全。

### 12.3 共同纠偏原则

后续优先处理已被普通场景证明的过敏和无法收敛，不再以“还可能有一种未知风险”为由无限增加阻断。安全边界保持少而明确；风险提示要可解释、可关闭且不会污染正常证据；流程默认值与真正的强制不变量分开写；拒绝危险动作时同时说明下一步如何恢复或上报。此次只形成以上具体纠偏清单，未实施新命令、新状态字段或新框架，也未重新宣称项目已经完整解决灵活性与安全性的平衡。

## 13. 全篇审读后的最小纠偏实施

### 13.1 范围与交叉裁决

用户随后要求全篇阅读，并说明暂时更换子代理模型。本轮新开 agent-55／56，使用调用方当前默认模型，不恢复旧 Luna 实例；两路分别完整阅读项目自有的 README、SKILL、agent、design、全部 guidance、状态模板与 references 历史材料，再从产品可执行性、状态机与风险比例交叉裁决。外部 upstream-skills 快照不属于自写全篇，历史现场材料只用于识别旧结论，不改写原文。

除第 12 节三项外，全文审读新增四类候选：directory_id 缺少可执行获取路径；未终结 operations 无通用关闭入口且会占预算；pending overflow 满时实际整轮不提交；scope／游标说明存在分层重复。两路共同反驳了“所有候选都应改代码”的倾向：pending 不能为活性静默丢弃精确 finding，operations 不能为腾空间自动淘汰证据，重复文本在没有口径漂移且承担不同层入口时不强行合并。

### 13.2 实际修改

1. **身份与元数据分层。** `tools/investigate.py` 不再把普通文件 size/mtime 拼入稳定身份；`tools/inventory.py` 新增 `metadata_continuity`，以 baseline_created/same/changed/not_observed/not_comparable 保留可变观测。路径身份／类型或服务启动配置换代仍锁存复核，旧 latch 在 missing/same 后仍保持。旧文件五段 anchor 仅在稳定前缀一致时兼容匹配，不在读取时改写；不声称 size/mtime 是内容哈希或能够识别所有 inode 复用。
2. **正常维护入口可执行。** `guidance/setup.md` 明确从 `status --path` 的 `directory_index` 精确 path 行读取 `id=dev:ino`，没有精确行时不能用父目录身份或猜测值替代。
3. **流程按影响分层。** `agent.md` 与 `design.md` 将完整计划—核验—执行—验证—记录限定于托管对象、授权和恢复关键变更；自身派生事实、pending 与知识记录不伪造 operation id，按风险使用锁、结构校验、容量预检与原子写。
4. **故障影响与下一步写准。** recovery 说明 current 损坏对 patrol/status/resolve 和文件调查的实际影响，以及备份原件、副本定位、可信来源核对、只读验证的人工顺序；明确当前没有通用 abandon/reconcile CLI，未终结证据不自动淘汰，不能把手工挑选删除当成恢复。README 与 patrol 说明 overflow 满时整轮 current（含新基线、观测和事件游标）不提交，先用 status／resolve 释放已有事项位置再重试。
5. **身份说明同步。** README、SKILL、design 与 inventory 统一稳定身份／metadata 口径，并写清真实复核后以新来源或证据时间更新定义的现有重建出口；相同定义不能为消提示而假装发生变化。修复后复核发现枚举漏写 baseline_created/not_observed，已补齐。

### 13.3 未改代码的候选

- **operations 通用关闭入口**：事实和预算影响已写入 recovery，但新增 abandon/reconcile 是新的状态转换，本轮不借文档纠偏扩张；仍需后续按真实场景单独设计。
- **pending overflow 提交策略**：保留整轮 fail-closed，未改成丢弃或摘要化新 finding；现有逃生路径是处理已有 pending／overflow。
- **scope／游标去重**：没有确认语义漂移，保留 README 速查、design 契约和现场指导的不同粒度，未为减少行数制造跨层引用跳跃。
- init 不覆盖旧状态、状态区保护、损坏状态不静默重建、未完成操作不盲重放、身份 latch 不因 missing/same 自动清除均保持不变。

### 13.4 验证与复核

- `test_inventory` 定向 **29/29 通过**；最终全量 `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`：**169/169 通过**。新增同 inode 普通追加与旧 anchor 兼容回归，原有身份换代测试改为真实 `os.replace`，不靠同 inode 改写冒充换代。
- 真实 CLI 在 TemporaryDirectory 验证：status 精确行给出的 directory_id 与 `dev:ino` 一致；普通追加得到 identity=same、metadata=changed、review=false；inode 替换得到 changed／not_comparable／review=true；相同定义保持 latch，真实复核后的定义更新重建为 baseline_created。
- 独立 demo **13/13 checks 通过**，历史重读 verified=false 且字节不变；bash/zsh 入口语法与 18 份 Python 源文件 AST 解析通过。
- agent-55／56 恢复上下文复核实际交付，均未发现阻断或可证明回归；唯一文档枚举遗漏补完后重新运行全量 169 项仍通过。
- 未修改真实 `.local-state`、既有 `.demo` 或历史现场原文，未增加依赖、未创建 Git 提交。以上结果只覆盖本轮明确场景，不表示 operations 收敛、inode 复用识别或项目整体灵活性已经彻底解决。
