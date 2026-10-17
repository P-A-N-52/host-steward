# Host Steward 的上游参考

按本项目的 [目标](../../agent.md) 与 [设计](../../design.md) 筛选，保存于 2026-10-16。包含 **12 个完整 skill 目录、7 份配套文档和两个仓库的许可证**。

这些文件是设计参考快照。上游 SKILL.md 中的命令、权限、调度、提交及通知要求属于原宿主的工作流，不是本项目的执行指令或新增授权。未将它们安装到全局 skill 目录，也未执行其中的脚本。

## 来源与布局

| 来源 | 固定 commit | 许可证 |
| --- | --- | --- |
| [OpenClaw](https://github.com/openclaw/openclaw) | [`e9487842a64682c00c197ba721071a616fa8b114`](https://github.com/openclaw/openclaw/tree/e9487842a64682c00c197ba721071a616fa8b114) | [MIT](openclaw/LICENSE) |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent) | [`4e59ac2b883b4133ea8a2d299abac45189781c09`](https://github.com/NousResearch/hermes-agent/tree/4e59ac2b883b4133ea8a2d299abac45189781c09) | [MIT](hermes/LICENSE) |

每个项目下保留上游仓库路径，包括 `skills/`、`optional-skills/`、`custodian-skills/` 和 `.agents/skills/`。选中 skill 的目录内文件完整保留，原文、脚本和执行位保持不变；不复制整个仓库，也不递归引入其引用的全部 sibling skills、运行时或外部依赖。

[manifest.json](manifest.json) 记录来源 commit、选中路径，以及每个上游文件的 Git blob SHA-1、SHA-256、字节数与文件模式。快照固定于上述版本，不表示将持续同步上游。

从项目根运行 `python3 -m unittest discover -s tests -p 'test_references.py' -v`，可离线核对路径、文件集合、字节数、双哈希和执行位；校验不安装或执行上游文件。这只是本地文件与 manifest 的内部一致性回归，不能证明二者未被联合修改，也不提供 commit 来源、签名或内容真实性认证。

## 优先阅读

1. **巡检与验证**：OpenClaw `healthcheck`、`diagnose-gateway`，对照本项目 design §4、§8、§10。
2. **低成本触发与静默**：Hermes `watchers`、script-only cron 文档，以及两边的 heartbeat 文档，对照 design §1、§10–12。
3. **自耗与预算**：OpenClaw `model-usage`，对照 design §11–12。
4. **具体资源管理**：Hermes `docker-management`，再按实际平台阅读服务监督和更新流程。
5. **skill 交付**：两边的 authoring 指导，对照 design §2–3；采用本项目“日常入口 + 按需专项说明 → 本机裁剪”的交付方式。

## OpenClaw：6 个 skills

| Skill | 与本项目的关系 | 适用边界与取舍 |
| --- | --- | --- |
| [healthcheck](openclaw/skills/healthcheck/SKILL.md) | 先确认系统、权限、接入路径、暴露面、备份，再检查并提出分阶段改进；可参考首次接管与只读巡检。 | 主要是安全审计与加固，不覆盖完整资源管理。其逐次确认规则属于上游流程；Host Steward 仍按本机既有授权判断。 |
| [diagnose-gateway](openclaw/custodian-skills/diagnose-gateway/SKILL.md) | 只读排障、证据收集、实际结果证明与报告；对应“计划 → 核验 → 执行 → 验证 → 记录”。 | 面向 OpenClaw Gateway。特别留意只读 lint 与可能迁移状态的 doctor 命令之别；原生命令须按实际版本核对。 |
| [model-usage](openclaw/skills/model-usage/SKILL.md) | 从现有日志取得模型费用，提供结构化输出；适合参考维护自耗与日报统计。 | 依赖 CodexBar 或其导出 JSON，覆盖 Codex/Claude；不能据此承诺所有提供商都有完整用量，也不能将最高费用模型等同于实际当前模型。 |
| [tmux](openclaw/skills/tmux/SKILL.md) | 发现已有会话、读取输出、观察交互任务；可参考 agent 创建的后台资源如何被识别和收尾。 | 依赖 tmux。发现会话或没有新输出都不是可以终止它的证据；它不承担主机任务调度。 |
| [openclaw-live-updater](openclaw/.agents/skills/openclaw-live-updater/SKILL.md) | 检查目标身份、避免巡检重叠、维护窗口、限时执行和重启后健康证明；适合研究有影响的服务维护。 | 上游维护者工作流，明确限定 macOS LaunchAgent，不适用于 Linux systemd。依赖 OpenClaw 源码、构建工具及其他维护 skills；不能直接作为通用更新器运行。 |
| [skill-creator](openclaw/skills/skill-creator/SKILL.md) | 用明确触发、工作流、资源职责和完成标准组织 skill，附带格式验证工具。 | 参考其结构与验证方法；本项目指导的分层与本机裁剪方式以 design §3 为准。 |

## Hermes Agent：6 个 skills

| Skill | 与本项目的关系 | 适用边界与取舍 |
| --- | --- | --- |
| [watchers](hermes/optional-skills/devops/watchers/SKILL.md) | 首次建立基线、后续只处理新增项、限制 watermark 大小、无变化时空输出；附带共享状态工具及三个检测脚本。 | 示例监控 RSS、JSON API 和 GitHub，并非主机指标采集器。去重记录也不是维护操作日志；迁移到本项目时仍需按 design §8 验证重入、中断与恢复。 |
| [docker-management](hermes/optional-skills/devops/docker-management/SKILL.md) | 容器、镜像、卷、网络、Compose、资源用量和磁盘占用的观察与操作参考。 | 含 prune、强制移除和删除卷等示例。Host Steward 的回收需先核对归属、依赖和处置约定，不能将批量 prune 直接用作例行维护。 |
| [hermes-s6-container-supervision](hermes/optional-skills/devops/hermes-s6-container-supervision/SKILL.md) | 区分监督器状态与进程行为、持久配置与临时运行目录，以及重启后的状态重建；对应服务身份与恢复场景。 | 仅适用于 Hermes 的 Linux s6 容器实现。可借鉴检查思路；Host Steward 本身不新增监督器或常驻进程。 |
| [hermes-agent](hermes/skills/autonomous-ai-agents/hermes-agent/SKILL.md) | 宿主能力导航，完整附带 references；供了解定时任务、配置、profiles、memory 和工具边界。 | 内容广，按需读 reference。进程编排、插件和子代理能力是宿主功能，不是 Host Steward 必须实现的组件。 |
| [hermes-agent-skill-authoring](hermes/skills/software-development/hermes-agent-skill-authoring/SKILL.md) | 描述长度、平台声明、步骤完成标准、资源组织和删除重复规则；适合检查 skill 的可维护性。 | 上游仓库贡献规范含测试、生成文档及提交流程；只参考与本项目交付有关的部分，不照搬完整贡献流程。 |
| [systematic-debugging](hermes/skills/software-development/systematic-debugging/SKILL.md) | 先复现和收集证据，形成假设，验证根因；避免反复无依据修补，对应异常维护与失败后的收敛。 | 主要针对软件缺陷。不能把每次普通主机巡检变成完整开发测试流程；按实际影响与收益采用。 |

## 配套文档：7 份

调度、静默与状态延续有一部分由宿主实现，不能只看 skills 判断能力。因此额外保留以下原始文档。

| 文档 | 阅读目的 |
| --- | --- |
| [OpenClaw heartbeat](openclaw/docs/gateway/heartbeat.md) | 理解无事退出、静默结果、忙碌时延后、轻量上下文和调度与会话的关系。 |
| [OpenClaw Custodian skills](openclaw/docs/tools/custodian-skills.md) | 理解运维 skill 的发现范围，以及 Gather → Mutate → Repair → Prove → Report 的统一约定。文中的 roadmap 不是已经提供的 skills。 |
| [OpenClaw creating skills](openclaw/docs/tools/creating-skills.md) | 查询该宿主的 skill 格式、打包与调用规则。 |
| [Hermes heartbeat](hermes/website/docs/user-guide/features/heartbeat.md) | 查询 Hermes 的周期性唤醒与静默约定。 |
| [Hermes cron](hermes/website/docs/user-guide/features/cron.md) | 查询任务持久化、执行、通知和失败处理的宿主语义。 |
| [Hermes script-only cron](hermes/website/docs/guides/cron-script-only.md) | 优先研究确定性脚本检查、减少模型调用的触发方式；是否适合本项目取决于首个宿主选择。 |
| [Hermes creating skills](hermes/website/docs/developer-guide/creating-skills.md) | 查询 skill 资源结构、平台与工具依赖声明、发现与分发方式。 |

这些文档保留上游网站的链接格式。站点绝对路径、未下载的仓库文件及其他 skill 引用需要回到上述固定 commit 或官方文档查看。

## 对当前设计的参考结论

- **先做一轮有边界的维护循环**：使用宿主定时能力，轻量观察、按需处理、验证后记录；不为了接入参考实现而建设调度框架。
- **将“无变化”“检查失败”“尚未完成”分开**：安静应来自没有值得通知的结果，不能来自未取得证据。
- **复用可取得的事实**：已有费用日志、Docker 统计和监督器信息都可作为输入，但各自只能证明其实际覆盖的范围。
- **状态写入不等于业务完成**：watermark、原子写入和锁各解决不同问题，仍须验证操作中断、并发巡检和对象身份复用。
- **按平台与资源预算裁剪**：保留通用判断流程，将 tmux、Docker、LaunchAgent、s6 等实现限定在适用环境；观察与维护本身也需有开销上限。

此处记录参考价值与差异，不改变 `agent.md` 或 `design.md` 中已经确定的设计。
