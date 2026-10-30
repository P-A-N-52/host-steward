# 自定义检查

自定义检查把用户确认的本机健康脚本接入 Steward 的有界执行入口。它只按 `host.json` 中的显式名单执行脚本并整形结果，不发现脚本、不安装服务，也不把输出自动写进长期状态。是否运行、何时运行以及如何跟进由 agent 和宿主调度决定。

## 配置

`custom_checks` 是 `host.json` 顶层可选数组，省略等价于空数组；`init` 生成的模板包含 `"custom_checks": []`，已有 `host.json` 不写该字段仍然合法。最多 32 项，每项必须有且仅有 `name`、`command`、`purpose`：

| 字段 | 约束 | 用途 |
| --- | --- | --- |
| `name` | 1–64 字节；以字母或数字开头；只含字母、数字、点、下划线、连字符；同一配置内唯一 | CLI 选择、`HOST_STEWARD_CHECK_NAME` |
| `command` | 1–16 个非空字符串参数；首项必须是绝对路径；每个参数不超过 1024 字节且不含 NUL | 直接 exec，不经 shell，不按 PATH 查找 |
| `purpose` | 非空短文本，最长 512 字节 | 说明检查什么、为谁服务 |

示例：

```json
{
  "custom_checks": [
    {
      "name": "backup-freshness",
      "command": ["/usr/bin/python3", "/绝对路径/scripts/check_backup.py", "--max-age-hours", "48"],
      "purpose": "核对最近的备份是否在 48 小时内"
    }
  ]
}
```

`command` 首项是解释器时，列表中的 `executable_available` 只核对解释器本身；脚本路径、参数和脚本内容仍需另行确认。额外字段、重复 `name`、相对首项、空参数或超长文本都会使整份本机约定校验失败，按[恢复指导](recovery.md)处理，不要临时绕过校验。

只有用户确认过用途、完整命令、运行用户、预算和副作用的脚本才能写入。配置条目是授权记录，不是脚本发现或安装机制。

## 脚本契约

脚本以当前用户权限运行，继承当前环境，并额外收到：

| 变量 | 值 |
| --- | --- |
| `HOST_STEWARD_STATE` | 本机状态目录的规范绝对路径 |
| `HOST_STEWARD_CHECK_NAME` | 当前检查的 `name` |

工具还设置 `LC_ALL=C`。命令直接 exec，不经过 shell，因此管道、重定向、通配符和变量展开都要由脚本自己完成；需要组合命令时，把逻辑写进脚本或显式传入参数。

stdout 必须是 UTF-8；stderr 合并进 stdout，与工具其他 `command` 调用的语义一致。退出码与结果的对应关系：

| 情况 | `status` | 附带字段 |
| --- | --- | --- |
| 退出码 0 | `ok` | `exit_code: 0`、`format` 与输出 |
| 退出码非零 | `failed` | `exit_code`、`reason`、输出 |
| 超过单项时间预算 | `timeout` | `reason`、已读取字节数；进程组被终止 |
| 输出超过 `command_bytes` | `output_limited` | `output_bytes`、`reason`；不保留已捕获输出 |
| 无法执行 | `failed` | `reason`，通常是 `无法执行：...` |
| 输出不是 UTF-8 | `failed` | `reason` |
| `--all` 总预算耗尽 | `skipped_budget` | `reason` |
| 脚本启动前本机约定变化或无法重新核对 | `skipped_policy_changed` | `reason`；当前项与剩余项都不启动 |

输出整形规则：

- 输出未被终端返回预算截断，且能解析为 JSON 对象或数组时，返回 `format: "json"` 与 `data`。
- 其他情况返回 `format: "text"` 与 `output`；JSON 标量也按文本返回。
- 单项输出超过分到的终端返回预算时截断，`truncated` 为 `true`，`returned_bytes` 小于 `output_bytes`。截断后不再尝试解析 JSON，即使原始输出是合法对象。
- 超时与 `output_limited` 都会终止脚本进程组；脚本应为子进程和临时文件自行收尾。工具无法保证脚本只读，`command` 也不是沙箱。

若脚本用退出码表达检查结论，非零会整体按 `failed` 处理并使 CLI 退出 2。需要区分“检查完成并发现问题”和“检查无法执行”时，建议保持退出码 0，把结论编码在 JSON 或文本中，由 agent 结合 `purpose` 解释。

## CLI

### 列出配置

```sh
python3 /绝对路径/tools/steward.py check --state /绝对路径/本机状态
```

返回 `status: "custom_checks"`，包含每项的 `name`、`purpose`、`command` 和 `executable_available`，以及 `count`、`budget` 和提示。该模式只读取并展示配置，不运行脚本。

`executable_available` 表示 `command` 首项当前是普通文件且可执行；它不校验后续参数、脚本内容、解释器版本或运行结果，只是执行前的可用性线索。

### 运行一项

```sh
python3 /绝对路径/tools/steward.py check --state /绝对路径/本机状态 --name backup-freshness
```

未配置的 `name` 直接报错，不会运行任何脚本。启动前会重新核对整份 `host.json`；约定变化或无法核对时该项不启动，状态为 `skipped_policy_changed`，CLI 退出 2。

### 运行全部

```sh
python3 /绝对路径/tools/steward.py check --state /绝对路径/本机状态 --all
```

`--name` 与 `--all` 互斥。`--all` 按配置顺序串行运行，总时长受 `limits.scan_seconds` 限制；空配置返回 `count: 0`、`complete: true`。

每个脚本实际启动前，CLI 都会重新读取并校验整份 `host.json`，与维护命令在副作用前重新确认约定的做法一致。条目删除、改名、命令/用途/预算等语义变化，以及仅格式变化，都会中止本次运行：当前项与所有剩余项标为 `skipped_policy_changed`，脚本不启动，报告顶层追加 `policy_changed`，CLI 退出 2。总预算已耗尽的项仍先按 `skipped_budget` 处理，不触发复核；列表模式不执行脚本，也不做逐项复核。

结果报告形如：

```json
{
  "status": "custom_check_results",
  "checks": [
    {"name": "backup-freshness", "purpose": "核对最近的备份是否在 48 小时内",
     "status": "ok", "exit_code": 0, "format": "json", "data": {"fresh": true},
     "output_bytes": 14, "returned_bytes": 14, "truncated": false, "elapsed_seconds": 0.08}
  ],
  "count": 1, "executed": 1, "failed": 0, "skipped": 0,
  "complete": true,
  "budget": {"timeout_seconds": 3, "command_bytes": 262144, "output_bytes": 32768},
  "elapsed_seconds": 0.1
}
```

约定在运行中变化时，报告追加中止项与顶层 `policy_changed`：

```json
{
  "status": "custom_check_results",
  "checks": [
    {"name": "first", "purpose": "第一项", "status": "ok", "exit_code": 0,
     "format": "text", "output": "", "output_bytes": 0, "returned_bytes": 0,
     "truncated": false, "elapsed_seconds": 0.01},
    {"name": "second", "purpose": "第二项", "status": "skipped_policy_changed",
     "reason": "本机约定在检查运行期间变化或无法重新核对；脚本未启动"}
  ],
  "count": 2, "executed": 1, "failed": 0, "skipped": 1,
  "complete": false,
  "policy_changed": {
    "reason": "本机约定在检查运行期间变化或无法重新核对；后续脚本未启动，请重新运行",
    "detail": "本机约定在本轮执行期间变化，旧计划未提交；请重新运行"
  },
  "budget": {"timeout_seconds": 3, "command_bytes": 262144, "output_bytes": 32768},
  "elapsed_seconds": 0.1
}
```

`failed` 统计状态不是 `ok`、`skipped_budget` 或 `skipped_policy_changed` 的项；`skipped` 同时统计 `skipped_budget` 与 `skipped_policy_changed`；`complete` 仅在 `failed == 0` 且 `skipped == 0` 时为真。`policy_changed.reason` 是检查语境的固定文案，`detail` 是重新核对时的原始消息（最多 512 字符）。

### 退出码

- 列出模式不运行脚本，正常返回退出 0；整份输出被裁剪时按下面的裁剪处理退出 2。
- 运行模式全部 `ok` 时退出 0。
- 任一执行项为 `failed`、`timeout`、`output_limited` 或 `skipped_budget` 时退出 2。
- 存在 `skipped_policy_changed` 时退出 2：本机约定在运行中变化或无法重新核对，后续脚本未启动；重新核对并修复 `host.json` 后重跑。
- 整份报告超过 `limits.output_bytes`、终端只返回 `output_limited` 摘要时退出 2。此时改用 `--name` 缩小范围，或减少输出后重跑；裁剪摘要不保留 `policy_changed` 细节。
- 单项结果中的 `truncated` 只表示该项返回文本被裁剪，本身不改变 `status`；整份报告仍可能因输出预算被替换并触发退出 2。

## 预算

| 预算 | 来源 | 作用 |
| --- | --- | --- |
| `scan_seconds` | `limits` | 单项执行超时；`--all` 的总执行时长 |
| `command_bytes` | `limits` | 单项 stdout/stderr 捕获上限；超过即 `output_limited` |
| `output_bytes` | `limits` | CLI 终端返回上限；单项结果会按项数分摊，整份报告仍可能被替换为裁剪摘要 |

`--all` 使用同一个 `scan_seconds` 作为全部检查的总预算，而不是每项各得一份。每项实际超时取总预算剩余时间；某项用完后，后面的项标为 `skipped_budget`。默认 3 秒对多个脚本通常偏紧，先实测单项耗时，再决定拆分调用或请用户确认调整 `host.json.limits.scan_seconds`。

终端返回预算在为报告元数据预留开销后按本次运行的检查数分摊到单项，并保留最低 256 字节；检查越多，每项能返回的文本越短。需要完整输出时用 `--name` 单独运行，或让脚本只输出必要摘要。

调整预算属于修改本机约定：说明现有耗时、预期影响和替代做法，取得用户确认后再改。不要为了让脚本跑完而临时绕过预算。

## 结果与状态

- `check` 启动时读取 `host.json`，并在每个脚本实际启动前重新核对整份 `host.json`；不读写 `steward.sqlite3` 中的观测、档案、事项和 operations，也不把检查结果写入状态。
- 因此没有检查历史、没有跨轮趋势，也不能用 `status` 找回上次输出。需要保留结论时，由 agent 在当轮汇总，并用既有流程保存：跨轮跟进用 `track`，目录说明用 `note`，长期资源知识用 `inventory`；宿主调度日志是另一条可选的原始输出保存位置。
- `patrol` 不会自动运行自定义检查，检查也不会增加巡检的扫描或写状态开销。需要例行检查时，由宿主调度或 agent 在巡检中显式调用 `check`。
- 检查脚本不应承担维护。脚本若会修改文件、服务或配置，应按维护动作计划、核验、执行、验证和记录，而不是伪装成只读检查；工具无法代替这种授权判断。

## 授权与副作用

脚本以当前用户权限运行，能访问该用户可访问的文件、网络和服务。工具只能限制执行时间与输出，不能限制系统调用、文件写入、网络请求或权限范围，也不能保证脚本只读。

每项启动前的复核只覆盖尚未启动的脚本：已经运行的脚本无法撤回，其结果按实际执行记录；复核通过到 `command()` 实际 exec 之间仍有极短窗口，`host.json` 的原子写入只保证复核读到完整快照，不是沙箱。运行 `check` 期间不要编辑 `host.json`；编辑后重新运行，让新名单在新一轮授权下生效。

新增或修改一个检查前，说明：

- 检查什么、为什么需要，以及结果由谁使用；
- 完整 `command`（含绝对路径和参数）、运行用户与依赖；
- 单项和总时间预算、预计输出量和 `command_bytes` 影响；
- 可能读取或写入的路径、网络访问、服务操作和其他副作用；
- 失败或超时时的处理方式，以及是否需要通知。

只有用户确认后才能写入 `custom_checks`。修改 `host.json` 前在状态目录外保存副本，修改后用列出模式核对命令与 `executable_available`，再运行单项验证。需要 root 或其他用户的脚本不要通过这个入口运行，改用另有授权的机制。

## 与巡检、调度的关系

在巡检中运行自定义检查时：

1. 先完成 `patrol` 和常规覆盖、变化、资源判断，再按任务需要运行 `check`；检查失败不改变 `patrol` 已提交的巡检结果。
2. 用 `--all` 做常规批量检查，用 `--name` 复跑单项或补取完整输出。
3. 读取 `complete`、`failed`、`skipped` 和每项 `status`，再结合 `purpose` 判断影响。失败、超时和跳过都要如实报告，不能把未运行当作正常。
4. 需要跨轮跟进的事项用 `track` 保存；目录相关结论用 `note` 写入说明；当轮已处理完的检查结果不必写入状态。

需要定时运行时，在宿主调度中建立明确任务，调用固定的绝对路径，并把 stdout、stderr 和退出码交给 agent 或日志：

```sh
python3 /绝对路径/tools/steward.py check --state /绝对路径/本机状态 --all
```

调度任务与巡检任务可以合并，也可以分开；合并时在 agent 的一轮工作里显式调用，分开时注意不要让两个任务并发运行同一组有副作用的脚本。`check` 自身不安装定时任务、不派生后台进程，也不会因为配置了 `custom_checks` 就自动执行任何脚本。

## 如何验证

用临时脚本或已确认的本机脚本验证，不要用生产维护脚本做失败测试。

1. **配置可读**：运行列出模式，确认 `count`、每项 `command` 和 `executable_available`；确认脚本没有执行，命令退出 0。
2. **单项成功**：运行 `--name`，确认 `status: "ok"`、`exit_code: 0`，并核对 `format` 与 `data`/`output` 是否符合脚本约定；需要时让脚本回显 `HOST_STEWARD_STATE` 与 `HOST_STEWARD_CHECK_NAME`。
3. **全部运行**：运行 `--all`，确认 `count`、`executed`、`failed`、`skipped`、`complete` 与实际一致，退出码为 0。
4. **失败路径**：用临时脚本分别制造非零退出、超过 `scan_seconds`、超过 `command_bytes` 和多个慢检查耗尽总预算，确认状态分别为 `failed`、`timeout`、`output_limited`、`skipped_budget`，并确认退出码为 2。
5. **配置变更中止**：让第一项脚本删除或改写第二项（删除条目、改 `command` 或 `purpose`，或写坏/删除 `host.json`），运行 `--all`；确认第二项没有执行、状态为 `skipped_policy_changed`、报告含 `policy_changed`，退出码为 2。恢复配置后重新运行应回到正常结果。
6. **状态不变**：检查前后对照 `status` 和 operations，确认没有新增检查记录；`check` 不写状态库。若宿主调度需要运行证据，在调度日志或 `track` 中保存。
7. **配置回退**：恢复 `host.json` 副本后重新列出，确认检查名单回到预期。
