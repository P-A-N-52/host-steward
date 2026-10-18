# 本机档案与只读调查

## 查读与登记

调查对象前先读已有用途、依赖和保留理由，再补充当前证据。宿主提供 skill 目录与本机状态路径：

```sh
/skill目录/steward inventory --state /本机状态 --id 资源编号
/skill目录/steward inventory --state /本机状态 --path /相关目录 --limit 10
/skill目录/steward inspect --state /本机状态 --id 资源编号
```

按 skill 目录中的 `state/resource.example.json` 填写资源定义，再用 `inventory --state /本机状态 --record /资源定义.json` 登记。每份定义最多 8 KiB，档案最多 128 项，容量不足时保留原档案并拒绝写入。

`inventory.json` 按 id 保存当前定义和一份最新调查。相同 id 的新定义替换旧定义，同时清空调查与身份基准；完全相同的定义返回 `unchanged`。登记后的第一次成功调查建立新基准。旧状态缺少此文件时按空档案查询，首次登记时创建。

## 知识字段与来源时间

定义包含稳定 id、类别、位置、用途、归属、依赖、保留理由、维护方法和来源。路径资源使用无符号链接的规范绝对路径，服务位置使用带管理器和范围的名称。

| 字段 | 含义 |
| --- | --- |
| `basis` | 登记者声称的依据类型：observed / reported / user_statement；作者身份仍需执行者核对 |
| `source` | 原始观察、文件或陈述的出处，转述注明原作者 |
| `evidence_at` | 来源实际对应的 Unix 时间 |
| `review_after_hours` | 知识复核期限 |
| `recorded_at` | 工具写入本条定义的时间，与来源时间分开保存 |

查询分别展示复核是否到期、是否需要身份复核、最新调查时间，以及 `host.json` 的相关规则位置。元数据调查更新对象的当前事实；用途、依赖及其来源时间经实际复核后更新定义。

## 身份变化与复核

调查以对象标识、可取得的 birth 和对象类型核对路径资源的稳定身份；服务身份依据启动配置。size、mtime 等可变观测单独以 `metadata_continuity` 报告：baseline_created / same / changed / not_observed / not_comparable。普通原位追加属于元数据变化。

路径身份、类型或服务启动配置更换会触发 `identity_review_required`。提示持续保留到实际复核完成，即使对象暂时不可见、权限不足或之后回到原身份。完成复核后，将新来源或实际证据时间写入定义并重新登记，再调查建立基准；`unchanged` 保留原有复核要求。

旧别名路径的档案按原位置展示，标为 `legacy_noncanonical`；路径查询临时归一双方位置以便匹配。`inspect --id` 对这类资源返回 `migration_required`，保留旧证据。迁移前核对当前目标、引用和旧记录，再显式登记规范位置；重新登记会重建基准。旧恢复证据的处理见 [recovery](situations/recovery.md)。

## 针对性调查

```sh
/skill目录/steward inspect --state /本机状态 --path /明确目标
/skill目录/steward inspect --state /本机状态 --service launchd:user/com.example.job
/skill目录/steward inspect --state /本机状态 --service systemd:user/example.service
```

`inspect --id` 将最新调查保存到已登记条目。直接按 path 或 service 调查只返回输出（`recording.saved=false`），需要保留时先登记资源，再按 id 调查。文件目标限于 `host.json.roots` 内的规范路径；服务调查的管理器、进程、端点与功能验证范围见 [services](situations/services.md)。

引用搜索在 roots 内选定的文本后缀中，按路径或服务名字面匹配，返回文件位置与类型：configuration / source / documentation / self_definition。`AGENTS.md` 仅定位；搜索跳过符号链接、其他卷、排除项和状态目录。大文件、权限、深度、预算和各根覆盖缺口随结果返回，引用内容留在原文件中。

搜索结果用于确定下一步核对范围。无命中表示在已查范围内没有匹配，依赖结论还需结合实际使用者、调用线索与资源用途判断。

## 调查预算

整次调查共用 `host.json.limits` 的时间和条目预算，并有以下固定上限：读取最多 100 个文件，每个最多 min(command_bytes, 256 KiB)；文件读取与子进程输出累计最多 min(file_bytes, 2 MiB)；展示最多 20 个引用，截断数量可见。已登记资源的调查摘要最多 32 KiB，同时受状态单文件与总容量限制。这些是工具硬上限，配置预算可以更小。
