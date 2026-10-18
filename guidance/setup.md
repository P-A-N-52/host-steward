# 首次接管

## 确定范围与部署位置

确认主机主要用途、观察目录、常驻程序和保护对象，分别约定桌面、共享缓存、模型及其他用户或 agent 工作区的观察与变更范围。首次接管按只读模式建立空间地图，登记用途、归属、依赖、可重建条件和保留理由；重要资源的长期知识按 [inventory](inventory.md) 保存。

将可更新的 skill 和本机状态分开部署。宿主向每轮 agent 提供 skill 目录与同一份 `--state` 路径，命令使用绝对路径：

```sh
/skill目录/steward init --state /绝对路径/本机状态 --root /绝对路径/观察目录 --purpose '主机主要用途'
/skill目录/steward patrol --state /绝对路径/本机状态
```

观察目录用 `--root` 逐个指定，选择不包含 skill 内容的范围；整机资源观测与目录覆盖分别报告。

## 初始化与状态布局

`init` 接受新建或空状态目录，普通 `.lock` 文件可以保留。初始化成功后有以下内容：

```text
host.json                      本机用途、观察范围、授权、保护与预算约定
inventory.json                 长期资源知识与最新调查
guidance/                      本机指导副本
adaptation.json                指导来源版本与裁剪记录
```

首轮 `patrol` 创建 `current.json`，保存当前事实、目录索引、近期变化、采样与待核验事项；实际执行维护时创建 `operations.json`，保存操作计划、结果和恢复证据，预览仅返回计划。两者在对应动作之前缺失属正常情况。已有状态的修复、初始化失败与残留处理见 [recovery](situations/recovery.md)。

接管时验证独立轮次能按上述路径读回规则与知识；新 agent 会话是否自动加载这些入口，由宿主另行验证。查询时区分检索失败、尚未覆盖和没有匹配。

## 配置本机约定

初始常驻清单与目录规则为空，按接管结果在 `host.json` 中填写。roots 和规则路径使用无符号链接的规范绝对路径；常驻条目包含 `executable` 和保护原因 `reason`。

目录规则包含 `path`、`purpose` 和 `kind`（cold / temporary / active / service）。每个规范路径配置一条，嵌套目录采用最具体的规则。`allow_notes`、`allow_quarantine` 缺省为不允许，按接管时确认的动作填写。

允许写说明或回收的目录还需配置 `directory_id`：运行 `/skill目录/steward status --state /本机状态 --path /约定目录`，在 `directory_index` 中找到 path 完全相同的行，取其 `id`（`dev:ino`）。缺少精确行时先补观测。临时内容回收还需 `retention_days` 和 `recycle_bytes`；工具按修改时间判断期限，任务是否结束、依赖是否解除由执行者现场核对。

用途不明的自定义目录先调查，确认用途后登记规则，并按 [files-storage](situations/files-storage.md) 预览目录说明。目录说明保留已有用户原文，只更新 Steward 标记区。

编辑约定前在状态目录外保存副本，编辑后运行 `/skill目录/steward status --state /本机状态` 验证。约定校验失败时按 [recovery](situations/recovery.md) 恢复副本。

## 预算与指导更新

初始预算来自 skill 目录的 `state/host.example.json`，仅 `init` 读取；运行时使用本机 `host.json.limits`。预算分别限制扫描条数、时间与深度，进程采样与命令读取，状态单文件与总容量，工具输出，以及变化、采样和操作记录的条数与保留窗口。状态总容量包含替换时的临时文件。

结合硬件容量、磁盘读写、前台负载和实际巡检开销调整预算；达到限制时工具报告缺口或拒绝写入，先检查采集范围与记录方式。

`init` 将全部通用指导复制到状态区。按本机情况裁剪后，在 `adaptation.json` 记录版本、删减内容和原因。skill 更新时对照差异复核本机指导，保留已确认的本机约定。模板与公共入口 `SKILL.md` 始终从宿主提供的 skill 目录读取，状态区副本中的专项链接用于本机指导之间跳转。
