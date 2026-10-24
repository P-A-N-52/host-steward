# 持续优化想法存档

日期：2026-10-24。原则：先记录想法与证据，再小步尝试；每项都要有测量、行为说明和测试；可回退到 Git 检查点。

## 已做

- 采集批次状态两次事务合并：`dc640b9` → `f2de002`，每批写事务 2→1。
- database 整份二次 JSON 编码：改为按行累计，接近预算时回退精确整份校验；K6 同一 1.45MB `current.json` 写入 38.86ms → 27.27ms。
- 阶段 4 重复目录归一、六种入参兼容、三段过滤、子树判断去重：`dc640b9` 前完成。

## 候选与状态（按证据排序）

1. **database 整份二次 JSON 编码**（`tools/database.py`）
   - 已做：复用行级编码结果，正常写入不再整份 `_json(data)`；接近 `total_limit` 90% 时仍做精确校验。
   - 测量：1.45MB 数据集写入 38.86ms → 27.27ms（K6 ext4）。

2. **resource_query 多段输出裁剪重复编码**（`tools/resource_query.py:549-771`）
   - 样本裁剪已从逐条 pop 改为二分保留条数；`detail/boundary/source/gap` 前置压缩段暂未动。
   - 测量：120 样本、32/64/128KB 预算，`fit_history_output` 685.6ms → 142.1ms（二分裁剪）→ 131.1ms（入口编码往返）→ 66.5ms（跳过无变化/空列表的整份编码）；样本裁剪段 121.9ms → 5.6ms；216 组真实报告 + 4735 组合成用例 + 100 组随机输入输出逐字节一致。
   - 试验：用逐样本 `dumps` 长度 + 占位候选精确计算二分候选大小，120 样本 68.3ms → 66.1ms；逐样本编码成本抵消收益，已回退，不保留复杂度。
   - 状态：已做；剩余主要是必要编码与二分候选编码。

3. **sample_store 按 run 缓存解码**（`tools/sample_store.py:624-625`）
   - 每条样本重复解码同一 run 的 policy/evidence。
   - 预期：大窗口查询减少重复 JSON decode。
   - 风险：低；缓存生命周期限于一次查询。
   - 状态：已试并回退。K6 15 条样本、输出预算只保留 1 条时查询 2.92ms → 2.84ms，落在噪声范围；收益不足，不留缓存复杂度。

4. **steward 事件状态判定重复**（`tools/steward.py:238-316`）
   - 已做：抽出 `_event_reason` 供 `event_gap` 与 `degrade_event_clues` 共用；保留 `unavailable → history_invalid` 与降级路径中 `unavailable → baseline` 的原有优先级，`event_rebuild_gap` 不动。
   - 验证：128 种状态组合（来源、可用性、历史失效、游标待定、历史完整、基线、旧游标）新旧判定逐项一致；本地 480 项与 K6 480 项回归无新增失败；临时状态实机巡检两次，缺口与降级队列均为空。
   - 状态：已做。

5. **测试专用生产分支**（`files.scan`、`policy.root_rule`、metadata 探测）
   - 生产不走的代码保留在 tools，增加维护面。
   - 预期：减少产品代码；可能削弱独立对照测试。
   - 状态：暂缓，先确认测试价值。

6. **steward 扫描返回值兼容分支**（`tools/steward.py:471-477`）
   - `scan` 只转发 `resumable_scan`，后者所有返回路径都是 `(快照, 进度)`；patrol 里的 `isinstance(scanned, tuple)` 回退只服务返回 dict 的测试替身，并顺带沿用上一轮进度。
   - 预期：删 4 行生产分支与注释，3 处测试替身改为返回 `({}, {})`；正式 CLI 行为不变。
   - 状态：待试。

7. **输出别名重复**（`last_append`、`run/latest_run`、计数三份）
   - 只影响 JSON 长度，收益低。
   - 状态：不做。

## 约束

- 任何优化不改变正式 CLI 的可观察行为，除非单独说明并更新测试。
- 先测再改；改完跑 480 项测试与 K6 回归；提交前 `git diff --check`。
