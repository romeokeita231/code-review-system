# 0005 评测双轨、最大权配对与行级指标

- Status: Accepted
- Date: 2026-11-11
- Source: #8、#16、#11、#7

## Context

AOR 只能审工作区且分钟级；全 live 会引入生成侧方差，污染检测指标。GT 与 finding 的对应关系若靠隐式约定，重叠命中会被重复计数，且配对结果依赖遍历顺序或分数。检测指标与成本指标混算会掩盖两个方向上的问题。

## Decision

- 双轨：replay 用冻结代码 + 钉死的 `repo_rev`，负责 B0–B4 检测与成本；live 只跑验收线。两条轨的样本集不同，必须分开报。
- replay 的原始源输出落盘，可离线重算，不重复支付 AOR。
- 配对改为四级字典序最大权一对一：配对数↑ → 总交集行数↑ → 总并集行数↓ → 规范键序最小；score 不参与。逐连通分量用 `linear_sum_assignment`，矩形补零权哑元，第 4 级用前缀贪心 + 可行性复解。
- 配对作用域 `(run_id, session_id, call_id)`，跨调用不配对；live 不进 fit。配对结果落独立配对表（主键 `(run_id, gt_id)`），不挂在 finding 上；`merged_id` 由 `(path, start, end, cwe)` 散列单端生成，raw finding 带 `raw_id`。
- 行级指标 `TP = |∪F ∩ ∪G|`、`FP = |∪F| − TP`、`FN = |∪G| − TP`，按行取并、不按条目累加，且不依赖配对结果。
- 检测与成本两类指标分开报告，不合成单一分数。
- 主表 k=1 取 cold；方差取 warm 重复之间的离散度；`cache` 由 `cache_read_tokens > 0` 派生，缺字段记 null。
- 失败只对 `failed / partial / timeout` 重试 1 次；半截 JSON 判 unknown 不重试；unknown 覆盖与错误率必须并列报告。
- 成本按 repo 报，并用 30/100/250 三尺寸曲线外推，不实测大仓。

## Consequences

- 所有已发表数值须按新配对口径重算，`configHash` 作废，阈值不回头调。
- 报告必须同时给出 `n` 与 `k`，以及 unknown / 错误率，否则召回不可解释。
- B0 只存在于 live；跨轨混表视为无效结果。
