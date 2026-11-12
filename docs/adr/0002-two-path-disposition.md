# 0002 双路径处置与物理机制命名

- Status: Accepted
- Date: 2026-11-11
- Source: #12、#13、#9、#4

## Context

DSH 的 `tools/pre-execute` 只能整调用 deny，且不能附带提示；`tools/post-execute` 可以注入 `additionalContexts`。AOR 是分钟级，塞不进阻塞路径。两个源的分值不在同一量纲，Semgrep 是规则等级、AOR 是过度自信的模型自报概率。

## Decision

- 处置按物理机制命名：机械阻断 / 指令纠偏 / 记录。`warn` 只是 UI 概念，协议与论文不再使用；Finding 的 severity 是分数档位，不等于处置结果。
- pre 路径只跑 Semgrep，`p_semgrep ≥ t_block` → deny，适用任意档位；AOR 的结果不参与写前判定。
- post 路径用融合分，`p_fused ≥ t_warn` → `inject_warn`，否则 `none`。
- `t_block` 定在 `p_semgrep` 上（目标精度 0.90）、`t_warn` 定在 `p_fused` 上（目标精度 0.70），两个分布不同，不共用阈值。
- pre 已 deny 时无落盘，不做 post 复评；tier 0 有落盘时 `p_fused` 取单源校准值，不记 null。
- 超时或降级一律 fail-open，记 `review_status`，且降级来源不得产出机械阻断。
- 同 `(file, rule-id)` 连续 deny 2 次后第 3 次起降级为指令纠偏，记 `block_loop`。
- 模型可见文本只由结构化字段 + 固定模板拼装；AOR 自由文本只落 JSONL。
- post-block 保留定义但 v1 不启用；bash 写文件的阻断归 future work。

## Consequences

- 语义发现永远不进写前拦截，论文须写明这是有意取舍。
- 阻断能力以 Semgrep 可用为前提，Semgrep 可用率必须与阻断率一并报出。
- 处置类指标按 tier 分面；记录级处置计入全部分母。
- 改判率是 replay 反事实量，只能标 `counterfactual` 报告。
