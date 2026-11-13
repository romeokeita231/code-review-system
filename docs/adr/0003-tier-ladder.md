# 0003 梯子 B0/B1/B2/B3/B4g/B4

- Status: Accepted
- Date: 2026-11-11
- Source: #8、#11、#12

## Context

原定义 B3 → B4 同时改变了「仲裁」与「影响范围门控」两个变量，B4 − B3 不能归因给仲裁层。五档必须每档只比上一档多一个变量。

## Decision

- 梯子固定为六档：B0 无审查；B1 仅 Semgrep；B2 仅 AOR；B3 双源拼接（融合阶段全关，取最大置信度）；B4g 双源 + 四步融合、门控关；B4 = B4g + 门控开。
- B3→B4g 是纯仲裁 delta，B4g→B4 是纯门控 delta，两条分开上报，不合成一个数。
- B4g 与 B4 共用同一批 Change Event，唯一差异是 triage 开关，且必须是配置开关而非代码分支。
- B0 只在 live 轨出现（提供 agent token 与延迟基线）；replay 的 B0 留空并注「不适用」，禁止与 replay 各档混表。
- 门控不另立消融组；A5（gate 开 + fusion 关）由离线重放派生。
- tier 0 是单源模式，报告源数恒为 1，其成绩不得解释为融合效果。

## Consequences

- 「B4 − B3 即仲裁层贡献」被替换为两条可归因的 delta。
- 任何按档位汇总的表格必须按 `mode` 分面，否则 B0 会污染结论。
- tier 0 的单源阻断成绩须单列披露。

## 勘误一（2026-11-13）：档位只由改动文件数决定，`risk_level` 不参与

原文与 #26 的叙述把成本分档写成「风险等级驱动」，与实现不一致。`src/l2/triage.ts` 实际读取的输入是：

- `staticTier(changedFiles)`：**只读 `changedFiles`**。`changedFiles <= tier0.filesMax(3)` → 0，`<= tier1.filesMax(10)` → 1，否则 2。行数、CWE、`risk_level` 一律不读。
- `computeTier(...)`：读 `impactedFiles`、`impactedNodes`、`truncated`、`unresolvedCallSites`；`changedFiles` 只在 `indexReady=false` 或 `indexStale=true` 的降级分支里被读。
- 生产路径 `orchestrator.decideTier` 在 `triage` 适配器缺失或抛错时直接 `staticTier`；否则查图。

两处后果：

1. **一次三文件的写入，无论内容多危险，都是 tier 0**。`risk_level: high` 的样本只要单文件写入就落 tier 0，AOR 被摘掉（`orchestrator.ts:409`），semgrep 与 registry 仍跑。
2. **live 路径上查图这一步在实践中不生效**：`budgets.crgQueryMs = 300`，而 `code-review-graph impact` 是 Python CLI，启动就超过该预算。实测（2026-11-13，`ts-cwe079-0001` 单文件 post 事件，真 semgrep/crg/ocr）：`tier_source: "static"`、`skip_reason: "index_not_ready"`。所以 live 轨的档位实际就是文件数。

`risk_level` 的唯一用途是数据集池的划分（低风险负样本池），不是成本门控。任何按 `risk_level` 分档汇总的报告都是错的。

