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

## 勘误二（2026-11-13）：`crgQueryMs = 300` 是 bug，不是预算；第三来源从未上过 live

勘误一记录了「live 轨查图不生效」，但没有把它当成缺陷处理。补做延迟测量后，事实是：

- `code-review-graph impact` 的可观测地板是 ~600 ms（进程启动主导，与图规模几乎无关）。三母体钉定 commit 上 n = 44 次实测：goof p99 662、dvna p99 639、juice-shop（674 文件）p99 652；合并 p99 662 ms，最大 662 ms。
- 300 ms 低于地板 ⇒ **任何调用都无法满足的预算** ⇒ `analyze` 每次都 `timedOut` ⇒ `computeTier` 从未执行 ⇒ `tier_source` 恒为 `static`。
- 因此 `fit` 那次是**两来源**测量，不是三来源；爆炸半径（第三来源）自上線以来没有任何 live 数据。

处置：

- `crgQueryMs = ceil(p99 × 1.5) = 993 ms`。**先定值、后看 tier**：取值时没有计算任何 tier，`tier` 结果不是输入。冻结进 `artifacts/preregistration.json` 的 `frozen.budgets.crg_query_ms`，preflight 的 `crg budget` 闸门比对 config。
- 被测对象不动：`tier0.filesMax = 3`、`tier1.filesMax = 10`、变更单位（单文件事件）、规则集、阈值、`staticTier` 全部不变。
- 预路径预算关系进配置校验（`assertBudgetRelations`）：`semgrepKillMs 5000 + crgQueryMs 993 = 5993 ≤ min(callMs 8000, turnMs 8000)`。此前这两个数各自被填过，彼此的关系从未被断言。
- 修复后 tier 1 由**爆炸半径**给出：同一 214 行单文件写入，无 importer 时 `tier 0 / static`；3 个干净 importer（4 文件闭包）时 `tier 1 / triage`、`files=4 nodes=3`、AOR `status ok`、24,200 tok / 19 s。演练的 10 条正样本行即按此布置（`live/<id>/__importers__/n.ts`），9 条负样本保持单文件。
- 风险已上机制：`prepare` 的「分层投影」对 19 行只跑 `impact` + `computeTier`（零检测器输出），硬断言 A 全 tier 0、B 全 tier ≥1 且 `tier_source = triage`，不满足即拒绝启动；`evaluate` 在实际行上复查同一条规则。

## 勘误三（2026-11-13）：压测用的 importer 是本项目写的；`triage.enabled = false` 等于 tier 2

勘误二把 tier 1 归因于爆炸半径，但没有说清那个半径是谁造的。两件事必须补上，否则数字会被误读。

**一、importer 是自造上下文，须逐行自标。** 十条正样本的 `live/<id>/__importers__/n.ts` 由本项目写入（每行一条 side-effect import）。测量本身正确（图正确报边、`tier0.filesMax = 3` 正确判定），但结论范围受此约束。处置：

- 每个 staged 行在 `run.json` 里带 `authored_context: true`、`authored_importers: 3`。
- `artifacts/staged-context.json`（`npm run drill:context` 重算）用**同一个 `CrgTriage.analyze`** 在钉定 commit 的**完整**仓库上量同一批文件，并把文件字节按 git blob 与 `origin.blob_sha` 对齐，证明答案属于那个 revision。结果：上游 importer 数 3、3、96、3、4、3、4、4、3、3 ⇒ **未造上下文时 0/10 是 tier 0**，`lib/insecurity.ts` 已是 tier 2。
- 因此 importer 不制造半径，只是在二十文件的子集里复现仓库本来就有的事实；但**负样本侧相反**：9 条上游全部 tier ≥1（0/9 为 tier 0），子集丢掉 importer 才使它们落到 tier 0。第 4 行测的是「子集里的 tier 0 路径」，不是「真实仓库里低风险改动的占比」。

**二、B4g 的 tier 是 2，不是 0。** `decideTier` 在 `triage.enabled = false` 时直接返回 `{tier: 2, tierSource: "none"}`（`src/l2/orchestrator.ts:119`），**不查图也不看文件数**。所以 B4g 的 19 行全部进 AOR，B4 只有 10 条正样本进 AOR。B4/B4g 之差测的是**阶梯排除了什么**，不是「图让 AOR 变得可达」。分层投影也随之修正：每个 baseline 按自己的 config 断言（B4g 必须全为 `tier 2 / none`），否则「两个 baseline 用了同一份 config」这一故障仍会静默通过。


