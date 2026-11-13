# 0008 降级不可表示为正常值

- Status: Accepted
- Date: 2026-11-13
- Source: #41

## Context

同一个错误犯了五次，每次都是**降级路径产出的数被读成事实**，而且每次都不是笔误：

| # | 降级源 | 落地的「正常值」 | 被读成 | 后果 |
| --- | --- | --- | --- | --- |
| ① | 分母为 0 | `n=0 available=0` | 「样本不够」 | line 1 静默通过 |
| ② | `loadTruth` 读错字段 | 全部 `false` | 「没有真值」 | 召回面整体为空 |
| ③ | CRG 查询超预算 | `files=1` | 「这文件没有 importer」 | tier 由文件数决定，第三源未参与 |
| ④ | B4g 不建索引 | `index_build_ms = 0` | 「建索引不花时间」 | 预算解释被反向使用 |
| ⑤ | 合成 fixture | `median_token_ratio=0.909` | 「阶梯省了 9%」 | 与真实比值形状相同，无法区分 |

④ 是在 ① 的修复里产生的：修「0 当空」的那次改动，顺手给另一个 0 赋予了含义。所以问题不在
某一处取值，而在**类型允许降级与观测共用一个表示**。⑤ 同理，出现在 ①④ 的同一份报告里：
`wiring:check` 的 `1000/1100` 是个占位数，渲染出来却与测量值同形。

## Decision

- 任何**可能由降级路径产生**的观测，必须与干净观测在结构上不可混淆。只允许 `null`、
  `"not_applicable"`、`degraded`（或其结构化等价物）；禁止用 `0`、`""`、`[]`、`false` 冒充。
- 已有落点：`StrataRow.impacted_files/impacted_nodes/ms` 在阶梯之外为 `null`；
  `strata_projection.index_build_ms.<baseline>` 不建索引时为 `"not_applicable"`；
  `wall_clock_estimate.index_build_ms` 在 staging 之前为 `null`（不是 0）；
  `authored_context` 缺失时 line 4 打印 `upstream_tier0=na` + `counterfactual=not_measured`；
  `upstream_*` 无对应文件时为 `null` 且 `upstream_applicable: false`；
  line 4 以 `source=live|synthetic|unknown` 开头，未声明来源的调用方得到 `unknown`。
- 判据是「能否被读成一句关于被测对象的陈述」，**不是一份词表**。四词白名单（`0`/`""`/`[]`/
  `false`）只是这条判据的推论，下一个写法（⑤ 的 `0.909`、`"1.0"`、`false` 的字符串形式）
  会漏；测试按判据写，不按词表写。
- 承载结论的数值缺失时**拒绝**，不写脚注：`tier0Counterfactual` 在 artefact 自相矛盾时抛错，
  `n=0` 的召回面直接抛「wiring error」而不是报 `pass`。
- 消费方必须渲染 `na` / `not_applicable`，类型上就得接受它——否则下一个人会把这个 0 当真。

## Consequences

- 报告里出现 `na` / `not_applicable` 的次数变多，这是**准确**，不是噪声。
- 每加一个「没测到就是 0」的捷径，就欠一次同类事故。判据：如果这个 0 能被读成一句关于
  被测对象的陈述，它就不许出现。
