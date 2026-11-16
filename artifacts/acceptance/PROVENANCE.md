# 证据与哈希（acceptance）

本文件是 `artifacts/acceptance/` 的溯源记录。规则：**报告引用到的任何文件，要么入库，要么在此记其 SHA256。**
本节所有哈希由脚本对文件逐份计算后写入（无手工填写），生成脚本见文件末尾。

## 本次 run 的采集件

`rows.jsonl` 是报告真正读取的那份采集行，已按 `git add -f` 入库；它与 run 目录内的原件逐字节相同（哈希由脚本比对，见下行）。

| 文件 | SHA256 | 字节 |
| --- | --- | --- |
| rows.jsonl（入库副本） | `4e55f3c47d464a12a421de325c22e4d0d3800b140d70742a6cf1a505d21cce80` | 205100 |
| runs/live/.../rows.jsonl（原件，未入库） | `4e55f3c47d464a12a421de325c22e4d0d3800b140d70742a6cf1a505d21cce80` | 205100 |

两行哈希 **相同**；行数 = 171（原始记录，未改动）。

## `run.json`（未入库，按哈希记录）

run 目录 `runs/live/eval-ds-2.0.0-20261114T132232` 不在版本库内。报告只用它记录"时长"与"量具"，其余字段不参与任何读数：

| 文件 | SHA256 | 字节 |
| --- | --- | --- |
| run.json | `89d1c4d0e128fc58298fcaf272ed0acf8acfa2acea3a301fb27f037aad13f7b4` | 24551 |

### run.json 中与"时长"和"量具"相关的字段（run 时长的唯一合法来源）

| 字段 | 值 |
| --- | --- |
| `ocr_identity.before.at` | `2026-11-14T06:34:41.810Z` |
| `ocr_identity.after.at` | `2026-11-14T07:08:43.312Z` |
| 差值（墙钟） | 34 min 1.5 s（2041502 ms） |
| `ocr_identity.drifted` | `false` |
| `ocr_identity.before.sha256` | `7230310d964929787e77b9a0e5a563b7b44271315df61f2570330dbcf08bcaa9` |
| `ocr_identity.after.sha256` | `7230310d964929787e77b9a0e5a563b7b44271315df61f2570330dbcf08bcaa9` |
| `one_shot.at` | `2026-11-14T05:22:51.946Z` |
| `created_at` | `2026-11-14T05:23:05.568Z` |
| `cost.actual` | `{"tokens":1567271,"rows":356,"rows_without_tokens":286,"wall_ms":1187819}` |

`one_shot.at` 与 `created_at` 由 staging 写入，比 run 起点早约 71 分钟，**不能**用它们推算 run 时长（此结论可由代码反证）。

## 本目录（入库）

重述后的报告（`source=live`，同一次 run 的另一种表示，非新测量）：

| 文件 | SHA256 | 字节 |
| --- | --- | --- |
| report.md | `8b1b7e404bf806604bb585cb2719b31565ad4b49cae8ed44c09ce8491d060de9` | 3823 |
| verdict.md | `ec9ccf9963937c161b8ca5956ce86db663d42daf23fc10dea920bba1df01aefe` | 1818 |
| verdict.json | `fde7387b07cfcbbd23d109623c60e2f912492c0838fbfa3beb5258df5dcfba95` | 2091 |

原始 `2/5` 表示的三份原件，逐字节副本（复制前后 SHA256 相同）：

| 文件 | SHA256 | 字节 |
| --- | --- | --- |
| original-2of5/report.md | `f3b254f3dac0a4b003e497a72c54dec80a29e22fae9d5222ccb271efb74b2626` | 2702 |
| original-2of5/verdict.json | `9a4def8ca4b3fadbad6ea469319cba52671cdf8b2263259c8108db0ed0ed1f4f` | 1591 |
| original-2of5/verdict.md | `29a3f606285274a7d3ed387c85648789fd602034b4b3edfa23ba5057f870b127` | 1024 |

## 两条与读数有关的说明

1. 本 run 的行**没有** `aor_invoked` 字段（该字段本提交才落地）。line4 的 0 由 `tier: 0` + `tier_source: "triage"` 推导：`src/l2/orchestrator.ts` 在 tier 0 时把 AOR 移出 runnable 集合，没有任何代码路径能在 tier 0 发起 AOR 调用。报告把它与 raw `na` 并列打印，并逐对记录 `basis`。
2. 设计方裁定原文（`2/5`）保留在 `original-2of5/`，引用规则：原始数字可原样引用，但每句须自带总体与分母，且不得作为质量结论。

## 免检区的密钥形状串：来源登记

`datasets/`、`research/`、`artifacts/acceptance/` 已按 `.github/secret_scanning.yml` 免检。免检的对价是来源登记：凡含密钥形状串的文件，本表必须回答三件事——**谁放进来的**（引入提交）、**字节来自何处**（字节来源）、**凭什么可复核**（可复算锚）。`scripts/secret-gate.ts` 的第二层闸门按本表判定：缺行、行不可解析、或无锚，均失败。

列约定：

- **引入提交**：`self@<sha>`，本仓引入该文件的提交。它回答"谁放进来的"，**不回答**"字节来自何处"。
- **字节来源**：`upstream:<repo>@<sha>:<path>`（上游逐字节或截断摘引）、`url:<url>`（文档/发布页里的原样值）、`synthetic:<生成方式>`（本仓生成的材料）、`derived:<本仓已登记行的路径>`（密钥字节来自本表另一行，如归档副本）。`upstream:` 必须带 `repo@commit:path`，否则判失败；`derived:` 的目标必须是本表已登记的行，闸门沿链解析（深度上限 4 跳、成环失败、目标未登记失败），链的终点须是 `upstream:`/`url:`/`synthetic:` 之一。
- **可复算锚**：`sha256:<64 hex>`（闸门当场重算文件哈希后比对）、`bytes:<n>`（重算大小）、`upstream:<repo>@<sha>[:<path>]`（本机无法离线复核，闸门会明说"未复核"）。**无锚的登记行视为失败**——本表位于免检区内、又是闸门 2 的判据来源，没有可复算锚就是自证。

| 文件 | provider | 来源仓库 | 引入提交 | 字节来源 | 可复算锚 | 说明 |
| --- | --- | --- | --- | --- | --- | --- |
| datasets/aacr/samples/aacr-ts-0003.json | AIza | cline/cline | self@dc354d0761a0f11b56905480a8fa591aee2d78cc | upstream:cline/cline@190d3bd2dc7279aa577c745b005ff778d49a7653:src/services/auth/AuthService.ts | sha256:cf4994d069871f7a20c95297c475ab00bc04b8ca4f9f46b4efa40638624baaf3 | 经 alibaba/aacr-bench `dataset/v1` 分发（`import-report.json` 记 PR #4786、`src/services/auth/AuthService.ts:33`）；`after` 字段与上游该 commit 逐字节相同（11,379 B），3 个键的集合摘要 `be40e418fa1d754e`；本样本文件 26,261 B |
| datasets/self-built/samples/ts-cwe798-0001.json | PRIVATE KEY | juice-shop/juice-shop | self@8a62a25b878aca79944a51842c372beb789c2040 | upstream:juice-shop/juice-shop@266448aba68cd8ba5915f526a128da4fa7bc3f9f:lib/insecurity.ts | sha256:deb89c2d64c8aaad520e6d76c290430f315118c0e677b02f7a9ab858c801adda | `after` 字段与上游整文件逐字节相同（7,906 B，blob `b6039a86c17b02cdf026a6d3353765be9beb801c`）；PEM 段（`BEGIN`→`END`，同一行内转义写法）880 B，段摘要 `252770604bb12a29`。样本自带 `origin.kind=public_repo`、`origin.ref` 即上列 ref。**不是自建夹具**：上一版此格写"synthetic"，未核对就下了结论 |
| research/dataset-candidates/inventory.json | PRIVATE KEY | juice-shop/juice-shop | self@9ebdc46ffc929ccd2332e7e02758021ab9e21836 | upstream:juice-shop/juice-shop@266448aba68cd8ba5915f526a128da4fa7bc3f9f:lib/insecurity.ts | sha256:4416c6517bd3793775aa54d10018f25fd73753d21005510f5bc1c66f1cdb4af8 | `sink` 为 59 字符的截断摘引：上游 `lib/insecurity.ts:21` 的 `const privateKey = '` + PEM 头，之后即以 `...` 截断；checkout pin 见 `inventory.md`（2026-11-08） |
| research/semgrep-bench/_raw_core_py.json | AKIA | romeokeita231/code-review-system | self@01787a316a6dfbe0c95b62ba7ea2094b337a06c9 | url:https://docs.aws.amazon.com/ja_jp/sdkref/latest/guide/aws-sdk-ref.pdf | sha256:49fe37043d9bdac4d2bf48785e7d677cfd0ba372a025a2d39aa3b90ea2f18df6 | 本文件是 `semgrep 1.184.0 --json` 的原样输出（15,425 B），匹配片段来自临时夹具 `fixtures/_run_931071/target.py`（未入库）；`AKIA…EXAMPLE` 是 AWS 文档里的示例值，非真实凭据 |
| artifacts/acceptance/rows.jsonl | PRIVATE KEY | romeokeita231/code-review-system | self@30711d88c59e51616f614f0cc1e63299dab2f32b | derived:datasets/self-built/samples/ts-cwe798-0001.json | sha256:4e55f3c47d464a12a421de325c22e4d0d3800b140d70742a6cf1a505d21cce80 | run 目录 `rows.jsonl` 的逐字节副本，sha256 同上（见上文哈希表，`4e55f3c4…`）；其 `evidence` 字段是目标行第 21 行的前 **200 字符**（起 `const privateKey = '-----BEGIN…`，到 `…exou/F`），不是完整 PEM 段：目标整段 880 B，本文件只带其前 200 字符 |

本表共 5 行，对应 `git ls-files` 里全部 5 组（文件 × provider）命中；组数由闸门自己数，不由本表声明。表内文字自身不得写出完整的 provider 形状串——`AKIA…EXAMPLE` 这种省略写法是必须的，否则本表会被闸门 2 判为"未登记的命中"，自己需要登记自己。

三条边界，读表前先读：

- 锚证明的是「该文件自本表写下这一行以来未变」：`sha256:` 由闸门当场对磁盘字节重算，改字节或改表都会失败。它不追溯历史，也不校验 `upstream:` 指称的仓库确有那个 commit。
- **来源列是主张**，不是机器验证的结果：每行由人工核验过一次（方法与日期见下表），闸门只做格式检查、对 `upstream:` 明说"未复核"、对 `derived:` 做链解析。因此 `5/5 anchor(s) recomputed here` 只读作「5 个文件的字节与表中哈希一致」，不读作「5 条来源均经机器验证」。
- **归档不含完整私钥**：`rows.jsonl` 的 `evidence` 只带目标第 21 行的前 200 字符（目标整段 880 B），所以「归档会把外部字节复制进来」这一面要按 200 字符算，不按整段算；该行的严重性因此低于 `datasets/self-built/samples/ts-cwe798-0001.json` 本身（7,906 B 整文件）。这一半此前讨论时缺着。

### 核验记录（人工，一次）

| 行 | 日期 | 方法 | 结果 |
| --- | --- | --- | --- |
| aacr-ts-0003 | 2026-11-15 | 取 `cline/cline@190d3bd` 的 `src/services/auth/AuthService.ts` 原始字节，与样本 `after` 比较；另比对 3 个键的集合摘要 | 相同（11,379 B），摘要 `be40e418fa1d754e` 两侧一致 |
| ts-cwe798-0001 | 2026-11-15 | 取 `juice-shop@266448a` 的 `lib/insecurity.ts`，与样本 `after` 比较并重算 git blob id | 相同（7,906 B），blob id `b6039a86…` 一致 |
| inventory.json | 2026-11-15 | 读 `sink` 值，与上游同一文件第 21 行比较 | 前 59 字符的截断摘引（`...` 收尾），非整段 |
| _raw_core_py.json | 2026-11-15 | 抓取 `url:` 所指文档页，确认页面含该示例串；本文件字节是 semgrep 输出，与页面无字节关系 | 页面含 `AKIA…EXAMPLE`（示例值，非凭据） |
| rows.jsonl | 2026-11-15 | 本地比较：`evidence` 是否为目标行前缀；文件级 sha256 与 run 原件比较 | 是前 200 字符；文件级哈希与原件相同 |

## 生成方式

`node .tmp/provenance.mjs`（一次性脚本，读取 `run.json`/`rows.jsonl` 与本目录文件后写出本文件；哈希为文件当时内容）。
