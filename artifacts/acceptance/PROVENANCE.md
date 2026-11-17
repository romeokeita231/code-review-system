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

1. 本 run 的行**没有** `aor_invoked` 字段（该字段在后续提交落地，未写进本 run 的行）。line4 的 0 由 `tier: 0` + `tier_source: "triage"` 推导：`src/l2/orchestrator.ts` 在 tier 0 时把 AOR 移出 runnable 集合，没有任何代码路径能在 tier 0 发起 AOR 调用。报告把它与 raw `na` 并列打印，并逐对记录 `basis`。
2. 设计方裁定原文（`2/5`）保留在 `original-2of5/`，引用规则：原始数字可原样引用，但每句须自带总体与分母，且不得作为质量结论。

## 同一 run 的两个成绩：原始 2/5 与重算 3/5

`original-2of5/` 与 `artifacts/acceptance/*` 是**同一 run**（`runs/live/eval-ds-2.0.0-20261114T132232`）、**同一份 171 行 `rows.jsonl`**（哈希 `4e55f3c4…`，见上表）在两个版本的评估器下的两次读数：行数据未动，判定代码只动了 `scripts/acceptance.ts`（`335635c`、`4e09756`、`8defdde`、`fdf4cdc`；`30711d8` 只改输出与闸门计数的表示）。重算命令：

```
npx tsx scripts/live-drill.ts --stage evaluate --allow-eval=eval-ds-2.0.0-20261114T132232
```

产物与入库的 `report.md`/`verdict.md`/`verdict.json` 逐字节相同（`git status --porcelain artifacts/acceptance` 为空）。

| line | 原始 2/5 | 重算 3/5 | 状态 | 原因（判定代码/字段） |
| --- | --- | --- | --- | --- |
| 1 | FAIL：`n=50` 行、`hits=0`、`recall_status=gated`、`missed=50` | FAIL：`n=10` 样本（`rows=50`）、`certified=0/10`、`block_face=empty`、`recall_status=unblockable`、`missed=10` | 不变 | 单位由行改样本（`scripts/acceptance.ts:720-723`）、`certifiedSubsets()` 读钉定配置（`:595-615`）：TS 子集 `blockRules: []` ⇒ `semgrep.ts:493` 的 `certified` 全 false ⇒ `orchestrator.ts:390` 丢掉 ⇒ `deny` 不可达；空阻断面按 D13 记 FAIL 而非 `na`（`:700-701`，`fdf4cdc`）。两处都更严 |
| 2 | PASS：`registry_hits=2` | PASS：`registry_hits=2` | 不变 | 同函数同字段（`scripts/acceptance.ts:756-770`），同一批 `sources[].findings[].evidence` |
| 3 | FAIL：`classed=40` 行、`corrected=26`、`repeats=14` | FAIL：`classed=10` 样本、`corrected=0`、`recurred=1`、`unfixed=9`（行级 26/4/10 作辅助） | 不变 | 三态互斥 + 样本级最坏优先（`scripts/acceptance.ts:775-841`）：40 是行、10 是样本；26 是行级、0 是样本级。换单位后闭合数下降，方向更严 |
| 4 | FAIL：`pairs=8`、`median_token_ratio=null`（8/8 对不可判定） | PASS：raw `na`、`median_token_ratio_derived=0.000`、`tokens_derived_pairs=8`、`undetermined=0` | **FAIL→PASS（+1）** | 见下段 |
| 5 | PASS：`warned=53 anchored=53` | PASS：`warned=53 anchored=53` | 不变 | 同函数同字段（`scripts/acceptance.ts:1020-1033`） |

line 4 是唯一变好的格，也是唯一需要论证的格。归档 8 对的 B4 行全部记录 `tier: 0`、`tier_source: "triage"`、`tokens: null`，且 `sources` 里没有 `aor` 条目（8/8）；`src/l2/orchestrator.ts:414` 在 tier 0 把 AOR 移出 runnable 集合，`aorInvoked` 因此为 false——**没有任何代码路径能在 tier 0 发起 AOR 调用**。旧 `tokensOf()`（`scripts/acceptance.ts:432-436`）只读 `tokens` 字段，把「没发起调用」读成「没测到」，8/8 对因此得 `na`；新 `tokenCost()`（`:897-906`）读同一行已记录的 tier 决策得 0，并把 raw `na` 与 derived `0.000` 并列打印、逐对记 `basis`。同一提交还把 `undetermined>0` 定为 `na`（更严），两个方向相反。判据 `median <= 1` 未改。

**阈值、口径、通过域都没有变**，唯一变化是把一行本来就可读的事实（AOR 未发起 ⇒ 成本 0）从「缺失」改为「读到」。此前收尾句「若设计方判定这仍是口径变化，则 line 4 回到 FAIL、总分为 2/5，规格按 2/5 落笔——判定权在规格，证据在此」已由 2026-11-17 的裁定回答；判定权在规格评审这一点未变，裁定与签署见下。

## line 4 的签署（设计方，2026-11-17）

**裁定原文：**

> 判准非「结论变好或变坏」，而是**真相变了，还是读取能力变了**：
>
> - 8 对行记录 `tier: 0`、`tier_source: "triage"`、`sources` 无 `aor`；`orchestrator.ts:414` 于 tier 0 将 AOR 移出可运行集合 ⇒ **真实花费一直为 0，非「未知」**。
> - 旧 `tokensOf()` 仅读 `tokens` 字段，将「未发起调用」读作「未测到」；行内已有三处独立痕迹可区分二者。
> - 通过域 `pairs===8 && undetermined===0 && median<=1` 未改；`undetermined>0 ⇒ na` 系同批提交新增（更严）。**变更仅在「何为已判定」，不在「何为通过」。**
>
> 结论：本条为**读取缺陷**，非口径变化。

**签署方**：设计方。**签署依据**：上述三处代码位置与 8 对行内事实。**签署效力**：3/5 可引用。**作废条件**：下列三项缺一即作废；作废后 line 4 回 FAIL、总分回 2/5，规格按 2/5 落笔。

1. **tier 0 全链路确无 LLM 调用**，含**分档判断本身**。须以代码位置证明，不得以「显然」代替。若 triage 分类器或 CRG 索引构建调用模型，则 0 为低报，性质变为口径变化。
   - 证据：`src/l2/triage.ts:35-39`（`staticTier`）与 `:47-68`（`computeTier`）是纯算术，输入只有文件数/节点数与截断标志，`risk_level` 不在其中；`src/l2/orchestrator.ts:109-173`（`decideTier`）只调用 `CrgTriage.analyze` 或 `staticTier`。
   - 证据：`src/l3/crg.ts:86-117`（`CrgTriage.analyze`）是子进程调用——`config.sources.crg.command`（`code-review-graph`）+ `["impact","--repo",root,"--files",…]`——只读本地图库，无 HTTP。
   - 证据：该工具 `cli.py:618-626` 把 `impact` 交给 `tools.get_impact_radius`（`tools/query.py:204` → `store.get_impact_radius`，SQLite 遍历）；`cli.py:477-497` 与 `tools/build.py:55-73` 规定嵌入刷新必须显式给 `--embedding-provider` + `--embedding-model`；`scripts/live-drill.ts:796`（`buildIndex`）只传 `["build","--repo",root,"-q","--skip-flows"]`，两者都没给 ⇒ 不建嵌入、不调模型；`impact` 子命令没有嵌入参数（`cli.py:1446-1462`）。
   - 证据：本系统内唯一发起模型调用的源是 AOR（`src/l3/aor.ts:166-187` 的 `scan … --max-tokens-budget`）；`src/l2/orchestrator.ts:414` 在 tier 0 把它移出 `runnable`，`aorInvoked` 因此为 false（`:418`）。registry 的 npm/PyPI 请求（`src/l3/registry.ts:201-202`）是网络调用，不调模型、不产 token。
   - 证据边界（版本）：CRG 的代码位置来自本机安装的 `code-review-graph` **2.3.9**（`%APPDATA%\uv\tools\code-review-graph\Lib\site-packages\code_review_graph\`），其 `cli.py` 修改时间 **2026-11-12**，早于本 run 起点 `2026-11-14T05:22:51.946Z`，期间未重装。`run.json` 的 `frozen_instruments` 只钉了 semgrep/ocr/aor_model，**没有 CRG 版本**——这是 spec「CRG 版本待钉」的已知缺口，本条证据对该安装成立。
2. **8/8 派生值逐对等于 0**，不得仅报 `median 0.000`。8 值中位数为第 4、5 位均值，三位小数可容纳 0.0004；本线结论实为「不花钱」而非「花得少」，故须报全 8 对。
   - 8 对全表见下，逐对列出分母（该行 B4g 自报 tokens）与分子（B4 派生 tokens）。
3. **派生须为三事实之合取**（`tier=0` ∧ `tier_source=triage` ∧ `sources` 无 `aor`），并须含**反例测试**：构造 `tier=0` 且 `aor_invoked=true`（或 `sources` 含 `aor`）之行，断言其**不得**派生为 0，只能为 `na` 或 FAIL。`aor_invoked` 落地后，此 legacy 推导**必须退役**。
   - 实现：`scripts/acceptance.ts` 的 `tokenCost()` 读取 `row.sources.some((source) => source.source === "aor")`，三事实全部成立才派生 0。
   - 反例测试：`tests/acceptance/acceptance.test.ts`「refuses to derive 0 for a tier-0 row that contradicts itself」构造两类行——`tier: 0` ∧ `aor_invoked: true`，以及 `tier: 0` ∧ `sources` 含 `aor`——断言整线为 `na`、`tokens_derived_pairs=0`、`undetermined_pairs=8`，不得为 PASS。
   - 退役：代码注释写明「once every row records `aor_invoked`, delete it rather than keep two ways to say one thing」；本 run 的 171 行没有该字段（见上文第 1 条说明），故本文件仍用 legacy 推导。

**8 对派生值全表（line 4 的证据；分子 = B4 派生 tokens，分母 = 该行 B4g 自报 tokens；数值由 `rows.jsonl` 复算，不手工填）**

| 样本 | B4g tokens | B4 派生 tokens | 比值 |
| --- | --- | --- | --- |
| ts-cwe022-9001 | 9438 | 0 | 0.000000 |
| ts-cwe022-9002 | 10980 | 0 | 0.000000 |
| ts-cwe022-9003 | 9763 | 0 | 0.000000 |
| ts-cwe022-9008 | 30275 | 0 | 0.000000 |
| ts-cwe079-9005 | 17974 | 0 | 0.000000 |
| ts-cwe094-9004 | 23485 | 0 | 0.000000 |
| ts-cwe601-0001 | 27182 | 0 | 0.000000 |
| ts-cwe918-9007 | 39037 | 0 | 0.000000 |

8 对全部为 `0.000000`，中位数因此也是 0；「不花钱」的证据是 8/8 的 AOR 调用数为 0（`tier: 0` + `tier_source: "triage"` + `sources` 无 `aor`），不是中位数的小数位。

**算术闭合**（两口径各自闭合，不互相换算）：行级 `26 + 14 = 40`（corrected 26 + repeats 14 = classed 40；另有 unfixed 10 行，三态 26/4/10）；样本级 `recurred 1 + unfixed 9 = 10`（corrected 0）。

## 单位敏感性（为何不是换算法凑结果）

warn 是样本级事件：同一 warn 辖 4 行，改好 3 行、未改 1 行，该 warn 未算处理完毕；行级计数会把「处理一半」记成 3 次正确 + 1 次失败，属把「处理一半」记为「处理过」，故样本级最坏优先是预注册中文的忠实读法，不是新判据。其余四条对单位不敏感：line 1 两单位下 `certified` 均为 0（FAIL 真因是 `blockRules: []`）、line 2 无单位（`registry_hits`）、line 4 两侧均 8 对、line 5 两侧均 53/53——**仅 line 3 敏感，且偏向更严**。

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

`node .tmp/provenance.mjs`（一次性脚本，读取 `run.json`/`rows.jsonl` 与本目录文件后写出本文件；哈希为文件当时内容）。此后新增的「line 4 的签署」「单位敏感性」两节与「8 对派生值全表」为手工写入；表中的 artifact 哈希仍由文件当时内容得出，未改动。
