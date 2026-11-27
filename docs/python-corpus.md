# Python 语料调研：issue #44 的只读笔记（2026-11-19）

这是 issue #44 的调研笔记，日期 2026-11-19；全程只读，未运行 semgrep / ocr / drill，未改代码、配置或数据集。

**标注约定**：`[已核实]` = 本次读过源码/清单/只读 GitHub API；`[源码推断，未实跑]` = 静态代码推断，未执行验证；`[待人工决定]` = 需要人拍板的判断或授权。

一手来源：

| 来源 | 用途 |
| --- | --- |
| issue #44 <https://github.com/romeokeita231/code-review-system/issues/44> | 本票前置条件与 5 条 AC |
| #44 补充事实 <https://github.com/romeokeita231/code-review-system/issues/44#issuecomment-6948970201> | 29 TS + 6 JS、并集 8 / 交集 4 |
| #44 Ready-for-human Brief <https://github.com/romeokeita231/code-review-system/issues/44#issuecomment-6956121054> | AC、why human、out of scope |
| issue #26 <https://github.com/romeokeita231/code-review-system/issues/26> | D13 line 1 判据 |
| issue #41 <https://github.com/romeokeita231/code-review-system/issues/41> | T15 已闭合结论 |
| issue #45 <https://github.com/romeokeita231/code-review-system/issues/45> | TS 规则族，out of scope |

---

## A. D13 line 1 的判据

### A1. 文本判据与代码判据有一处实质差异

| 项目 | 文本 / 代码 | 出处 |
| --- | --- | --- |
| D13 定义的 population | eval 注入正样本中 `expected_detectable_by ∋ semgrep` 的子集（非 ground truth） | issue #26 D13，<https://github.com/romeokeita231/code-review-system/issues/26> |
| 实际选择器 | 不看 `expected_detectable_by`：`split=eval`、有 defects、规则表对样本 CWE 有声明覆盖、语言可扫描 | `docs/live-drill.md:401-412`；`scripts/acceptance.ts:519-548` |
| 显式注释 | `expected_detectable_by` 是 non-truth hint，不得进入分母 | `scripts/acceptance.ts:534-536`；`docs/live-drill.md:401-403` |

结论 `[已核实]`：issue #44 的 `expected_detectable_by ∋ semgrep` 不是代码门槛。代码门槛是「规则表声明覆盖 + 语言可扫描」。两者在当前语料上恰好都成立，所以差别被掩盖；换 python 语料后仍不会被 `edb` 过滤。

### A2. recall 分母、precision 分母、n/k

| 面 | 单位 / 分母 | 门槛 | 不足时 | 出处 |
| --- | --- | --- | --- | --- |
| recall | 样本：covered、scannable 的 eval 正样本 `n`；`k` = 其中 `preDecision=deny` 的样本数 | `n ≥ 20` 且 `k/n ≥ 0.70` | `insufficient_n`，仍报 k/n + Wilson | `docs/live-drill.md:429-437`；`scripts/acceptance.ts:579-587`、`698-706` |
| precision | finding：eval 行上的 `findings_merged` 条目；负样本上的 finding 计 FP | finding 数 `≥ 20` 且 `tp/n ≥ 0.90` | `no_negatives` / `insufficient_n` | `scripts/acceptance.ts:673-693`、`686-693` |
| block facet | 样本 `n` 与 `k`，并要求 `certified` 规则存在 | block face 为空则本线 fail，结论句固定 | `unblockable` | `scripts/acceptance.ts:588-638`；`src/l3/semgrep.ts:493` |
| `n < 15` | 结论句须带「不具统计意义」 | 仅文本限定 | — | `scripts/acceptance.ts:630-637`；issue #26 D13 |

`[已核实]` 当前 ds-2 的 recall 分母：14 个 eval 正样本中 11 个 TS 可 gate，per-class cap 实际 stage 10，所以 `n=10`、`available=11`（`docs/live-drill.md:434-436`；`docs/datasets.md:182-184`）。D13 文本说「eval 侧 42 个负样本」，与当前 ds-2 的 9 个 eval 负样本不一致，42 是旧 ds-1 口径（`docs/datasets.md:121-126`；`datasets/self-built/manifest.json` 的 `declared.negatives = 9`）。

### A3. `insufficient_n` / `out_of_scope` 如何记账

- `out_of_scope` 只对**已 stage 的行**生效：行的 `review_skip_reason` 或 semgrep source 的 `errorKind` 为 `language_unsupported`（`scripts/acceptance.ts:527-532`）。
- 当前 planner 在装载时直接按语言过滤（`scripts/live-drill.ts:302-336`），所以未被选中的语言根本不会成为 row；`docs/live-drill.md:16` 所说的「6 条 JS out_of_scope」在当前代码路径上不会以 `out_of_scope` 出现，而是根本不 stage。`[已核实]`（静态）；这处文档与实现有口径差。
- `availableN === 0` 不是 `insufficient_n`，而是 wiring error，直接 throw（`scripts/acceptance.ts:651-664`）。

---

## B. 当前语料精确清点

### B1. `datasets/self-built`（ds-2.0.0）

| 维度 | 数量 | 出处 |
| --- | --- | --- |
| 总行数 | 35 | `datasets/self-built/manifest.json` `declared.samples` |
| 语言 | TS 29 / JS 6 | manifest 逐行统计；`docs/datasets.md:9` |
| 正/负 | 正 26 / 负 9 | manifest 逐行统计 |
| split | fit 12 / eval 23 | manifest 逐行统计 |
| eval 正样本 | 14（TS 11 + JS 3） | manifest；`docs/datasets.md:182-184` |
| eval 负样本 | 9（全 TS） | manifest；`docs/datasets.md:121-126` |
| fit 负样本 | 0 | manifest |
| 类别 | CWE-022:5、078:2、079:7、089:3、094:4、798:4、918:1 | manifest `declared.per_class` |
| 类不足 | CWE-078=2、CWE-918=1，`insufficient_n`，各有 supply 记录 | manifest `declared.per_class_status` / `supply_exhausted` |

Python 行数：0。AACR 行数：0。

### B2. `datasets/aacr`

| 维度 | 数量 | 出处 |
| --- | --- | --- |
| 总行数 | 22 | `datasets/aacr/manifest.json` |
| 语言 | 22 全 `ts` | 逐 sample 文件统计 |
| 正/负 | 7 正 / 15 负 | manifest `label` |
| split | 全部 eval（导入集只做 eval） | manifest `split` |
| `sample_cwe` | 22 条全 `null` | 逐 sample 文件统计 |
| `expected_detectable_by` | 22 条全 `null` | 逐 sample 文件统计 |

`[已核实]` AACR 对 line 1 的分母贡献为 0：`sample_cwe=null`，`coveredSample()` 返回 false（`scripts/acceptance.ts:537-541`）。另外 AACR manifest 只有 `dataset_version`，没有 `version`；行级也没有 `language` / `expected_detectable_by` / `paired_safe` / `cwe`（`cwe` 全 null），因此不能通过 `DatasetManifest.parse`（`src/contracts/index.ts:426-451`；`scripts/live-drill.ts:307`）；它不是 drill 可装载的集合。

### B3. `expected_detectable_by` 的两种表示

| 表示 | 实际值 | 出处 |
| --- | --- | --- |
| sample 文件字段 | 正样本字符串 `"semgrep_only"`；负样本 `null` | `scripts/build-ds2.ts:325`；`scripts/verify-dataset.ts:135` |
| manifest 投影字段 | 正样本数组 `["semgrep"]`；负样本 `[]` | `scripts/build-ds2.ts:353` |
| 谁消费它 | 选择器不消费；只在 schema/投影/报告出现 | `scripts/acceptance.ts:534-536`；`docs/live-drill.md:401-403` |

issue #44 的 `∋ semgrep` 对应 **manifest 的数组表示**，不是 sample 的字符串枚举；但两者都不是 line 1 的实际分母条件。

### B4. 语言面实际状态

| 语言 | semgrep subset | sMax | 结果 | 出处 |
| --- | --- | --- | --- | --- |
| python | `py-block`、`py-nontaint` | 743188 | 配置就绪，无数据 | `configs/b4.json:12-52`、`132-135` |
| typescript | `ts-dedup` | 102400 | 有数据，blockRules 空 | `configs/b4.json:28-35`、`134` |
| javascript | 无 | 无 | `language_unsupported` 先例 | `configs/b4.json:132-135`；`docs/live-drill.md:16` |

---

## C. Python 行进入 line 1 的硬条件

### C1. 当前会直接拒绝 python 的位置

| # | 约束 | 现状 | 出处 |
| --- | --- | --- | --- |
| 1 | `language` 枚举 | 只允许 `ts/js/tsx/jsx`，`python` 直接 schema fail | `scripts/verify-dataset.ts:125` |
| 2 | `sample_id` 形状 | 只允许 `^(ts\|js\|tsx\|jsx)-cwe\d{3}-\d{4}$`（AACR 另有前缀） | `scripts/verify-dataset.ts:95-98` |
| 3 | manifest 版本前缀 | 必须是 `ds-2...`，不能直接开 `ds-3` | `scripts/verify-dataset.ts:565-567` |
| 4 | builder 版本 | 硬编码 `"ds-2.0.0"` | `scripts/build-ds2.ts:369-370` |
| 5 | 版本不变 | 根哈希变化则 build 拒绝 | `scripts/build-ds2.ts:429-441` |
| 6 | 负样本 split | 负样本必须在 eval | `scripts/verify-dataset.ts:607-609` |
| 7 | 负样本同文件 | 一个文件不能同时放正样本和负样本 | `scripts/verify-dataset.ts:618-633` |
| 8 | 低风险池 | 至少 8 条 defect-free low-risk | `scripts/verify-dataset.ts:36`、`734-743` |
| 9 | create 样本 | 至少 1 条 `create` 负样本 | `scripts/verify-dataset.ts:727-732` |
| 10 | 正样本 `expected_detectable_by` | 必须非 null（builder 自动填 `semgrep_only`） | `scripts/verify-dataset.ts:496-501`；`scripts/build-ds2.ts:325` |
| 11 | provenance | `origin.kind=public_repo`、`ref=<repo>@<commit>:<basePath>`、40 hex `blob_sha` | `scripts/verify-dataset.ts:447-460`；`scripts/build-ds2.ts:329-335` |
| 12 | 正样本真实性 | `defect_origin="real"`，`after` 必须是 pinned blob 的原始字节 | `scripts/verify-dataset.ts:462-474`；`docs/datasets.md:100-106` |
| 13 | defect 窗口 | defect 必须在 changed window 内、span ≤ 3 行、CWE 与 `sample_cwe` 一致 | `scripts/verify-dataset.ts:505-545` |

`[已核实]` 第 1、2 条是 python 的真正 schema 门槛；第 3–5 条决定版本必须走 `ds-2.1.0` 这类递增，而不是 `ds-3`。

### C2. split 不是手工指定，增加 python 会重排现有 TS 行

- 分组键是 `repo\0path`，组按 `sha256(group_key)` 排序，`eval` 目标 0.6，greedy 填充；任何含负样本的组被强制 eval（`scripts/build-ds2.ts:152-174`、`245-250`）。
- 因此新增 python 组会改变 budget 与排序，**已有 TS 行的 fit/eval 归属会变化**；新数据集不是「在原集合上追加」。
- eval 正样本占比必须落在 `[0.5, 0.7]`，每类 ≥3 且两类都有（`scripts/verify-dataset.ts:26-28`、`635-651`）。

### C3. 一条 python 样本的最小可行形状

以「正样本、edit、eval」为例，字段必须同时满足 sample schema 与 manifest 投影：

| 字段 | 值 / 约束 |
| --- | --- |
| `sample_id` | `py-cwe089-0001`（需先扩 `specSampleId`） |
| `schema_version` | `2` |
| `unit` | `file_write` |
| `language` | `python`（不是 `py`；planner 用字符串精确匹配） |
| `sample_set` | `self` |
| `group_id` | `<repo>:<path>` |
| `repo` / `file_path` | 真实上游仓库与文件 |
| `before` | pinned blob + 一条 re-added control（用于构造最小 change event） |
| `after` | pinned blob 的原样字节 |
| `changed_lines` | 由 diff 派生，不手填 |
| `event_kind` | 由 `before === ""` 派生 |
| `label` | `1` |
| `defects[0]` | `cwe=CWE-089`、`line_start/line_end` 在 changed window 内、span ≤3 |
| `sample_cwe` | `CWE-089` |
| `variant_of` / `rationale` | `variant_of=null`；`rationale` 仍必填，且必须命名控制（正样本的 `before` 是我们写的，所以也要 rationale） |
| `expected_detectable_by` | `"semgrep_only"` |
| `risk_level` | CWE-078/022/089 一律 `high`（`specRiskLevel` 只让 079/798 + ≤30 行为 low） |
| `contamination_risk` | `high`（教学靶场，`origin.kind=public_repo` 且 pedagogical） |
| `defect_origin` | `"real"` |
| `origin` | `{kind:"public_repo", ref:"<repo>@<sha>:<path>", advisory:null, blob_sha:"<40hex>", base_path:null}` |
| `annotator` | `self` |
| `split` | `eval` 或 `fit`（由上面的分组算法决定，不可手填） |

`[已核实]` 字段集合来自 `scripts/build-ds2.ts:307-338` 与 `scripts/verify-dataset.ts:122-136`；`risk_level` 派生规则见 `scripts/verify-dataset.ts:81-92`；`rationale` 必填且须命名控制，见 `scripts/verify-dataset.ts:487-494`。

**最低可行性结论**：样本能进 schema ≠ 能进 line 1 的分子。它还必须命中一条 **certified** 且 **实际被 semgrep 产出的** 规则（见 D），并且该语言默认会被 drill 选中（见 E3、E4）。

---

## D. Python 规则覆盖矩阵

### D1. 配置里列出的 6 条与快照实际内容

| 类别 | python 规则数 | `py-block.blockRules` | 快照中是否存在 | 小文件（≤100 KiB）能否 block | 出处 |
| --- | ---: | --- | --- | --- | --- |
| CWE-022 路径穿越 | 5 | `path-traversal-open` | 基名不存在；只有 `.django` / `.flask` | **否**（基名永不产出） | `configs/b4.json:18-25`；`research/semgrep-bench/snapshot/py_block.yaml` |
| CWE-078 命令注入 | 33 | `command-injection-os-system`、`dangerous-subprocess-use`、`subprocess-shell-true` | `dangerous-subprocess-use` 基名不存在（只有 `.lang` / `.aws-lambda` 等）；另两条存在 | **是**（2 条可达） | 同上 |
| CWE-079 XSS | 23 | 无 | — | **否** | `configs/b4.json:18-25` |
| CWE-089 SQL 注入 | 23 | `formatted-sql-query`、`sql-injection-db-cursor-execute` | 两条都存在 | **是** | 同上 |
| CWE-094 代码执行 | 0 | 无 | — | **否**（无 python 规则） | `rules_table.json` 自算 |
| CWE-798 硬编码密钥 | 2 | 无 | — | **否** | 同上 |
| CWE-918 SSRF | 5 | 无 | — | **否** | 同上 |

`[已核实]` 并集与交集：配置列出的规则 id 并集 8、交集 4（issue #44 的数字正确）；但 **8 条里有 2 条基名在快照中不存在**（`dangerous-subprocess-use`、`path-traversal-open`），所以「可被产出的认证 id」并集是 6：
`command-injection-os-system`、`subprocess-shell-true`、`formatted-sql-query`、`sql-injection-db-cursor-execute`、`path-traversal-open.django`、`path-traversal-open.flask`。

### D2. 文件大小决定加载哪一个 subset，规则面随之变化

- ≤ `fullBlockMaxBytes`（102400）的样本走 **py-block**；更大的走 **py-nontaint**（`src/l3/semgrep.ts:218-237`、`328-330`；`configs/b4.json:54-58`）。
- `blockRules` 只从**本次加载的 subset** 取并集（`src/l3/semgrep.ts:371`）。
- 因此普通小样本的认证集合是 py-block 的 6 条基线，其中 4 条可达、`path-traversal-open` 不可达 → **CWE-022 在小文件上无法 block**；只有 >100 KiB 的样本才加载 py-nontaint，才拥有 `.django` / `.flask`。
- `py-block` / `py-nontaint` 中都存在 `.django` / `.flask` 两个规则 id（本次逐条 grep 核实），把这两个 id 加进 `py-block.blockRules` 在机械上可行，但属于 certification / blockRules 变更决策，不是加语料能解决的。

### D3. `block` 只发生在 pre-execute

- `certified` 仅当 `check_id ∈ blockRules`（`src/l3/semgrep.ts:493`）。
- 未认证的 finding 被过滤，不进入 deny（`src/l2/orchestrator.ts:389-396`）。
- `deny` 只在 pre 阶段产生；post 阶段的 sources 明确排除 semgrep（`src/l2/orchestrator.ts:398-413`）。
- 同一 (file, rule) 重复触发时 `deny=false, blockLoop=true`（`src/l2/orchestrator.ts:36-43`）。

### D4. 与 cap 的联合算术（最关键）

- 每类最多 stage 4 条：`POSITIVE_CAP_PER_CLASS = 4`（`scripts/live-drill.ts:75-76`）；总上限 20（`scripts/live-drill.ts:139`）。
- `n ≥ 20` 且 recall ≥0.70 ⇒ 至少 14 条必须被 certified 规则 deny。
- 诚实语料下，可 block 的类最多 3 个（022 仅大文件、078、089）；即使 022 修复，3 类 × 4 = **12 条上限**。
- 因此 `12/20 = 0.60 < 0.70`；把 n 拉到 24 也只有 `12/24 = 0.50`。
- 结论：**在当前 cap=4 且只有 3 个可 block 类的前提下，issue #44 的 n≥20 与 recall≥0.70 不可能同时成立**。要通过，必须至少满足其一：
  1. 把 cap 提到 ≥5（3 类 ×5 =15，15/20=0.75）；这是采样方法变更，必须新预注册；
  2. 认证第 4 个 python 类（4 类 ×4 =16，16/20=0.80）；这是规则族/认证决策，超出「加语料」；
  3. 接受 line 1 仍为 FAIL，仅以新分母记录一次测量。

`[已核实]`（纯静态算术，基于 `scripts/live-drill.ts:76`、`scripts/acceptance.ts:582-586`、`configs/b4.json:18-25`）。

---

## E. 语料变更后必须重做的流水线产物

### E1. 依赖顺序（硬顺序）

| 步 | 产物 / 动作 | 为什么不能跳过 | 出处 |
| ---: | --- | --- | --- |
| 0 | 人工选定 python 源、样本、GT、授权 | agent 不能代替真实仓库与 GT 认领 | issue #44 Brief「Why human」 |
| 1 | 增加 `language` / `sample_id` schema，改 `py-block.blockRules`（若决定） | 否则 build/verify 直接拒绝 | `scripts/verify-dataset.ts:95-98`、`125`；`configs/b4.json:18-25` |
| 2 | 行源 + pinned clone + provenance（`blob_sha`） | builder 从真实 blob 取字节 | `scripts/build-ds2.ts:245-276` |
| 3 | 更新 `scripts/build-ds2.ts` 的版本为 `ds-2.1.0`，`npm run dataset:build` | 版本不变会撞根哈希守卫 | `scripts/build-ds2.ts:369-370`、`429-441` |
| 4 | `npm run dataset:verify` | 校验 split、class、负样本、provenance、low-risk 池 | `scripts/verify-dataset.ts:563-573`、`734-743` |
| 5 | `npm run record:fit`（若新 python fit 行要参与校准） | 新 fit 行没有 recorded fixtures，calibrate 只能跳过它们 | `scripts/calibrate.ts:72-92`；`scripts/record-dataset.ts:132` |
| 6 | `npm run calibrate` | `dataset_version` 变了，旧 artifact 硬失败 | `src/config/index.ts:122-154`；`docs/datasets.md:43-50` |
| 7 | 新预注册（`artifacts/preregistration.json` 或新版本文件） | 新分母、新预测、新预算必须在盲跑前冻结 | `artifacts/preregistration.json:1-5`；issue #44 Brief |
| 8 | `npm run drill:context` 重生成 `artifacts/staged-context.json` | 该文件按 `dataset_version` 拒绝错配，且每个 stage 行都必须有 upstream 行 | `scripts/live-drill.ts:1153-1166`、`1178-1198` |
| 9 | `--stage check` | 校验 calibration、pins、instrument | `docs/live-drill.md:538`；`scripts/live-drill.ts:1624-1644` |
| 10 | `--stage prepare --allow-eval=eval-ds-2.1.0-<stamp>` | run 目录名就是一次性 token | `docs/live-drill.md:527-555` |
| 11 | `run` → `collect` → `evaluate` | 盲跑后才有新分母结果 | `docs/live-drill.md:532-545` |

### E2. 具体会硬失败/必须重生成的断言

- `content_sha256_root` 由所有行的 `sample_id:content` 排序哈希；任何 python 行都会改根（`scripts/build-ds2.ts:340-372`）。
- `assertVersionTracksPopulation`：version 不变而根变化直接 throw（`scripts/build-ds2.ts:429-441`）。
- `assertCalibrationMatches`：`dataset_version`、`ruleset_fingerprint`、`categories` 任一不符即 throw（`src/config/index.ts:122-154`）。
- `staged-context.json` 的 `dataset_version` 不符即 throw；缺任一行也 throw（`scripts/live-drill.ts:1159-1166`、`1193-1198`）。
- `prepare` 对同一 `dataset_version` 拒绝第二次运行，除非 `--archive-and-restart`（`docs/live-drill.md:547-549`）。
- `evaluate` 拒绝跨 dataset 的 run 目录与 `run.json`（`docs/live-drill.md:551-562`）。

### E3. 三个隐藏的「python 不会自动生效」点

1. **check 阶段硬编码 self-built + typescript**：`manifest` 读 `datasets/self-built/manifest.json`，categories 用 `declaredCoverage(..., "typescript")`（`scripts/live-drill.ts:1631-1644`）。若把 python 放进别的目录，check 仍看旧集合；若放进同一 manifest，python 专属类也不会进入 categories（当前 python 类都是 TS 已声明的 7 类，所以暂时不炸）。
2. **evaluate 的 `pinnedTsRuleset` 也是 TS 专属**（`scripts/live-drill.ts:2603`），只用于打印/校验；不影响 python 扫描，但名字与报告会误导。
3. **`drill:context` 把数据集路径写死**：`package.json:47` 固定 `--dataset datasets/self-built`，所以把 python 放到独立目录时，必须同步改这个 npm script，否则 staged-context 永远只看旧集合。

### E4. 新增 python 行会重排现有 split

见 C2。`ds-2.0.0` 的 14 个 eval 正样本不是固定名单；新组加入后，greedy 分配可能把原有 TS 组移到 fit。任何「新集合上重算 line 1」的对照都必须承认 TS 分母也变了，不能把两个版本的 TS 数字直接比较。

---

## F. Python 供给候选

### F1. 仓库内已有调研没有评估过 python

`research/dataset-candidates/inventory.md` 只清点了 TS/JS 三个父仓库（goof、dvna、juice-shop）以及 nodegoat；没有 python 候选（`research/dataset-candidates/inventory.md:3`、`38`、`67-70`）。`[已核实]`

### F2. 只读 API 核实的候选（未 clone、未下载样本）

| 候选 | 默认分支 / HEAD | License | `.py` 总数 / 非 migration+test | 路径级证据（树，非内容） | 适配判断 |
| --- | --- | --- | --- | --- | --- |
| `adeyosemanputra/pygoat` | `master@2aa4cc14f251e4a780e94e200aed6b36a5b15c21` | MIT | 116 / 73 | `dockerized_labs/command_injection_lab/app.py`、`sql_injection_lab/app.py`、`ssrf_lab/app.py`、`package_injection_lab/app.py` | 078/089/918 路径存在；022 未见明确 lab |
| `erev0s/VAmPI` | `master@f16052dce83f05847133ec98f01c5193a41de7d8` | MIT | 11 / 11 | `api_views/books.py`、`api_views/users.py`、`models/books_model.py` | 文件太少，难以提供 20 条独立正样本 |
| `NetSPI/django.nV` | `master@a48901f106da4888417339b7b44b8ed56b64c63f` | **GPL-2.0** | 50 / 10 | `taskManager/views.py`、`taskManager/models.py` 等（大量 migration 占 40 个文件） | 授权需决策；有效文件少；**已 archived** |
| `Contrast-Security-OSS/vulnpy` | `master@b81885e58283a3449b578d20c20557aff637e5ea` | MIT | 95 / 56 | `src/vulnpy/{django,flask,bottle,aiohttp}/vulnerable*.py`、`common/templating.py` | 按框架组织、专为漏洞演示；**已 archived**，可供给 20 条但需确认是否接受归档源 |

`[源码推断，未实跑]` 上表只能证明「仓库有这些 python 文件」，不能证明每个文件真的含 certified sink；sink 存在性必须由人工 `git grep` + 阅读数据流确认（`docs/datasets.md:199-203` 的既有方法）。本次未 clone、未下载样本、未运行 semgrep。

### F3. 供给量判断

- 要满足 `n ≥ 20` 且 cap 4 分 5 个类，需要至少 5 个有声明覆盖的类；python 有 6 个类（022/078/079/089/798/918）。
- 但 certified 可 block 的只有 022/078/089；079/798/918 只能充数，且会成为 recall 分母里的 miss（见 D4）。
- 因此 python 语料必须优先保证 078/089/022 各有 ≥4 条**命中认证规则原语**的真实样本：`os.system` / `subprocess(..., shell=True)`、DB cursor execute / formatted SQL、Django/Flask 的 `open()` 路径穿越。
- `django.nV` 的 GPL-2.0 与 archived、`vulnpy` 的 archived 状态是授权/来源决策点。

---

## G. 人工闸门

| 闸门 | 为什么 agent 不能替代 | 需要人给出的东西 |
| --- | --- | --- |
| 真实仓库与样本选取 | 需要判断数据流、可达性、sink 真实性，不能用元数据代替 GT | 选定的 repo/commit/path、每条的 defect 行号与 CWE |
| GT 认领 | D13 的 recall 分子按人工 label 计算 | 谁标注、双人一致性（κ 门槛）、争议裁决 |
| 语料授权 | GPL-2.0 / archived 源 / 教学靶场的再分发与引用 | 允许的 repo 清单、License 处理方式 |
| 盲跑预算 | 新盲跑消耗新的 live 预算与 `DEEPSEEK_API_KEY` | 预算上限、批准人、run 名 |
| 数据集范围与版本 | 混入现有 ds-2 会重排 TS split，并改变默认语言 | 选 `ds-2.1.0` 混合集还是独立目录 |
| 规则认证 | 新增 blockRules / 第 4 个类需要 fp_bait 与 spec 决策 | 是否认证、认证哪条规则、谁签字 |

---

## H. Python 侧特有风险

1. **认证规则是 python 专用 sink，且两条配置 id 永不产出**：`dangerous-subprocess-use`、`path-traversal-open` 不在两份快照中；小文件只加载 py-block，所以 CWE-022 在小样本上根本不能 block（`configs/b4.json:18-25`；`src/l3/semgrep.ts:328-330`、`371`、`493`）。`[已核实]`
2. **语料必须按规则原语构造，不是按 CWE 构造**：`subprocess.run(cmd)` 若不带 `shell=True` 不命中 `subprocess-shell-true`；普通 `open(user_input)` 不命中基名 `path-traversal-open`。按 CWE 选样本会得到大量「类覆盖但规则不命中」的 miss。`[源码推断，未实跑]`
3. **cap=4 与 3 个可 block 类的算术冲突**：见 D4；这是 issue #44 最硬的结构性障碍，不是供给量问题。
4. **一个 drill 只跑一种语言，且切换语言没有 CLI 开关**：`planDrill` 支持 `options.language`，但 `main` 没有传（`scripts/live-drill.ts:111-118`、`2602`）；默认语言取 eval 正样本最多的语言（`scripts/live-drill.ts:325-335`）。加入 20 条 python eval 正样本后会超过 11 条 TS eval 正样本，**默认语言自动翻成 python**，现有 TS line 1 无法按原样重跑。`[已核实]`
5. **Python run 需要 python 负样本**：precision 的 `negatives` 只从已 stage 的行里取（`scripts/acceptance.ts:549-552`、`686-693`）；line 4 的 8 对低风险也只看已 stage 的行（`scripts/acceptance.ts:889-897`）。只有 python 正样本时，precision 为 `no_negatives`、line 4 直接 fail。issue #44 的 AC 只写了正样本，这是缺口。`[已核实]`
6. **投影要求 tier ≥1，importer 仍是 `.ts`**：`assertStrata` 对 positive 断言 `tier >= 1 && tier_source=triage`（`scripts/live-drill.ts:1096-1101`），而 authored importer 文件名硬编码 `.ts`（`scripts/live-drill.ts:918-927`）。python 文件会被写成 `__importers__/n.ts`，既不是合法 python import，也可能不建立 CRG 边。需要 python importer 生成器；CRG 对 `.py` 的支持未核实。`[源码推断，未实跑]`
7. **AOR / OCR 对 python 的支持未核实**：`src/l3/aor.ts` 没有扩展名过滤，但上游 `ocr` 的语言支持、python 的 prompt/tool 行为未验证。line 1 只依赖 semgrep，所以不阻塞 line 1；但同一次 drill 的 line 3/5 会受影响。`[源码推断，未实跑]`
8. **precision 统计所有 merged findings，不只 blockRules**：python 两个 subset 共 139 条规则（py-block 85 + py-nontaint 54），误报面比 TS 的 dedup 子集大；precision ≥0.90 风险高。`[源码推断，未实跑]`
9. **semgrep 环境本身尚未被证明可测**：预注册 v8（2026-11-19）记录「a single-file TypeScript scan did not return within five minutes and `--version` hangs」；在新环境重测前，python line 1 的可用性没有运行时证据（`artifacts/preregistration.json` revision 8）。`[已核实]`（记录本身）
10. **校准类别与 check 的语言硬编码**：`calibrate` 用 config 扫描的所有语言，`check` 只用 typescript（`scripts/calibrate.ts:52-58`；`scripts/live-drill.ts:1634-1639`）。若 python 引入 TS 未声明的新类，check 的 categories 会漏类并硬失败。`[已核实]`
11. **全部教学靶场 → contamination 全 high**：recall 必须按来源分别报告，不能合并（`docs/datasets.md:108-119`）。`[已核实]`
12. **`n<15` 的措辞**：若最终只建出 12–14 条可 block 样本，D13 要求明写「不具统计意义」，不能把它写成 pass/fail 的检测器结论。`[已核实]`

---

## 结论

1. **事实核对**：本仓确实没有 python 语料；AACR 22 条全 ts 且 `sample_cwe` 全 null，对 line 1 分母贡献为 0；self-built 35 条中 ts 29、js 6，python 0。`[已核实]`
2. **门是三重而非一重**：除了「建语料」，还有 (a) schema 只允许 ts/js/tsx/jsx、id 正则不接受 `py-`；(b) 版本必须走 `ds-2.x`，且新组会重排 TS 的 fit/eval；(c) python run 需要自己的负样本与低风险池，否则 precision/line 4 直接失败。`[已核实]`
3. **最关键的结构性发现**：即使建出 20 条 python 正样本，在 `POSITIVE_CAP_PER_CLASS=4`、普通文件只加载 py-block、而 py-block 只有 078/089 两类可达认证规则（022 的基名不在快照）的条件下，最多 8 条可 block；把 `.django/.flask` 加进 py-block 后也只有 12 条。`12/20 = 0.60 < 0.70`。**issue #44 只靠加语料无法让 line 1 通过**；要么改 cap（方法变更 + 新预注册），要么认证第 4 个 python 类（规则族变更），要么接受本次结论仍为 FAIL。`[已核实]`（算术）/ `[待人工决定]`（选哪条路）
4. **issue 的两处口径漂移**：`expected_detectable_by ∋ semgrep` 不是 line 1 的实际分母条件（代码显式不用它）；D13 的「42 个负样本」是旧 ds-1 口径，当前是 9 个。`[已核实]`
5. **`block facet is Python-only` 的真实含义比 issue 假设窄**：python 有配置，但小文件可 block 的类只有 078/089；022 只在大文件路径才可能有 `.django/.flask`。这不是「python 认证面已完整存在」。`[已核实]`

## 待人工决定的问题

1. **数据集放哪里、版本怎么走？** 是把 python 行并入 `datasets/self-built` 升到 `ds-2.1.0`（会重排现有 TS split，并让默认语言翻成 python），还是新建独立 python 目录（则 calibration/check 的 `datasets/self-built` 硬编码与 `ds-2` 版本前缀都要改）？
2. **line 1 是要「能通过」还是「重测并记录」？** 若要通过：是把 `POSITIVE_CAP_PER_CLASS` 从 4 提到 5（方法变更，需新预注册），还是认证第 4 个 python 类（例如把 `path-traversal-open.django/.flask` 加入 `py-block.blockRules` 并补 fp_bait，或认证 079/798/918 中的一类）？若只重测，是否接受结论仍为 FAIL/`insufficient_n`？
3. **是否补 python 负样本？** precision 分母和 line 4 都需要 python 的 8 条 defect-free low-risk（1 edit + 1 create 结构），issue #44 的 AC 没有列。批准补 8 条 python 负样本，还是接受 line 4 在这次 run 中为 `na`/fail？
4. **哪些源获得授权、谁做 GT？** 目前只读核实了 PyGoat（MIT）、VAmPI（MIT，11 个 py 文件）、django.nV（GPL-2.0，archived）、vulnpy（MIT，archived）。哪几个可用？GPL-2.0 / archived 源是否可接受？GT 由谁认领、κ 门槛多少？
5. **盲跑预算与运行环境由谁批？** 新 `dataset_version` 需要新的 `--allow-eval` 一次性名字、新的成本上限和 `DEEPSEEK_API_KEY`；且预注册 v8 记录 semgrep 在该环境 5 分钟未返回。谁批准这次消费、谁先验证 semgrep 在本机可跑？

## 拍板记录（2026-11-20）

决策原文见 issue #44 评论：<https://github.com/romeokeita231/code-review-system/issues/44#issuecomment-7032211484>。

1. 新建独立 python 数据集目录，不并入 `datasets/self-built`；同步改 `drill:context`、`check` 阶段硬编码与版本前缀。
2. 本票只做「建语料并如实重测」，结论允许为 FAIL / `insufficient_n`；改 cap 或认证第 4 个类单独立项。
3. 补 7 条 edit + 1 条 create 的 defect-free low-risk 负样本，均在 eval、不与正样本同文件。
4. 先做最小环境验证（单文件 python 扫描 + `--version`）并写入新预注册；未通过不开工。
5. 源授权：接受 MIT 源（含 archived 的 vulnpy）；GPL-2.0 不进本仓（公开仓无 LICENSE、数据字节冻结归档、缺少第三方许可证台账）。源集合：PyGoat（主）、vulnpy（archived）、VAmPI（补充）；每条仍须逐条核实 sink 与数据流。
6. GT 认领：`annotator=self`，advisor 按 CWE 分层抽检，分歧由 advisor 裁决，κ≥0.70 为门槛；抽检比例与 κ 算法写入新预注册；若无复核须写成「单标注、无一致性检验」的限制。决策原文：<https://github.com/romeokeita231/code-review-system/issues/44#issuecomment-7032487996>。
