# 公开安全基准调研（面向 TS 代码审查中间件）

调研时间：2026-10-31。所有数字均标注来源；无法从一手来源核实的写"未确认"，不估算。
评估对象：主评测"安全类缺陷"，需要能驱动 **一次代码写入事件** 粒度的评测（见 §1）。

## 0. 结论速览

| 基准 | 规模 | 语言 | TS/JS 条数 | CWE 标注 | 行号级标注 | 许可 | 写入事件粒度 |
|---|---|---|---|---|---|---|---|
| SecurityEval | 121 条提示 / 69 CWE（v2.1）；v1.0 为 130 条 / 75 CWE | Python 单语言 | 0 | 有，按 CWE 可分 | 无（整文件/整函数） | 仓库无 LICENSE（未声明） | 单文件/单函数 |
| OWASP Benchmark (Java) | 2,740 个测试用例，11 类 | Java | 0 | 有（每用例 1 个 CWE） | 无（整文件） | GPL-2.0 | 整文件 |
| CWE-Bench-Java | 120 个 CVE，4 个 CWE | Java | 0 | 有（22/78/79/94） | 函数级 + 行区间 | MIT | 整项目（可裁到函数） |
| CyberSecEval | 未确认（数据集 instruct-v2 约 1.7k 条，二手来源） | 未确认 | 未确认 | 不按 CWE 组织 | 无 | MIT | 生成侧片段，不是检出基准 |
| AACR-Bench（AOR 自带） | 200 PR / 50 仓库 / 2,145 条评论（1,505 真 + 640 假） | 10 种，含 TypeScript、JavaScript | 未确认（只有分布图） | 无 CWE，仅 4 类 issue | 有（from_line/to_line） | Apache-2.0 | PR 级 diff（多文件） |

**一句话**：唯一在语言上覆盖 TS 的公开基准是 AACR-Bench，但它不标 CWE、且 ground truth 是"评论是否正确"而非"这段代码有洞"；唯一按 CWE 细粒度（69–75 个）标注的是 SecurityEval，但只有 Python、每类样本 1–6 条。**TS + CWE 两个条件没有任何公开基准同时满足**，这是自建标注集必须存在的理由，不是可选项。

## 1. 判定口径

"一次代码写入事件"在三个层次上可落地，下文按此归类：

- **L1 整文件**：一次写入 = 一个文件。样本本身是完整文件，可直接喂给 `tools/post-execute`。
- **L2 函数/片段**：一次写入 = 一个函数或一段代码。需要把样本裁成片段，或对整文件只评分相关函数。
- **L3 项目/PR**：一次写入 = 一次多文件 diff。需要从 PR 里抽 diff 才能对上 Change Event。

同时记录标注质量的两档：**位置级**（文件 + 行/行区间）vs **存在级**（只说明这条样本有缺陷）。

## 2. 各基准

### 2.1 SecurityEval

来源：<https://github.com/s2e-lab/SecurityEval>（s2e-lab，MSR4P&S '22）

- **规模**：README 明示"we have now 121 prompts for 69 CWEs in this version"，对应 v2.1 的 `dataset.jsonl`；v1.0 的论文口径是"130 samples for 75 vulnerability types"。两个数字都来自 <https://github.com/s2e-lab/SecurityEval/blob/main/README.md>。
- **语言构成**：Python 单语言。依据：README 的评测流程只有 `codeql database create --language=python` 与 `bandit -r`（Bandit 仅支持 Python），仓库仅有 `Testcases_*` 三类 Python 用例目录。**TS/JS 条数 = 0**。
- **CWE 覆盖**：可按 CWE 完全切分。`Result/DataTable.csv` 逐 CWE 给出样本数（见 <https://github.com/s2e-lab/SecurityEval/blob/main/Result/DataTable.csv>），该表 75 行、Total 列求和 = 130（与 v1.0 的 130 条一致）。分布极不均衡：单 CWE 最多 6 条（CWE-020、CWE-611），其次 CWE-601 = 5 条，CWE-022 / CWE-297 / CWE-327 / CWE-502 各 4 条，其余多为 1–3 条。覆盖到的高价值类别包括 CWE-022 路径穿越、CWE-078 命令注入、CWE-079 XSS、CWE-089 SQL 注入、CWE-094 代码注入、CWE-259/798 硬编码凭证、CWE-327 弱加密、CWE-502 反序列化、CWE-611 XXE、CWE-643 XPath 注入、CWE-918 SSRF。
- **标注质量**：**存在级**。每个样本是"一个带洞的完整函数/文件"（`Testcases_Insecure_Code/` 下的 .py），没有"漏洞在第几行"的标注；正确性靠 CodeQL / Bandit 是否命中该 CWE 判定（README 的 Usage 一节）。
- **许可证与获取**：仓库根目录无 `LICENSE` 文件（2026-10-31 核对仓库根列表，只有 `.gitignore`、`CITATION.cff`、`DatasetCreator.py`、`README.md`、`dataset.jsonl` 与各用例目录），即**未声明许可**，默认版权保留；商用/再分发前需向作者确认。可直接 `git clone`，或 `datasets.load_dataset("s2e-lab/SecurityEval")`（README 给出，HF 页面 <https://huggingface.co/datasets/s2e-lab/SecurityEval>）。
- **粒度适配**：L1/L2。样本是 10–30 行量级的单函数，可直接当"整文件写入"喂进挂载层；**不适合** diff 级评测（没有 before/after，也没有真正的仓库上下文）。

### 2.2 OWASP Benchmark

来源：<https://github.com/OWASP-Benchmark/BenchmarkJava>、项目主页 <https://owasp.org/www-project-benchmark/>

- **规模**：v1.2 共 **2,740 个测试用例**（v1.1 为 21,041）。逐类数字（v1.2 / CWE）：命令注入 251 / CWE-78、弱加密 246 / CWE-327、弱哈希 236 / CWE-328、LDAP 注入 59 / CWE-90、路径穿越 268 / CWE-22、Secure Cookie 67 / CWE-614、SQL 注入 504 / CWE-89、信任边界 126 / CWE-501、弱随机 493 / CWE-330、XPath 注入 35 / CWE-643、XSS 455 / CWE-79。全部来自 <https://owasp.org/www-project-benchmark/?tab=java-test-cases> 的测试用例表（合计 2,740 可自行相加校验）。
- **语言构成**：Java。项目已扩展为"Java and Python test suite"（同页首段），Python 版为独立仓库/套件，本次未逐条核实其规模（**未确认**）。**TS/JS 条数 = 0**。
- **CWE 覆盖**：11 类，每类一个 CWE 编号，可按 CWE 切分；但只有这 11 个编号，覆盖面窄于 SecurityEval。
- **标注质量**：**存在级 + 强弱对照**。`expectedresults-1.2.csv` 为每个测试用例给出"用例名、漏洞类别、CWE 编号、预期结果（真漏洞/误报）"（同上页："lists every test case, the vulnerability category, the CWE number, and the expected result"）。**没有行号**。价值在于每个真漏洞都有结构等价的"安全变体"，是测 Precision 的标准做法。
- **许可证与获取**：**GPL-2.0**（仓库 API 元数据 `license.spdx_id = GPL-2.0`，<https://github.com/OWASP-Benchmark/BenchmarkJava>；项目页亦标 GNU GPL v2.0）。可直接 clone；但要跑起来需 Maven 构建 + 部署（`runBenchmark.sh`），评分靠 BenchmarkUtils（<https://github.com/OWASP-Benchmark/BenchmarkUtils>）。GPL-2.0 对"只在实验里跑、不链接分发"通常无碍，但不要把它的代码并进主工程。
- **粒度适配**：L1。每个用例是一个 Servlet 类（约 50–100 行），天然对齐"一次写一个文件"。缺点是大量用例依赖 Java EE / Servlet API，TS 侧无法直接迁移。

### 2.3 CWE-Bench-Java（CWE-Bench 系列的 Java 版）

来源：<https://github.com/iris-sast/cwe-bench-java>，论文 <https://arxiv.org/abs/2405.17238>（LLM-Assisted Static Analysis for Detecting Security Vulnerabilities）

- **规模**：**120 个 CVE**，每个 CVE 一个 project slug（README："there are 120 projects in the CWE-Bench-Java dataset, we have 120 unique project slugs"）。
- **语言构成**：Java。**TS/JS 条数 = 0**。CWE-Bench 家族的其它语言版本（JS/Python）在公开资料里未见稳定发布，**未确认**。
- **CWE 覆盖**：仅 **4 个** CWE——CWE-022 路径穿越、CWE-078 OS 命令注入、CWE-079 XSS、CWE-094 代码注入（README："120 CVEs spanning 4 CWEs"，且 `project_info.csv` 的 `cwe_id` 只取这四个值）。**按 CWE 可分，但类别很少**。各类具体条数未在 README 给出（**未确认**）。
- **标注质量**：**位置级，且到函数**。`data/fix_info.csv` 每行给出 `file`、`class`、`class_start/class_end`、`method`、`method_start/method_end`、`signature`；README 说明"Many of the rows in this table is manually vetted and labeled"。这是六个候选里唯一给出"真实缺陷精确文件 + 行区间"的。
- **许可证与获取**：**MIT**（`LICENSE` 文件："MIT License, Copyright (c) 2024 Ziyang Li"）。可直接 clone；也可用 HF（<https://huggingface.co/datasets/iris-sast/CWE-Bench-Java>）。注意代价：要复现需按 `scripts/setup.py` 拉取并构建 120 个历史项目（README 明说需 Linux x64、自备 JDK 7u80/8u202/17，Oracle JDK 需账号手动下载）。不想构建可 `--no-build` 只取源码。
- **粒度适配**：L3 → 可裁到 L2。原始形态是"整项目 + buggy commit"，不是"一次写入"；但 `fix_info.csv` 的函数边界让你能把缺陷函数单独切出来当 L2 样本，这条路径成本可控，是本基准相对其它候选的最大优势。

### 2.4 CyberSecEval（Meta PurpleLlama）

来源：<https://github.com/meta-llama/PurpleLlama>（`CybersecurityBenchmarks/`），论文 <https://arxiv.org/abs/2312.04724>

- **规模**：**未确认**。官方仓库以 JSON 形式提供 `CybersecurityBenchmarks/datasets/instruct/instruct.json`（3,399,489 B）与 `instruct-v2.json`（3,006,400 B），条目数未在可核实的一手文档中给出。二手线索：第三方转换卡称 instruct-v2 为 **1,681 行**（<https://huggingface.co/datasets/OctoReasoner/cyberseceval_verl>），**未经 Meta 官方确认，不要写进论文正文当数字**。
- **语言构成**：**未确认**（官方页面未按语言给出分布）。已知与 TS/JS 无对应关系，**不能计入 TS 覆盖**。
- **CWE 覆盖**：不按 CWE 组织。CyberSecEval 的分项是"instruct / autocomplete / mitre / mitre_frr / prompt_injection / canary_exploit / interpreter / autonomous_uplift / autopatch / spear_phishing 等"（<https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks/datasets>），其中 `mitre` 对齐 ATT&CK，不是 CWE。
- **标注质量**：**无位置标注**。它评的是"模型倾向"：给的是一段代码或一次补全，判"是否写出不安全代码"或"是否配合攻击"，由规则/LLM judge 打分（论文摘要：评估"propensity to generate insecure code"与"compliance when asked to assist in cyberattacks"）。
- **许可证与获取**：**MIT**（`CybersecurityBenchmarks/LICENSE`："MIT License, Copyright (c) Meta Platforms, Inc. and affiliates"）。仓库内直接可取，无需构建。
- **粒度适配**：**不适配**。它是生成侧（我给提示，看模型写不写洞），不是检出侧（我给代码，看工具报不报）。可以借鉴它的"不安全代码模式库"来做我们自建集的种子，但不能作为 B0–B4 的评测集。

### 2.5 AACR-Bench（alibaba/open-code-review 自带评测集）

来源：<https://github.com/alibaba/aacr-bench>、数据 <https://huggingface.co/datasets/Alibaba-Aone/aacr-bench>、论文 <https://arxiv.org/abs/2601.19494>。AOR 的 README 直接把它作为官方 benchmark（"A real-world code review benchmark built from 50 popular open-source repositories, 200 real Pull Requests, and 10 programming languages … 1,505 annotated ground-truth issues"，<https://github.com/alibaba/open-code-review/blob/main/README.md>）。

- **规模**：**200 个 PR、50 个开源仓库、2,145 条评审评论**，其中 **1,505 条专家确认为正确、640 条为错误**（HF 数据集卡："The dataset contains 2,145 code review comments, consisting of 1,505 expert-verified correct comments and 640 incorrect comments"）。
- **语言构成**：**10 种，明确包含 TypeScript 与 JavaScript**。README 的语言分组：系统级 C++/Rust/Go；企业级 Java/C#/**TypeScript**；脚本 Python/**JavaScript**/Ruby/PHP。**这是本次调研中唯一覆盖 TS 的公开基准**。但各语言的具体条数只有分布图（`imgs/comments-distribution.png`），**TS/JS 各多少条：未确认**。
- **CWE 覆盖**：**无 CWE 编号**。评论的 `category` 只有 4 类：Security / Defect / Maintainability / Performance（README 的 Data Format）。所以"按 CWE 算 P/R/F1"这条在本基准上只能退化为"Security 一类的整体 P/R/F1"，或靠我们自己的映射把评论归到 CWE（属于二次标注，需在论文里交代）。
- **标注质量**：**位置级，但语义是"评论对不对"，不是"这里有没有洞"**。每条含 `path`、`from_line`、`to_line`、`side`、`category`、`context`（diff/file/repo 三级）、`source_model`、`label`（1/0）。也就是说真值形状是"某文件某行区间上，这条评审意见是否成立"，与我们 Finding 六元组几乎同构——这点非常契合。风险：640 条负样本是"错误评论"，不是"漏报的真缺陷"，所以它天然适合量 Precision/噪声率，**不直接给 Recall 的分母**（Recall 分母只能用 1,505 条正样本）。
- **许可证与获取**：**Apache-2.0**（两个仓库与 HF 数据集卡一致，AOR README 末尾 "Apache-2.0 — Copyright 2026 Alibaba"）。可直接 clone / `load_dataset`，配套 `evaluation/` 目录有"数据加载 → 评审执行 → 评测"的完整流水线，且支持 OpenCodeReview / Claude Code / Codex 三种 reviewer。
- **粒度适配**：L3，最贴近"一次代码写入事件"。种子是 PR，但每条标注都锚在 diff 的行区间上，抽取成单文件 diff 后即可对齐 Change Event。

### 2.6 补充候选（只列已核实存在的，未做规模核实）

- **OWASP BenchmarkPython**：OWASP 项目页已把 Benchmark 描述为"Java and Python test suite"，Python 套件与 Java 版同源同 CWE 口径（<https://owasp.org/www-project-benchmark/>）。规模**未确认**。若自建集要跨语言对照 CWE 语义，它比 Java 版更省事。
- **NIST Juliet / SARD**：OWASP 项目页把它列为并列资源（<https://samate.nist.gov/SARD/testsuite.php>）。合成用例、CWE 齐全，但语言为 C/C++/Java/C#，**无 TS**；规模与许可见 SARD 站点，本次**未核实**。
- **semgrep/semgrep-rules 测试语料**：仓库已有 `typescript/{lang,react,nestjs,angular,aws-cdk,mcp}` 等 TS 目录（<https://github.com/semgrep/semgrep-rules/tree/develop/typescript>），规则内联测试用 `// ruleid:` / `// ok:` 标注命中行（约定见 <https://semgrep.dev/docs/writing-rules/testing-rules>）。它是**行级标注 + 天然覆盖 TS** 的现成语料，但它标的是"规则命中"而非"真实漏洞"，只能当我们自建集的**种子与负样本来源**，不能当基准。规则条数与其中带 CWE 元数据的比例**未确认**。

## 3. 横向对比（按论文要回答的三个问题排）

**问题一：能不能按 CWE 类别算 P/R/F1？**

| 基准 | CWE 类别数 | 单类样本量 | 可用性 |
|---|---|---|---|
| SecurityEval | 69（v2.1）/ 75（v1.0） | 1–6 条 | 类别维度够，单类样本量太小，F1 方差会很大 |
| OWASP Benchmark | 11 | 35–504 条 | 单类样本量够，但只有 11 类，且不含凭证泄露类 |
| CWE-Bench-Java | 4 | 未确认（总 120） | 类别太少，只能当"真实缺陷"补充 |
| AACR-Bench | 0（4 类 issue） | — | 需二次映射才能到 CWE |

**问题二：语言上能不能代表 TS 系统？** 只有 AACR-Bench 有 TS/JS 样本（条数未确认）；其余四个全是 Python/Java，**TS 覆盖率 0**。

**问题三：粒度能不能对上"一次写入"？** 见 §1 表格最后一列。AACR-Bench（PR diff）与 SecurityEval（单文件）可直接用；OWASP 需接受"整文件单洞"；CWE-Bench-Java 需按 `fix_info.csv` 切函数；CyberSecEval 不可用。

## 4. 选型建议

**主评测（1）：AACR-Bench。**

理由：

1. 唯一有 TS/JS 的公开基准，与"系统主要跑 TS"直接对齐，避免"用 Python 成绩论证 TS 系统"这种答辩必被问的漏洞。
2. 标注形状（path + from_line/to_line + category + label）与我们的 Finding 六元组同构，`to_line` 天然支持我们"行区间重叠即同一问题"的归并规则（§8.1），等于免费拿到一套评测格式。
3. Apache-2.0 + 官方 `evaluation/` 流水线，且它本来就是 AOR（我们唯一的语义源）的官方 benchmark——用对手自己的尺子量它，比自选尺子更难被质疑。
4. PR 级 diff 与"提交前拦截"的时序一致，B0–B4 五档可以在同一批 diff 上跑，成本指标（token/延迟）也可直接按 PR 聚合。

必须写进论文的局限：`label` 判的是"这条评审意见对不对"，**不判"这段代码有没有洞"**。因此在本基准上我们只能报 Precision 与噪声率，Recall 的分母是 1,505 条正样本、且这些正样本来自模型/人写的评论而非穷举的真值集合，**Recall 会被系统性高估**。这一点必须显式声明，不能当作"检出率"。

**补充对照（2）：SecurityEval（CWE 口径）+ CWE-Bench-Java（真实缺陷、函数级）。**

- SecurityEval 用来做**类别维度的校准与权重估计**（§8.3 保序回归、§8.4 每类准确率）：69–75 个 CWE 的标签体系现成，样本小反而适合当"先验"，不占评测预算。需在论文里说明它是 Python、且单类样本 1–6 条，因此只报"类别可分性"不报"类别 F1"。
- CWE-Bench-Java 用来证明"不是只认合成样本"：4 个 CWE（22/78/79/94）与我们的注入/路径穿越主线重合，函数级行区间可裁成 L2 样本，120 条的量级正好够跑一次五档对照而不爆预算。代价是要搭 Java 构建环境，建议只取 `--no-build` 的源码 + `fix_info.csv` 切片。

**不建议用作主评测**：OWASP Benchmark（GPL-2.0 且 Java EE 强绑定，迁移成本高于收益；可留作 Java 侧的第三方对照）、CyberSecEval（生成侧基准，问题不同）。

**必须靠自建标注集补的缺口**（按优先级）：

1. **TS 上的 CWE 级标注**——没有任何公开基准提供。这是唯一的硬缺口，自建集必须至少覆盖 CWE-022 / 078 / 079 / 089 / 094 / 798 / 918 这 7 类（对齐我们两源都能覆盖的类别）。
2. **精确到行的"真实缺陷"标注**——AACR-Bench 是"评论对不对"，CWE-Bench-Java 是 Java。TS 的行级真值只能自建。
3. **凭证泄露类（CWE-259/798/321）**——OWASP 的 11 类里完全没有，SecurityEval 只有 2 条，必须自建。
4. **负样本（安全的等价写法）**——OWASP 的做法值得抄：每个自建正样本配一个结构等价的安全变体，才能量出真实的 Precision，否则 Precision 会被我们自己选的"干净样本"抬高。
5. **依赖幻觉**——没有任何公开安全基准覆盖，闭环验证只能全自建（用 Registry 查询核实）。

自建集的种子建议直接用 `semgrep-rules` 的 TS 用例（`// ruleid:` / `// ok:` 已是行级标注），代价最低；但需人工把"规则命中"复核成"真实缺陷"，否则等于用 Semgrep 的标准答案去考 Semgrep（B1 档会虚高，B4−B3 的增量也会被污染）。

## 5. 未确认清单（不要当数字用）

- CyberSecEval 的样本条数、语言分布、CWE 对应关系。
- AACR-Bench 中 TypeScript / JavaScript 各自的评论条数。
- CWE-Bench-Java 四个 CWE 各自的 CVE 条数。
- OWASP BenchmarkPython 的用例规模。
- semgrep-rules 中 TS 规则条数、以及带 CWE 元数据的比例。
- SecurityEval 的许可证（仓库无 LICENSE 文件，需向作者确认）。

## 6. 来源

- SecurityEval 仓库与 README：<https://github.com/s2e-lab/SecurityEval>；CWE 分布表：<https://github.com/s2e-lab/SecurityEval/blob/main/Result/DataTable.csv>；HF：<https://huggingface.co/datasets/s2e-lab/SecurityEval>
- OWASP Benchmark 仓库：<https://github.com/OWASP-Benchmark/BenchmarkJava>；测试用例与 CWE 数字：<https://owasp.org/www-project-benchmark/?tab=java-test-cases>；计分工具：<https://github.com/OWASP-Benchmark/BenchmarkUtils>
- CWE-Bench-Java：<https://github.com/iris-sast/cwe-bench-java>；论文：<https://arxiv.org/abs/2405.17238>；HF：<https://huggingface.co/datasets/iris-sast/CWE-Bench-Java>
- CyberSecEval：<https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks>；论文：<https://arxiv.org/abs/2312.04724>；数据集目录：<https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks/datasets>
- AACR-Bench：<https://github.com/alibaba/aacr-bench>；数据卡：<https://huggingface.co/datasets/Alibaba-Aone/aacr-bench>；论文：<https://arxiv.org/abs/2601.19494>；AOR README 的 benchmark 段：<https://github.com/alibaba/open-code-review/blob/main/README.md>
- semgrep-rules TS 目录：<https://github.com/semgrep/semgrep-rules/tree/develop/typescript>；测试注解约定：<https://semgrep.dev/docs/writing-rules/testing-rules>
