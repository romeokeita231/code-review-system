# 0007 pre 阻断范围与预算

- Status: Accepted
- Date: 2026-11-11
- Source: #9、#21、#23、#25

## Context

实测推翻了「静态预估单文件耗时」的三次尝试：成本主要由 CLI/core 固定开销与规则规模决定，与文件大小弱相关；大文件上 taint 是唯一长尾。8 s 硬上限是用户可接受的上界，超时必须 fail-open。

## Decision

- 阻塞路径只跑 Semgrep + CRG 查询；硬上限 8 s/次且每 turn 8 s（turn = `(session_id, rootCallId)`）；剩余预算不足则**不发起**，不缩 deadline。
- 预算切分：Semgrep 5 s 硬杀进程树、CRG 300 ms、融合与回写 0.5 s；软上限 6 s；零重试。
- 预算策略改为「保守起步价 + 在线兜底」，不承诺静态预估耗时。
- 大小梯子：≤100 KiB 全量可阻断；100 KiB–`S_max` 只跑 nontaint 且只有已认证规则可阻断；>`S_max` fail-open。`S_max` 由 manifest 给（py = 743188 B），禁手填。
- py 阻断保留：6 条规则（3 条 taint），三条判据在 `7caf50f0…` 下重测通过（小档 max 396.8 ms、6/7 类有会响规则、载荷与 `paths.scanned == 1` 契约通过）。
- ts 阻断只在 5–50 KiB 保证，50–100 KiB 外推，>100 KiB 保持 fail-open。
- 删 `oversize` 与 256 KiB 判据；新增 `resource_limit`（≥10 MB，纯资源）/ `turn_budget_exhausted` / `language_unsupported` 三个 skip reason。
- denylist 键 `(path, sha256(LF), subset_sha256)`，另存 `subset_id`；`rules_sha256` 按 per-subset 失效。
- 路径改写是主键正确性前提，必须保留；`.semgrepignore` 忽略语义删除；hunk 扫描不进 pre。

## 勘误（2026-11-13）

第 18 行「ts 阻断只在 5–50 KiB 保证」**不成立**，作废。`configs/b4.json` 的 `ts-dedup`
子集 `blockRules` 为空，而 `src/l3/semgrep.ts` 只在规则 id 命中 `blockRules` 时置
`certified: true` ⇒ TS 事实无法在 `pre-execute` 阻断。补认证的三条并列判据中第一条
（与已认证 py 6 条同 `upstream_id` 家族）在 TS 侧判定域为空（0/95）——6 条认证规则
全是 Python 专有 sink，javascript/typescript 规则目录下无任何变体。

延迟不是原因：`ts_dedup.yaml` 在真实 .ts 5–50 KiB 上 n=10，`semgrep-core` 形态
p99 651.3 ms（≤1.2 s），完整 CLI 形态 p99 3254.9 ms。证据见
`research/semgrep-bench/ts_block_bench.json`。

结论：机械阻断仅 Python 可用；TS 事实只进 post 阶段的 warn/计数。line 1 的 block 分面
按 `na`（`n=0 / k=样本数`）报，不得用可检测率顶替，也不得为凑数放宽第一条判据。
另：1.2 s 判据只对 `semgrep-core` 直接调用成立——见勘误二，该判据已退役。

## 勘误二（2026-11-13）：1.2 s 判据退役，只报 shipped 形态

1.2 s 判据**退役**，不再作为门槛，也不作为可引用值。原因不是「数字不准」，而是**它
描述的不是 shipped 形态**：`src/l3/semgrep.ts` 启动的是 `semgrep scan --config`，固定
启动成本约 2.8 s。第 4 步 fit 跑（ds-2，12 行）实测：ok 行 3.3–4.7 s，4.3 KB 的
`ts-cwe022-0003` 在 5.9 s 超时。5 s 的 `semgrepKillMs` / `timeoutsMs.callMs` 因此不是
安全上界——这是「该路径会在真实使用中失守」，不是估算偏差。

保留的是两预算而非单一延迟数：`budgets.semgrepKillMs`（进程树硬杀）与
`sources.semgrep.timeoutsMs.callMs`（单次调用）。对外只报 shipped 形态的 p50/p95/p99，
并注明形态；`semgrep-core` 数字仅作对照行。

通用要求（第三次）：**任何延迟判据必须标注出处形态**（`semgrep-core` / `semgrep scan`
/ 其他）。跨形态比较不构成证据。回收 ~2.8 s 固定开销（切 `semgrep-core -rules
-targets -json`）是独立 perf 票，不并入 #41。

## 勘误三（2026-11-13）：探针必须先声明它扫的是 fit 还是 eval

演练里曾有一条 `dataset detectability` 预检：它数「计划中的正样本有几个能被检测器看见」，
看起来只是选样辅助。但它扫的是 `plan.positives`，也就是 **eval 正样本**——在冻结之前就
产生检测器输出，直接违反「fit → 冻结 → eval 只跑一次」的次序。删除理由因此不是「随
ds-1 一起过时」，而是**它本身就是一次未登记的 eval 观察**。

规则：**任何探针、预检、冒烟测试都必须声明其扫描对象属于 fit 还是 eval；扫描对象含
eval 的探针，只能在冻结之后、作为唯一一次 eval 运行的一部分执行。** 覆盖矩阵只碰 fit
（`npm run record:fit --matrix`），故不受此限。

## 勘误四（2026-11-13）：测量物必须自带量具身份，消费者必须拒发

同一缺陷的第三次出现：`ts_all` 探针 vs `ts_dedup` 装载、`semgrep scan` vs
`semgrep-core` 判据、`ocr` 从钉定的 `04deca6` 自更新漂到 `4236c87`。三次都是
**产物看起来完整**：行有效、报告齐全，只是量具不是声称的那一把。

根因是结构性的：行里记的是 `toolchain`，它抄自配置（「本应使用什么」），没有记
「实际回答 `--version` 的是谁」。所以：

- `ReviewRow.instrument = {semgrep, ocr}`，各带 `{name, version, commit, source}`，
  `source ∈ {observed, declared}`：live 运行探测二进制（每进程一次，缓存），replay 只能
  声明，且声明过的行**结构上不能**充当 live 测量。
- `evaluate` 在产出任何数字之前调用 `assertInstrumentIdentity`：缺失、`declared`、
  跨行不一致、或与 `configs/b4.json` 的钉定值不同，一律 **抛错拒发**，不是警告。
  理由很直接：漂移事故的产物看起来完全正常，警告会被当成噪音。
- 量具身份进 `report.md` 顶部的表，报告本身可追溯。

同一原则适用于数据集身份：`collect`/`evaluate` 拒绝 `run.json` 里 `dataset_version`
不一致的目录（ds-1 残留就曾与 ds-2 的运行目录并列），运行目录一律命名为
`eval-<dataset>-<stamp>`。

## 勘误五（2026-11-13）：`ocr` 的自更新必须关掉，钉定按 commit 而非版本号

`ocr` 每次调用都会 spawn `scripts/update.js`，发现新版本就 `npm i -g`。这就是钉定失效的
「允许漂移发生」那一环：门禁判断正确、拦住了事故，但没有东西阻止漂移。

- `TOOL_ENV = { OCR_NO_UPDATE: "1" }`（`src/config`）注入本系统 spawn 的每个进程；用户级
  环境变量同时置位，覆盖人工 `ocr` 调用。
- 钉定值是 **build commit**：`v1.13.7` 打在 `b1dcffb`、`v1.13.8` 打在 `4236c87`，按版本号
  匹配会接受错误的二进制；`ocr --version` 输出的 `(04deca6)` 才是配置携带的值。
- `04deca6` 不是 release tag，只能按该 commit 重建（recipe 与 sha256 见
  `docs/toolchain.md`）。**「未钉定」不是运行可以携带的标签**：eval 只跑一次，在被替换的
  二进制上测得的数字永远无法在钉定二进制上复现。

## Consequences

- 阻断保证的范围是「认证规则 + 认证语言 + 文件 ≤100 KiB」，论文须按此边界写限制。
- 8 s 上限只能靠外层 kill 兜底；CLI 间歇卡死会直接抬高 fail-open 率。
- 预算数字绑平台（Windows 本机实测），换平台必须重测。
