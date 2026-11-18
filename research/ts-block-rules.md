# TS 阻断规则族：fp_bait 实测与提案（2026-11-18）

本票只回答一件事：**现有 TS 正样本里，哪些规则族在 3 条 `fp_bait` 上零命中，且还能覆盖正样本。**
不改 `configs/b4.json`，不重跑 calibration。

## 分母

- 自建样本共 **26 条正样本**，其中 **TS 20 条**、JS 6 条。本票的阻断面只作用于 TS，
  所以候选分母是 **20**，不是 26；JS 不在分母内。
- 20 条 TS 正样本按 split 与 CWE：

| split | CWE-22 | CWE-79 | CWE-89 | CWE-94 | CWE-798 | CWE-918 | 合计 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| fit | 3 | 2 | 2 | 2 | 0 | 0 | 9 |
| eval | 2 | 5 | 0 | 2 | 1 | 1 | 11 |

`n` 按规则族实际覆盖的正样本重算：**命中行与 `defects[].line_start..line_end` 有交集**
才算覆盖；只在同一文件别处命中，记为 `file-level`，不计入 `n`。

## 方法

`pysemgrep` 包装器在本机 `--version` 即挂起（1.184.0，沙箱内外一致），因此直接调用其
`semgrep-core` 引擎，规则文件仍是钉定的
`research/semgrep-bench/snapshot/ts_dedup.yaml`（sha256 `42e5be0…c470b`）。
夹具由 3 条 `fp_bait` 的 `before` 原文落盘到
`research/semgrep-bench/fp-bait/`：

| 夹具 | 数据行 | 控制 |
| --- | --- | --- |
| `logfileServer.ts` | `ts-cwe022-9001` | `!file.includes('/')` 后才 `path.resolve('logs/', file)` |
| `quarantineServer.ts` | `ts-cwe022-9002` | 同上，`ftp/quarantine/` |
| `keyServer.ts` | `ts-cwe022-9003` | 同上，`encryptionkeys/` |

枚举命令（每条夹具一次，结果里 `results` 为空即零命中）：

```powershell
$CORE = "$env:APPDATA\uv\tools\semgrep\Lib\site-packages\semgrep\bin\semgrep-core.exe"
& $CORE -rules research/semgrep-bench/snapshot/ts_dedup.yaml `
  -lang typescript -json research/semgrep-bench/fp-bait/logfileServer.ts
```

完整矩阵见 `research/semgrep-bench/ts-block-matrix.json`。

## 规则族清单与误报面

| family | 规则数 | 正样本 | 严格 n | file-level n | 3 条 fp_bait 命中 |
| --- | --- | --- | --- | --- | --- |
| CWE-22 | 3 | 5 | 0 | 0 | 0/3 |
| CWE-79 | 35 | 7 | 0 | 0 | 0/3 |
| CWE-89 | 10 | 2 | **2** | 2 | **0/3** |
| CWE-94 | 13 | 4 | 0 | 0 | 0/3 |
| CWE-798 | 5 | 1 | 0 | 1 | 0/3 |
| CWE-918 | 19 | 1 | 0 | 0 | 0/3 |
| CWE-78 | 7 | 0 | 0 | 0 | 0/3 |

零命中本身不等于可用：**CWE-22/79/94/798/918 的零命中是空的，因为它们连正样本都不命中。**

- CWE-22：`express-path-join-resolve-traversal` / `path-join-resolve-traversal` 的 taint
  source 是 `$REQ.params`，而这批样本写成 `({ params }: Request, ...)` 解构，source
  从不匹配。规则对 5 条正样本和 3 条 fp_bait 一起沉默——既证明不了安全，也证明不了覆盖。
- CWE-79：`angular-bypasssecuritytrust` 等不匹配 `this.sanitizer.bypassSecurityTrustHtml(...)`
  的调用形态；7 条正样本全部漏掉。
- CWE-94：`vm-runincontext-injection` 要求用户输入进入脚本参数，4 条样本都是常量脚本 +
  上下文注入，规则不触发。
- CWE-798：`hardcoded-hmac-key` 在 `ts-cwe798-0001` 的 42/150 行命中，但标注缺陷在 21 行
  （RSA 私钥）；严格 n=0，file-level=1。
- CWE-918：`express-ssrf` 等不匹配 `fetch(url)` 的裸调用。

## 唯一进入提案的族：CWE-89

| rule id | 目标 CWE | 覆盖的正样本（严格） | fp_bait |
| --- | --- | --- | --- |
| `sequelize-raw-query` | CWE-89 | `ts-cwe089-0001:23`、`ts-cwe089-0002:34` | 0/3 |
| `express-sequelize-injection` | CWE-89 | 同上 | 0/3 |

两条规则来自钉定规则集，未按样本手写，`research/semgrep-bench/ts-block-candidates.yml`
是它们的逐字副本。验证命令：

```powershell
$CORE = "$env:APPDATA\uv\tools\semgrep\Lib\site-packages\semgrep\bin\semgrep-core.exe"
foreach ($f in Get-ChildItem research/semgrep-bench/fp-bait/*.ts) {
  & $CORE -rules research/semgrep-bench/ts-block-candidates.yml -lang typescript -json $f.FullName
}
# logfileServer / quarantineServer / keyServer：results 均为 []
```

## 提案

1. **`blockRules` 变更**：只建议 `sequelize-raw-query` 与 `express-sequelize-injection`
   二选一（或并列）加入 `ts-dedup` 子集；其余族因 n=0 不立项。本票不写入
   `configs/b4.json`，待人工批准。
2. **覆盖后的 n**：fit split 2 条（两条 CWE-89 正样本都在 fit），eval split **0 条**。
3. **line 1 新分母**：eval 的 10 条样本里没有 CWE-89，分母仍是 **10，可认证覆盖 0**，
   line 1 仍是 **0/10 FAIL**。启用该规则族不会改变 T15 结论，只增加 fit 侧的认证样本。
4. **需重跑的 calibration 范围**：仅 TS 子集（fit 9 条）的规则级精确率与阈值；B4/B4g
   的融合、冲突消解、投票不动。因为 `blockRules` 进入 `configHash`，若批准，所有档位
   配置哈希需要一起刷新后再重跑，非 TS 子集保持不变。
5. **成本**：按 run 记录的 probe 14,471 tokens/行，`n=2` 的重评估上界为
   `14,471 × 2 × 2 × 1.5 = 86,826 tokens`；若把覆盖扩到 20 条则为 868,260 tokens。
   前者远低于 200 万预算。

**结论**：现有 TS 规则面里，唯一同时满足“fp_bait 零命中 + 覆盖正样本”的是 CWE-89 的两条
规则；它们覆盖的样本全在 fit，无法把 line 1 从 0/10 抬起来。因此在拿到 eval 侧的
CWE-89 样本（或新规则族）之前，`blockRules: []` 维持不变是唯一能同时保精度与可复现的选择。
