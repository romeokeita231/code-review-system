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
| report.md | `b907ec8d4af4dc3878102928eee538a6ed313f807651b107fc786d6c417fa14d` | 3742 |
| verdict.md | `447e0cb7127a9f1901269e1c92c5691ee500722002b91b3b1d214b3da2323ce9` | 2018 |
| verdict.json | `36db1a333784b62e99dcd54adc82e6f79da58c8ef3290242d52ce468e587afb3` | 2179 |

原始 `2/5` 表示的三份原件，逐字节副本（复制前后 SHA256 相同）：

| 文件 | SHA256 | 字节 |
| --- | --- | --- |
| original-2of5/report.md | `f3b254f3dac0a4b003e497a72c54dec80a29e22fae9d5222ccb271efb74b2626` | 2702 |
| original-2of5/verdict.json | `9a4def8ca4b3fadbad6ea469319cba52671cdf8b2263259c8108db0ed0ed1f4f` | 1591 |
| original-2of5/verdict.md | `29a3f606285274a7d3ed387c85648789fd602034b4b3edfa23ba5057f870b127` | 1024 |

## 两条与读数有关的说明

1. 本 run 的行**没有** `aor_invoked` 字段（该字段本提交才落地）。line4 的 0 由 `tier: 0` + `tier_source: "triage"` 推导：`src/l2/orchestrator.ts` 在 tier 0 时把 AOR 移出 runnable 集合，没有任何代码路径能在 tier 0 发起 AOR 调用。报告把它与 raw `na` 并列打印，并逐对记录 `basis`。
2. 设计方裁定原文（`2/5`）保留在 `original-2of5/`，引用规则：原始数字可原样引用，但每句须自带总体与分母，且不得作为质量结论。

## 生成方式

`node .tmp/provenance.mjs`（一次性脚本，读取 `run.json`/`rows.jsonl` 与本目录文件后写出本文件；哈希为文件当时内容）。
