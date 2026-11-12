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

## Consequences

- 阻断保证的范围是「认证规则 + 认证语言 + 文件 ≤100 KiB」，论文须按此边界写限制。
- 8 s 上限只能靠外层 kill 兜底；CLI 间歇卡死会直接抬高 fail-open 率。
- 预算数字绑平台（Windows 本机实测），换平台必须重测。
