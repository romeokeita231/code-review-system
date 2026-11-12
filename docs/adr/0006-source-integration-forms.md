# 0006 三源接入形态

- Status: Accepted
- Date: 2026-11-11
- Source: #17、#19、#21、#22、#23、#24、#25、#3、#14

## Context

三个源都没有「喂 diff」的能力：Semgrep 是 CLI 子进程，AOR 没有 MCP server 且只能审工作区，CRG 是 Python 包。时延相差三个数量级（毫秒 / 秒 / 分钟）。版本漂移会直接改变数值结论。

## Decision

- Semgrep：execa 子进程、单文件临时根 + 路径改写；引擎梯子 `core → osemgrep → degraded`，统计只认 core；规则按语言出（CLI 会按 id 跨语言去重），`rules_sha256` 钉 `7caf50f0…`；规则合并成单 YAML，不加 `--quiet`。
- AOR：进程外 execa，`ocr scan --path` 为主路径；`--preview` 只做预估与集合差；无 `--effort`；T1 = 60k，T2 = `--max-tools 100` + 150k；`--timeout` 按每文件预算换算，`outer_cap` 必填无默认；`--concurrency` 显式 2；`--no-summary` 进模板。
- AOR 版本钉 commit `04deca6`，token 取 `summary` 子对象；无 `manifest`，`status` 有五值，`summary.budget_exceeded` 是唯一权威预算布尔；`failed` 写 stderr，须双流解析 + 退出码校验。
- CRG：只能进程外接入；只提供受影响文件数与节点数，不产 Finding；索引异步建、路径内只查询。
- 三源适配器只做错误码归一、超时映射、位置表示归一；不重复校验 schema；单源超时用 AbortController + 每源预算，不得拖垮整体。

## Consequences

- pre 的 Semgrep 是「每次写入一次 CLI 调用」，成本是固定开销，不能靠缩小文件省下来。
- 集合差与覆盖完整性只能建立在 `--preview` 上；`files_complete` 由 missing / budget_exceeded / incomplete 三者共同定义。
- CRG 的 TS resolved edges 仅 52.9%，radius 低估，门控收益不可外推。
- 换源版本等于换结论，必须重测并更新 manifest。
