# 0001 单包 + 分层目录 + contracts 唯一源

- Status: Accepted
- Date: 2026-11-11
- Source: #6、#1

## Context

DSH 插件装载要求产物是「一个包」。三个信号源（Semgrep 二进制、AOR CLI、CRG Python 包）都在包外，workspace 拆分只能拆自研部分，拆完仍要把 core 重新 bundle 进插件。融合层逻辑上独立成层，但代码归属编排层，不能为了实现分层制造跨层依赖。

## Decision

- 单个 npm 包，不拆 workspace；内部边界靠目录 + 依赖方向约束。
- 两个入口：DSH 插件与 eval CLI，共享同一 core 装配，差别只在谁驱动 L1 的 hook。
- 目录固定为 contracts / config / L1 host adapter / L2 orchestrator / L3 sources / L4 fusion / L5 eval / entry；每层只暴露一个门面，层内文件外部不可 import。
- `ReviewHook`、`SignalSource`、`FusionStage` 等接口定义在 contracts；各层只放实现。
- contracts 的 zod 是唯一定义处，TS 类型由 `z.infer` 推导；构建期导出 JSON Schema 并提交仓库，配生成后 diff 校验防漂移。
- L4 以可插拔 stage 数组被 L2 持有，空数组即 B3。

## Consequences

- 包边界不再约束分层，违规只能靠目录约定与 review 发现；换宿主时只改 L1。
- 适配器重复定义 schema 有了物理判定：不在 contracts 的类型即违规。
- Python 侧不装 Node 也能校验 JSONL。
- 新增信号源 = 一个适配器 + 一条配置，编排层不动。
