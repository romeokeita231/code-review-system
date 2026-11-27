# 0009 pre path 的启动成本被接受

- Status: Accepted
- Date: 2026-11-19
- Source: #42

## Context

pre path 的两个来源都是进程启动开销，不是工作量开销。`code-review-graph impact` 在 674 文件与 10 文件仓库上相差 8%（0.56 s / 0.50 s）；semgrep 每次把文件复制到新的临时目录、把规则合并写到新路径（`src/l3/semgrep.ts`），没有仓库级缓存，所以「冷 / 热」只来自进程启动与页缓存。

归档实测（2026-11-13）：池化 p99 662 ms；semgrep 冷 2.8 s、热 0.65 s。两者合计 ~3.4 s，占 8 s `callMs` 的一半，且发生在任何一行代码被读取之前。

常驻或预热的收益上限是每次调用约 1.2 s，代价是把进程生命周期变成长期依赖：谁启动、谁回收、宿主崩溃后孤儿怎么清、沙箱内能否常驻。本项目已经两次发生 detached 子进程在无人察觉时更换量具身份（`ocr` 自更新器），且 #48 至今无法证明孙进程已停。收益 1.2 s，代价是已知会失控的一类问题。

同一类缺陷在配置里还有两处：`softCapMs = 6000` 声明了软上限而没有任何读取点；`budgets.semgrepKillMs` 与 `sources.semgrep.timeoutsMs.callMs` 是同一个数的两个副本，实际生效的是后者。

## Decision

- 不引入常驻或预热进程；pre path 继续每次启动子进程。
- 预算下界规则：每份预算须 `>= ceil(1.5 x p99)`。下界由实测推出，写在 `artifacts/preregistration.json` 与 `docs/live-drill.md`；机器不持有 p99，只验不等式与算术。
- 冻结值只需满足下界；只有当新下界超过冻结值时才改冻结值，并以 revisions 追加的方式记录理由。
- 闸门归 preflight（`--stage check`）：`crg budget` 由「等于冻结值」改为「`>=` 下界」，新增 `semgrep budget`。`assertBudgetRelations` 只保留和 `<= min(callMs, turnMs)`。
- semgrep 的 kill 值收成一个键（`budgets.semgrepKillMs`），删除 `sources.semgrep.timeoutsMs.callMs`。
- 删除 `softCapMs`：无人读取的预算不是预算，其语义与既有和约束重复。
- 冷启动不进闸门：semgrep 无仓库级缓存，「冷」是机器级页缓存状态，无法按需复现。闸门只验 warm p99；冷启动作为一次性观察记录，并标注证据等级。

## Consequences

- pre path 每次继续支付进程启动成本；8 s 上限内的剩余余量不做二次分配。
- 本次改动只改变判定与记录，不改善用户可感知延迟。重新开启常驻需要新的进程托管方案与孤儿进程证明，而不是再次发现「卡三秒」。
- 2026-11-19 的复测未取得可比数字（见 `docs/live-drill.md`），冻结值未改；#42 的复测验收保持未满足。
  **2026-11-20 追加**：次日同一方法、同一版本、同一钉定检出上取得了完整复测（pooled p99 2672 ms，floor `ceil(1.5 x 2672) = 4008 ms`，`4008 + 5000 > 8000`）。结论不是「复测成功」，而是**本机不在支持环境内**：冻结值仍为 993，可比数字须在另一台机器上取得。上一句描述的是 11-19 那一次尝试的状态，不是复测的最终状态。
