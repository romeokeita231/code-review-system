# Code Review System

过程内嵌的多源代码审查系统：在智能体生成过程中拦截写入、归一出证并仲裁。

## Language

**机械阻断**：
写入前拒绝一次工具调用，变更未落盘。
_Avoid_: block，阻断（作处置名时）

**指令纠偏**：
变更已落盘后，把纠偏要求注入模型下一请求的上下文。
_Avoid_: warn，提示

**记录**：
只落审查日志、不进入模型上下文的处置。
_Avoid_: info

**改判率**：
replay 中本应机械阻断的样本，被融合分判为无需纠偏的比例；反事实量。
_Avoid_: 误杀率

**变更事件**：
宿主一次写入或命令执行归一后的事件，带 diffProvenance（synthesized / observed / none）。
_Avoid_: 变更集，diff

**分诊**：
读 blast-radius 决定审查档位的过程。
_Avoid_: 成本门控

**档位**：
按 blast-radius 决定的审查深度（tier 0/1/2），只 gate 语义源的 token 预算。
_Avoid_: 等级，B0–B4

**blast-radius**：
变动的波及范围（受影响文件与受影响节点），只作档位决策输入。
_Avoid_: 影响面，调用方数

**目标集**：
档位 1/2 传给语义源的文件集，恒等于变更事件的 files。
_Avoid_: 文件白名单

**融合**：
去重 → 冲突消解 → 校准 → 加权投票四步；每步可单独关闭，四步全关即 B3。
_Avoid_: 聚合，投票（单指第四步）

**校准**：
把各源原始分映射到统一概率量纲，含向先验收缩与档位单调化（PAVA）。
_Avoid_: 归一化，标准化

**配对**：
GT 与 merged finding 的最大权一对一认领；score 不参与。
_Avoid_: 匹配，对齐

**配对表**：
配对结果的独立落盘，主键 (run_id, gt_id)，不挂在 finding 上。
_Avoid_: matched_gt_id 字段

**阻断守卫**：
同 (file, rule-id) 连续 deny 2 次后的降级机制，记 block_loop。
_Avoid_: 重复拦截

**降级**：
源超时或不可用导致证据不完整的状态；降级来源不得产出机械阻断。
_Avoid_: 失败，fallback

**B0–B4 / B4g**：
对照基线，不是档位；B4g 是门控关的 B4。
_Avoid_: 档位
