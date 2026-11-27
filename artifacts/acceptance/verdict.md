# 验收结论（live）

闸门 3/5 通过（live）

量具身份：semgrep 1.184.0（observed）、ocr v1.13.6（04deca6，observed）、AOR 模型 deepseek-flash（requested deepseek-chat，https://api.deepseek.com，observed），与钉定值一致。

结果表见 report.md；本文件只给结论，不把接口通过当质量结论。

line1 的分母按单位分开：召回以样本计（每个漏洞样本是否被抓到），精度以 finding 计（每条 finding 是否落在真值行上）。召回 10 / 门槛 20（unblockable，available 11 staged 10）；精度 86 / 门槛 20（gated）。

line1 结论（预注册句，D13）：在所要求精度下该数据集不具备阻断能力。依据：钉定配置对 TS 的 `blockRules` 为空，certified 0/10 ⇒ 没有任何 finding 能被认证、`deny` 不可达。n=10 < 15，不具统计意义。该结论不读作「检测器漏检」：0 是配置面的事实，不是检测能力的度量。

line3 的判据是「每条 warn 均被处理」，不是「大部分被处理」：同一 classed 样本内 5 条 warn 已修、1 条未处理，该样本整条记 `unfixed`（优先级 unfixed > recurred > not_measured > not_removed > corrected）。所以 corrected 9/20 读作「闭环合上的样本数为 9」，不是「多数失败」。本线不设容忍度；将来若要容忍度，须是新的预注册阈值，而不是本次读数的注脚。

available 11 条可门禁的 eval 正样本中有 1 条未入演练（staged 10），短缺来自选样上限而非检测结果。

精度分母含 1 条 create 样本：它们只证明新建文件路径不是死代码，n=1 不支撑任何精度主张。

line1 分母口径：按钉定规则表声明的 typescript 规则分面，0 条 eval 正样本因规则集无该类规则不在分母内（见结果表末表）。
