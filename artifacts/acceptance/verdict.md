# 验收结论（live）

闸门 3/4 通过（live）；另有 1 条 na，单列、不进闸门分母。

量具身份：semgrep 1.184.0（observed）、ocr v1.13.6（04deca6，observed）、AOR 模型 deepseek-flash（requested deepseek-chat，https://api.deepseek.com，observed），与钉定值一致。

结果表见 report.md；本文件只给结论，不把接口通过当质量结论。

line1 的分母按单位分开：召回以样本计（每个漏洞样本是否被抓到），精度以 finding 计（每条 finding 是否落在真值行上）。召回 10 / 门槛 20（na，available 11 staged 10）；精度 86 / 门槛 20（gated）。

line3 的判据是「每条 warn 均被处理」，不是「大部分被处理」：同一 classed 样本内 5 条 warn 已修、1 条未处理，该样本整条记 `unfixed`（优先级 recurred > unfixed > corrected）。所以 corrected 0/10 读作「闭环合上的样本数为 0」，不是「多数失败」。本线不设容忍度；将来若要容忍度，须是新的预注册阈值，而不是本次读数的注脚。

na（不可测，不进闸门分母）：line1 — no certified TS rule (blockRules is empty for this language in the pinned config)。“测不了”既不等于“没通过”，也不等于“通过”。后果按线分：line1 不在闸门分母内，G 不变；line2–5 是闸线，任一为 na 都会使 G 减 1，而 na 永不记为通过，故闸线上一旦出现 na，通过数最多 G−1，闸门必然失败 —— 闸线上的 na 劣于 FAIL，这是反空转设计，不因读数难看而豁免。

available 11 条可门禁的 eval 正样本中有 1 条未入演练（staged 10），短缺来自选样上限而非检测结果。

精度分母含 1 条 create 样本：它们只证明新建文件路径不是死代码，n=1 不支撑任何精度主张。

line1 分母口径：按钉定规则表声明的 typescript 规则分面，0 条 eval 正样本因规则集无该类规则不在分母内（见结果表末表）。
