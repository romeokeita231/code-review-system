# 验收结论（live）

五条线：2/5 通过。

量具身份：semgrep 1.184.0（observed）、ocr v1.13.6（04deca6，observed）、AOR 模型 deepseek-flash（requested deepseek-chat，https://api.deepseek.com，observed），与钉定值一致。

结果表见 report.md；本文件只给结论，不把接口通过当质量结论。

line1 的分母按单位分开：召回以样本计（每个漏洞样本是否被抓到），精度以 finding 计（每条 finding 是否落在真值行上）。召回 50 / 门槛 20（gated，available 11 staged 10）；精度 86 / 门槛 20（gated）。

available 11 条可门禁的 eval 正样本中有 1 条未入演练（staged 10），短缺来自选样上限而非检测结果。

精度分母含 1 条 create 样本：它们只证明新建文件路径不是死代码，n=1 不支撑任何精度主张。

line1 分母口径：按钉定规则表声明的 typescript 规则分面，0 条 eval 正样本因规则集无该类规则不在分母内（见结果表末表）。
