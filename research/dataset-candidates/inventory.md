# 自建集候选清点（#41 第 1 步）

对象：`juice-shop` @ `266448a`（2026-11-08，664 个 `.ts`）+ `snyk-labs/nodejs-goof` @ `add14ba`（2026-05-01，10 个 `.js`）。
方法：`git grep -nE` 按类抓 sink（`research/dataset-candidates/scan_sinks.py`），再逐条人工核对 sink 处的数据流与控制。
**本文件不含标注**：`disposition` 只是清点结论（可当候选 / 假阳性诱饵 / 不作候选），数据集标注按 #7 §5 走人工 + κ≥0.70，在第 3 步做。也没有跑任何探测器。

机器可读版本（含每条的证据文本与 fp_bait/sink_only 行）：`inventory.json`。

## 一、候选正样本（24 条）

| 仓库 | 路径:sink 行 | 拟 CWE | sink 是否存在 | 控制 |
| --- | --- | --- | --- | --- |
| juice-shop | `routes/dataErasure.ts:104` | 022 | 是 `path.resolve(req.body.layout)` | 弱（黑名单） |
| juice-shop | `routes/fileServer.ts:32` | 022 | 是 `sendFile(path.resolve('ftp/', file))` | 弱（后缀白名单 + 去空字节） |
| juice-shop | `routes/vulnCodeSnippet.ts:90` | 022 | 是 `readFile('./…/codefixes/'+key)` | 无 |
| juice-shop | `routes/vulnCodeFixes.ts:83` | 022 | 是 同上拼路径 | 无 |
| juice-shop | `routes/fileUpload.ts:31` | 022 | 是 `path.resolve('uploads/…/'+fileName)` | 弱（`includes('.')`） |
| goof | `routes/index.js:174` | 078 | 是 `exec('identify ' + url)` | 无 |
| juice-shop | `frontend/…/search-result.component.ts:146` | 079 | 是 `bypassSecurityTrustHtml(queryParam)` | 无 |
| juice-shop | `frontend/…/search-result.component.ts:113` | 079 | 是 `bypassSecurityTrustHtml(description)` | 无 |
| juice-shop | `frontend/…/data-export.component.ts:72` | 079 | 是 `document.write(this.userData)` | 无 |
| juice-shop | `frontend/…/track-result.component.ts:49` | 079 | 是 `bypassSecurityTrustHtml(orderId)` | 无 |
| juice-shop | `frontend/…/administration.component.ts:74` | 079 | 是 `bypassSecurityTrustHtml(…user.email…)` | 无 |
| juice-shop | `frontend/…/administration.component.ts:92` | 079 | 是 `bypassSecurityTrustHtml(feedback.comment)` | 无 |
| juice-shop | `frontend/…/last-login-ip.component.ts:40` | 079 | 是 `bypassSecurityTrustHtml(…lastLoginIp…)` | 无 |
| juice-shop | `routes/search.ts:23` | 089 | 是 `sequelize.query(\`…'${criteria}'…\`)` | 无 |
| juice-shop | `routes/login.ts:34` | 089 | 是 `sequelize.query(\`…'${req.body.email}'…\`)` | 无 |
| juice-shop | `routes/userProfile.ts:65` | 094 | 是 `eval(code)` | 无 |
| juice-shop | `routes/b2bOrder.ts:23` | 094 | 是 `vm.runInContext('safeEval(orderLinesData)')` | 弱（vm 沙箱） |
| juice-shop | `routes/fileUpload.ts:114` | 094 | 是 `vm.runInContext('yaml.load(data)')` | 弱（vm 沙箱） |
| juice-shop | `lib/xml.ts:38` | 094 | 是 `vm.runInContext('…fromString(data…)')` | 弱（vm 沙箱） |
| juice-shop | `lib/insecurity.ts:21` | 798 | 是 RSA 私钥字面量 | 无 |
| goof | `app.js:83` | 798 | 是 `SECRET_TOKEN_…` 常量 | 无 |
| goof | `app.js:43` | 798 | 是 `secret: 'keyboard cat'` | 无 |
| goof | `mongoose-db.js:52` | 798 | 是 明文 `SuperSecretPassword` | 无 |
| juice-shop | `routes/profileImageUrlUpload.ts:24` | 918 | 是 `fetch(req.body.imageUrl)` | 无 |

按类计数：022 = 5、078 = 1、079 = 7、089 = 2、094 = 4、798 = 4、918 = 1。**七类都有真实来源**，合计 24 条。

## 二、两条必须先摊开的事实

**1）每类 ≥5 只有 2 类，不是 5 类。** 022（5）与 079（7）达标，798（4）差一条，094（4）差一条，089（2）、078（1）、918（1）远不够。总数 24 ≥ line1 的 n≥20，但"≥5 类 × ≥5 正样本"的目标实际命中 **0 类同时满足类数与每类数**（按"类有来源"计 7 类，按"每类 ≥5"计 2 类）。

**2）TS 现状没有干净的漏洞引入 diff 可取。**

```
git log -S'models.sequelize.query' -- routes/search.ts    # 全历史 23854 提交
→ 唯一命中 d6dc878b1 2021-03-05 "Migrate /routes/*.js to .ts"
```

也就是说，TS 形态的 sink 是被**整批 JS→TS 迁移提交**带进来的，不是漏洞引入提交。单次 `-S` 探测 105 s（惰性取 blob + 代理）。真实 diff 只剩两种：2016 年代 ES5 的引入版（`before` 那个文件还不存在，或还是 `.js` 旧布局），以及上面这种大迁移提交。两者都不能给出"同一文件、干净的前置状态"。

⇒ 自建正样本只能是「**真实文件 + 自拟最小 diff**」：文件内容与框架上下文是真的（这正是 E2 缺的东西），diff 是我们自己把控制摘掉/写上。`origin.kind = self_rewritten`，`contamination_risk` 记 `authored-diff`。这不是"手写样本补位"（手写指的是编造代码），但必须在 #7 里写清楚，否则会被当成真实提交。

## 三、副产品：假阳性诱饵

`disposition = fp_bait` 的 3 条是**同一个 sink 但已被正确控制**的真实代码 —— 它们正好是精度分母要的东西，而且比自造的"安全变体"强：不用编，控制就摆在那儿。

| 路径:行 | 为什么 s 是诱饵 |
| --- | --- |
| `routes/logfileServer.ts:14` | `res.sendFile(path.resolve('logs/', file))`，上游 `if (!file.includes('/'))` 直接拒路径分隔符 |
| `routes/quarantineServer.ts:14` | 同上守卫 |
| `routes/keyServer.ts:14` | 同上守卫 |

另有 5 条 `sink_only` 必须排除，否则会把 FP 记成 TP：`routes/captcha.ts:22` 的 `eval` 只吃 `Math.random` 拼出来的表达式；`score-board.component.ts:103` 的 `bypassSecurityTrustHtml` 吃的是应用自有文案；`lib/insecurity.ts:53` 是随机 secret（弱随机，不是 798）；`validatePreconditions.ts:165` 的 `fetch` 目标是配置项；`videoHandler.ts:82` 的字幕路径来源待确认。

## 四、第 2 步的裁定（按"<5 类动 goof；<4 类整体降级"执行）

- **动 goof**：已动。078 的唯一真实来源就是 goof `routes/index.js:174`；juice-shop 全仓 0 条 078 sink（唯一的 `child_process` 命中是 Cypress 测试夹具，`exec` 命中全是 `RegExp.exec`）。goof 另外贡献了 3 条 798。
- **是否需要"整体降级为实测覆盖报告"**：按"每类 ≥5"的字面口径，达标类只有 2 个（<4）⇒ 触发降级；但七类都有真实来源，总数 23 ≥ 20。两条口径给出相反答案，这是**需要设计方裁的口径问题**，我不自行改判：

  - 口径 A（严格按 ≥5 类 × ≥5 条）：自建集不成立 ⇒ 只出「真实仓上的覆盖报告」，line1 的样本集退回 AACR（22 条，已过 `--conformance`）。
  - 口径 B（按总样本数与类覆盖）：23 条够 line1 的 n≥20，七类都在，但 089/078/918 只有 1–2 条，这三类的 per-class 表必须并列 n 与区间，不能出阈值。

  两种口径都**不削弱**已经成立的结论：line1 的 block 分面是 `na`（见 #41 第 0 步结论），与自建集选哪条口径无关。

## 五、我没有做的事

- 没有写任何 `label` / `risk_level` / `expected_detectable_by`；没有生成任何样本行。
- 没有跑 semgrep / AOR（#7 §4.5 的顺序：标注先于探测器；第 3 步才跑）。
- 没有把 `data/static/codefixes/*.ts` 当样本源：那 169 个文件是**片段**（无 import、`botName`/`productModel`/`req` 均未定义），既过不了 `tsc --noEmit`，也正是 E2 抱怨的那类"没有真实上下文"。它们只能当"控制长什么样"的参考。
