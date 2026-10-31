# DSH（DeepSeek Harness）Review Hook 真实接口调研

> 调研对象：本机安装的 DSH（`C:\Users\romeo_keta\AppData\Local\Programs\DSH NEXT\resources\app.asar`）+ 官方公开文档与 GitHub 源码。
> 调研目的：为 Code-Review-System 的 L1 挂载层（Review Hook Interface）确定真实的挂载点名、payload、可执行处置与装载方式。
> 结论针对 **DSH 核心 0.2.1-rc.3**；官方 docs / GitHub master 可能更新，凡关键结论均在本机 asar 内复核过。

## 0. 证据记法

| 记法 | 含义 |
|---|---|
| `app.asar!/<path>:<line>` | 本机安装包内文件与行号。根目录 `C:\Users\romeo_keta\AppData\Local\Programs\DSH NEXT\resources\app.asar`，路径为 asar 内相对路径，行号为解包后文本行号（已校准，直接从文件首字节读取） |
| `unpacked/<path>:<line>` | `app.asar.unpacked` 下的实体文件（未被归档，可直接读） |
| `DOC <url>` | 官方文档站 |
| `GH <path>` | GitHub `deepseek-ai/deepseek-harness` master 源码路径 |

版本锚点：
- DSH 外壳 `dsh-desktop-next` 2.0.20-next —— `app.asar!/package.json:3`
- DSH 核心 `@deepseek-ai/dsh-tools` 0.2.1-rc.3 —— `app.asar!/node_modules/@deepseek-ai/dsh-tools/package.json:4`
- 本机 profile patch：`C:\Users\romeo_keta\.dsh\cordis.patch.yml`（当前只有 MCP 行，无审查类插件）

---

## 1. 结论速查

| # | 问题 | 结论 |
|---|---|---|
| 1 | `tools/pre-execute` / `tools/post-execute` 是否存在、准确名字、怎么注册 | **存在，名字完全一致**。同族还有 `tools/execute`（环绕派发）与 `tools/result`（只读观测）。注册方式 = **Cordis 插件 API**（`ctx.on(...)`）**+** 配置文件（profile 的 `cordis.patch.yml` 装载插件行）。**不存在**任何叫 "Review Hook" 的接口或包 |
| 2 | handler 签名与 payload 字段 | 签名确定（见 §3）。**能拿到**：工具名、工具参数（深冻结）、callId、`exec.agent.session.id`、取消信号；**命令退出码**只在 post-execute 的 result 里。**拿不到统一 diff**，也拿不到"归一化的文件路径 + 文件内容"——这些必须按工具名自己解析 `exec.arguments` |
| 3 | 执行后能否改变 outcome | **能阻断**：pre-execute 返回 `deny`（工具体不执行，模型看到 `Error: <reason>`）；**能追罚**：post-execute 返回 `block` + `feedback`（把已经跑完的结果改成错误结果）；**能注入上下文**：决策里带 `additionalContexts`；**能只记录**：`tools/result`（emit，抛错被吞）或 post-execute 返回 `accept` |
| 4 | 插件装载与版本协商 | 发现 = profile `package.json` 的 `dsh.profile.bundles` + 包内 `dsh.bundle.patch` 指向的 patch 文件，经 Loader 合成；安装 = `plugin_manager` 工具 / Web「Plugins」页 / `dsh plugin` CLI。**版本协商 = `engines.dsh`（SemVer range）+ peerDependencies**，安装前检查、启动时复查，不满足即 `incompatible-version` 拒绝；例外可写 `compatibility.json` 豁免 |
| 5 | handler 耗时是否阻塞生成、有无超时 | **同步阻塞**：pipeline 直接 `await this.ctx.waterfall(...)`，handler 不 resolve，工具就不派发。**没有内建超时**，只有 `exec.signal`；`dsh-tool-call-timeout-policy` 只包 `tools/execute`（在 pre-execute 之后），且 `write`/`edit`/`bash` 不声明 `timeoutMs`，等于默认无预算 |
| 6 | 官方示例插件 | **有，且本机就能读**：`dsh-experimental-auto-review`（最贴近——每工具 LLM 审查 + deny/ask）、`dsh-workspace-changes`（pre-execute 记录）、`dsh-repeat-tool-reminder`（post-execute + additionalContexts）、`dsh-tool-call-timeout-policy`（tools/execute 包装）、`dsh-tool-jobs`（prepend pre-execute）。另有插件模板 `unpacked/.../dsh-agent-preset/skills/cordis-plugin-development/templates/` |

---

## 2. Q1：挂载点是否存在、准确名字、怎么注册

### 2.1 精确名字（存在，四个同族事件）

`@deepseek-ai/dsh-tools` 的 `Events` 声明（`GH packages/core/tools/src/events.ts`）在本机生成的 API 目录里逐条可见：

| 事件 | mode | 本机证据 |
|---|---|---|
| `tools/pre-execute` | waterfall | `app.asar!/node_modules/@deepseek-ai/dsh-tool-cordis/lib/types/api-catalog.js:4484` |
| `tools/post-execute` | waterfall | `.../api-catalog.js:4476` |
| `tools/execute` | waterfall（环绕派发） | `.../api-catalog.js:4468` |
| `tools/result` | emit（只读） | `.../api-catalog.js:4500` |
| `tools/change` | emit（工具集变化） | `.../api-catalog.js:4460` |

派发处的真实调用点：
- `app.asar!/node_modules/@deepseek-ai/dsh-tools/lib/index.js:3321` —— `const gate = await this.ctx.waterfall(carrier, "tools/pre-execute", exec, () => Promise.resolve({ kind: "allow" }));`
- `.../lib/index.js:3427` —— `const result = await this.ctx.waterfall(carrier, "tools/execute", mutableExec, () => this.dispatchToolBody(mutableExec));`
- `.../lib/index.js:3600` —— `const decision = await this.ctx.waterfall(scopeTarget(this, exec.agent), "tools/post-execute", exec, result, () => Promise.resolve({ kind: "accept" }));`
- `.../lib/index.js:3513` —— 触发 `"tools/result"`

固定顺序（决定性）：`tools/pre-execute`（可扩展 allow/deny/ask）→ 单调 guard → `tools/execute`（环绕派发）→ `tools/post-execute`（检查/替换/阻断/挂上下文）→ 定义自带 `finalizeContent` → `tools/result`（只读）。
证据：`app.asar!/node_modules/@deepseek-ai/dsh-tools/README.md:89`；`DOC https://deepseek-harness.github.io/deepseek-harness/en/reference/cookbook/adding-a-tool.md`（"Execution policy and observation"）。

> 附：另有一条**文件级**挂载缝，粒度比工具级更细 —— `fs/write-intent`（waterfall）与 `fs/edit-intent`（waterfall），签名见 `.../api-catalog.js:4252` / `:4236`。它们是 `FileSystem.writeText` / `editText` 的单槽决策点，`write` 工具内部就是 `await ctx.waterfall("fs/write-intent", target, exec, () => void 0)`（`app.asar!/node_modules/@deepseek-ai/dsh-tool-fs/lib/index.js:607`）。原生插件若要按"文件"而不是按"工具调用"取证，这是更贴的挂点。

### 2.2 注册方式：插件 API + 配置文件，两者都要

**(a) 代码侧：Cordis 插件，`ctx.on`**

```ts
// DOC https://deepseek-harness.github.io/deepseek-harness/en/reference/cookbook/extension-cookbook.md
ctx.on('tools/pre-execute', async (exec, next) => {
  if (!ok) return { kind: 'deny', reason: 'Denied by policy.' }
  return next()
})
```

真实官方代码同形：`app.asar!/node_modules/@deepseek-ai/dsh-experimental-auto-review/lib/index.js:461`（`yield ctx.on("tools/pre-execute", async (exec, next) => {`），并在 `:488` 用 `{ prepend: true }` 抢到 waterfall 队首。

**(b) 配置侧：profile 的 `cordis.patch.yml` + 包内 `dsh.bundle.patch`**

- 插件包在自己的 `package.json` 里声明 bundle patch：`app.asar!/node_modules/@deepseek-ai/dsh-experimental-auto-review/package.json:79-83`
  ```json
  "dsh": { "bundle": { "patch": "./cordis.patch.yml" } }
  ```
- 该 patch 只做一件事——insert 一行 Loader row：`app.asar!/node_modules/@deepseek-ai/dsh-experimental-auto-review/cordis.patch.yml:2-3`（`id: auto-review` / `name: '@deepseek-ai/dsh-experimental-auto-review'`）
- 用户侧 profile patch 同格式：`C:\Users\romeo_keta\.dsh\cordis.patch.yml:1-10`（现有 MCP 行就是 `- insert: - id: ... name: ... config: ...`）
- patch 方言（`insert` / 按 `id` override / `group` / `disabled` / `isolate` / `!!js`）：`unpacked/node_modules/@deepseek-ai/dsh-agent-preset/skills/cordis-composition-reference/SKILL.md:10-25`

**不要手写 profile 的 `package.json` / `cordis.patch.yml`**：官方 skill 明确要求走 `plugin_manager` 的 `install_bundle`（`unpacked/.../cordis-plugin-development/SKILL.md:10`）。

---

## 3. Q2：handler 签名与 payload

### 3.1 签名（逐字）

```ts
'tools/pre-execute'(this: Scoped<ToolsService>, exec: ToolExecution, next: () => Promise<PreToolDecision>): Promise<PreToolDecision>
'tools/execute'(this: Scoped<ToolsService>, exec: ToolDispatchExecution, next: () => Promise<ToolExecutionResult>): Promise<ToolExecutionResult>
'tools/post-execute'(this: Scoped<ToolsService>, exec: ToolExecution, result: Readonly<ToolExecutionResult>, next: () => Promise<PostToolDecision>): Promise<PostToolDecision>
'tools/result'(this: Scoped<ToolsService>, exec: Readonly<ToolExecution>, result: Readonly<ToolExecutionResult>): undefined
```

证据：`GH packages/core/tools/src/events.ts`；本机同签名：`app.asar!/node_modules/@deepseek-ai/dsh-tool-cordis/lib/types/api-catalog.js:4485`（pre）、`:4477`（post）、`:4469`（execute）、`:4501`（result）。

### 3.2 `ToolExecution` 的字段（GH `packages/core/tools/src/contracts.ts`）

| 字段 | 类型 | 说明 |
|---|---|---|
| `callId` | `ToolCallId` | 模型侧调用 id |
| `rootCallId` | `ToolCallId` | 整棵执行树的根调用 |
| `name` | `string` | 工具名（`write` / `edit` / `read` / `bash` / `run_code` …） |
| `arguments` | `unknown`（**深冻结**） | 已解析、无损 JSON 化的模型参数；**schema 由各工具自己定义**，registry 不做统一解释 |
| `schema?` | `ToolSchema` | 仅 PTC 内部调用有 |
| `agent?` | `Agent` | 发起调用的 agent；**会话 id = `exec.agent.session.id`** |
| `parent?` | `ToolExecutionToken` | PTC 内层调用才有；`run_code` 的直接调用没有 parent |
| `signal` | `AbortSignal` | 调用方取消信号（必填，不可移除） |
| `token` | `ToolExecutionToken` | 执行器分配的关联不透明 id |
| `toolSet?` | `ResolvedToolSet` | 本步准入集合 |

会话 id 的取法有直接代码证据：`app.asar!/node_modules/@deepseek-ai/dsh-tools/lib/index.js:1531`（`calls.run(exec.agent.session.id, ...)`）、`app.asar!/node_modules/@deepseek-ai/dsh-experimental-auto-review/lib/index.js:464`（`permissionPresets.current(agent.session)`）、`app.asar!/node_modules/@deepseek-ai/dsh-session/lib/index.js:1344`（`get id()`）。

### 3.3 逐项对照我们的诉求

| 诉求 | 是否拿到 | 真实来源 / 限制 |
|---|---|---|
| 工具名 | ✅ | `exec.name` |
| 工具参数 | ✅ 但不统一 | `exec.arguments`（冻结）。`write` → `file_path` + `content`（`app.asar!/node_modules/@deepseek-ai/dsh-tool-fs/lib/index.js:552,557`）；`edit` → `file_path` + `old_string` + `new_string`（`:693,770-771`）；`read` → `file_path`（`:254`）；`bash` → `command` 等（**未逐字核对 bash 参数名，见 §8**） |
| 写入的文件路径 | ⚠️ 需自己解析 | 工具级：读 `arguments.file_path`。文件级：`fs/write-intent` 的 `target: FsTarget`（"the resolved target about to be written"，`.../api-catalog.js:4256`） |
| 文件内容（新） | ⚠️ 部分 | 只有 `write` 有全文 `arguments.content`；`edit` 只有 `old_string`/`new_string` 片段，**没有改后全文**，需自己读盘重放 |
| 文件内容（旧） | ❌ | payload 里没有；要么自己读盘，要么走 `dsh-workspace-changes` 的 per-turn git 快照（`app.asar!/node_modules/@deepseek-ai/dsh-workspace-changes/lib/index.js:1086` 在 pre-execute 里 `recorder.settled()` 等基线就绪） |
| **统一 diff** | ❌ **primary 接口不提供** | 最接近的是 post-execute 里的 `result.meta.diffs`：`write`/`edit` 的 `presentationMeta` 产出 `{ path, oldText, newText }` **hunk 级**结构（`app.asar!/node_modules/@deepseek-ai/dsh-tool-fs/lib/index.js:593-601`、`:738-744`），由 `computeHunkDiffs` 生成（`:422-423`）。它是"presentation meta"，不是 git 风格 unified diff，也不覆盖非 fs 工具 |
| 会话 id | ✅ | `exec.agent.session.id`（见上） |
| 命令执行结果 / 退出码 | ✅（仅 post 侧） | `bash` 的规范返回值含 `exitCode`（`app.asar!/node_modules/@deepseek-ai/dsh-tool-bash/lib/index.js:303,577`），post-execute 从 `result.value.exitCode` 取；pre-execute 阶段命令还没跑，**必然拿不到** |
| 模型可见内容 | ✅ | `result.content: ContentBlock[]`、`result.isError` |
| 是否已被拒绝 | ✅（post 侧） | 被 pre-execute 拒绝的调用**仍会经过 post-execute**（`app.asar!/node_modules/@deepseek-ai/dsh-repeat-tool-reminder/README.md:84`），此时 result 是 `isError: true` 且内容为 `Error: <reason>`（`.../dsh-tools/lib/index.js:3339-3350`） |
| 统一口径的"变更类型（写入/命令）" | ❌ | 需自己按 `exec.name` 分类 |

### 3.4 关键限制：**不能改参数**

`tools/pre-execute` 明确**不允许**改写 `exec.arguments`（否则日志/渲染参数会与实际执行脱节）。
证据：`app.asar!/node_modules/@deepseek-ai/dsh-tools/README.md:233`；`GH packages/core/tools/README.md`（Known Limitations，同条）。

---

## 4. Q3：执行后能否改变写入 outcome

### 4.1 三个决策联合类型（逐字，GH `packages/core/tools/src/contracts.ts`）

```ts
type PreToolDecision  = { kind:'allow' } | { kind:'deny'; reason:string; info?:ToolErrorInfo }
                      | { kind:'cancel' }
                      | { kind:'ask'; reason?:string; displayReason?:{en:string;[locale:string]:string} }
type PostToolDecision = { kind:'accept'; content?:ContentBlock[]; value?:never; additionalContexts?:UserMessage[] }
                      | { kind:'accept'; value:JsonValue;        content?:never; additionalContexts?:UserMessage[] }
                      | { kind:'block'; feedback:ContentBlock[]; additionalContexts?:UserMessage[] }
```

### 4.2 能力矩阵

| 想做的事 | 可行做法 | 效果与时序 | 证据 |
|---|---|---|---|
| **阻断（写入前）** | `tools/pre-execute` 返回 `{kind:'deny', reason, info?}` | 工具体**不执行**；pipeline 物化成 `content:[{type:'text',text:'Error: <reason>'}], isError:true`，模型下一步看到 | `app.asar!/node_modules/@deepseek-ai/dsh-tools/lib/index.js:3337-3350` |
| 阻断（静默取消） | 返回 `{kind:'cancel'}` | 走规范化的 `ABORTED_BEFORE_DISPATCH` 结果，不呈现"策略拒绝"语义 | `.../lib/index.js:3332-3336`；`api-catalog.js:4487` |
| 转人工审批 | 返回 `{kind:'ask', reason, displayReason}` | 经 `ctx.approval` 询问；**无审批通道时降级为拒绝** | `api-catalog.js:4487` |
| 单调拒绝（不可被后续放行） | `ctx.tools.guard(fn)`，返回字符串即拒绝 | 同步、无 allow 结果，顺序上在 pre-execute 之后 | `app.asar!/node_modules/@deepseek-ai/dsh-tools/README.md:89` |
| **执行后追罚** | `tools/post-execute` 返回 `{kind:'block', feedback:ContentBlock[]}` | 已执行完的结果被改写成错误结果，`feedback` 成为模型可见的纠正内容 → 等价"要求重做" | `GH packages/core/tools/src/contracts.ts`（PostToolDecision 注释："block by turning corrective feedback into an error result"） |
| 替换/遮蔽结果 | `{kind:'accept', content}` 或 `{kind:'accept', value}` | 二选一，**不可同时**替换 value 与 content；失败结果不能替换 value | `app.asar!/node_modules/@deepseek-ai/dsh-tools/lib/index.js:3611,3614` |
| **提示注入回模型上下文** | 决策对象上的 `additionalContexts: UserMessage[]` | 下一请求可见（durable，非唤醒） | 契约同上；官方用例 `app.asar!/node_modules/@deepseek-ai/dsh-repeat-tool-reminder/lib/index.js:2254,2258`；`.../dsh-spill-policy/lib/index.js:245-253` |
| **只记录** | 监听 `tools/result`（emit），或 post-execute 返回 `{kind:'accept'}` | 结果已深冻结；listener 抛错被吞掉，不影响调用 | `api-catalog.js:4503`（"Listener failures are contained"）；`.../dsh-tools/lib/index.js:3509` |
| 改写参数 / 净化入参 | ❌ 不支持 | 见 §3.4 | `.../dsh-tools/README.md:233` |

### 4.3 与「三级处置」的映射（我们的 L1 契约）

| 我们的级别 | DSH 落地 | 说明 |
|---|---|---|
| `block` | `tools/pre-execute` → `deny`（写前）；必要时 `post-execute` → `block`（写后追罚） | 只有 pre-execute 能真正阻止落盘 |
| `warn` | `tools/post-execute` → `accept` + `additionalContexts`（把提示塞进下一请求） | **注意**：此时文件已写，属"提示但不强制" |
| `info` | `tools/result` 观测，或 post-execute 返回 `accept` 不带上下文 | 不进模型上下文 |

> 一句话：**DSH 的三级能力与我们的 block/warn/info 是天然同构的**，但"warn 想在写之前就提示"做不到——pre-execute 的 allow 分支无法携带任何面向模型的内容（`{kind:'allow'}` 没有 message 字段）。

---

## 5. Q4：插件装载与版本协商

### 5.1 发现与装载

1. profile 的 `package.json` 用 `dsh.profile.bundles` 记录已选 bundle（`app.asar!/node_modules/@deepseek-ai/dsh-app-boot/lib/index.js:619` 写入该字段）。
2. 每个包用 `dsh.bundle.patch` 指向自己的 patch 文件（`.../dsh-experimental-auto-review/package.json:79-83`）。
3. Loader 按层级合成 patch：insert row → 按 `id` override → `disabled` / `isolate` / `!!js`（`unpacked/.../cordis-composition-reference/SKILL.md:10-25`）。
4. 安装/启停入口三选一：`plugin_manager` 工具（`install_bundle` / `set_bundle` / `set_plugin`）、Web「Plugins」页、`dsh plugin --profile <p>` CLI。证据：`GH packages/boot/plugin-manager/README.md`（"Use this package" 节）。
5. 生效时机：开了 HMR 立即重合成；否则返回 `restart-required`（同上 README，`reason: no-hmr`）。

### 5.2 版本协商（这是问题 4 的实质答案）

| 机制 | 语义 | 证据 |
|---|---|---|
| `engines.dsh` | 作者声明的**兼容 DSH 版本 SemVer range**（可含精确 prerelease），与 `engines.node` 并列 | `app.asar!/node_modules/@deepseek-ai/dsh-package-manifest/README.md:53` |
| `peerDependencies` | 对具体 DSH 包（`@deepseek-ai/dsh-tools` 等）的版本约束，同时参与兼容检查 | `.../dsh-experimental-auto-review/package.json:31-39`（peer 全锁 `0.2.1-rc.3`） |
| 安装前检查 | 命名了包的安装命令先解析 `engines`+`peerDependencies`，不满足**在 pnpm 运行前**就拒绝，不下载、不跑构建脚本 | `GH packages/boot/plugin-manager/README.md`（"Version compatibility and exemptions"） |
| 启动复查 | profile 启动独立做一次 range 检查，不满足则拒绝装载 | 同上（"Startup checks run independently"） |
| 拒绝码 | `incompatible-version`，附 `name` / `version` / `runtimeVersion` / `requirements` | 同上 |
| 豁免 | profile 目录下 `compatibility.json` 写 `package@version → [runtime versions]`；`plugin_manager` 的 `set_version_exemption` / CLI `allow-version`，**需显式接受风险** | 同上 |
| 平台声明 | bundle 可声明 Host 平台，不符返回 `unsupported-platform`（字段名未逐字核对，见 §8） | 同上（"Bundle platform declarations are checked before saving"） |

> 对我们 L1 的直接含义：L1 声明 `"engines": { "dsh": "^0.2.1-rc.3" }` + 对 `@deepseek-ai/dsh-tools` 的 peer，就完成了版本协商；**不需要自己写版本探测代码**。

---

## 6. Q5：耗时是否阻塞生成、有无超时

### 6.1 阻塞：是，硬阻塞

pipeline 直接 `await` waterfall（`app.asar!/node_modules/@deepseek-ai/dsh-tools/lib/index.js:3321`、`:3427`、`:3600`）。handler 不 settle，工具体不派发，模型该步停住等待。没有任何 `Promise.race` 式兜底。

### 6.2 超时：**hook handler 没有内建超时**

- 事件文档只说"Async gates must observe `exec.signal`；registry 在其 settle 后复查取消，但 **never abandons their promise**"（`.../api-catalog.js:4487`；`GH packages/core/tools/src/events.ts`）。也就是说：它不会替你超时，只会检查你是否已被取消。
- 唯一的内建超时机制是 `@deepseek-ai/dsh-tool-call-timeout-policy`，它是 **`tools/execute` 包装**（`app.asar!/node_modules/@deepseek-ai/dsh-tool-call-timeout-policy/README.md:90`），位置在 `tools/pre-execute` **之后**、工具体之前 —— **管不到 pre-execute 里的审查耗时**。
- 而且它只对声明了 `timeoutMs` 的工具生效："undeclared tools (the shipped `bash`, `read`, `write`, and `edit` declare none) have no registry-wide default"（同上 `:122`）。即 `write`/`edit` **零默认预算**。
- 该超时本身也是协作式的：只通过 `exec.signal` 通知，工具不理就不会被打断（同上 `:120` 附近）。

### 6.3 唯一的"有超时"路径：hooks.json 桥（另一条路线，本机未装）

`dsh-hook-protocol` 为命令式 hook 定义了 `DEFAULT_HOOK_TIMEOUT_MS = 6e5`（10 分钟）——`app.asar!/node_modules/@deepseek-ai/dsh-hook-protocol/lib/index.js:185`；执行走 `ctx.shell`（`.../README.md:88`）。但该超时属于 **桥接的命令 hook**，不属于原生 Cordis listener。
**注意**：`dsh-hooks-claude-code` / `dsh-hooks-codex` 这两个桥插件在 master 的包清单里有（`unpacked/.../cordis-composition-reference/references/packages.md:211-212`），但**本机 0.2.1-rc.3 只安装了 `dsh-hook-protocol` 库，没有安装桥插件**（`app.asar` 内 `@deepseek-ai/dsh-hooks*` 检索为空）。

### 6.4 对 L1 的强制要求

审查源（Semgrep 毫秒~秒，AOR 十秒~分钟）**直接计入端到端延迟**。必须：
1. 自己实现预算法 + `AbortController`，并把它与 `exec.signal` 合并（`AbortSignal.any([exec.signal, budget.signal])`，官方 auto-review 就是这么做的：`app.asar!/node_modules/@deepseek-ai/dsh-experimental-auto-review/lib/index.js:469`）；
2. 明确 **fail-open（超时 → allow）还是 fail-closed（超时 → deny）**，这是我们要在论文里交代的设计选择；
3. 并发安全：并行工具调用会并发进入 handler（`isConcurrencySafe`，`GH packages/core/tools/src/contracts.ts`），L1 状态不能假设串行。

---

## 7. Q6：官方示例插件

| 参考对象 | 为什么值得抄 | 位置 |
|---|---|---|
| `@deepseek-ai/dsh-experimental-auto-review` | **最贴近本课题**：每工具 LLM 审查 → allow/deny/ask；`{prepend:true}` 抢队首；`AbortSignal.any` 做生命周期取消；dispose 时 abort 在途审查 | `app.asar!/node_modules/@deepseek-ai/dsh-experimental-auto-review/lib/index.js:455-503`；README `:60` |
| `@deepseek-ai/dsh-workspace-changes` | pre-execute 里等 per-turn 基线就绪再放行——正是"取证前先固定快照"的写法 | `.../dsh-workspace-changes/lib/index.js:1086-1094` |
| `@deepseek-ai/dsh-repeat-tool-reminder` | post-execute + `additionalContexts`：典型"只提示、不阻断"（= 我们的 warn） | `.../dsh-repeat-tool-reminder/lib/index.js:2254`；README `:84` |
| `@deepseek-ai/dsh-tool-call-timeout-policy` | `tools/execute` 环绕包装的最小正解（换 signal、finally 还原） | `.../dsh-tool-call-timeout-policy/README.md:61-72` |
| `@deepseek-ai/dsh-tool-jobs` | `{prepend:true}` 在 pre-execute 抢跑捕获调用的用例 | `.../dsh-tool-jobs/lib/index.js:235` |
| `@deepseek-ai/dsh-spill-policy` | post-execute 决策合并 + 追加 context 的写法 | `.../dsh-spill-policy/lib/index.js:245-253` |
| 插件骨架模板 | 可直接复制的 `package.json` / `cordis.patch.yml` / `index.js` / locale / icon | `unpacked/node_modules/@deepseek-ai/dsh-agent-preset/skills/cordis-plugin-development/templates/decoration/`（`package.json` 含 `dsh.bundle.patch` 与 `dsh.client`） |
| 文档级最小例 | permission-gate 的 12 行示例 | `DOC https://deepseek-harness.github.io/deepseek-harness/en/reference/cookbook/extension-cookbook.md` |

> 官方**没有**"代码审查插件"这个品类的示例；最接近的语义参照就是 auto-review（它对"待执行动作"做 LLM 风险判定并 deny/ask）。这对我们其实是好消息：生态位是空的，与 context.md 的判断一致。

---

## 8. 对 L1 的落点（结论性建议）

### 8.1 Change Event 字段的可获得性

| Change Event 字段 | 落地方式 |
|---|---|
| 事件 id | `exec.callId`（+ `exec.token` 做内部关联） |
| 变更文件列表 | 按 `exec.name` 分派解析 `arguments.file_path`；PTC 场景要处理 `exec.parent` 与 `run_code` |
| 统一 diff | **必须自产**。首选：post-execute 读 `result.meta.diffs`（`{path, oldText, newText}` hunk，仅 tool-fs 的 write/edit）；补充：`dsh-workspace-changes` 的 git 快照。二者都不是 git unified diff，需要自己归一 |
| 触发类型 | `exec.name` 分类：`write`/`edit`/`str_replace`… → 写入；`bash`/`pwsh` → 命令 |
| 时间戳 | 自记 |
| 会话 id | `exec.agent.session.id` |

### 8.2 必须在设计文档里写明的四个硬约束

1. **pre-execute 只能整调用拒绝**，无法"只拒其中一个文件"。
2. **pre-execute 看不到磁盘旧内容**，diff 与真实落盘可能不一致；post-execute 的 `result.meta` 才是真值。
3. **不能改写入内容**（§3.4）——我们只判定，不改写，与 context.md「不直接改写用户代码」一致，属于天然契合。
4. **阻塞即延迟**（§6），成本门控的价值因此不只是 token，还有端到端时延。

### 8.3 命名纠正

context.md 6.4 写的挂载点 `tools/pre-execute` / `tools/post-execute` **是对的**；但"Review Hook 挂载接口已就绪"应表述为「DSH 提供的是通用工具拦截缝（`tools/*`）与文件拦截缝（`fs/*`），没有专门的 Review Hook 抽象」——L1 的价值正是把这层通用缝归一成审查专用契约。

---

## 9. 未确认（不猜）

1. **`FsTarget` / `FsWriteIntent` 的完整字段**：只确认签名里有 `target: FsTarget` 与返回值 `{ version: FsVersion }`，以及 `target` 是"已解析的待写目标"（`.../api-catalog.js:4236-4257`）。是否携带文件内容/版本守卫语义，未读 `@deepseek-ai/dsh-fs` 的类型源码，未确认。
2. **`bash` 工具的参数字段名**（是否叫 `command`、`description`、`run_in_background`）：未逐字核对 `dsh-tool-bash` 的 `parameters`；退出码字段 `exitCode` 已确认（`.../dsh-tool-bash/lib/index.js:303,577`）。
3. **bundle 平台声明的字段名**：只确认存在"Bundle platform declarations … `unsupported-platform`"这一行为，未读到具体 `dsh.*` 字段名。
4. **handler 抛出异常时的确切 outcome**：`tools/post-execute` 的 listener 抛错是否被 contained 未逐字确认（`tools/result` 明确 contained，见 `.../dsh-tools/lib/index.js:3509`）。pre-execute 抛错的行为未确认。
5. **`agent.inject()` 与 `additionalContexts` 的语义差异边界**：`inject` 是"下一次模型请求可见、但不唤醒空闲 agent"（`DOC .../adding-a-tool.md`「Use `exec.agent` for async notifications」）；两者对 turn 内可见性的精确差异未实测。
6. **本机版本与 master 的差异**：GitHub/docs 抓取的是 master，本机是 0.2.1-rc.3。四个事件名、决策联合类型、`engines.dsh` 均已在 asar 内复核一致；其余（`dsh-hooks-*` 桥的细节、`.agents/notes` 决策记录）**未在本机复核**。
7. **PTC 模式（`run_code`）下模型直接调用工具会被 `UNKNOWN_TOOL` 拒绝**（`GH packages/core/tools/src/contracts.ts`，`ToolExecutionInput.parent` 注释）——这对我们的"命令执行触发"路径有影响，但未实测本机默认 preset 是否启用 PTC。

---

## 10. 证据索引（实际读过的关键文件）

**本机安装包（asar 内）**
- `app.asar!/package.json`（外壳 2.0.20-next）
- `app.asar!/node_modules/@deepseek-ai/dsh-tools/package.json`、`lib/index.js`、`README.md`
- `app.asar!/node_modules/@deepseek-ai/dsh-tool-cordis/lib/types/api-catalog.js`（生成式运行时 API 目录：事件签名 / 决策形状）
- `app.asar!/node_modules/@deepseek-ai/dsh-tool-fs/lib/index.js`
- `app.asar!/node_modules/@deepseek-ai/dsh-tool-bash/lib/index.js`
- `app.asar!/node_modules/@deepseek-ai/dsh-session/lib/index.js`
- `app.asar!/node_modules/@deepseek-ai/dsh-experimental-auto-review/{package.json,cordis.patch.yml,README.md,lib/index.js}`
- `app.asar!/node_modules/@deepseek-ai/dsh-workspace-changes/lib/index.js`
- `app.asar!/node_modules/@deepseek-ai/dsh-repeat-tool-reminder/{README.md,lib/index.js}`
- `app.asar!/node_modules/@deepseek-ai/dsh-tool-call-timeout-policy/README.md`
- `app.asar!/node_modules/@deepseek-ai/dsh-hook-protocol/{README.md,lib/index.js}`
- `app.asar!/node_modules/@deepseek-ai/dsh-spill-policy/lib/index.js`
- `app.asar!/node_modules/@deepseek-ai/dsh-tool-jobs/lib/index.js`
- `app.asar!/node_modules/@deepseek-ai/dsh-package-manifest/README.md`
- `app.asar!/node_modules/@deepseek-ai/dsh-app-boot/lib/index.js`

**本机 unpacked（可直接读的实体文件）**
- `unpacked/node_modules/@deepseek-ai/dsh-agent-preset/skills/cordis-plugin-development/SKILL.md`
- `unpacked/.../skills/cordis-plugin-development/references/{host-plugin.md,practices.md,ui-plugin.md,mcp-bundle.md}`
- `unpacked/.../skills/cordis-composition-reference/SKILL.md` + `references/packages.md`
- `unpacked/.../skills/cordis-plugin-development/templates/decoration/{package.json,cordis.patch.yml,index.js}`

**本机 profile**
- `C:\Users\romeo_keta\.dsh\cordis.patch.yml`

**官方文档 / 源码**
- DOC https://deepseek-harness.github.io/deepseek-harness/en/reference/cookbook/extension-cookbook.md
- DOC https://deepseek-harness.github.io/deepseek-harness/en/reference/cookbook/adding-a-tool.md
- GH `packages/core/tools/src/events.ts`
- GH `packages/core/tools/src/contracts.ts`
- GH `packages/core/tools/README.md`
- GH `packages/boot/plugin-manager/README.md`
