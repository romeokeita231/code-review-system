# AOR 接入契约（alibaba/open-code-review）

调研日期：2026-10-31　调研对象：GitHub `alibaba/open-code-review` @ `main`，最新发布 v1.13.3

> 方法说明：全部结论来自仓库源码、仓库内官方文档与 GitHub/npm API。
> **未执行 `ocr` 二进制**（本环境无该 CLI、无 LLM 凭据），因此"真实响应样例"给的是
> 官方 CLI Reference 中的样例 + 源码结构体定义，不是实测抓包。凡属推断均标注。

---

## 0. 结论速览

| 问题 | 结论 |
|---|---|
| 接入形态 | **CLI（Go 编译的单一二进制）**，npm 包只是下载器。**不提供 MCP server**，也不可作为库 import |
| MCP 工具名（server+tool） | **不存在**。AOR 是 MCP **client**（消费别人的 MCP 工具），不是 server |
| 喂统一 diff | **不支持**。必须落在 Git 仓库里，按 workspace / range / commit 三种模式取 diff |
| 限定文件集合 | `review`：只能 `--exclude` 排除；无 include/path。`scan`：有 `--path`（逗号分隔，**单个 flag**） |
| TypeScript | **支持**（`.ts` `.tsx` 在白名单；`.mts` `.cts` **不在**） |
| "evidence" 字段 | **没有叫 evidence 的字段**。最接近的是 `existing_code`（被引用的源码片段），但它 `omitempty`，可能缺失 |
| 典型耗时 | 分钟量级。官方样例 9 文件 = `1m12s`；单子任务预算默认 15 min |
| 超时/取消 | 有 `--timeout`、`OCR_LLM_TIMEOUT`、SIGINT 优雅取消；**无专用取消退出码** |
| 并发 | 进程内 `--concurrency` 默认 8；多进程并发未被官方声明支持（推断安全，见 §4.4） |
| 许可证 | Apache-2.0 |
| 最新版本 | v1.13.3（2026-10-22），npm `@alibaba-group/open-code-review@1.13.3` |

**对课题最关键的一条：`context.md` §7 把 AOR 的接入方式写成 "MCP client" 是错的。**
AOR 没有可供外部连接的 MCP server，必须用 `execa` 起子进程调 `ocr`。

---

## 1. 对外暴露的接入形态

### 1.1 是 CLI，不是 MCP server，不是库

CLI 的全部子命令里没有任何 `mcp` 服务端命令：

```text
Commands:
  review, r    Start a code review
  rules        Inspect and debug review rules
  config       Manage configuration settings
  llm          LLM utility commands
  viewer       Start the WebUI session viewer
  session, sessions  List and inspect saved review sessions
  version      Show version information
```

（`ocr scan`、`ocr auth`、`ocr completion` 亦存在，均非 MCP server）

来源：<https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/cli-reference.md>

### 1.2 "MCP Server" 文档说的是 AOR 当 client

官方文档开篇即明确：

> OCR can act as a **Model Context Protocol (MCP) client**. You point it at
> one or more external MCP servers, and the tools those servers expose
> become available to the review agent — right alongside the built-in tools.

来源：<https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/mcp.md>

源码层面也只有客户端实现，没有服务端：

- `internal/mcp/client.go`（8.0 KB）— MCP 客户端
- `internal/mcp/provider.go` — 把远端工具注册给审查 agent
- 目录下无 `server.go` / `serve.go`

来源：<https://github.com/alibaba/open-code-review/tree/main/internal/mcp>

MCP 配置项挂在 AOR 自己的配置里，方向是"AOR 连出去"，配置键为 `mcp_servers.*`
（`type` / `command` / `args` / `url` / `headers` / `tools` / `setup` / `env`），
写入 `~/.opencodereview/config.json`。

来源：<https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/mcp.md>

### 1.3 也不是可 import 的库

- 语言是 **Go**（`go.mod` 存在，GitHub language 字段为 `Go`）。
- npm 包 `@alibaba-group/open-code-review` 的 `bin` 只有 `ocr`，`files` 只含
  `bin/ocr.js` 与 `scripts/*`，`postinstall` 会去 GitHub Releases 下载对应平台二进制：
  `"urlPattern": "https://github.com/alibaba/open-code-review/releases/download/v{version}/opencodereview-{os}-{arch}"`

来源：<https://github.com/alibaba/open-code-review/blob/main/package.json>、
<https://registry.npmjs.org/@alibaba-group/open-code-review/latest>

结论：**TypeScript 侧只能按"外部进程 + JSON 契约"接入**，与 `context.md` §7 给 Semgrep 的
`execa` 子进程方式同构。

### 1.4 另一个可选形态：ACP（非 MCP，实验性）

`acp/` 是一个**独立的 Agent Client Protocol v1 stdio 适配器**（独立 Go module，独立二进制 `ocr-acp`）：

- 暴露 `/review` 和 `/scan` 两个 ACP slash command
- **仅可源码编译**：`make -C acp build`
- 官方标注：`The ACP adapter is experimental and currently unstable.`

来源：<https://github.com/alibaba/open-code-review/blob/main/acp/README.md>

与课题无关（DSH 不是 ACP 客户端），列出仅为排除。

---

## 2. 输入形态：能不能喂 diff、限定文件集、支持 TS

### 2.1 不能直接喂统一 diff

`ocr review` 自己从 Git 取 diff，**没有任何 stdin / `--diff <file>` 入口**。三种模式：

| 模式 | 取值方式 |
|---|---|
| workspace（默认，无 flag） | `git diff HEAD`（staged+unstaged），空则回退 `git diff --staged`；未跟踪文件用 `git ls-files --others --exclude-standard` 读盘后当作整文件新增 |
| range | `--from <ref> --to <ref>`，实际算 `merge-base(from,to)..to` |
| commit | `--commit <sha>`，等价 `git show <sha>` |

来源：<https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/cli-reference.md>

ACP 文档进一步确认非 Git 场景被拒绝：

> Review resolves locations against the nearest Git root; non-Git review is refused.

来源：<https://github.com/alibaba/open-code-review/blob/main/acp/README.md>

**对课题的含义**：`Change Event`（§6.1）里已经算好的"统一 diff"无法直接交给 AOR。
只能二选一：
1. 让 AOR 读工作区当前状态（workspace 模式）——但这样拿到的是"整个工作区 vs HEAD"，
   不是"这一次写入"；
2. 用 `ocr scan --path <改动文件列表>` 做**整文件审查**（丢掉 diff 语义，成本更高、噪声更多）。

这是设计约束，不是实现细节。

### 2.2 限定文件集合

`ocr review` 的 flag 表里**没有 `--path` / `--include`**，只有：

| Flag | 说明 |
|---|---|
| `--exclude <patterns>` | 逗号分隔、gitignore 风格，与 `rule.json` 的 `excludes` 合并 |
| `--repo <path>` | 仓库根 |
| `--rule <path>` | 自定义规则文件 |

来源：同上 cli-reference

`ocr scan` 才有 `--path`：

> `--path <list>` — Comma-separated repo-relative directories or files to scan
> (e.g., `internal/agent`, `internal/llm/client.go`) … a selector that names no
> existing path is an error rather than an empty scan.

来源：同上 cli-reference

**重要坑（官方明写）**：`--path` 必须**一个 flag 逗号拼接**，重复传只取最后一个：

> It pins the `--path` comma-joining rule end to end (a repeated `--path` would
> silently scan only the last path).

来源：<https://github.com/alibaba/open-code-review/blob/main/acp/README.md>

**对成本门控的含义**：档位 1 想要的"语义源限定文件集"在 `review` 模式下**做不到**
（只能反向用 `--exclude` 排除掉其余文件）。可行实现是把非目标路径构造成 `--exclude` 列表，
或用 `scan --path` 换取精确文件集、付出整文件 token 代价。

### 2.3 文件是否进入审查的确定性筛选

`review` 的筛选是**纯函数、预先决定**的，顺序为：
binary → secret path → 用户 exclude → 用户 include（命中即放行）→ 扩展名白名单 → 默认排除路径，
之后还有"单文件 diff 超过 `MAX_TOKENS` 80%"的体积门。

来源：<https://github.com/alibaba/open-code-review/blob/main/internal/agent/selection.go>

### 2.4 TypeScript 支持：支持

白名单里明确包含 `.ts` / `.tsx` / `.js` / `.jsx` / `.mjs` / `.cjs`：

```json
".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
```

来源：<https://github.com/alibaba/open-code-review/blob/main/internal/config/allowlist/supported_file_types.json>

**坑**：`.mts` / `.cts` **不在白名单**。纯 ESM/CJS 双格式的 TS 项目里这两类文件
会被静默排除（`ExcludeExtension`），不报错。若课题工程用 `.mts`，需在适配层显式记录该盲区。

### 2.5 其它会影响接入的参数

| 参数 | 默认 | 为什么重要 |
|---|---|---|
| `--format` | `text` | 取 `json` 或 `sarif`（SARIF 2.1.0，可用于 GitHub Code Scanning） |
| `--audience` | `human` | `json` 下进度行走 stderr；`agent` 完全静默。**建议固定 `--audience agent`** |
| `--output` | stdout | 写文件（懒创建，失败不覆盖旧文件） |
| `--concurrency` | `8` | 进程内并行子任务数 |
| `--max-git-procs` | `16` | 并发 git 子进程上限 |
| `--effort` | `medium` | `low`=1 轮、`medium`=2 轮、`high`=3 轮；`--timeout` 随轮数线性放大 |
| `--no-filter` | `false` | 跳过 `REVIEW_FILTER_TASK` 这道"评论过滤"LLM 后处理 |
| `--background` / `-B` | — | 注入需求/业务上下文，官方称"调用质量杠杆最高的 flag" |
| `--max-tokens-budget` | `0`（不限） | 总 token 上限，超了给最后一轮提交机会并标 `failed(budget)` |

来源：<https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/cli-reference.md>

---

## 3. 返回体：评论 / 位置 / 证据片段

### 3.1 顶层信封（`--format json`）

`jsonOutput` 结构体定义（`cmd/opencodereview/output.go`）：

```go
type jsonOutput struct {
	Status         string                `json:"status"`
	LLM            *jsonLLMIdentity      `json:"llm,omitempty"`      // provider, model
	TraceID        string                `json:"trace_id,omitempty"`
	Message        string                `json:"message,omitempty"`
	Summary        *jsonSummary          `json:"summary,omitempty"`
	ToolCalls      *jsonToolCalls        `json:"tool_calls"`
	Comments       []model.LlmComment    `json:"comments"`
	Groups         []agent.FileGroupInfo `json:"groups,omitempty"`
	Warnings       []agent.AgentWarning  `json:"warnings,omitempty"`
	ProjectSummary string                `json:"project_summary,omitempty"`
	Resume         *agent.ResumeInfo     `json:"resume,omitempty"`
	SessionID      string                `json:"session_id,omitempty"`
	Manifest       *session.RunManifest  `json:"manifest,omitempty"`
	RetryReport    *llm.RetryReport      `json:"retry_report,omitempty"`
}
```

`jsonSummary`：

```go
type jsonSummary struct {
	FilesReviewed    int64  `json:"files_reviewed"`
	Comments         int64  `json:"comments"`
	TotalTokens      int64  `json:"total_tokens"`
	InputTokens      int64  `json:"input_tokens"`
	OutputTokens     int64  `json:"output_tokens"`
	CacheReadTokens  int64  `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens int64  `json:"cache_write_tokens,omitempty"`
	Elapsed          string `json:"elapsed"`
	BudgetExceeded   bool   `json:"budget_exceeded,omitempty"`
}
```

来源：<https://github.com/alibaba/open-code-review/blob/main/cmd/opencodereview/output.go>

### 3.2 单条评论 = 位置 + 证据的唯一载体

```go
// LlmComment represents a code review comment generated by the LLM.
type LlmComment struct {
	Path           string `json:"path"`
	Content        string `json:"content"`
	SuggestionCode string `json:"suggestion_code,omitempty"`
	ExistingCode   string `json:"existing_code,omitempty"`
	StartLine      int    `json:"start_line"`
	EndLine        int    `json:"end_line"`
	Thinking       string `json:"thinking,omitempty"`
	// Category: bug, security, performance, maintainability, test, style, documentation, other.
	Category string `json:"category,omitempty"`
	// Severity: critical, high, medium, low.
	Severity string `json:"severity,omitempty"`
}
```

来源：<https://github.com/alibaba/open-code-review/blob/main/internal/model/review.go>

**字段语义对照到 `Finding` 六元组**：

| Finding 字段 | AOR 来源字段 | 备注 |
|---|---|---|
| 文件 | `path` | 仓库相对路径 |
| 行/行区间 | `start_line` / `end_line` | **1-indexed**；**`0/0` 表示文件级评论**，此时禁止编造行号 |
| 符号 | **无** | AOR 不返回符号名，只能置空 |
| 严重度 | `severity` | **可选**，open set（critical/high/medium/low 见过） |
| 置信度 | **无** | AOR 不返回任何概率/分数 → 校准环节对 AOR 无原始分值可用 |
| 来源 | 常量 `aor` | — |
| 缺陷类别 | `category` | **可选**，open set，含 `security` |
| 可执行证据 | `existing_code`（+`suggestion_code`） | **`omitempty`，可能缺失** |

1-indexed 与 `0/0` 的原文：

> `StartLine` and `EndLine` are 1-indexed; when both are 0 the finding is
> file-level and the adapter must not invent a line number. Severity is an open
> set (critical, high, medium, low have been observed, but consumers must
> tolerate unknown values).

来源：<https://github.com/alibaba/open-code-review/blob/main/acp/internal/contract/result.go>

### 3.3 没有 `evidence` 字段——这是课题最需要警惕的点

全仓库搜不到叫 `evidence` 的 JSON 字段。"证据片段"在 AOR 里由三样东西分担：

| 字段 | 是什么 | 能不能当 evidence |
|---|---|---|
| `existing_code` | 评论所指的**原文片段**（用于渲染 `-`/`+` 建议 diff） | ✅ 最接近，但 `omitempty`，为空时整条评论可能只剩散文 |
| `suggestion_code` | 建议替换后的代码 | 是"修法"不是"证据" |
| `thinking` | 模型推理过程 | ❌ AOR 自己明确不对外传播：Contract 层注释写 `thinking` is deliberately not modeled … must never reach the user |

`thinking` 的排除原文：

> `thinking` is deliberately not modeled. It is per-comment model reasoning
> that must never reach the user, and a field that does not exist on the DTO
> cannot leak by accident.

来源：<https://github.com/alibaba/open-code-review/blob/main/acp/internal/contract/result.go>

**对 `context.md` §6.2 硬规则的直接影响**："没有 evidence 的 AOR 发现直接丢弃"
在实现上会等价于"`existing_code` 为空的发现丢弃"。由于 `existing_code` 是 `omitempty`
且由模型生成，这条规则会**静默丢掉一部分真实发现**，需要在论文里显式说明这条取舍，
并在适配层单独统计丢弃率（否则会污染 Recall 指标）。

### 3.4 官方 JSON 样例（9 文件一轮，含 1 条评论）

```json
{
  "status": "success",
  "llm": {
    "provider": "anthropic",
    "model": "claude-opus-4-6"
  },
  "summary": {
    "files_reviewed": 9,
    "comments": 1,
    "total_tokens": 21344,
    "input_tokens": 18012,
    "output_tokens": 3332,
    "elapsed": "1m12s"
  },
  "comments": [
    {
      "path": "src/foo.go",
      "content": "Concurrent map access without a lock — wrap with sync.RWMutex.",
      "start_line": 42,
      "end_line": 47,
      "existing_code": "m[k] = v",
      "suggestion_code": "mu.Lock(); defer mu.Unlock(); m[k] = v",
      "thinking": "Looking at line 42, the map …"
    }
  ]
}
```

来源：<https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/cli-reference.md>

（注意该样例未出现 `category` / `severity`，因为二者 `omitempty`；这本身就是证据：
**这两个字段经常为空**。）

### 3.5 无改动 / 无命中 用 `skipped` 区分

```json
{
  "status": "skipped",
  "message": "No supported files changed.",
  "llm": { "provider": "anthropic", "model": "claude-opus-4-6" },
  "comments": []
}
```

来源：同上 cli-reference。对应 `outputJSONNoFiles()`：<https://github.com/alibaba/open-code-review/blob/main/cmd/opencodereview/output.go>

### 3.6 `status` 取值与 `manifest`（判断"审完了没"必须看它）

- 有 `manifest` 时：`complete` / `partial` / `failed` / `skipped`（取 manifest 的 terminal state）
- 无 `manifest` 时：`success` / `completed_with_warnings` / `completed_with_errors`

`manifest` 结构（契约镜像）：`schema_version`、`operation`、`terminal_state`、
`run_failure{classification,reason}`、`coverage{selected,completed,reused,failed,waived}`，
每个 `CoverageItem` 带 `path` / `classification` / `reason`。

来源：<https://github.com/alibaba/open-code-review/blob/main/acp/internal/contract/result.go>

**仲裁层用法**：`partial` / `completed_with_errors` 意味着"有文件没审"，此时 AOR 的
"未报"不能当作"干净"用于冲突消解（§8.2 的"一源报有、另一源未报"会被 coverage 缺口污染）。

### 3.7 另一条更标准的出口：SARIF

`--format sarif` 输出 SARIF 2.1.0（官方描述：`for GitHub Code Scanning`）。
`--preview` 与 sarif 互斥。若融合层愿意接标准格式，SARIF 的 `region.startLine/endLine`
比自定义 JSON 更稳；但 SARIF 不含 `existing_code` 这类证据片段，**证据仍只能从 JSON 拿**。

来源：<https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/cli-reference.md>

---

## 4. 耗时、超时、取消、并发

### 4.1 耗时量级：分钟

| 证据 | 数值 |
|---|---|
| 官方 CLI 输出样例（9 文件 / 14 评论） | `1m12s elapsed` |
| 单子任务预算 `--timeout` 默认 | `15` 分钟（含 LLM、工具、重试等待） |
| `--timeout` 随 effort 线性放大 | low/medium/high → 15/30/45 分钟 |
| 单次 LLM 请求超时 `OCR_LLM_TIMEOUT` / provider `timeout_sec` | 默认 `300` 秒 |
| ACP 文档对 `/review --effort low` 的说法 | "faster development check"（≤1 轮） |

来源：<https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/cli-reference.md>、
<https://github.com/alibaba/open-code-review/blob/main/acp/README.md>

**所以 `context.md` §7 写的"AOR 十秒到分钟"应改为"分钟级，单次常见 1–3 min，
大 changeset 可达 10 min+"**。"十秒"只可能出现在 `--effort low` + 极少文件时。

绝对均值官方**未给**（README benchmark 只有相对结论："比通用 agent 快"、"~1/9 token"），
故：**具体 P50/P95 数值未确认**，必须自测。

### 4.2 超时控制（多层，可组合）

1. `--timeout <minutes>`：**per-subtask** 预算，`0` 关闭任务级 deadline（但不关请求超时）
2. `OCR_LLM_TIMEOUT` 或 provider `timeout_sec`：**per-request** 超时，默认 300s
3. `--max-tokens-budget`：总 token 预算，超了不再派发新子任务，已派发的给最后一轮
4. `--max-tools` / `--max-tokens`：单子任务工具轮次与 prompt token 上限

来源：<https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/cli-reference.md>

适配层的 `AbortController + 每源预算上限`（`context.md` §7）应映射到 **① `--timeout` 传小值 +
② 宿主侧 kill 进程树**，因为 CLI 自己不会因为宿主超时而退出。

### 4.3 取消机制与它的坑

- **SIGINT/SIGTERM**：文件派发开始后 Ctrl-C 会优雅取消，并写出带 manifest 的会话
  （因此 `complete` 之外的 `cancelled` 可从 manifest 读出）。
- **没有专用取消退出码**：

  > the CLI has no dedicated cancellation exit code

  取消的表现是 `manifest.run_failure.classification == "cancelled"` 或
  `coverage.failed[].classification == "cancelled"`，**退出码仍是 1**。
  来源：<https://github.com/alibaba/open-code-review/blob/main/acp/README.md>

**对课题的含义**：靠退出码区分"审完无问题"与"被杀"不可行。必须解析 stdout 的
`status` + `manifest.coverage.failed[].classification`。而进程被硬杀（kill -9 / Job Object
强杀）时 stdout 可能只有半截 JSON → 适配层必须做**容错解析 + 判定为 `unknown`**，
不能把解析失败当"无发现"。

ACP 侧的取消实现值得参考（幂等、进程组/Job Object 清理）：
`Cancel is idempotent`、EOF/SIGINT/SIGTERM 取消并等待子进程清理、Windows 用 Job Object。
来源：<https://github.com/alibaba/open-code-review/blob/main/acp/README.md>

### 4.4 并发

**进程内**：`--concurrency` 默认 8（并行审子任务），`--max-git-procs` 默认 16。

**多进程并发调用同一个仓库**——官方**未声明**支持，以下是源码推断：

- 审查过程**不写仓库**，只往 `$HOME/.opencodereview/sessions/<encoded-repo-path>/<session-id>.jsonl` 写
- 文件名用 **UUID v4** 生成，`O_CREATE|O_WRONLY|O_TRUNC` 打开独立文件
- 写入器有 `sync.Mutex`，但那是**进程内**保护；跨进程靠文件名不冲突
- 运行时只**读** `~/.opencodereview/config.json`

来源：<https://github.com/alibaba/open-code-review/blob/main/internal/session/persist.go>

推断结论：**同仓库并发跑多个 `ocr` 在文件落盘上大概率安全**（各自独立 session 文件、不写仓库），
但 `ocr config set` 并发写配置没有加锁，且 git 子进程在同仓库并发仍受 git 自身锁影响。
→ 标记为 **"推断：基本安全，官方未确认"**。工程上建议：并发调用时用不同 `--output`、
不要并发执行 `ocr config`，并给每个进程独立超时。

### 4.5 退出码只有两档

| Code | 含义 |
|---|---|
| `0` | 审完（可能 0 条评论，可能有非致命 warning） |
| `1` | 致命错误（flag 错、LLM 端点解析失败、所有子 agent 全失败等） |

来源：<https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/cli-reference.md>

→ 错误码归一（`context.md` §7 "适配器负责错误码归一"）在 AOR 上信息量极低，
**必须靠 stdout JSON 本体**。

---

## 5. 许可证、活跃度、版本

| 项 | 值 | 来源 |
|---|---|---|
| 许可证 | **Apache-2.0**（`LICENSE`，Copyright 2026 Alibaba） | <https://github.com/alibaba/open-code-review/blob/main/LICENSE>；GitHub API `license.spdx_id = "apache-2.0"` |
| 最新 Release | **v1.13.3**，发布于 2026-10-22 | <https://github.com/alibaba/open-code-review/releases/tag/v1.13.3> |
| npm 最新版 | **1.13.3**（与 Release 对齐，可信发布 + SLSA provenance） | <https://registry.npmjs.org/@alibaba-group/open-code-review/latest> |
| 创建时间 | 2026-05-18 | <https://api.github.com/repos/alibaba/open-code-review> |
| 最后 push | 2026-10-29 | 同上 |
| Stars / Forks | **48,981** / **3,584** | 同上 |
| Open issues | 359 | 同上 |
| 主语言 | Go | 同上 |

**发布节奏**（近期，可判断活跃度）：

| 版本 | 日期 |
|---|---|
| v1.13.3 | 2026-10-22 |
| v1.13.2 | 2026-10-20 |
| v1.13.0 | 2026-10-13 |
| v1.12.13 | 2026-10-08 |

**约每周 1–2 次发版**，2026-10 月内至少 4 个版本 → 维护高度活跃。

其它治理信号：仓库含 `GOVERNANCE.md`、`CONTRIBUTING.md`、`ROADMAP.md`、
`ASSURANCE_CASE.md`，README 挂 OpenSSF Best Practices **Gold** 徽章。

**风险提示**：迭代这么快意味着 **JSON 契约（尤其 `manifest` / `status`）会漂移**。
契约方自己也承认这点：

> Status values are an open set. Review and scan report different names, and a
> newer CLI may add more, so consumers must tolerate unknown values rather than
> fail on them.

来源：<https://github.com/alibaba/open-code-review/blob/main/acp/internal/contract/result.go>

→ 适配层必须**版本固定 + 宽松解析 + 未知字段忽略**，与 `context.md` §7 对 Semgrep
"版本必须固定"的要求同理。

---

## 6. 对 `context.md` 的修正建议（仅记录，未改文件）

| 位置 | 现状 | 建议 |
|---|---|---|
| §7 信号源表 | AOR 接入方式 = "MCP client" | 改为 **"execa 子进程 + `--format json`"**，与 Semgrep 同构；MCP 不适用 |
| §7 信号源表 | AOR 输出 = "评论 + 位置 + 证据片段" | 补准确字段名：`content` / `path`+`start_line`+`end_line` / `existing_code` |
| §7 信号源表 | AOR 约束 "十秒到分钟" | 改"分钟级，默认单次 1–3 min，per-subtask 预算默认 15 min" |
| §6.2 硬规则 | 无 evidence 即丢弃 | 明确"evidence = `existing_code` 非空"，并**统计丢弃率**写进评测 |
| §6.2 置信度 | 六元组必备"置信度原始分值" | AOR **不返回任何分值** → 必须定义"无分值"的表示（如 `null` + 来源先验），否则 schema 无法落地 |
| §9 档位 1 | "语义源限定文件集" | `review` 只能 `--exclude` 反向排除；要正向指定文件集只能用 `scan --path`（成本不同），需在论文里交代这个实现妥协 |

**额外可用的一个杠杆**：`--background` / `-B` 可把需求/变更意图注入 AOR 的 plan+main prompt，
官方称其为"调用质量杠杆最高的 flag"。正好对应课题的"意图偏移"类，可用于 B2/B3/B4 对照。

---

## 7. 未确认清单（不要当结论用）

1. **实测 JSON 响应**：本环境无 `ocr` 二进制与 LLM 凭据，未跑真实调用。样例来自官方文档。
2. **P50/P95 延迟绝对值**：官方只给相对 benchmark 结论，无绝对秒数。
3. **同仓库多进程并发的官方保证**：无文档声明；§4.4 结论为源码推断。
4. **`category` / `severity` 的实际出现率**：二者 `omitempty`，官方样例中缺失；真实填充率未确认。
5. **`evidence` 是否存在其它别名**（如 SARIF `snippet`）：SARIF 分支未逐字段核对。
6. **v1.13.3 之后是否已有契约变更**：调研快照为 2026-10-31，`main` 仍在动。

---

## 8. 来源索引

| # | 用途 | 链接 |
|---|---|---|
| 1 | 命令全集、全部 flag、JSON 样例、退出码 | <https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/cli-reference.md> |
| 2 | AOR 是 MCP client 的官方说明 | <https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/mcp.md> |
| 3 | MCP 客户端源码（无 server） | <https://github.com/alibaba/open-code-review/tree/main/internal/mcp> |
| 4 | `LlmComment` 定义（评论字段） | <https://github.com/alibaba/open-code-review/blob/main/internal/model/review.go> |
| 5 | `jsonOutput` / `jsonSummary` 信封 | <https://github.com/alibaba/open-code-review/blob/main/cmd/opencodereview/output.go> |
| 6 | 契约镜像 + 1-indexed / 0-0 / open set 注解 | <https://github.com/alibaba/open-code-review/blob/main/acp/internal/contract/result.go> |
| 7 | ACP 适配器、取消语义、`--path` 坑 | <https://github.com/alibaba/open-code-review/blob/main/acp/README.md> |
| 8 | 扩展名白名单（TS 支持） | <https://github.com/alibaba/open-code-review/blob/main/internal/config/allowlist/supported_file_types.json> |
| 9 | 文件筛选确定性逻辑 | <https://github.com/alibaba/open-code-review/blob/main/internal/agent/selection.go> |
| 10 | 会话落盘与并发隔离 | <https://github.com/alibaba/open-code-review/blob/main/internal/session/persist.go> |
| 11 | 项目概览、许可证、安装 | <https://github.com/alibaba/open-code-review/blob/main/README.md> |
| 12 | 仓库元数据（stars/活跃度/许可） | <https://api.github.com/repos/alibaba/open-code-review> |
| 13 | 版本与发版节奏 | <https://github.com/alibaba/open-code-review/releases> |
| 14 | npm 包版本与分发方式 | <https://registry.npmjs.org/@alibaba-group/open-code-review/latest> |
