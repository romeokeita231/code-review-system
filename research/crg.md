# CRG（tirth8205/code-review-graph）接入契约

调研对象：GitHub `tirth8205/code-review-graph`，简称 CRG。
调研日期：2026-10-31。结论所依据的版本：**PyPI 2.3.9（2026-09-18 发布）**，仓库默认分支 `staging`。
调研方式：读官方 README / docs / 源码，并在本机用 `uv` 装了 `code-review-graph==2.3.9`，在一个自建的 TypeScript 夹具上真实跑通建图与 blast-radius 查询（复现步骤见 §9）。凡是在本机跑出来的数字，都标了「实测」；凡是官方没给、我也没跑到的，标「未确认」。

---

## 0. 结论先行：能否满足「分诊只需要受影响文件数 + 调用方数」

**一半能满足，一半不能——缺的正是「调用方数」。**

| 分诊输入 | 可得性 | 字段 / 取法 | 一次调用够不够 |
| --- | --- | --- | --- |
| 受影响文件数 | ✅ 直接有 | `detail_level="minimal"` → `impacted_file_count`（未截断的真实总数）；`"standard"` → `len(impacted_files)` | 够 |
| 调用方数 | ❌ **没有这个字段** | 只能用代理量或额外查询，见下 | 不够 |

三个替代口径，按代价从低到高：

1. **`total_impacted`（standard 模式）**：2 跳内受影响**节点**数，不是调用方数——它把 File 节点、测试节点、传递依赖都算进去了。语义最近，实现最便宜（仍是同一次调用）。
2. **`impacted_nodes[*].call_site_count`（standard 模式）**：只对「一跳内直接 CALLS/REFERENCES 到改动代码」的节点出现，是该节点直连改动点的调用点数，且列表被 100 节点上限截断（见 §2.4）。它统计的是「调用点」不是「调用方节点」。
3. **逐符号 `query_graph(pattern="callers_of")`**：真正给出调用方——响应里 `result_count`（调用点总数）和 `distinct_nodes`（去重后的调用方节点数）。代价是对每个变更符号发一次 MCP 调用（实测单次 ≈7 ms，见 §5），符号多时是 N 次往返。

关键源码依据：`get_impact_radius` 的返回字典里不存在 `caller_count` / `callers` 字段（源码见 [tools/query.py](https://github.com/tirth8205/code-review-graph/blob/staging/code_review_graph/tools/query.py)，本机 2.3.9 实测返回的键为 `changed_files, changed_nodes, changed_nodes_omitted, context_savings, edges, edges_omitted, impacted_files, impacted_files_omitted, impacted_nodes, nodes_omitted, resolution, status, summary, total_impacted, truncated, unresolved_call_sites`）。数据库里确实有每符号的 `risk_index.caller_count` 列（[docs/schema.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/schema.md)），本机实测该表已按符号填满（200 文件夹具 → 400 行，如 `src/m1.ts::f1` 的 `caller_count=2`），但它只被 `detect_changes` 的风险打分内部消费，**没有被 `get_impact_radius` 的任何响应字段暴露**。

**给本课题的判定**：分诊契约不能写成「受影响文件数 + 调用方数」两个输入，除非接受其中一个是代理量。建议二选一并写进设计规格：

- **方案 A（推荐，零额外调用）**：门控输入改为 `(impacted_file_count, total_impacted)`，其中 `total_impacted` 明确定义为「2 跳内受影响节点数」，论文里说明它与「调用方数」的偏差（含测试节点与文件节点，且 CAP 在 500 节点 / 深度 2）。
- **方案 B（语义严格，N 次调用）**：变更符号集合 → 逐个 `callers_of` 求和去重。要把「符号数 × 单次延迟」计入分诊预算，并为符号数设上限，否则一次大改动会退化成几十次 MCP 往返。

---

## 1. 接入形态：MCP server / CLI / Python 库（三者都有，无 Node 库）

CRG 是一个 **Python 包**（`>=3.10`，PyPI `requires_python >=3.10`），不是 TypeScript/Node 库。对 TS 主工程而言，**只能进程外接入**：MCP 子进程、CLI 子进程，或另起一个 Python 进程 import 它。三条路都存在：

| 形态 | 入口 | 适用 |
| --- | --- | --- |
| MCP server（推荐） | `code-review-graph serve`（stdio，默认） | 与 `@modelcontextprotocol/sdk` 的 MCP client 对接，工具调用即结构化 JSON |
| MCP over HTTP | `code-review-graph serve --http`（默认 `127.0.0.1:5555`，`--host`/`--port` 可改） | 需要长驻、多客户端共享一个 server 时 |
| CLI | `build` / `update` / `status` / `detect-changes --brief` / `serve` | 人工排障、CI（GitHub Action） |
| Python 库 | `from code_review_graph.tools.query import get_impact_radius` | 只在本机 Python 侧写脚本/评测时 |

来源：[README Quick Start 与 CLI reference](https://github.com/tirth8205/code-review-graph/blob/staging/README.md)、[docs/COMMANDS.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/COMMANDS.md)、[PyPI 2.3.9 元数据](https://pypi.org/pypi/code-review-graph/2.3.9/json)。

### 1.1 准确的 server 启动方式

`serve` 的实际参数（本机 `code-review-graph serve --help` 实测，2.3.9）：

```
usage: code-review-graph serve [-h] [--repo REPO] [--auto-watch]
                               [--tools TOOLS] [--http] [--host ADDR]
                               [--port PORT]
  --repo REPO    Repository root (auto-detected)
  --auto-watch   Start filesystem watch in a daemon thread while MCP server runs
  --tools TOOLS  Comma-separated list of tool names to expose ... Falls back to CRG_TOOLS env var
  --http         Listen for MCP over Streamable HTTP on localhost (default port 5555)
  --host ADDR    Bind address for --http (default: 127.0.0.1)
  --port PORT    Port for --http (default: 5555)
```

`code-review-graph mcp` 是 `serve` 的别名，但只接受 `--repo` 和 `--auto-watch`（[docs/COMMANDS.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/COMMANDS.md)）。

stdio 形态的 MCP 客户端配置（官方给的就是 `command` + `args: ["serve", "--repo", ...]`）：

```json
{
  "mcpServers": {
    "code-review-graph": {
      "command": "code-review-graph",
      "args": ["serve", "--repo", "F:\\path\\to\\repo"]
    }
  }
}
```

Windows 上官方建议直接把 `command` 指向 venv 里的 `.exe`，不要套 `cmd /c`，并设 `PYTHONUTF8=1`，否则会报 `Invalid JSON: EOF while parsing` / `MCP error -32000: Connection closed`（[README Troubleshooting](https://github.com/tirth8205/code-review-graph/blob/staging/README.md)）。

对本课题最有用的一条：**用 `--tools` 把 30 个工具裁到 1–2 个**，如 `serve --tools get_impact_radius_tool,query_graph_tool`。既不暴露用不到的工具（少 30 个工具的 schema token），也避免模型误调到写工具。

### 1.2 工具名称与入参 schema

MCP 工具名 = 函数名 + `_tool` 后缀，用 FastMCP 的 `@mcp.tool()` 注册，schema 由函数签名自动生成（本机读安装包 `code_review_graph/main.py` 确认：`@mcp.tool() async def get_impact_radius_tool(...)`）。工具总数 30（[README](https://github.com/tirth8205/code-review-graph/blob/staging/README.md)、[tools/\_\_init\_\_.py](https://github.com/tirth8205/code-review-graph/blob/staging/code_review_graph/tools/__init__.py)）。

`get_impact_radius_tool` 的入参（源码签名，[tools/query.py](https://github.com/tirth8205/code-review-graph/blob/staging/code_review_graph/tools/query.py)）：

| 参数 | 类型 | 默认 | 含义 |
| --- | --- | --- | --- |
| `changed_files` | `list[str] \| None` | `None` | 变更文件，相对仓库根。**不传则自动跑 git diff**，由 `base` 决定基线 |
| `max_depth` | `int` | `2` | 图遍历跳数（可用 `CRG_MAX_IMPACT_DEPTH` 改默认） |
| `max_results` | `int` | `500` | 每个列表的显示上限（仍受硬上限压制，见 §2.4） |
| `repo_root` | `str \| None` | `None` | 仓库根；不传则自动探测 |
| `base` | `str` | `"HEAD~1"` | 仅在 `changed_files` 为空时用于 git 发现变更 |
| `detail_level` | `"standard" \| "minimal"` | `"standard"` | 精简/完整输出 |
| `resolution` | `"all" \| "direct" \| "unresolved"` | `"all"` | `direct` 会拒绝沿「目标从未绑定到已索引节点」的 CALLS/REFERENCES 边扩散 |

`resolution` 对分诊很关键：`direct` 是「宁可少报也不臆测」的开关，会缩小 radius，适合我们对误报敏感的门控；`all` 是默认的保守扩张。`max_results` 小于 1 或传 bool 会直接 `ValueError`（源码里显式校验）。

---

## 2. blast-radius 查询返回什么

### 2.1 真实响应样例（本机 2.3.9 实测，非文档转述）

夹具：4 个 TS 文件 / 12 节点 / 22 边（`src/math.ts`、`src/use.ts`、`src/main.ts`、`src/use.test.ts`，含跨文件 import、调用与一条 vitest 测试）。
调用：`get_impact_radius(changed_files=["src/math.ts"], detail_level="standard")`。
下面是**原样输出**，仅把绝对路径前缀 `C:/Users/…/fixture/` 缩写成 `<fx>/`：

```json
{
  "status": "ok",
  "summary": "Blast radius for 1 changed file(s):\n  - 4 nodes directly changed\n  - 7 nodes impacted (within 2 hops)\n  - 3 additional files affected",
  "changed_files": ["src/math.ts"],
  "changed_nodes": [
    {"id": 3, "kind": "File", "name": "<fx>/src/math.ts", "qualified_name": "<fx>/src/math.ts",
     "file_path": "<fx>/src/math.ts", "line_start": 1, "line_end": 4,
     "language": "typescript", "parent_name": null, "is_test": false},
    {"id": 4, "kind": "Function", "name": "add", "qualified_name": "<fx>/src/math.ts::add",
     "file_path": "<fx>/src/math.ts", "line_start": 1, "line_end": 1,
     "language": "typescript", "parent_name": null, "is_test": false},
    {"id": 6, "kind": "Function", "name": "handler", "qualified_name": "<fx>/src/math.ts::handler", "...": "..."},
    {"id": 5, "kind": "Function", "name": "scale", "qualified_name": "<fx>/src/math.ts::scale", "...": "..."}
  ],
  "changed_nodes_omitted": 0,
  "impacted_nodes": [
    {"id": 11, "kind": "Function", "name": "total", "qualified_name": "<fx>/src/use.ts::total",
     "file_path": "<fx>/src/use.ts", "line_start": 2, "line_end": 4,
     "language": "typescript", "parent_name": null, "is_test": false,
     "impact_score": 0.6, "call_site": {"line": 3}},
    {"id": 12, "kind": "Function", "name": "twice", "qualified_name": "<fx>/src/use.ts::twice",
     "...": "...", "impact_score": 0.6, "call_site": {"line": 5}, "call_site_count": 2},
    {"id": 2, "kind": "Function", "name": "run", "qualified_name": "<fx>/src/main.ts::run",
     "...": "...", "impact_score": 0.36},
    {"id": 9, "kind": "Test", "name": "it:sums@L3", "qualified_name": "<fx>/src/use.test.ts::it:sums@L3",
     "...": "...", "is_test": true, "impact_score": 0.36},
    {"id": 10, "kind": "File", "name": "<fx>/src/use.ts", "...": "...", "impact_score": 0.3},
    {"id": 1, "kind": "File", "name": "<fx>/src/main.ts", "...": "...", "impact_score": 0.09},
    {"id": 7, "kind": "File", "name": "<fx>/src/use.test.ts", "...": "...", "is_test": true, "impact_score": 0.09}
  ],
  "impacted_files": [
    "<fx>/src/use.test.ts",
    "<fx>/src/use.ts",
    "<fx>/src/main.ts"
  ],
  "impacted_files_omitted": 0,
  "edges": [
    {"id": 5, "kind": "CONTAINS", "source": "<fx>/src/math.ts", "target": "<fx>/src/math.ts::add",
     "file_path": "<fx>/src/math.ts", "line": 0, "confidence": 1.0, "confidence_tier": "EXTRACTED"}
  ],
  "edges_omitted": 0,
  "truncated": false,
  "total_impacted": 7,
  "nodes_omitted": 0,
  "resolution": "all",
  "unresolved_call_sites": 0,
  "context_savings": {"estimated": true, "saved_tokens": 0, "saved_percent": 0}
}
```

（`"...": "..."` 表示我为篇幅省略了同构字段，键名与取值未改；`edges` 数组原本有多条，这里只留一条示例。）

同一个调用换 `detail_level="minimal"`，**全文**如下（这就是分诊最该用的形态，体积 ~100 token 级）：

```json
{
  "status": "ok",
  "summary": "Blast radius for 1 changed file(s):\n  - 4 nodes directly changed\n  - 7 nodes impacted (within 2 hops)\n  - 3 additional files affected",
  "risk": "medium",
  "impacted_file_count": 3,
  "key_entities": ["total", "twice", "run", "it:sums@L3", "<fx>/src/use.ts"],
  "truncated": false,
  "nodes_omitted": 0,
  "unresolved_call_sites": 0,
  "context_savings": {"estimated": true, "saved_tokens": 0, "saved_percent": 0}
}
```

注意 minimal 里**没有** `total_impacted`：`risk` 的档位就是由它内部裁出来的（>20 → `high`，>5 → `medium`，否则 `low`），档位阈值硬编码在源码的这一段，不可配置。如果门控要连续的数值而不是三档，就得用 `standard` 拿 `total_impacted`。

### 2.2 受影响文件列表：有

`impacted_files` 是纯字符串数组（文件路径），`impacted_files_omitted` 与之配对。空结果时返回 `status: "ok"` + `summary: "No changed files detected."`，其余列表为空、`total_impacted: 0`，并**不报错**（源码分支）。所以调用侧必须区分「真的没有影响」与「这些文件根本没被索引」——CRG 为此在空结果时附加 `confidence`（`why` 最多 140 字符），依据是 `empty_impact_confidence()`。

### 2.3 是否到符号粒度：是，比文件粒度更细

`changed_nodes` / `impacted_nodes` 的元素是节点字典（本机实测字段）：
`id, kind, name, qualified_name, file_path, line_start, line_end, language, parent_name, is_test`，受影响节点额外带 `impact_score`，直达调用点还带 `call_site: {line}` 与 `call_site_count`。

- `kind` ∈ File / Class / Function / Test / Type / Endpoint / Scheduler / ConfigProperty / Event（[docs/schema.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/schema.md)）。
- `qualified_name` 形如 `<abs path>::ClassName.method`，`line_start`/`line_end` 是定义区间——**行号粒度足够回填 Finding 的位置**。
- 边字典带 `confidence`（0–1）与 `confidence_tier`（`EXTRACTED`/`INFERRED`），可直接作为「这条影响边有多可信」的权重输入；边还有 `line`（关系被看到的位置）。

这比「只给受影响文件列表」的预期更好：能给出「哪个函数受影响、它的第几行在调用改动代码、这条边是抽取的还是推断的」。

### 2.4 上限与截断语义（必须处理）

- 硬上限：单次响应 **100 个节点 / 150 条边 / 200 个文件**（源码 `_MAX_IMPACT_NODES_SHOWN = 100`、`_MAX_IMPACT_EDGES = 150`、`_MAX_IMPACT_FILES = 200`；`_bounded` 取 `min(max_results, hard_cap)`）。`max_results` 只能把上限压得更低，压不上去。
- `truncated` 的含义是「还有更多」，任一上限触发都为 true；`nodes_omitted` / `edges_omitted` / `impacted_files_omitted` / `changed_nodes_omitted` 给出被砍掉的条数。
- **`impacted_file_count`（minimal）与 `total_impacted` 都是未截断的真实总数**，但 `impacted_files` 数组会被 200 砍掉——所以「受影响文件数」应当读 `impacted_file_count`，不要读 `len(impacted_files)`（后者在大改动上会静默封顶在 200）。
- 遍历预算：`CRG_MAX_IMPACT_NODES=500`、`CRG_MAX_IMPACT_DEPTH=2` 是环境变量默认（[README 环境变量表](https://github.com/tirth8205/code-review-graph/blob/staging/README.md)）。
- `unresolved_call_sites` 是「明明点名了变更符号、但从未绑定到图节点」的调用点数，用来区分「空 radius」与「有盲区」——**分诊读到它非零时，radius 是低估的**。

---

## 3. 建索引的成本

### 3.1 存储：单文件 SQLite，需要持久化

一个 SQLite 文件 `.code-review-graph/graph.db`（目录自动 gitignore，可用 `CRG_DATA_DIR` 改位置），无外部数据库、无服务端（[README Features](https://github.com/tirth8205/code-review-graph/blob/staging/README.md)、[docs/FEATURES.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/FEATURES.md)）。schema 版本 **13**，表包括 `nodes`/`edges`/`flows`/`communities`/`risk_index`/`nodes_fts`(FTS5)/`embeddings`（[docs/schema.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/schema.md)）。语义检索用的向量是**可选**的，不装 `[embeddings]` 就没有 `embeddings` 表。

**索引必须持久化**：没有 `graph.db` 时 `serve`/查询会报「No graph found」，必须先 `build`。

### 3.2 耗时（官方口径）

来自 [docs/REPRODUCING.md#incremental-update-latency](https://github.com/tirth8205/code-review-graph/blob/staging/docs/REPRODUCING.md)（~3,000 文件、django）：

| 场景 | 墙钟 | 重新解析文件数 |
| --- | --- | --- |
| 冷启动全量 build | 40.3 s | 2,998 |
| `update`，无改动 | 1.4 s | 0 |
| `update --skip-flows`，改 2 文件（hook 路径） | 2.4–2.9 s | 2 |
| `update`，改 2 文件（全 postprocess） | 9.8 s | 2 |

官方还给了逐仓库的建图基准，其中 **zod（TypeScript，534 文件）**：7,082 节点 / 98,833 边 / 解析成功率——**resolved edges 52.9%、resolved imports 43.4%**，build 13.9 s，0 parse error。

### 3.3 耗时与体积（本机 2.3.9 实测）

| 规模 | build | `update` 无改动 | `update` 改 1 文件 | `graph.db` |
| --- | --- | --- | --- | --- |
| 4 个 TS 文件 / 12 节点 / 22 边 | 首次含 migration，~1 s 内 | — | — | 192 KiB |
| 200 个 TS 文件 / 600 节点 / 998 边 | **1.79 s** | 0.53 s | 0.72 s | **2.33 MiB** |

口径说明：Windows、Python 3.11、`CRG_SERIAL_PARSE=1`（关掉默认的并行解析，原因见 §3.5）、单线程、冷文件缓存。200 文件图上 2.33 MiB 意味着**每千文件约 12 MiB**量级，对课程/毕设规模的仓库完全可接受。

官方对大仓的体积口径（v2.3.9 起「Go/Ruby import 绑定」使 DB 变大，[CHANGELOG](https://github.com/tirth8205/code-review-graph/blob/staging/CHANGELOG.md)）：`kubernetes/kubernetes` 的 DB 由 4.41 GB 涨到 **5.36 GB**（+21.5%），build 由 ~115–123 s 涨到 ~147–149 s；`cli/cli` 由 281.1 MB / 7.6 s 涨到 **325.9 MB / 9.3 s**。

### 3.4 增量更新：支持，且是它的主打能力

- 机制：`update` 用 git diff 找出变更文件，沿 import/call 边找依赖者，**只重解析 SHA-256 变了的文件**（`nodes.file_hash`）。没有 git 的目录也能跑（v1.5.3 起），此时全量扫描比对。
- 触发方式：编辑器 hook、git pre-commit hook、`watch` 模式、`crg-daemon` 多仓守护；或显式 `update`。
- 一个坑：变更文件被索引后又被回滚时，`update` 比对磁盘 hash 而不是只信 git diff，所以会重解析（`CHANGELOG` #860 段）。对我们「提交前拦截」的场景是好事——工作区状态永远比 git 状态新。
- 另一个坑：局部解析失败不会中断，返回 `status: "partial"` 并在 summary 里点名失败文件，那些文件保留旧行——**必须检查 status**，否则会把陈旧的 radius 当最新的用。

### 3.5 并行解析与沙箱（实测踩到）

默认 `full_build` 走 `ProcessPoolExecutor` 并行解析（`incremental.py` 里 `_make_executor(_MAX_PARSE_WORKERS)`）。本机受限沙箱里进程池报 `PermissionError: [WinError 5]`（命名管道被拒），设 `CRG_SERIAL_PARSE=1` 后全部正常。这是环境限制而非 CRG 缺陷，但如果主工程的 CI/沙箱对子进程有限制，需要预留这个变量——**它会额外起进程池，不是纯单进程**。

---

## 4. 对 TypeScript 的支持程度

结论：**TS 是一等支持语言，但不是「全解析」支持**。它对 TS 的解析深度明显高于「只支持 Python/Java」的预期，代价是调用图有一半左右落不到已绑定节点上（官方 zod 基准：resolved edges 52.9%）。

### 4.1 明确支持的部分

- **扩展名**：`.ts` / `.mts` / `.cts` → `typescript`，`.tsx` → `tsx`（本机读安装包 `parser.py` 的 `EXTENSION_TO_LANGUAGE` 确认）。`.astro` 也用 TS 语法解析；Vue/Svelte SFC 支持（[README 语言覆盖](https://github.com/tirth8205/code-review-graph/blob/staging/README.md)）。
- **节点类型**：`function_declaration`、`method_definition`、`arrow_function`（本机 `parser.py` 实测的 TS 函数节点表），类/接口/类型、imports、call sites、inheritance 都会抽。
- **导入解析**：支持 `tsconfig.json` 的 `paths` / `baseUrl` 别名（v2.0.0 起），并让 `package.json` 的 `imports` 字段优先，从而覆盖 `@/...` 这类 Vite/Nuxt 写法（CHANGELOG #776 段）；`references_to` 对未解析的 specifier（npm workspace alias、tsconfig path mapping 失败）仍会返回依赖者，但标 `target_resolution: "unresolved"`。
- **测试识别**：`*.test.ts` / `*.spec.ts` / `__tests__/` 下的 `describe`/`it`/`test` 会被识别为 `Test` 节点并建 `TESTED_BY` 边（[docs/schema.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/schema.md) 的 Test 判定规则）。本机夹具里 `src/use.test.ts` 的 `it:sums@L3` 确实作为 Test 节点出现在 radius 里。
- **跨文件调用**：本机夹具验证——`math.ts::handler` 被 `use.ts::twice` 调用，`twice` 被 `main.ts::run` 调用，radius 正确跨了 3 个文件并给出调用行号。

### 4.2 要打折的部分

- **约一半边不落到已绑定节点**：zod 基准 52.9% resolved edges / 43.4% resolved imports（[REPRODUCING](https://github.com/tirth8205/code-review-graph/blob/staging/docs/REPRODUCING.md)）。未绑定的调用点不会被遍历，radius 会低估——这正是 `unresolved_call_sites` 存在的原因。
- **flow（执行流）检测对 JS 系偏弱**：README 的 Limitations 明说 "Entry-point detection is strongest for Python and PHP/Laravel. JavaScript and Go flow detection needs work"。所以 `get_affected_flows_tool` / `list_flows_tool` 不要在 TS 仓库上作为门控依据；`get_impact_radius` 走的是 CALLS/IMPORTS 遍历，不受这条限制同等影响。
- **TS 专属回归测试存在但看不出覆盖强度**：仓库有 `test_typescript_declaration_gaps.py`、`test_typescript_node_extensions.py`、`test_tsconfig_resolver.py`、`test_commonjs_imports.py`、`test_typed_receiver_calls.py`（[tests/](https://github.com/tirth8205/code-review-graph/tree/staging/tests)），说明 TS 路径是被持续测的；但**没有任何公开的「TS 仓库 impact 准确率」指标**（影响准确率基准只覆盖 6 个 Python/Go/Rust 仓库，见 §7）。

### 4.3 对我们最要紧的一条

主工程自己就是 TS，而 CRG 的解析字段（`nodes` 表）本身不区分「类型擦除后的运行时调用」与「类型层引用」，所以**类型别名/接口继承会被算进 radius**（`Type` 节点、`IMPLEMENTS` 边）。门控阈值如果直接对着文件数标定，会在纯类型改动（`.d.ts` 式重构）上偏保守。建议在标注集上单独统计「类型层改动」这一类样本的 radius 分布，再定阈值。

---

## 5. 一次 blast-radius 查询的延迟量级

**毫秒到十几毫秒（进程内、图已建好）**，这是本机实测：

| 图规模 | `detail_level` | n | p50 | p95 | max |
| --- | --- | --- | --- | --- | --- |
| 200 文件 / 600 节点 / 998 边 | minimal | 30 | **6.96 ms** | 7.94 ms | 11.64 ms |
| 同上 | standard | 30 | 6.83 ms | 7.29 ms | 7.47 ms |
| 同上，一次查 2 个文件 | minimal | 10 | 7.43 ms | — | 7.79 ms |
| 4 文件 / 12 节点 | 两者 | 20 | ~4.7 ms | — | 6.0 ms |

口径：每次调用都重新 `_get_store`（打开 SQLite、查 schema），即**这是「每次 MCP 调用完整重建连接」的延迟，不是复用连接的乐观值**。`detail_level` 对延迟几乎没影响（差别在序列化体积，不在遍历）。

进程外要另加的成本：

- **Python 冷启动**：一条 CLI 命令（含 import + 建 store）约 0.5 s 量级（本机 `update` 无改动 0.53 s，其中绝大部分是启动）。MCP 常驻进程则只在首次付这笔钱。
- **大图未确认**：官方没有给 impact radius 在 1k–10k 文件仓库上的专项数字。唯一接近的公开数据是 kubernetes 上的一次遍历「原本 18 s（19 s 总耗时中的 18 s），优化后 1.8 s，per-file fan-out 则 6.5 s」（[CHANGELOG](https://github.com/tirth8205/code-review-graph/blob/staging/CHANGELOG.md)）。**这一档我标未确认**，需要用真实仓库补测。
- **超时保护**：只读工具受 `CRG_TOOL_TIMEOUT`（默认 `0` = 不限）约束，超时返回 `status: "error"` 并自报预算，而不是让客户端吃 MCP `-32001`（v2.3.9 新增）。写工具（build/postprocess/embed/wiki/apply-refactor）故意不受此限。

对分诊的结论：**单次 ~7 ms 完全可以放在「每次写入事件」的同步路径上**，不必异步化；瓶颈是建图/增量更新（0.5–3 s），不是查询。

---

## 6. 许可证、维护活跃度、最新版本

| 项 | 值 | 来源 |
| --- | --- | --- |
| 许可证 | **MIT**（`license_expression: "MIT"`，仓库 `LICENSE`） | [PyPI 2.3.9](https://pypi.org/pypi/code-review-graph/2.3.9/json)、[LICENSE](https://github.com/tirth8205/code-review-graph/blob/staging/LICENSE) |
| 最新版本 | **2.3.9**，2026-09-18 发布（wheel + sdist） | [PyPI](https://pypi.org/pypi/code-review-graph/2.3.9/json) |
| 版本节奏 | 2.0.0 (2026-03-27) → 2.3.9 (2026-09-18)，半年 20+ 个版本；2.3.3 一版就 141 个非 merge commit | [PyPI releases](https://pypi.org/project/code-review-graph/#history)、[CHANGELOG](https://github.com/tirth8205/code-review-graph/blob/staging/CHANGELOG.md) |
| 开发状态 | `Development Status :: 4 - Beta` | [PyPI classifiers](https://pypi.org/pypi/code-review-graph/2.3.9/json) |
| 仓库活跃度 | 创建 2026-02-26，最后 push **2026-10-29**，32,516 stars / 2,958 forks / 194 open issues（2026-10-31 抓取） | [GitHub API](https://api.github.com/repos/tirth8205/code-review-graph) |
| 分支模型 | 默认分支 `staging`；`staging` → `testing` → `main` 晋升，release 从 `main` 打 tag；`staging`→`testing` 每日自动 | [README Contributing](https://github.com/tirth8205/code-review-graph/blob/staging/README.md)、[CONTRIBUTING](https://github.com/tirth8205/code-review-graph/blob/staging/CONTRIBUTING.md) |
| 依赖面 | Python ≥3.10；`fastmcp>=3.2.4,<4`、`mcp>=1.0,<3`、`networkx`、`tree-sitter-language-pack`、`watchdog`；向量/社区检测/评测都是可选 extra | [PyPI requires_dist](https://pypi.org/pypi/code-review-graph/2.3.9/json) |

对本课题的三条影响：

1. **MIT 无授权风险**，可以直接作为第三方信号源在论文里引用，无需处理 copyleft。
2. **Beta 且高频演进**是主要风险：2.3.8 才刚给多数工具加返回上限，2.3.9 又改了 schema（9→13）并要求重建库。适配器不能依赖字段顺序或「字段一定存在」，要按「字段缺失降级」写，并把版本钉死（`code-review-graph==2.3.9`）后写进复现说明。
3. 194 个 open issue / 3.2 万 star 说明这是**社区驱动的热点项目**，行为可能随 issue 修复变化——评测期必须锁定版本与 schema，否则 B0–B4 的对比不可复现。

---

## 7. 与本课题系统边界的关系（只作决策输入，不产 Finding）

CRG 的定位是「上下文裁剪」，输出里**没有任何 finding/severity/缺陷类别字段**——`impact_score` 是影响强度，`risk`（minimal 的 low/medium/high）是**受影响节点数**的分档（>20 / >5 / 否则），不是缺陷风险。这正好符合 `context.md` 里「CRG 只提供影响范围、不产 Finding」的边界：**不需要为它写 Finding 适配器，需要写的是「图查询适配器 + 分诊输入归一」**。

给出的 `impact_score` 权重来自边类型（`IMPACT_EDGE_WEIGHTS`：CALLS/INHERITS/IMPLEMENTS 等入边权重更高，默认 0.5），所以它天然是「结构重要性」而非「缺陷概率」。**不要把它混进置信度校准**（§8.3 的 PAVA 拟合），否则会把两个量纲搅在一起。

一个额外可用但需谨慎的入口：`get_minimal_context_tool`（“~100 tokens，call this first”）。它的历史问题是**会自己跑最多 5 个 git 子进程、曾耗到 ~130 s**（v2.3.9 已用 `CRG_DISCOVERY_TIMEOUT`（默认 5 s）收敛，超时抛 `ChangeDiscoveryError`）。对「提交前拦截」的场景，**不要用它**，直接给 `changed_files` 调 `get_impact_radius`——绕开 git 发现即可绕开这条超时链。

---

## 8. 建议写进设计规格的接入契约

以下是我基于上面事实给出的建议形态（不是 CRG 的既有契约）：

1. **接入方式**：MCP stdio 子进程，启动参数 `serve --repo <repoRoot> --tools get_impact_radius_tool`。只暴露一个工具，schema 面最小，也不可能误调写工具。
2. **调用形态**：每次变更事件用 `detail_level="standard"` 一次调用（拿 `impacted_file_count` 与 `total_impacted` 两个数），`changed_files` 显式传入（走 `Change Event` 的相对路径，适配器负责转绝对/归一），`base` 留空不用。
3. **分诊输入归一**（建议的 TS 类型，非代码）：
   `{ impactedFileCount: number, impactedNodeCount: number, risk: "low"|"medium"|"high", truncated: boolean, unresolvedCallSites: number, resolution: "all"|"direct" }`
   其中 `impactedNodeCount` 即 `total_impacted`，**在文档里显式命名为「受影响节点数」而不是「调用方数」**，避免后续章节的语义漂移。
4. **必须检查的三个降级信号**：`truncated`（真值被砍）、`unresolved_call_sites`（radius 低估）、`status`（`partial` 表示建图有失败文件）。任一异常时门控应**升档而不是降档**（宁可多审，不可漏审）。
5. **索引生命周期**：仓库级常驻一个 `graph.db`，只在首次 `build`，之后由 `update` 增量维护；**绝不在每次 change event 上重建**（200 文件全量 1.79 s、3000 文件 40 s，都远超一次查询的 7 ms）。
6. **超时预算**：查询侧给 200–500 ms 预算即可（实测 7 ms，留两个数量级余量）；建图侧独立预算（首次 60 s、增量 5 s），且建图失败不得阻塞审查主流程——退化为「无 radius → 默认档位」。
7. **路径约定**：CRG 内部存绝对路径（`nodes.file_path` 是绝对路径，`docs/schema.md` 明确 File 节点 `name` 为 as-stored absolute），响应里也是绝对路径。适配器必须做「仓库相对 ↔ 绝对」双向归一，否则跨平台/跨机器比较会碎。

---

## 9. 复现方式（我实际做了什么）

```powershell
# 1) 装 2.3.9（uv，装在系统临时目录，未污染工程）
uv venv .venv
uv pip install --python .venv\Scripts\python.exe code-review-graph==2.3.9

# 2) 建夹具（4 个 TS 文件：math.ts / use.ts / main.ts / use.test.ts）
#    另建 200 文件链路夹具 big/src/m0..m199.ts

# 3) 建图（沙箱内需关并行解析）
$env:CRG_SERIAL_PARSE = '1'
code-review-graph build --repo <fixture>
code-review-graph status --repo <fixture>

# 4) 直连库函数做测量（等价于 MCP 工具调用）
python -c "from code_review_graph.tools.query import get_impact_radius; ..."
```

要点：夹具**不是 git 仓库**，因此全程 `changed_files` 显式传入，未触发任何 git 发现路径；环境为 Windows + Python 3.11.15 + CRG 2.3.9 + schema 13。建图产物落在夹具目录的 `.code-review-graph/graph.db`，与工程目录无关。

---

## 10. 未确认项（不猜）

1. **中大型仓库（1k–10k 文件）上单次 impact radius 的实测延迟**：官方无公开数字；本机只测到 200 文件（7 ms）。唯一相近的公开数据是大图上的一次遍历 1.8–6.5 s（kubernetes），但那是遍历不是本工具。
2. **`risk_index.caller_count` 是否经任何 MCP 工具响应暴露**：只确认它被 `detect_changes` 的风险打分内部消费、表内按符号填满；没有确认哪个工具的返回体里带这个数。要断言「CRG 能直接给调用方数」，需要再验 `detect_changes_tool` 的完整响应（本次未做）。
3. **官方是否发布过 impact radius 的 JSON 响应样例**：README/docs 里没有找到完整样例，本文 §2.1 的样例是本机实测，不是文档转述。
4. **TypeScript 仓库上的 impact 准确率**：官方影响准确率基准（13 个 commit，平均 F1 0.693 / precision 0.546 / recall 1.0 且注明 recall 是「图派生上界、循环论证」）只覆盖 httpx / code-review-graph / fastapi / express / flask / gin，**没有 TS 仓库**。express 是 JS，可作参考但不能替代 TS。
5. **`resolution="direct"` 对 radius 大小的实际影响幅度**：只从源码与签名确认了语义（拒绝沿未绑定边扩散），没有量化。

---

## 参考来源

- [README（staging）](https://github.com/tirth8205/code-review-graph/blob/staging/README.md) — 接入形态、30 个工具、语言覆盖、环境变量、Windows MCP 配置、Limitations
- [code_review_graph/tools/query.py](https://github.com/tirth8205/code-review-graph/blob/staging/code_review_graph/tools/query.py) — `get_impact_radius` 签名、返回字段、硬上限、`_bounded`
- [code_review_graph/tools/\_\_init\_\_.py](https://github.com/tirth8205/code-review-graph/blob/staging/code_review_graph/tools/__init__.py) — 工具清单
- [code_review_graph/main.py](https://github.com/tirth8205/code-review-graph/blob/staging/code_review_graph/main.py) — `@mcp.tool()` 注册（本机安装包核对）
- [docs/schema.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/schema.md) — 节点/边表结构、kind 取值、`risk_index.caller_count`、qualified name 格式
- [docs/REPRODUCING.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/REPRODUCING.md) — 冷构建 40.3 s、增量 1.4 s、zod(TS) 建图基准、impact 准确率 F1
- [docs/COMMANDS.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/COMMANDS.md) — `serve` 系列参数
- [docs/FEATURES.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/FEATURES.md) — 版本特性（如 v1.8.4 的 `truncated`/`total_impacted`/`max_results`）
- [CHANGELOG.md](https://github.com/tirth8205/code-review-graph/blob/staging/CHANGELOG.md) — DB 体积（kubernetes 5.36 GB / cli/cli 325.9 MB）、遍历延迟、上限与 timeout 变更
- [docs/USAGE.md](https://github.com/tirth8205/code-review-graph/blob/staging/docs/USAGE.md) — 「Applies to code-review-graph 2.3.9」、索引内容与忽略规则
- [PyPI 2.3.9 metadata](https://pypi.org/pypi/code-review-graph/2.3.9/json) — 版本、发布时间、MIT、`requires_dist`、classifiers
- [GitHub repo API](https://api.github.com/repos/tirth8205/code-review-graph) — stars/forks/issues、created_at、pushed_at、默认分支
