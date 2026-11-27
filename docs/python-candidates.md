# Python 语料候选：逐文件 sink 证据包（2026-11-20）

本文件只为人工标注准备证据，不写 label、不给 GT、不判断「通过」。全程只读：仅用 `gh api` 读一手内容与提交历史；未 clone、未下载样本进仓、未运行 semgrep / ocr / drill、未改代码或数据集。

**范围**：issue #44 拍板的三个 MIT 源——PyGoat（主）、vulnpy（archived）、VAmPI（补充）。GPL-2.0 源（django.nV）不在范围内。

**本次 pin（2026-11-20 用 `branches/master` 重新核实，与上次一致）**：

| 源 | 默认分支 | commit | 授权 |
| --- | --- | --- | --- |
| `adeyosemanputra/pygoat` | master | `2aa4cc14f251e4a780e94e200aed6b36a5b15c21` | MIT |
| `Contrast-Security-OSS/vulnpy` | master | `b81885e58283a3449b578d20c20557aff637e5ea` | MIT（archived） |
| `erev0s/VAmPI` | master | `f16052dce83f05847133ec98f01c5193a41de7d8` | MIT |

下文 `repo@sha` 用短 sha：`pygoat@2aa4cc1`、`vulnpy@b81885e`、`VAmPI@f16052d`。

**证据等级**：

- `[已核实]`：本次读过该文件原文、行号或 `gh api` 返回的树/提交历史。
- `[源码推断，未实跑]`：规则命中与否是按快照 yaml 的 pattern 静态推断，未执行 semgrep。
- `[未核实]`：本次没有读到或没有查到的部分。

**规则快照事实（复用上一次调研，不重新论证）** `[已核实]`：≤102400 bytes 的文件只加载 `py-block`，其 `blockRules` 中实际存在的只有 `command-injection-os-system`、`subprocess-shell-true`、`formatted-sql-query`、`sql-injection-db-cursor-execute`；`path-traversal-open` 与 `dangerous-subprocess-use` 两个基名不在快照。`path-traversal-open.django/.flask` 只在 >102400 bytes 的 `py-nontaint` 路径可用。本次三个源的所有 `.py` 文件最大为 `pygoat@2aa4cc1:challenge/views.py` 26236 bytes，**没有任何文件 >102400**，所以 `.django/.flask` 在本源集合内不可达 `[已核实]`（tree sizes）。

四条规则的判定要点（读自 `research/semgrep-bench/snapshot/py_block.yaml`）`[已核实]`：

- `command-injection-os-system`（L2198-2309）：要求同函数内出现 `request.$W.get(...)` 且 sink 是 `os.system`。
- `sql-injection-db-cursor-execute`（L4423-4525）：要求同函数内 `request.$W.get(...)`，sink 是 `$CURSOR.execute(...)`；包含 `$DATA=request...`、`$INTERM=f"...{$DATA}..."` 的跨语句分支。
- `formatted-sql-query`（L8883-8929）：纯 pattern，不要 request；命中 `$DB.execute(f"...")` 或 `$SQL = f"..."` 后 `$DB.execute($SQL)`。
- `subprocess-shell-true`（L9032-9071）：命中任何 `subprocess.$FUNC(..., shell=True, ...)`，但 `pattern-not` 排除首个参数是字面量字符串的调用。

---

## CWE-078

| repo@sha:path | bytes | sink 行（代码原文） | 数据流 | 命中规则 id | 判定 | 可 block | diff provenance |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| `pygoat@2aa4cc1:dockerized_labs/command_injection_lab/app.py` | 1771 | L29-31 `subprocess.Popen(command, shell=True, ...)` | L19 `domain=request.form.get("domain")` → L23/25 `f"nslookup {domain}"` / `f"dig {domain}"` → L29 Popen；无 sanitizer、无白名单 | `subprocess-shell-true`（L29-31）；`command-injection-os-system` 不命中（无 `os.system`） | `positive` | 是 | 引入 `ae9a02c0`（2025-07-13）；格式化 `6bd0973a`；迁移 `3eb9e5ce`（2026-02-27）。sink 自初始 lab 提交即存在，无自然 before/after → 只能真实文件 + authored minimal diff `[已核实]` |
| `vulnpy@b81885e:src/vulnpy/trigger/cmdi.py` | 295 | L10-12 `subprocess.Popen(command, ..., shell=True)`；另 L6 `os.system(command)` | L5/L9 函数参数 `command`；flask `blueprint.py` L46-50、django `vulnerable.py` L27-31 等把 `request...get("user_input")` 传入（跨文件） | `subprocess-shell-true`（L10-12）；`command-injection-os-system` **不命中**（同文件无 `request.$W.get`） | `positive`（库函数，调用方跨文件可达） | 是 | 引入 `4505ab6a`（2020-06-26，建仓即有）；`09cd1f63` 仅加 Falcon 路由 → 只能真实文件 + authored minimal diff `[已核实]` |

**078 供给结论**：仅 2 条，2 条可 block。三个源里 `subprocess`/`os.system` 的 python 文件只有上述两个（PyGoat 的 `uninstaller.py` 是 list 形式、无 `shell=True`，不命中；`PyGoatBot.py` 无进程调用）`[已核实]`。**供给不足（目标 ≥6）**。

---

## CWE-089

| repo@sha:path | bytes | sink 行（代码原文） | 数据流 | 命中规则 id | 判定 | 可 block | diff provenance |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| `pygoat@2aa4cc1:dockerized_labs/sql_injection_lab/app.py` | 2199 | L50-52 `sql_query = (f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")`；L57 `c.execute(sql_query)` | L46-47 `request.form.get("username"/"password")` → L50-52 f-string → L57 `cursor.execute`；无参数化 | `sql-injection-db-cursor-execute`（L46-47→L50-52→L57 的 `$INTERM = f"...{$DATA}..."` 分支）；`formatted-sql-query`（L50-52 + L57） | `positive` | 是 | 引入 `ae9a02c0`（2025-07-13）；`bf4702dd` 格式化；`3eb9e5ce` 迁移 → 只能真实文件 + authored minimal diff `[已核实]` |
| `vulnpy@b81885e:src/vulnpy/trigger/sqli.py` | 1511 | L36-37 `sql = EXECUTE_QUERY_FMT.format(user_input)` / `cursor.execute(sql)` | L34 参数 `user_input` ← flask/django 等路由的 `user_input`（跨文件）；无白名单 | `formatted-sql-query`（L36-37，`$SQL="...".format(...)` + `$DB.execute($SQL)`）；`sql-injection-db-cursor-execute` **不命中**（同文件无 request） | `positive`（库函数，跨文件可达） | 是 | 引入 `85edfd36`（2020-10-14）；`3e7214b1` 改连接管理 → 只能真实文件 + authored minimal diff `[已核实]` |
| `VAmPI@f16052d:models/user_model.py` | 3642 | L72-73 `user_query = f"SELECT * FROM users WHERE username = '{username}'"` / `db.session.execute(text(user_query))` | `api_views/users.py` L45-47 路由 path 参数 `username` → `User.get_user(username)` → L72 f-string → L73 `text()` + execute；无参数化 | **不命中**：`text()` 包裹使 `sql-injection-db-cursor-execute` 的 `$CURSOR.execute(..., $INTERM, ...)` 与 `formatted-sql-query` 的 `$DB.execute($SQL)` 都不匹配 | `positive` | 否 | 文件 `a488a528`（2020-10-04 init）；sink 在初始提交内 → 只能真实文件 + authored minimal diff `[已核实]`；未逐行确认 sink 是否在 `a488a528` 即存在 → `[未核实]` |
| `VAmPI@f16052d:api_views/users.py` | 9257 | L45-47 `get_by_username(username)` → `User.get_user(username)` | connexion path 参数 `username` 直接进入 raw-SQL helper（sink 在上一行文件） | **不命中**（本文件无 execute） | `positive`（同链上游，**不得与上一行当两个独立漏洞**） | 否 | 初始 `a488a528`（2020-10-04）`[已核实]`；`beca4615` 等后续 |

**089 供给结论**：独立机制 3 条，可 block 2 条；第 4 行只是同链上游。VAmPI 的 `text()` 包装是真实规则盲区，故 CWE-089 的**可 block** 供给只有 2。**供给不足（目标 ≥6）**。

---

## CWE-022

| repo@sha:path | bytes | sink 行（代码原文） | 数据流 | 命中规则 id | 判定 | 可 block | diff provenance |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| `pygoat@2aa4cc1:dockerized_labs/ssrf_lab/app.py` | 2020 | L21-22 `file_path = os.path.join(os.path.dirname(__file__), file)` / `open(file_path, "r")` | L18 `file=request.form.get("blog")` → L21 join → L22 open；无 basename/realpath/白名单 | **不命中**：`path-traversal-open` 基名不在 `py-block`；文件 2020B 只走 `py-block` | `positive` | 否 | 引入 `4799cfce`（2025-07-09）；`6bd0973a` 格式化；`3eb9e5ce` 迁移 → 只能真实文件 + authored minimal diff `[已核实]` |
| `vulnpy@b81885e:src/vulnpy/trigger/pt.py` | 1421 | L57 `open(user_input)`；另 L48 `io.open(user_input)`、L40 `bz2.open`、L24 `tarfile.open` | L54 参数 `user_input` ← 各框架路由 `user_input`（跨文件）；无校验 | **不命中**（基名缺失；1421B 走 `py-block`） | `positive`（库函数，跨文件可达） | 否 | 引入 `4788a733`（2020-09-29）；`4995d456` 补 bz2/tar → 只能真实文件 + authored minimal diff `[已核实]` |
| `pygoat@2aa4cc1:dockerized_labs/template_injection_lab/app.py` | 3300 | L109-111 `return render_template(f"blogs/{filename}")` | L107-108 URL 变量 `filename` → L111 模板路径拼接；无 basename/白名单 | **不命中**：规则原语是 `open`，此处是 `render_template`；且基名缺失 | `positive`（模板路径穿越，非 `open`） | 否 | 引入 `ae9a02c0`（2025-07-13）；`dd914cdf`（2026-10-21）只改 `toggle_theme` → 只能真实文件 + authored minimal diff `[已核实]` |

**022 供给结论**：3 条，**0 条可 block**。两点硬限制：三个源没有 >102400 的 py 文件（最大 26236），`py-nontaint` 永不加载；`py-block.blockRules` 又没有 `path-traversal-open` 基名。**目标里的「022 只能靠 >100KiB 单独标注」在本源集合内连大文件都没有**；本类真实可用但不可 block。`[已核实]`（大小与规则 id）

---

## 其他覆盖类（079 / 798 / 918）

这些行只能作为「覆盖但必然 miss」的样本；即使命中 079/798/918 的规则，`py-block.blockRules` 未认证，也不可 block。

### CWE-079

| repo@sha:path | bytes | sink 行（代码原文） | 数据流 | 命中规则 id | 判定 | 可 block | diff provenance |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| `pygoat@2aa4cc1:dockerized_labs/xss_lab/app.py` | 2629 | L54-55 `return render_template("lab1.html", query=q)`；L63-66 `username.replace("<script>","")` 后渲染；L76-78 `re.sub(r"\w","",username)` | L43 `request.args.get("q")`；L61 `request.form.get("username")`；过滤只删固定串/只删非字母数字，可绕过 | 079 规则未认证 → 不 block | `positive` | 否 | 引入 `4655bb65`（2025-06-18）；`6bd0973a` 格式化 → 只能真实文件 + authored minimal diff `[已核实]` |
| `vulnpy@b81885e:src/vulnpy/flask/blueprint.py` | 1799 | L55 `template += "<p>XSS: " + user_input + "</p>"` | L46 `_get_user_input()`（header/args/form）→ L55 直接拼接返回 | 未认证 → 不 block | `positive` | 否 | 引入 `4505ab6a`（2020-06-26）`[已核实]` |
| `vulnpy@b81885e:src/vulnpy/django/vulnerable.py` | 1951 | L36 `template += "<p>XSS: " + user_input + "</p>"` | L27 `_get_user_input(request)`（GET/POST `user_input`）→ L36 | 未认证 | `positive` | 否 | 引入 `7189bc70`（2020-08-05）`[已核实]` |
| `vulnpy@b81885e:src/vulnpy/django/vulnerable_asgi.py` | 2675 | L54-55 `template += "<p>XSS: " + user_input + "</p>"` | L46 `await _get_user_input(request)` → L55 | 未认证 | `positive` | 否 | 引入 `f7839a87`（2022-06-20）`[已核实]` |
| `vulnpy@b81885e:src/vulnpy/falcon/vulnerable.py` | 3364 | L121-123 `_set_xss_response(..., user_input)` 内 `template += "<p>XSS: " + user_input + "</p>"` | L31 `req.get_param("user_input")` → L43 → L123 | 未认证 | `positive` | 否 | 引入 `09cd1f63`（2020-08-03）`[已核实]` |
| `vulnpy@b81885e:src/vulnpy/falcon/vulnerable_asgi.py` | 3381 | L123 `template += "<p>XSS: " + user_input + "</p>"` | L31 `req.get_param("user_input")` → L43 → L123 | 未认证 | `positive` | 否 | 引入 `4a1d6b14`（2022-05-24）`[已核实]` |
| `vulnpy@b81885e:src/vulnpy/aiohttp/vulnerable_routes.py` | 2132 | L28-29 `template += "<p>XSS: " + user_input + "</p>"` | L7 `request.rel_url.query.get("user_input")` → L20 → L29 | 未认证 | `positive` | 否 | 引入 `b1cfd678`（2021-10-27）`[已核实]` |
| `vulnpy@b81885e:src/vulnpy/bottle/vulnerable_routes.py` | 1633 | L38-39 `template += "<p>XSS: " + user_input + "</p>"` | L6-9 GET/POST `user_input` → L31 → L39 | 未认证 | `positive` | 否 | 引入 `2ddeeb93`（2021-02-05）`[已核实]` |
| `vulnpy@b81885e:src/vulnpy/pyramid/vulnerable_routes.py` | 2705 | L50-51 `template += "<p>XSS: " + user_input + "</p>"` | L7-10 GET/POST `user_input` → L42 → L51 | 未认证 | `positive` | 否 | 引入 `d6b0b366`（2020-07-30）`[已核实]` |
| `vulnpy@b81885e:src/vulnpy/quart/blueprint.py` | 1729 | L52-53 `template += "<p>XSS: " + user_input + "</p>"` | L9-13 header/args `user_input` → L44 → L53 | 未认证 | `positive` | 否 | 引入 `9786c26b`（2022-02-10）`[已核实]` |
| `vulnpy@b81885e:src/vulnpy/wsgi/app.py` | 3222 | L25-26 `"<p>XSS: {}</p>".format(user_input)` | L57 `QUERY_STRING` 的 `user_input` → L23 → L26 | 未认证 | `positive` | 否 | 引入 `b9ba3159`（2020-11-16）`[已核实]` |

### CWE-798

| repo@sha:path | bytes | sink 行（代码原文） | 数据流 | 命中规则 id | 判定 | 可 block | diff provenance |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| `pygoat@2aa4cc1:dockerized_labs/sde/app.py` | 1311 | L6-15 `app.config["SECRET_KEY"]="..."`、`DATABASE_URI`、`API_KEY`、`PRIVATE_KEY`、`TOKEN`、`PASS` | 模块级常量，无外部源 | 未认证 | `positive` | 否 | 引入 `901c69eb`（2025-08-28）；`92246e51` 删未用产物 → 只能真实文件 + authored minimal diff `[已核实]` |
| `pygoat@2aa4cc1:dockerized_labs/package_injection_lab/app.py` | 8448 | L10-15 `SENSITIVE_DATA = {"api_key": "sk_live_...", "db_password": ...}` | 模块级常量；L11-15 硬编码 | 未认证 | `positive` | 否 | 引入 `5db7327c`（2026-01-27）；`c8dddf8a`（2026-10-21）修 release blockers → 只能真实文件 + authored minimal diff `[已核实]` |
| `pygoat@2aa4cc1:dockerized_labs/broken_auth_lab/app.py` | 4126 | L16 `app.secret_key = "your-secret-key-here"`；L20-22 `"password": "admin123"` | 模块级常量 | 未认证 | `positive` | 否 | 引入 `0caf5473`（2025-04-25）`[已核实]` |
| `pygoat@2aa4cc1:challenge/labs/security_headers_lab/app.py` | 6292 | L15 `app.secret_key = "security_headers_secret_key_2024"`；L20-31 明文 `password` | 模块级常量 | 未认证 | `positive` | 否 | 引入 `a4ee58d8`（2025-08-31）`[已核实]` |
| `VAmPI@f16052d:config.py` | 920 | L13 `vuln_app.app.config['SECRET_KEY'] = 'random'` | 模块级常量；JWT 签名复用（`models/user_model.py` L37-41） | 未认证 | `positive` | 否 | 未查 `commits?path=config.py` → `[未核实]` |

### CWE-918

| repo@sha:path | bytes | sink 行（代码原文） | 数据流 | 命中规则 id | 判定 | 可 block | diff provenance |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| `pygoat@2aa4cc1:dockerized_labs/ssrf_lab/app.py` | 2020 | L35-37 `url = request.form.get("url")` / `requests.get(url)` | L35 form → L37 直接请求；无 scheme/host 白名单 | 未认证 | `positive`（与 022 同一文件，若一文件只允许一条样本则本行作废） | 否 | 同 022 行 `[已核实]` |

`vulnpy@b81885e:src/vulnpy/trigger/ssrf.py` L48-69 的 `urlopen(user_input)` 被 `mock_connection` 装饰：默认 `mock.patch("socket.create_connection")`，只有 `VULNPY_REAL_SSRF_REQUESTS` 时才真连。因此它是 **fp_bait 形状（危险调用已被环境开关控制）**，不是 `positive`；详见负样本表。`[已核实]`（L26-45、L64-69）

---

## 负样本候选（≥10）

约定：负样本是「真实上游文件 + 一处 ≤30 行、defect-free 的写入」；`sample_cwe=null` 时按 `specRiskLevel` 只受行数约束（`scripts/verify-dataset.ts:81-92`），所以下列写入在 ≤30 行内可记为 `low`。`fp_bait` = 写入里保留了危险调用形状，但参数/路径已被固定值、字面量、参数化或 allowlist 控制。所有文件均 ≤102400。

| repo@sha:path | 安全写入点 | edit/create | low risk | 备注 |
| --- | --- | --- | --- | --- |
| `pygoat@2aa4cc1:uninstaller.py` | L30 后新增 `def print_python_version(): subprocess.run("python --version", shell=True, ...)` | edit | 是（≤30 行） | **fp_bait**：首个参数是字面量，`subprocess-shell-true` 的 `pattern-not subprocess.$FUNC("...", shell=True, ...)` 排除；无 request 源。文件引入 `699918b3`（2022-04-19）`[已核实]` |
| `pygoat@2aa4cc1:challenge/utility.py` | L11 后新增 `def announce_ready(): os.system("echo pygoat-ready")`（需补 `import os`） | edit | 是 | **fp_bait**：`os.system` 参数为字面量、同函数无 `request.$W.get` → `command-injection-os-system` 不命中。文件 360B、11 行，`eb60468a`（2023-03-03）创建 `[已核实]` |
| `pygoat@2aa4cc1:dockerized_labs/a9_uckv_lab/app.py` | L70 后新增 `def load_config_safe(raw): return yaml.safe_load(raw)` | edit | 是 | **fp_bait**：危险 YAML 调用已换成 `safe_load`；用于压 798/502 邻域的误报。同文件现有 `yaml.load`（L62）保持不动 `[已核实]` |
| `pygoat@2aa4cc1:dockerized_labs/crypto_failure_lab/app.py` | L25 后新增 `def derive_key(password, salt): return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)` | edit | 是 | 安全写入（无危险调用）；补一个「正确 KDF」对照，defect-free `[已核实]` |
| `pygoat@2aa4cc1:dockerized_labs/broken_access_lab/main.py` | L60 后新增 `def set_admin_cookie(resp): resp.set_cookie("admin", "0", httponly=True, secure=True, samesite="Lax")` | edit | 是 | 安全 Cookie 标志；defect-free，不含 078/089/022 原语 `[已核实]` |
| `vulnpy@b81885e:src/vulnpy/common/templating.py` | L28 后新增 `def get_template_safe(path): name = os.path.basename(path); with open(os.path.join(TEMPLATES_LOCATION, name)) as f: return f.read()` | edit | 是 | **fp_bait**：`open` + join 的形状与 `path-traversal-open` 一致，但已 `basename` 收敛；文件仅 646B、29 行，创建于 `aa197dac`（2020-08-19）`[已核实]` |
| `vulnpy@b81885e:src/vulnpy/trigger/xss.py` | L5 后新增 `def escape_html(user_input): return html.escape(user_input, quote=True)`（需补 `import html`） | edit | 是 | **fp_bait**：输出编码替代裸拼接；文件 82B，`3074ad41`（2020-09-17）创建 `[已核实]` |
| `VAmPI@f16052d:api_views/books.py` | L72 后新增 `def fetch_book_by_title(book_title): return db.session.execute(text("SELECT * FROM books WHERE book_title = :title"), {"title": book_title}).fetchone()`（需补 `from sqlalchemy.sql import text`） | edit | 是 | **fp_bait**：`text()` + bound param，`formatted-sql-query` 不命中（非 f-string/format），`sql-injection-db-cursor-execute` 无 request-in-file `[已核实]` |
| `VAmPI@f16052d:api_views/users.py` | L223 后新增 `def check_password_safe(user, password): return hmac.compare_digest(user.password, password)` | edit | 是 | 安全比较，需补 `import hmac`；defect-free `[已核实]` |
| `VAmPI@f16052d:models/books_model.py` | L28 后新增 `def find_by_title_safe(title): return Book.query.filter_by(book_title=title).first()` | edit | 是 | ORM 参数化，安全写入；文件 28 行 `[已核实]` |
| `VAmPI@f16052d:api_views/main.py` | 整文件（20 行，`populate_db`/`basic`），`before=""` | create | 是 | **create 负样本**：真实文件、无 sink、defect-free；791B。新增提交未查 → `[未核实]` |
| `vulnpy@b81885e:src/vulnpy/utils/utils_string.py` | 整文件（16 行，`ensure_binary`/`ensure_str`），`before=""` | create | 是 | **create 负样本**：真实文件、无 sink；文件 495B、16 行；最早可查提交 `1eca33c1`（2022-01-07）是修改，「真实新增提交」未核实 → 用 authored create + 真实 blob `[已核实]`（内容）/ `[未核实]`（新增提交） |

**负样本统计**：12 条 = 10 条 edit + 2 条 create；全部可 ≤30 行、defect-free、可记 `low`。其中 7 条是显式 fp_bait（字面量/参数化/basename/allowlist/safe API），3 条是普通安全写入，2 条 create 是整文件 defect-free。**每条都与正样本文件不同**，避免 `verify-dataset.ts` 的同文件正负冲突。`[已核实]`（路径与写入点）/ `[已实测]`（规则不命中，见文末复测）

---

## 供给统计

| 类 | positive 行数 | 唯一文件 | 可 block | 说明 |
| --- | ---: | ---: | ---: | --- |
| CWE-078 | 2 | 2 | 2 | PyGoat 1 + vulnpy 1；`os.system` 分支不命中 |
| CWE-089 | 4 | 4 | 2 | 独立机制 3；VAmPI 两条同链；`text()` 导致 2 条不可 block |
| CWE-022 | 3 | 3 | 0 | 基名缺失；无 >100KiB 文件，`.django/.flask` 不可达 |
| CWE-079 | 11 | 11 | 0 | 覆盖但必然 miss |
| CWE-798 | 5 | 5 | 0 | 覆盖但必然 miss |
| CWE-918 | 1 | 1（与 022 复用同一文件） | 0 | 覆盖但必然 miss |
| **合计** | **26 行** | **25** | **4** | 可 block 仅 078×2 + 089×2 |

- **positive 唯一文件 25**，达到「≥25」的数量目标；但其中 19 条属于不可 block 的 079/798/918 或 022，**真正可 block 的只有 4 条**。
- 078/089 各只有 2 条可 block，**远低于「各 ≥6」**；022 为 0 条可 block。
- 负样本 12 条（10 edit + 2 create），满足「≥10」与「1 create」；均为 defect-free，均可记 low。

## 缺口与未核实项

1. **CWE-078 供给不足（2/6）**：已搜 `os.system`、`subprocess`、`shell=True` 于三个源的全部 py 文件与 GitHub code search。PyGoat 只有 `command_injection_lab/app.py`；`uninstaller.py` 是 list 形式无 `shell=True`；vulnpy 只有 `trigger/cmdi.py`；VAmPI 无进程调用。`[已核实]`
2. **CWE-089 供给不足（3 个独立机制 / 目标 6）**：PyGoat 仅 `sql_injection_lab/app.py`；vulnpy 仅 `trigger/sqli.py`（其他两函数是 `executemany`/`executescript`，不命中 `execute` 原语）；VAmPI 仅 `models/user_model.py`，且被 `text()` 包装导致规则不命中。已搜 `execute`、`cursor.execute`、`text(`、`raw(`。`[已核实]`
3. **CWE-022 不可 block 的结构性缺口**：三个源无任何 >102400 的 py 文件（最大 26236），`py-nontaint` 不可加载；`py-block.blockRules` 无 `path-traversal-open` 基名。因此即便收 3 条真实 022，也无法产生 block。`[已核实]`
4. **规则命中已实跑（2026-11-20）**：见文末「复测结果」。静态推断与实测一致的有：PyGoat 089 两条规则均命中；VAmPI `text()` 确实 0 命中；vulnpy `cmdi.py` 只命中 `subprocess-shell-true`。**需修正的一处**：`uninstaller.py` 并非完全不命中，现有文件在 L51、L73 命中 `dangerous-subprocess-use-audit`（未认证，不阻断，但作为负样本会进 precision 的 FP）。`[已实测]`
5. **create 事件真实性**：`challenge/utility.py` 有真实新增提交 `eb60468a`；`utils_string.py` 的最早提交是修改，真实新增点未核实。若 builder 要求 create 的 `after` 必须来自真实新增提交，后者需换文件。`[未核实]`
6. **行号可回溯**：所有行号来自本次 `contents?ref=<sha>` 读取的原文；`config.py`、`utils_string.py` 的提交历史未查全，相关 provenance 标 `[未核实]`。
7. **未做的事**：没有写 label、没有声称 GT、没有判定「是否通过」；sink 可达性的人工确认（尤其跨文件的 vulnpy 库函数与 VAmPI `text()` 路径）仍需标注者复核。

---

## 复测结果（2026-11-20）

**范围**：本文 25 个唯一 positive 文件 + 12 个已在上游存在的负样本候选文件，共 37 个，全部 `exit 0`、`errors=0`。

**调用形状**：本机 shipped 的 `semgrep scan --config` 在沙箱下挂起（120s 超时），改用 `semgrep-core -rules <snapshot> -lang python <file> -json -timeout 30 -filter_irrelevant_rules` 逐文件执行。`semgrep-core` 版本 1.184.0，与 `configs/b4.json` 一致；两个子集 sha256 与 config 一致；输出 `engine_kind: "OSS"` 会被 `src/l3/semgrep.ts:143-149` 归一为 `core`，解析形状与 shipped 一致。**结论仍应标注为「core 直调」，不是 shipped CLI 路径**。

**认证规则命中（`check_id` 精确等于 `blockRules`）**：

| 文件 | 命中 | 行 |
| --- | --- | --- |
| `pygoat@2aa4cc1:dockerized_labs/command_injection_lab/app.py` | `subprocess-shell-true` | L30 |
| `vulnpy@b81885e:src/vulnpy/trigger/cmdi.py` | `subprocess-shell-true` | L11 |
| `pygoat@2aa4cc1:dockerized_labs/sql_injection_lab/app.py` | `sql-injection-db-cursor-execute`（两条）、`formatted-sql-query` | L46、L47 → L57 |
| `vulnpy@b81885e:src/vulnpy/trigger/sqli.py` | `formatted-sql-query` | L37 |

**未认证命中（不产生 deny）**：`dangerous-subprocess-use-audit`（PyGoat cmdi L29、uninstaller L51/L73）、`dangerous-subprocess-use.lang`（cmdi L30）、`subprocess-injection.flask`（cmdi L29）、`dangerous-system-call-audit`（vulnpy cmdi L6）、`sqlalchemy-execute-raw-query`（PyGoat sql L57、vulnpy sqli L37）、`ssrf-injection-requests` / `ssrf-requests`（PyGoat ssrf L35/L37）、`direct-use-of-httpresponse`（vulnpy django vulnerable L20/L38、vulnerable_asgi L39/L57）。其余文件 0 命中，包括 VAmPI 全部 6 个文件、022 的 `pt.py` 与 `template_injection_lab`、079 的 PyGoat xss 与其 8 个 vulnpy 文件、798 全部 5 个文件。

**结论**：

- 可 deny 的独立样本仍只有 4 个（078×2、089×2）。
- 按 `POSITIVE_CAP_PER_CLASS = 4` 最多 stage 17 个样本（078:2 + 089:3 + 022:3 + 079:4 + 798:4），`n < 20`，判 `insufficient_n`。
- 即使放宽 cap，recall = 4/17 ≈ 0.235，远低于 0.70。
- 更硬的上限：认证规则只覆盖 078/089，可 deny 机制总数 ≤5；在 `n ≥ 20` 约束下 recall ≤ 5/20 = 0.25。**只要 `blockRules` 不变，扩本类语料无法让 line 1 达标**，缺口在规则认证与 078/089 供给，不在语料数量。
- 负样本 precision 风险：`uninstaller.py` 现有 2 条 `dangerous-subprocess-use-audit`；precision 统计 eval 行上所有 merged findings（`scripts/acceptance.ts:676-688`），这两条会计入 FP。
