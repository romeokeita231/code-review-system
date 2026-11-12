"""#41 第 1 步：候选清点（只出路径与行号，不做标注，不跑探测器）。

按类跑 `git grep -nE`，输出机器可核的候选行；判定列（sink 是否存在 / 是否缺控制型）
由人工在 docs 里填，脚本不做判断。
"""

import collections
import json
import os
import subprocess
import sys

PATTERNS = {
    "078": [r"child_process", r"\bexecSync?\s*\(", r"\bexecFile\s*\(", r"\bspawn\s*\(",
            r"shell\s*:\s*true"],
    "022": [r"path\.(join|resolve)\s*\(", r"fs\.(readFile|readFileSync|createReadStream)\s*\(",
            r"res\.sendFile\s*\(", r"express\.static\s*\("],
    "089": [r"sequelize\.query\s*\(", r"\.query\s*\(\s*[\"'`]", r"knex\.raw\s*\(", r"\.raw\s*\("],
    "094": [r"\beval\s*\(", r"new\s+Function\s*\(", r"vm\.runIn", r"\bvm2\b",
            r"require\s*\(\s*[^'\"\s]"],
    "079": [r"innerHTML", r"dangerouslySetInnerHTML", r"document\.write",
            r"bypassSecurityTrust", r"\$sce\.trustAs", r"res\.send\s*\([^)]*\+"],
    "918": [r"axios\.(get|post|request)\s*\(", r"\bfetch\s*\(", r"\brequest\s*\(",
            r"https?\.(get|request)\s*\(", r"puppeteer", r"wkhtmlto"],
    "798": [r"(secret|password|passwd|api[_-]?key|token)\s*[:=]\s*['\"][^'\"]{6,}",
            r"jwt\.sign\s*\(", r"JWT_SECRET"],
}

EXCLUDES = [
    ":(exclude)**/*.spec.ts",
    ":(exclude)**/*.spec.js",
    ":(exclude)test/**",
    ":(exclude)**/test/**",
    ":(exclude)**/node_modules/**",
    ":(exclude)**/*.d.ts",
    ":(exclude)frontend/**/*.html",
    ":(exclude)**/*.json",
]


def git_grep(repo, pattern):
    cmd = [
        "git", "-C", repo, "grep", "-n", "-I", "-E",
        "--", pattern, "--", "*.ts", "*.js", *EXCLUDES,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    if proc.returncode not in (0, 1):
        raise SystemExit(f"git grep failed ({proc.returncode}): {proc.stderr[:400]}")
    rows = []
    for line in proc.stdout.splitlines():
        # `git grep -n` emits path:line:text (three fields, no column); splitting on
        # four silently drops every hit whose text has no colon.
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path, lineno, text = parts
        rows.append({"path": path, "line": int(lineno), "text": text.strip()[:200]})
    return rows


def main():
    repo = sys.argv[1]
    out = sys.argv[2]
    result = {}
    for cwe, pats in PATTERNS.items():
        seen = {}
        for pat in pats:
            for row in git_grep(repo, pat):
                key = (row["path"], row["line"])
                seen.setdefault(key, {**row, "pattern": pat})
        rows = sorted(seen.values(), key=lambda r: (r["path"], r["line"]))
        by_file = collections.Counter(r["path"] for r in rows)
        result[cwe] = {
            "hits": len(rows),
            "files": len(by_file),
            "top_files": by_file.most_common(15),
            "rows": rows,
        }
        print(f"{cwe}: {len(rows)} hits in {len(by_file)} files", flush=True)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"repo": repo, "excludes": EXCLUDES, "classes": result}, fh,
                  indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
