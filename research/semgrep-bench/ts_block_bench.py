"""TS 小档（5-50 KiB）block 侧延迟实测：#41 第 0 步 / #25 R2 欠账。

两种调用形态分开报，因为 1.2 s 判据当初是对着 semgrep-core 直接调用认证的，
而 src/l3/semgrep.ts 实际走的是完整 CLI：

  core: semgrep-core -rules <ts_dedup.yaml> -targets <targets.json> -json
  cli : semgrep scan --config <ruleFile> --json --no-git-ignore
        --x-semgrepignore-filename .semgrepignore <rel>

协议与 research/semgrep-bench/core_bench.py / bench.py 保持一致：
每个样本文件 1 次、n = 样本数、1 次 warmup 丢弃、线性插值百分位。

样本是 node_modules 里真实的第三方 .ts 文件（5-50 KiB，按体积升序取 10 个等距点），
路径 + 字节数 + sha256 全部写进输出，保证可复现。
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid

RULES_SHA256 = "42e5be0c4fe108ed7d3be0575d45c1d34990050b28d9a60c2b376e146a7c470b"
MIN_BYTES = 5 * 1024
MAX_BYTES = 50 * 1024
LIMIT_MS = 1200.0


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def percentile(sorted_values, p):
    """线性插值百分位，与 results.json / recert_after_rename.json 同法。"""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    rank = (len(sorted_values) - 1) * (p / 100.0)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = rank - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def pick_samples(root, count):
    """真实 .ts 文件（5-50 KiB），按体积升序等距取点。"""
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if not name.endswith(".ts"):
                continue
            path = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if MIN_BYTES <= size <= MAX_BYTES:
                found.append((size, path))
    found.sort()
    if len(found) < count:
        raise SystemExit(f"only {len(found)} candidates in range, need {count}")
    step = (len(found) - 1) / (count - 1)
    picked = [found[round(i * step)] for i in range(count)]
    return [
        {
            "rel": os.path.relpath(path, root).replace("\\", "/"),
            "bytes": size,
            "sha256": sha256_file(path),
        }
        for size, path in picked
    ]


def run_core(core, rules, sample_path, run_dir, index):
    target = os.path.join(run_dir, f"t{index:03d}.ts")
    shutil.copyfile(sample_path, target)
    targets_path = os.path.join(run_dir, f"tg{index:03d}.json")
    with open(targets_path, "w", encoding="utf-8") as fh:
        json.dump(
            [
                "Targets",
                [
                    [
                        "CodeTarget",
                        {
                            "path": {
                                "fpath": os.path.abspath(target),
                                "ppath": "/" + os.path.basename(target),
                            },
                            "analyzer": "typescript",
                            "products": ["sast"],
                        },
                    ]
                ],
            ],
            fh,
        )
    started = time.perf_counter()
    proc = subprocess.run(
        [core, "-rules", os.path.abspath(rules), "-targets", targets_path, "-json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    return (time.perf_counter() - started) * 1000.0, proc


def run_cli(semgrep_bin, rules, sample_path, work, index):
    root = os.path.join(work, "cli", uuid.uuid4().hex)
    os.makedirs(root)
    try:
        rel = "sample.ts"
        shutil.copyfile(sample_path, os.path.join(root, rel))
        rule_file = os.path.join(root, "rules-typescript-full.yaml")
        shutil.copyfile(rules, rule_file)
        with open(os.path.join(root, ".semgrepignore"), "w", encoding="utf-8") as fh:
            fh.write("")
        started = time.perf_counter()
        proc = subprocess.run(
            [
                semgrep_bin,
                "scan",
                "--config",
                rule_file,
                "--json",
                "--no-git-ignore",
                "--x-semgrepignore-filename",
                ".semgrepignore",
                rel,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            timeout=300,
        )
        return (time.perf_counter() - started) * 1000.0, proc
    finally:
        shutil.rmtree(root, ignore_errors=True)


def parse_findings(stdout, mode):
    try:
        raw = stdout[stdout.find("{"):] if mode == "core" else stdout
        doc = json.loads(raw.lstrip("\ufeff"))
    except Exception:  # noqa: BLE001
        return None
    return len(doc.get("results", []))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["core", "cli"], required=True)
    ap.add_argument("--core", default=None)
    ap.add_argument("--semgrep", default=None)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--samples-root", required=True)
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rules_sha = sha256_file(args.rules)
    if rules_sha != RULES_SHA256:
        raise SystemExit(f"rules sha256 {rules_sha} != pinned {RULES_SHA256}")

    work = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(work, exist_ok=True)
    samples = pick_samples(args.samples_root, args.count)

    run_dir = os.path.join(work, f"tbb_{uuid.uuid4().hex[:8]}")
    os.makedirs(run_dir)
    rows = []
    try:
        plan = [("warmup", samples[0])] + [("run", s) for s in samples]
        for i, (phase, sample) in enumerate(plan):
            path = os.path.join(args.samples_root, sample["rel"])
            try:
                if args.mode == "core":
                    ms, proc = run_core(args.core, args.rules, path, run_dir, i)
                    findings = parse_findings(proc.stdout, "core")
                else:
                    ms, proc = run_cli(args.semgrep, args.rules, path, work, i)
                    findings = parse_findings(proc.stdout, "cli")
                row = {
                    "phase": phase,
                    "i": i,
                    "sample": sample["rel"],
                    "bytes": sample["bytes"],
                    "ms": round(ms, 1),
                    "rc": proc.returncode,
                    "results": findings,
                    "err_tail": (proc.stderr.strip().splitlines() or [""])[-1][:200],
                }
            except subprocess.TimeoutExpired:
                row = {
                    "phase": phase,
                    "i": i,
                    "sample": sample["rel"],
                    "bytes": sample["bytes"],
                    "ms": None,
                    "rc": -9,
                    "results": None,
                    "err_tail": "timeout",
                }
            rows.append(row)
            print(json.dumps({k: row[k] for k in ("phase", "sample", "ms", "rc", "results")}), flush=True)
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    measured = [r for r in rows if r["phase"] == "run"]
    times = sorted(r["ms"] for r in measured if r["ms"] is not None)
    failures = [r for r in measured if r["rc"] != 0 or r["ms"] is None]
    summary = {
        "mode": args.mode,
        "rules": {
            "path": os.path.relpath(args.rules, os.getcwd()).replace("\\", "/"),
            "sha256": rules_sha,
            "bytes": os.path.getsize(args.rules),
        },
        "samples": samples,
        "n": len(measured),
        "failures": len(failures),
        "results_total": sum(r["results"] or 0 for r in measured),
        "p50_ms": round(percentile(times, 50), 1),
        "p95_ms": round(percentile(times, 95), 1),
        "p99_ms": round(percentile(times, 99), 1),
        "min_ms": times[0] if times else None,
        "max_ms": times[-1] if times else None,
        "limit_ms": LIMIT_MS,
        "verdict": "pass" if times and percentile(times, 99) <= LIMIT_MS else "fail",
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "rows": rows}, fh, indent=1, ensure_ascii=False)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
