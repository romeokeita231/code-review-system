import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid

import yaml

ANALYZER = {".py": "python", ".ts": "typescript", ".tsx": "typescript",
            ".js": "javascript", ".jsx": "javascript"}


def engine_version(core):
    proc = subprocess.run([core, "-version"], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=60)
    return (proc.stdout or proc.stderr).strip().splitlines()[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--files", required=True, help="JSON list of sample paths")
    ap.add_argument("--n", type=int, default=1, help="runs per file")
    ap.add_argument("--label", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dump-doc-dir")
    ap.add_argument("--timeout", type=float, default=300)
    args = ap.parse_args()

    with open(args.rules, "rb") as fh:
        rules_sha = hashlib.sha256(fh.read()).hexdigest()
    with open(args.rules, "r", encoding="utf-8") as fh:
        rule_count = len(yaml.safe_load(fh)["rules"])
    with open(args.files, "r", encoding="utf-8") as fh:
        samples = json.load(fh)

    version = engine_version(args.core)
    os.makedirs(args.work, exist_ok=True)
    os.makedirs(args.dump_doc_dir or args.work, exist_ok=True)
    rows = []
    dumped = set()
    for sample in samples:
        ext = os.path.splitext(sample)[1].lower()
        analyzer = ANALYZER.get(ext)
        if not analyzer:
            print(json.dumps({"sample": sample, "skip": "unsupported ext"}), flush=True)
            continue
        for i in range(args.n):
            run_dir = os.path.join(args.work, "cb_" + uuid.uuid4().hex[:8])
            os.makedirs(run_dir)
            target = os.path.join(run_dir, "target" + ext)
            with open(sample, "rb") as src, open(target, "wb") as dst:
                dst.write(src.read())
            tg = os.path.join(run_dir, "targets.json")
            with open(tg, "w", encoding="utf-8") as fh:
                json.dump(["Targets", [["CodeTarget", {
                    "path": {"fpath": os.path.abspath(target),
                             "ppath": "/target" + ext},
                    "analyzer": analyzer, "products": ["sast"]}]]], fh)
            t0 = time.perf_counter()
            try:
                proc = subprocess.run(
                    [args.core, "-rules", os.path.abspath(args.rules),
                     "-targets", tg, "-json"],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=args.timeout)
                ms = (time.perf_counter() - t0) * 1000
                rc = proc.returncode
                raw = proc.stdout
                err_tail = proc.stderr.strip().splitlines()[-1][:160] if proc.stderr.strip() else ""
            except subprocess.TimeoutExpired:
                ms, rc, raw, err_tail = (time.perf_counter() - t0) * 1000, -9, "", "timeout"
            doc = {}
            start = raw.find("{")
            if start >= 0:
                try:
                    doc = json.loads(raw[start:].lstrip("\ufeff"))
                except Exception:
                    doc = {}
            scanned = (doc.get("paths") or {}).get("scanned")
            row = {
                "label": args.label,
                "sample": os.path.basename(sample),
                "sample_path": sample,
                "sample_bytes": os.path.getsize(sample),
                "i": i,
                "ms": round(ms, 1),
                "rc": rc,
                "results": len(doc.get("results", [])),
                "errors": len(doc.get("errors") or []),
                "paths_scanned": len(scanned) if isinstance(scanned, list) else scanned,
                "engine": "semgrep-core",
                "engine_version": version,
                "rules_sha256": rules_sha,
                "rules_count": rule_count,
                "err_tail": err_tail,
            }
            rows.append(row)
            print(json.dumps({k: row[k] for k in ("label", "sample", "i", "ms", "rc",
                                                  "results", "paths_scanned")}), flush=True)
            if args.dump_doc_dir and raw and sample not in dumped:
                dumped.add(sample)
                dump_path = os.path.join(
                    args.dump_doc_dir, f"doc_{args.label}_{os.path.splitext(os.path.basename(sample))[0]}.json")
                with open(dump_path, "w", encoding="utf-8") as fh:
                    json.dump({"engine_version": version, "rules_sha256": rules_sha,
                               "rules_count": rule_count, "sample": sample,
                               "doc": doc}, fh, ensure_ascii=False)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)
    ok = sorted(r["ms"] for r in rows if r["rc"] == 0)
    if ok:
        def pct(q):
            k = (len(ok) - 1) * q
            lo, hi = int(k), min(int(k) + 1, len(ok) - 1)
            return round(ok[lo] + (ok[hi] - ok[lo]) * (k - lo), 1)
        print(json.dumps({"label": args.label, "n": len(ok), "p50_ms": pct(0.5),
                          "p95_ms": pct(0.95), "max_ms": ok[-1], "min_ms": ok[0],
                          "failures": [r for r in rows if r["rc"] != 0][:5]}))


if __name__ == "__main__":
    main()
