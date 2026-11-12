import argparse
import json
import os
import subprocess
import tempfile

import yaml

EXTS = [".py", ".ts", ".tsx", ".js", ".jsx"]
ANALYZER = {".py": "python", ".ts": "typescript", ".tsx": "typescript",
            ".js": "javascript", ".jsx": "javascript"}


def find_sample(rules_repo, source_file):
    stem = os.path.splitext(os.path.join(rules_repo, source_file))[0]
    cands = [stem + e for e in EXTS if os.path.exists(stem + e)]
    return cands[0] if cands else None


def ppath_of(path):
    return "/" + os.path.basename(path).replace("\\", "/")


def run_core(core, rule, sample, workdir):
    rule_path = os.path.join(workdir, "rule.yaml")
    with open(rule_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump({"rules": [rule]}, fh, sort_keys=False, allow_unicode=True)
    ext = os.path.splitext(sample)[1]
    tg_path = os.path.join(workdir, "targets.json")
    with open(tg_path, "w", encoding="utf-8") as fh:
        json.dump(["Targets", [["CodeTarget", {
            "path": {"fpath": os.path.abspath(sample), "ppath": ppath_of(sample)},
            "analyzer": ANALYZER.get(ext, "generic"), "products": ["sast"]}]]], fh)
    proc = subprocess.run(
        [core, "-rules", rule_path, "-targets", tg_path, "-json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    raw = proc.stdout
    start = raw.find("{")
    doc = {}
    if start >= 0:
        try:
            doc = json.loads(raw[start:].lstrip("\ufeff"))
        except Exception:
            doc = {}
    hits = [r.get("check_id") for r in doc.get("results", [])]
    scanned = (doc.get("paths") or {}).get("scanned")
    return {
        "rc": proc.returncode,
        "hits": hits,
        "scanned": len(scanned) if isinstance(scanned, list) else scanned,
        "errors": len(doc.get("errors") or []),
        "err_tail": proc.stderr.strip().splitlines()[-1][:200] if proc.stderr.strip() else "",
    }


LANGS = ["python", "javascript", "typescript"]


def summarize(rows, meta):
    matrix = {}
    for row in rows:
        for cwe in row["cwe"]:
            cell = matrix.setdefault(cwe, {})
            for lang in LANGS:
                if lang not in row["languages"]:
                    continue
                c = cell.setdefault(lang, {"rules": 0, "taint": 0, "firing": 0})
                c["rules"] += 1
                c["taint"] += 1 if row["is_taint"] else 0
                c["firing"] += 1 if row["fired"] else 0
    for cwe, cell in matrix.items():
        for lang, c in cell.items():
            c["taint_ratio"] = round(c["taint"] / c["rules"], 3) if c["rules"] else None
            c["firing_ratio"] = round(c["firing"] / c["rules"], 3) if c["rules"] else None
    py_firing = [r["rule_id"] for r in rows if r["fired"] and "python" in r["languages"]]
    ts_firing = [r["rule_id"] for r in rows if r["fired"]
                 and ("typescript" in r["languages"] or "javascript" in r["languages"])]
    not_firing = [{"rule_id": r["rule_id"], "cwe": r["cwe"], "languages": r["languages"],
                   "is_taint": r["is_taint"], "sample": r["sample"],
                   "reason": r.get("reason") or "no_hit"} for r in rows if not r["fired"]]
    return {
        **meta,
        "rules_total": len(rows),
        "firing_total": sum(1 for r in rows if r["fired"]),
        "matrix": {c: matrix[c] for c in sorted(matrix)},
        "py_firing_rules": sorted(py_firing),
        "py_firing_count": len(py_firing),
        "ts_js_firing_count": len(ts_firing),
        "not_firing": not_firing,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", required=True)
    ap.add_argument("--rules-repo", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--summary-out")
    ap.add_argument("--summarize-raw")
    args = ap.parse_args()

    if args.summarize_raw:
        with open(args.summarize_raw, "r", encoding="utf-8") as fh:
            rows = json.load(fh)
        with open(args.table, "r", encoding="utf-8") as fh:
            table = json.load(fh)
        meta = {"engine": "semgrep-core", "rules_total_table": table["rules_total"]}
        doc = summarize(rows, meta)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
        print(json.dumps({k: doc[k] for k in ("rules_total", "firing_total",
                                              "py_firing_count", "ts_js_firing_count")}))
        return

    with open(args.table, "r", encoding="utf-8") as fh:
        table = json.load(fh)
    with open(args.rules, "r", encoding="utf-8") as fh:
        bodies = {r["id"]: r for r in yaml.safe_load(fh)["rules"]}

    rows = []
    workdir = tempfile.mkdtemp(prefix="cov_")
    for i, row in enumerate(table["rules"]):
        rid = row["id"]
        sample = find_sample(args.rules_repo, row["source_file"])
        entry = {"rule_id": rid, "cwe": row["cwe"], "languages": row["languages"],
                 "is_taint": row["is_taint"], "severity": row["severity"],
                 "source_file": row["source_file"],
                 "sample": os.path.relpath(sample, args.rules_repo) if sample else None}
        if not sample:
            entry.update({"fired": False, "reason": "no_test_file"})
        else:
            try:
                res = run_core(args.core, bodies[rid], sample, workdir)
                entry.update({
                    "fired": rid in res["hits"],
                    "hits": len(res["hits"]),
                    "rc": res["rc"],
                    "paths_scanned": res["scanned"],
                    "errors": res["errors"],
                    "err_tail": res["err_tail"],
                })
            except subprocess.TimeoutExpired:
                entry.update({"fired": False, "reason": "timeout"})
        rows.append(entry)
        print(json.dumps({"i": i, "rule": rid, "fired": entry["fired"],
                          "hits": entry.get("hits"), "sample": entry["sample"]}), flush=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)


if __name__ == "__main__":
    main()
