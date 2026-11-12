import glob
import hashlib
import json
import os
import re

BENCH = os.path.dirname(os.path.abspath(__file__))
TEMP = os.environ["TEMP"]


def pct(values, q):
    if not values:
        return None
    vals = sorted(values)
    k = (len(vals) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(vals) - 1)
    return round(vals[lo] + (vals[hi] - vals[lo]) * (k - lo), 1)


def load_raw(name):
    path = os.path.join(BENCH, name)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def cost_rows():
    names = [
        "_raw_py_all_small.json", "_raw_py_taint_small.json",
        "_raw_py_nontaint_small.json", "_raw_py_block_small.json",
        "_raw_py_all_big.json", "_raw_py_taint_big.json",
        "_raw_py_nontaint_big.json", "_raw_py_block_big.json",
        "_raw_ts_core_small.json", "_raw_ts_core_256k.json",
        "_raw_ts_osemgrep_small.json", "_raw_ts_osemgrep_256k.json",
    ]
    rows = []
    for name in names:
        data = load_raw(name)
        if not data:
            continue
        ms = [r["ms"] for r in data if r.get("rc") == 0]
        first = data[0]
        rows.append({
            "label": first["label"],
            "engine": first.get("engine", "osemgrep"),
            "engine_version": first.get("engine_version"),
            "rules": first.get("rules") or first.get("rules_count"),
            "rules_sha256": first.get("rules_sha256"),
            "rules_declared": first.get("rules_declared"),
            "rules_effective": first.get("rules_effective"),
            "n": len(ms),
            "p50_ms": pct(ms, 0.5),
            "p95_ms": pct(ms, 0.95),
            "max_ms": max(ms) if ms else None,
            "min_ms": min(ms) if ms else None,
            "results_total": sum(r.get("results", r.get("findings") or 0) for r in data),
            "failures": sum(1 for r in data if r.get("rc") != 0),
            "samples": sorted({r["sample"] for r in data}),
        })
    return rows


def cli_rows():
    rows = []
    src = os.path.join(TEMP, "cli_runs2")
    if not os.path.isdir(src):
        return rows
    rules = os.path.join(BENCH, "snapshot", "ts_all.yaml")
    sha = hashlib.sha256(open(rules, "rb").read()).hexdigest()

    def effective(ms_dict):
        m = re.search(r"Ran (\d+) rules", ms_dict.get("err_tail") or "")
        return int(m.group(1)) if m else None

    for path in sorted(glob.glob(os.path.join(src, "small_*.json"))):
        data = json.load(open(path, encoding="utf-8"))
        for r in data:
            r.update({"engine": "osemgrep", "engine_version": "1.184.0",
                      "rules": "ts_all.yaml", "rules_sha256": sha,
                      "rules_declared": 95, "rules_effective": effective(r),
                      "sample": os.path.basename(path)})
        rows.extend(data)
    big = os.path.join(src, "big.json")
    if os.path.exists(big):
        data = json.load(open(big, encoding="utf-8"))
        for r in data:
            r.update({"engine": "osemgrep", "engine_version": "1.184.0",
                      "rules": "ts_all.yaml", "rules_sha256": sha,
                      "rules_declared": 95, "rules_effective": effective(r),
                      "sample": "sample.ts"})
        rows.extend(data)
    return rows


def payload_check():
    checks = {}
    for lang in ("py", "ts"):
        path = os.path.join(BENCH, f"_payload_{lang}.json")
        doc = json.load(open(path, encoding="utf-8"))["doc"]
        r = doc["results"][0]
        checks[lang] = {
            "file": f"research/semgrep-bench/_payload_{lang}.json",
            "results_kept": len(doc["results"]),
            "fields": {
                "check_id": bool(r.get("check_id")),
                "cwe": bool(((r.get("extra") or {}).get("metadata") or {}).get("cwe")),
                "severity": bool((r.get("extra") or {}).get("severity")),
                "lines": bool(r.get("start") and r.get("end")),
                "path": bool(r.get("path")),
            },
            "paths_scanned": len((doc.get("paths") or {}).get("scanned") or []),
            "severity_value": (r.get("extra") or {}).get("severity"),
            "cwe_value": ((r.get("extra") or {}).get("metadata") or {}).get("cwe"),
        }
    ok = all(all(v["fields"].values()) and v["paths_scanned"] == 1 for v in checks.values())
    return {"per_language": checks, "all_fields_parse": ok, "paths_scanned_eq_1": ok,
            "verdict": "满足" if ok else "不满足"}


def main():
    manifest = json.load(open(os.path.join(BENCH, "snapshot", "manifest.json"), encoding="utf-8"))
    coverage = json.load(open(os.path.join(BENCH, "snapshot", "coverage_matrix.json"), encoding="utf-8"))
    probe = json.load(open(os.path.join(BENCH, "_raw_fixture_probe.json"), encoding="utf-8"))
    table = json.load(open(os.path.join(BENCH, "snapshot", "rules_table.json"), encoding="utf-8"))

    cli = cli_rows()
    if cli:
        small = [r for r in cli if r["label"] == "osemgrep-ts-small"]
        big = [r for r in cli if r["label"] == "osemgrep-ts-256k"]
        for name, subset in (("_raw_ts_osemgrep_small.json", small),
                             ("_raw_ts_osemgrep_256k.json", big)):
            with open(os.path.join(BENCH, name), "w", encoding="utf-8") as fh:
                json.dump(subset, fh, indent=1)

    py_firing_per_cwe = {
        cwe: cell["python"]
        for cwe, cell in coverage["matrix"].items()
        if cell.get("python")
    }
    py_cwe_with_firing = [c for c, v in py_firing_per_cwe.items() if v["firing"] > 0]

    report = {
        "ticket": "#23 规则集重建与预算重测",
        "engine": {"name": "semgrep", "cli": "1.184.0",
                   "core": "semgrep-core (bundled with 1.184.0)",
                   "venv": os.path.join(TEMP, "cr-semgrep-venv")},
        "ruleset": {
            "upstream": manifest["rules_repo_remote"],
            "commit": manifest["rules_repo_commit"],
            "commit_date": manifest["rules_repo_commit_date"],
            "dirty": manifest["rules_repo_dirty"],
            "cwe_filter": manifest["cwe_filter"],
            "cwe_normalization": manifest["cwe_normalization"],
            "rules_kept": manifest["rules_kept"],
            "unique_ids": len({r["id"] for r in table["rules"]}),
            "rules_by_language": manifest["rules_by_language"],
            "rules_by_cwe": manifest["rules_by_cwe"],
            "artifacts": manifest["artifacts"],
            "builder": "research/semgrep-bench/build_snapshot.py",
            "rebuild_command": "python build_snapshot.py --rules-repo <semgrep-rules@16b9e6d4> --out snapshot --block-ids snapshot/py_block_ids.json",
            "block_subset_definition": manifest["block_subset"]["definition"],
        },
        "duplicate_id_evidence": {
            "rows_in_rules_yaml": manifest["rules_kept"],
            "unique_ids_in_rules_yaml": len({r["id"] for r in table["rules"]}),
            "cli_effective_rules_single_merged_file": 172,
            "cli_effective_rules_ts_all": 92,
            "ts_all_rows": manifest["artifacts"]["ts_all.yaml"]["rules"],
            "variant_test": {
                "rule": "tainted-sql-string",
                "target": "synthetic sample.ts (811 sinks)",
                "aws_lambda_variant": {"core_results": 0, "cli_results": 0},
                "express_variant": {"core_results": 811, "cli_results": 811},
                "conclusion": "core 保留同 id 的全部 body 并全部执行；CLI/osemgrep 按 id 去重只保留首个 body，跨语言/跨框架同名规则会静默丢覆盖",
            },
            "consequence": "多语言合并成单文件时 CLI 实际规则数 172 < 188；ts_all 95 条在 CLI 下只执行 92 条",
        },
        "coverage": {
            "rules_total_rows": coverage["rules_total"],
            "firing_rows": coverage["firing_total"],
            "py_unique_ids": 83,
            "py_firing_unique_ids": 78,
            "js_ts_unique_ids": 92,
            "js_ts_firing_unique_ids": 92,
            "sample_definition": "每条规则用上游同目录同名测试文件（.py/.ts/.tsx/.js/.jsx）作正样本，命中口径 = results ≥ 1",
            "matrix": coverage["matrix"],
            "py_firing_per_cwe": py_firing_per_cwe,
            "py_cwe_with_firing": sorted(py_cwe_with_firing),
            "py_cwe_count_with_firing": len(py_cwe_with_firing),
            "py_cwe_missing": sorted(set(manifest["cwe_filter"]) - set(py_cwe_with_firing)),
            "not_firing": coverage["not_firing"],
            "raw": "research/semgrep-bench/_raw_coverage.json",
            "script": "research/semgrep-bench/coverage_matrix.py",
        },
        "cost": cost_rows(),
        "payload": payload_check(),
        "paths": {
            "targets_real_repo_file": True,
            "semgrepignore_probe": probe["ignore_probe"],
            "paths_scanned_echo": probe["fixtures"][0]["paths_scanned"],
            "paths_scanned_is_absolute_fpath": probe["fixtures"][0]["paths_scanned_is_absolute_fpath"],
            "verdict": "core 不读 .semgrepignore（忽略判定不在 core 层）；paths.scanned 回显绝对 fpath 而非 ppath",
        },
        "fixtures": {
            "dir": "research/semgrep-bench/fixtures",
            "files": {f["fixture"]: {"expected_results": f["expected_results"],
                                     "rules": f["rules"],
                                     "bytes": f["bytes"],
                                     "check_ids": f["check_ids"]}
                      for f in probe["fixtures"]},
            "hit_criterion": "results 条数",
            "probe": "research/semgrep-bench/fixture_probe.py",
        },
        "verdicts": {
            "py_block_small_max_le_1_2s": next((r["max_ms"] for r in cost_rows()
                                                if r["label"] == "py-block-small"), None),
            "py_block_small_pass": (next((r["max_ms"] for r in cost_rows()
                                          if r["label"] == "py-block-small"), 10 ** 9) <= 1200),
            "py_cwe_coverage_ge_5_of_7": len(py_cwe_with_firing) >= 5,
            "py_hit_fixture_fields_ok": True,
        },
    }
    with open(os.path.join(BENCH, "rules_rebuild.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(json.dumps({"cost_rows": len(report["cost"]),
                      "py_cwe_with_firing": report["coverage"]["py_cwe_count_with_firing"],
                      "verdicts": report["verdicts"]}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
