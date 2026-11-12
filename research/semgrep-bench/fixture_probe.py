import argparse
import json
import os
import subprocess

ANALYZER = {".py": "python", ".ts": "typescript", ".tsx": "typescript"}


def run_core(core, rules, target, cwd):
    ext = os.path.splitext(target)[1].lower()
    tg = os.path.join(os.path.dirname(target), "_targets.json")
    with open(tg, "w", encoding="utf-8") as fh:
        json.dump(["Targets", [["CodeTarget", {
            "path": {"fpath": os.path.abspath(target),
                     "ppath": "/" + os.path.basename(target)},
            "analyzer": ANALYZER[ext], "products": ["sast"]}]]], fh)
    proc = subprocess.run([core, "-rules", rules, "-targets", tg, "-json"],
                          cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300)
    os.remove(tg)
    raw = proc.stdout
    start = raw.find("{")
    doc = json.loads(raw[start:].lstrip("\ufeff")) if start >= 0 else {}
    return proc, doc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", required=True)
    ap.add_argument("--fixtures", required=True)
    ap.add_argument("--py-rules", required=True)
    ap.add_argument("--ts-rules", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--doc-dir")
    args = ap.parse_args()

    fixtures = sorted(f for f in os.listdir(args.fixtures) if f.endswith((".py", ".ts")))
    report = {"rules": {}, "fixtures": [], "ignore_probe": {}}
    for name in fixtures:
        path = os.path.join(args.fixtures, name)
        rules = args.py_rules if name.endswith(".py") else args.ts_rules
        rules_label = os.path.basename(rules)
        proc, doc = run_core(args.core, rules, path, args.fixtures)
        scanned = (doc.get("paths") or {}).get("scanned") or []
        entry = {
            "fixture": name,
            "rules": rules_label,
            "bytes": os.path.getsize(path),
            "expected_results": len(doc.get("results", [])),
            "check_ids": sorted({r["check_id"] for r in doc.get("results", [])}),
            "rc": proc.returncode,
            "errors": len(doc.get("errors") or []),
            "paths_scanned": scanned,
            "paths_scanned_is_absolute_fpath": all(os.path.isabs(p) for p in scanned),
        }
        report["fixtures"].append(entry)
        if args.doc_dir:
            os.makedirs(args.doc_dir, exist_ok=True)
            with open(os.path.join(args.doc_dir, f"doc_{name.replace('.', '_')}.json"),
                      "w", encoding="utf-8") as fh:
                json.dump({"engine_version": doc.get("version"), "fixture": name,
                           "rules": rules_label, "doc": doc}, fh, ensure_ascii=False)

    ignore_path = os.path.join(args.fixtures, ".semgrepignore")
    target = os.path.join(args.fixtures, "target.py")
    with open(ignore_path, "w", encoding="utf-8") as fh:
        fh.write("target.py\n")
    try:
        proc, doc = run_core(args.core, args.py_rules, target, args.fixtures)
        report["ignore_probe"] = {
            "cwd": args.fixtures,
            "semgrepignore": "target.py",
            "target": "target.py",
            "results_with_ignore": len(doc.get("results", [])),
            "paths_scanned_with_ignore": (doc.get("paths") or {}).get("scanned"),
            "ignore_applied": len(doc.get("results", [])) == 0,
            "rc": proc.returncode,
        }
    finally:
        os.remove(ignore_path)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(json.dumps([{k: f[k] for k in ("fixture", "expected_results", "rc",
                                        "paths_scanned")} for f in report["fixtures"]],
                     ensure_ascii=False, indent=2))
    print(json.dumps(report["ignore_probe"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
