import argparse
import json
import os
import shutil
import subprocess
import time
import uuid


def ppath_of(path):
    return "/" + os.path.basename(path).replace("\\", "/")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--sample", required=True)
    ap.add_argument("--analyzer", default="typescript")
    ap.add_argument("--ext", default="ts")
    ap.add_argument("--n", type=int, default=15)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--extra", default="", help="extra core flags, space separated")
    ap.add_argument("--label", default="core")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    work = os.path.dirname(os.path.abspath(args.out))
    run_dir = os.path.join(work, "cb_" + uuid.uuid4().hex[:8])
    os.makedirs(run_dir)
    rows = []
    try:
        for i in range(args.warmup + args.n):
            target = os.path.join(run_dir, f"t{i:03d}.{args.ext}")
            shutil.copyfile(args.sample, target)
            targets_path = os.path.join(run_dir, f"tg{i:03d}.json")
            with open(targets_path, "w", encoding="utf-8") as fh:
                json.dump(["Targets", [["CodeTarget", {
                    "path": {"fpath": os.path.abspath(target), "ppath": ppath_of(target)},
                    "analyzer": args.analyzer, "products": ["sast"]}]]], fh)
            cmd = [args.core, "-rules", os.path.abspath(args.rules),
                   "-targets", targets_path, "-json"]
            if args.extra:
                cmd.extend(args.extra.split())
            t0 = time.perf_counter()
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=300)
            ms = (time.perf_counter() - t0) * 1000
            results = None
            errors = None
            out_bytes = len(proc.stdout.encode("utf-8"))
            try:
                raw = proc.stdout
                raw = raw[raw.find("{"):]
                doc = json.loads(raw.lstrip("\ufeff"))
                results = len(doc.get("results", []))
                errors = len(doc.get("errors", []))
                if args.extra and "-json_time" in args.extra:
                    rows.append({"phase": "warmup" if i < args.warmup else "run",
                                 "i": i, "ms": round(ms, 1), "rc": proc.returncode,
                                 "results": results, "errors": errors,
                                 "out_bytes": out_bytes, "label": args.label,
                                 "profile": doc.get("profiling_results")})
                    continue
            except Exception:
                pass
            row = {"phase": "warmup" if i < args.warmup else "run", "i": i,
                   "ms": round(ms, 1), "rc": proc.returncode, "results": results,
                   "errors": errors, "out_bytes": out_bytes, "label": args.label,
                   "err_head": proc.stderr.strip().splitlines()[-1][:160] if proc.stderr.strip() else ""}
            rows.append(row)
            print(json.dumps({k: row[k] for k in ("phase", "i", "ms", "rc", "results", "out_bytes")}), flush=True)
    finally:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=1)
        shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
