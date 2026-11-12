import argparse
import json
import os
import shutil
import subprocess
import time
import uuid

BIN = os.environ.get("SEMGREP_BIN") or shutil.which("semgrep")

WORK = None


def timed_run(config_dir, content, sample_rel, timeout):
    start = time.perf_counter()
    root = os.path.join(WORK, "tmp", uuid.uuid4().hex)
    target = os.path.join(root, sample_rel)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    with open(os.path.join(root, ".semgrepignore"), "w", encoding="utf-8") as fh:
        fh.write("")
    out_path = os.path.join(root, "_out.json")
    with open(os.path.join(root, "_empty.txt"), "w", encoding="utf-8") as empty_fh, open(
        out_path, "w", encoding="utf-8"
    ) as out_fh, open(
        os.path.join(root, "_err.txt"), "w", encoding="utf-8"
    ) as err_fh:
        proc = subprocess.run(
            [
                BIN,
                "scan",
                "--config",
                config_dir,
                "--json",
                "--metrics",
                "off",
                "--disable-version-check",
                "--x-semgrepignore-filename",
                ".semgrepignore",
                ".",
            ],
            cwd=root,
            stdin=empty_fh,
            stdout=out_fh,
            stderr=err_fh,
            text=True,
            timeout=timeout,
        )
    scan_end = time.perf_counter()
    data = {}
    try:
        with open(out_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:  # noqa: BLE001
        data = {}
    err_tail = ""
    try:
        with open(os.path.join(root, "_err.txt"), "r", encoding="utf-8") as fh:
            lines = [ln.strip() for ln in fh if ln.strip()]
            err_tail = lines[-1] if lines else ""
    except Exception:  # noqa: BLE001
        pass
    shutil.rmtree(root, ignore_errors=True)
    end = time.perf_counter()
    return {
        "total_ms": (end - start) * 1000,
        "scan_ms": (scan_end - start) * 1000,
        "rc": proc.returncode,
        "findings": len(data.get("results", [])) if data else None,
        "err_tail": err_tail[:200],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--sample", required=True)
    parser.add_argument("--rel", required=True)
    parser.add_argument("--mode", choices=["cold", "warm"], required=True)
    parser.add_argument("--n", type=int, default=10)
    parser.add_argument("--cold-copies", default=None)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--warmup", action="store_true")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    global WORK
    WORK = os.path.dirname(os.path.abspath(args.out))

    with open(args.sample, "r", encoding="utf-8") as fh:
        content = fh.read()

    if args.warmup:
        warmup = timed_run(args.config, content, args.rel, args.timeout)
        print(json.dumps({"warmup": round(warmup["total_ms"], 2), "rc": warmup["rc"]}), flush=True)

    rows = []
    for i in range(args.n):
        config_dir = args.config
        if args.mode == "cold":
            config_dir = os.path.join(args.cold_copies, f"c{i:02d}")
        try:
            result = timed_run(config_dir, content, args.rel, args.timeout)
        except subprocess.TimeoutExpired:
            result = {"total_ms": None, "scan_ms": None, "rc": -9, "findings": None, "err_tail": "timeout"}
        rows.append(
            {
                "mode": args.mode,
                "config": os.path.basename(args.config),
                "sample": os.path.basename(args.sample),
                "i": i,
                "total_ms": round(result["total_ms"], 2) if result["total_ms"] is not None else None,
                "scan_ms": round(result["scan_ms"], 2) if result["scan_ms"] is not None else None,
                "rc": result["rc"],
                "findings": result["findings"],
                "err_tail": result["err_tail"],
            }
        )
        print(json.dumps(rows[-1]), flush=True)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(rows, fh)


if __name__ == "__main__":
    main()
