import argparse
import json
import os
import shutil
import subprocess
import time
import uuid


def run_once(semgrep, rules, sample, flags, timeout, keep_dir):
    root = os.path.join(keep_dir, "cli_" + uuid.uuid4().hex[:8])
    os.makedirs(root)
    shutil.copyfile(sample, os.path.join(root, "target" + os.path.splitext(sample)[1]))
    shutil.copyfile(rules, os.path.join(root, "rules.yaml"))
    with open(os.path.join(root, ".semgrepignore"), "w", encoding="utf-8") as fh:
        fh.write("")
    cmd = [semgrep, "scan", "--config", "rules.yaml", "--json", "--metrics", "off",
           "--disable-version-check"] + flags + ["."]
    out_path = os.path.join(root, "_out.json")
    err_path = os.path.join(root, "_err.txt")
    t0 = time.perf_counter()
    rc = None
    stdout = ""
    err = ""
    with open(out_path, "w", encoding="utf-8") as out_fh, open(
            err_path, "w", encoding="utf-8") as err_fh, open(
            os.path.join(root, "_in.txt"), "w", encoding="utf-8") as in_fh:
        proc = subprocess.Popen(cmd, cwd=root, stdout=out_fh, stderr=err_fh,
                                stdin=in_fh)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rc = -9
            err = "timeout"
            try:
                import psutil
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
            except Exception:
                proc.kill()
    try:
        with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
            stdout = fh.read()
        with open(err_path, "r", encoding="utf-8", errors="replace") as fh:
            err = fh.read() if err != "timeout" else "timeout"
    except Exception:
        pass
    ms = (time.perf_counter() - t0) * 1000
    findings = None
    doc = None
    try:
        start = stdout.find("{")
        doc = json.loads(stdout[start:].lstrip("\ufeff"))
        findings = len(doc.get("results", []))
    except Exception:
        pass
    return {"ms": round(ms, 1), "rc": rc, "findings": findings,
            "out_bytes": len(stdout.encode("utf-8")), "err_tail": err.strip()[-160:],
            "doc": doc, "root": root}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--sample", required=True)
    ap.add_argument("--flags", default="")
    ap.add_argument("--label", default="cli")
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dump-doc")
    args = ap.parse_args()

    work = os.path.dirname(os.path.abspath(args.out))
    rows = []
    for i in range(args.warmup + args.n):
        r = run_once(args.semgrep, args.rules, args.sample, args.flags.split(),
                     args.timeout, work)
        row = {k: r[k] for k in ("ms", "rc", "findings", "out_bytes", "err_tail")}
        row["label"] = args.label
        row["phase"] = "warmup" if i < args.warmup else "run"
        rows.append(row)
        print(json.dumps(row), flush=True)
        if args.dump_doc and i == args.warmup:
            with open(args.dump_doc, "w", encoding="utf-8") as fh:
                json.dump(r["doc"], fh)
        shutil.rmtree(r["root"], ignore_errors=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)


if __name__ == "__main__":
    main()
