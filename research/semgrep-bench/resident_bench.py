import argparse
import json
import os
import shutil
import subprocess
import time
import uuid

ENCODING = "utf-8"


def write_packet(stream, payload):
    data = payload.encode(ENCODING)
    stream.write(str(len(data)).encode(ENCODING) + b"\n")
    stream.write(data)
    stream.flush()


def read_packet(stream):
    raw = stream.readline()
    if raw == b"":
        return None
    header = raw.decode(ENCODING, errors="replace").strip()
    if not header.isdigit():
        return None
    size = int(header)
    buf = b""
    while len(buf) < size:
        chunk = stream.read(size - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf.decode(ENCODING, errors="replace")


def start_core(core, cwd, extra=None):
    cmd = [core, "-rpc"] + (extra or [])
    return subprocess.Popen(
        cmd,
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


def build_targets(paths, analyzer):
    targets = [
        ["CodeTarget", {"path": {"fpath": p,
                                 "ppath": "/" + os.path.basename(p).replace("\\", "/")},
                        "analyzer": analyzer, "products": ["sast"]}]
        for p in paths
    ]
    return ["Targets", targets]


def call_scan(proc, rules_path, targets_path, timeout=0.0):
    payload = json.dumps({
        "call": ["CallScan", {
            "rules": rules_path,
            "targets": targets_path,
            "timeout": timeout,
            "timeout_threshold": 0,
        }]
    })
    write_packet(proc.stdin, payload)
    return read_packet(proc.stdout)


def proc_stats(pid):
    out = {}
    try:
        import psutil
        p = psutil.Process(pid)
        info = p.memory_info()
        out["rss_mb"] = round(info.rss / 1048576, 1)
        try:
            out["handles"] = p.num_handles()
        except Exception:
            pass
    except Exception:
        pass
    return out


def probe(args):
    proc = start_core(args.core, args.work)
    try:
        targets_path = os.path.join(args.work, "targets.json")
        with open(targets_path, "w", encoding=ENCODING) as fh:
            json.dump(build_targets([os.path.abspath(args.sample)], args.analyzer), fh)
        t0 = time.perf_counter()
        resp = call_scan(proc, os.path.abspath(args.rules), targets_path)
        ms = (time.perf_counter() - t0) * 1000
        print(json.dumps({"probe_ms": round(ms, 1), "bytes": len(resp) if resp else None,
                          "head": (resp or "")[:400]}, indent=2))
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def run_group(args, rules_path, sample, label):
    work = os.path.join(args.work, "g_" + uuid.uuid4().hex[:8])
    os.makedirs(work, exist_ok=True)
    proc = start_core(args.core, work)
    rows = []
    try:
        for i in range(args.n):
            target = os.path.join(work, f"t{i:03d}_{uuid.uuid4().hex[:6]}.{args.ext}")
            shutil.copyfile(sample, target)
            targets_path = os.path.join(work, f"targets{i:03d}.json")
            with open(targets_path, "w", encoding=ENCODING) as fh:
                json.dump(build_targets([target], args.analyzer), fh)
            stats_before = proc_stats(proc.pid)
            t0 = time.perf_counter()
            resp = call_scan(proc, rules_path, targets_path)
            ms = (time.perf_counter() - t0) * 1000
            stats_after = proc_stats(proc.pid)
            matches = None
            err = None
            if resp:
                try:
                    doc = json.loads(resp)
                    ret = doc.get("function_return")
                    if isinstance(ret, list) and ret[0] == "RetScan":
                        matches = len(ret[1].get("results", []))
                    elif isinstance(ret, list) and ret[0] == "RetError":
                        err = str(ret[1])[:200]
                except Exception as exc:
                    err = f"parse:{exc}"[:200]
            rows.append({
                "group": label,
                "i": i,
                "ms": round(ms, 1),
                "matches": matches,
                "resp_bytes": len(resp) if resp else None,
                "alive": proc.poll() is None,
                "rss_mb": stats_after.get("rss_mb"),
                "handles": stats_after.get("handles"),
                "err": err,
            })
            print(json.dumps(rows[-1]), flush=True)
            if not resp or proc.poll() is not None:
                break
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(work, ignore_errors=True)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--sample", required=True)
    ap.add_argument("--analyzer", default="typescript")
    ap.add_argument("--ext", default="ts")
    ap.add_argument("--n", type=int, default=15)
    ap.add_argument("--label", default="resident")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()
    if args.probe:
        probe(args)
        return
    rows = run_group(args, os.path.abspath(args.rules), args.sample, args.label)
    if args.out:
        with open(args.out, "w", encoding=ENCODING) as fh:
            json.dump(rows, fh, indent=2)


if __name__ == "__main__":
    main()
