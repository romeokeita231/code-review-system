import argparse
import json
import os
import queue
import shutil
import subprocess
import threading
import time

ENCODING = "utf-8"


class LspClient:
    def __init__(self, cmd, cwd):
        self.proc = subprocess.Popen(
            cmd, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.buf = b""
        self.lock = threading.Lock()
        self.inbox = queue.Queue()
        self.seen = []
        self.stderr_lines = []
        threading.Thread(target=self._read_loop, daemon=True).start()
        threading.Thread(target=self._stderr_loop, daemon=True).start()

    def _read_loop(self):
        fd = self.proc.stdout.fileno()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                self.inbox.put(None)
                return
            with self.lock:
                self.buf += chunk
                while True:
                    idx = self.buf.find(b"\r\n\r\n")
                    if idx < 0:
                        break
                    header = self.buf[:idx].decode(ENCODING, errors="replace")
                    length = None
                    for line in header.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            length = int(line.split(":", 1)[1].strip())
                    if length is None:
                        self.buf = self.buf[idx + 4:]
                        continue
                    start = idx + 4
                    if len(self.buf) < start + length:
                        break
                    body = self.buf[start:start + length]
                    self.buf = self.buf[start + length:]
                    try:
                        self.inbox.put(json.loads(body.decode(ENCODING, errors="replace")))
                    except Exception:
                        pass

    def _stderr_loop(self):
        for line in self.proc.stderr:
            text = line.decode(ENCODING, errors="replace").strip()
            if text:
                self.stderr_lines.append(text)
                if len(self.stderr_lines) > 200:
                    del self.stderr_lines[0]

    def send(self, obj):
        data = json.dumps(obj).encode(ENCODING)
        self.proc.stdin.write(b"Content-Length: %d\r\n\r\n" % len(data))
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def notify(self, method, params):
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, msg_id, method, params):
        self.send({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params})

    def wait(self, timeout, predicate):
        deadline = time.time() + timeout
        while True:
            remain = deadline - time.time()
            if remain <= 0:
                return None
            try:
                msg = self.inbox.get(timeout=remain)
            except queue.Empty:
                return None
            if msg is None:
                return {"__eof__": True}
            if msg.get("method") and "id" in msg:
                self._answer_server_request(msg)
                continue
            self.seen.append(msg)
            if predicate(msg):
                return msg

    def _answer_server_request(self, msg):
        method = msg.get("method")
        if method in ("client/registerCapability", "client/unregisterCapability",
                      "window/workDoneProgress/create"):
            result = None
        elif method == "workspace/configuration":
            result = [None] * len(msg.get("params", {}).get("items", []))
        else:
            result = None
        self.send({"jsonrpc": "2.0", "id": msg["id"], "result": result})

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def uri(path):
    return "file:///" + path.replace("\\", "/")


def uri_matches(msg_uri, path):
    from urllib.parse import unquote
    if not msg_uri:
        return False
    return unquote(msg_uri).replace("\\", "/").lower().endswith(
        path.replace("\\", "/").lower())


def stats(pid):
    out = {}
    try:
        import psutil
        p = psutil.Process(pid)
        procs = [p] + p.children(recursive=True)
        out["rss_mb"] = round(sum(x.memory_info().rss for x in procs) / 1048576, 1)
        out["nprocs"] = len(procs)
        try:
            out["handles"] = sum(x.num_handles() for x in procs)
        except Exception:
            pass
    except Exception:
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--sample", required=True)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--ext", default="ts")
    ap.add_argument("--language-id", default="typescript")
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--out")
    args = ap.parse_args()

    ws = os.path.join(args.work, "lsp_ws")
    shutil.rmtree(ws, ignore_errors=True)
    os.makedirs(ws)
    with open(args.sample, "r", encoding=ENCODING) as fh:
        content = fh.read()
    paths = []
    for i in range(args.n):
        path = os.path.join(ws, f"f{i:03d}.{args.ext}")
        with open(path, "w", encoding=ENCODING, newline="\n") as fh:
            fh.write(content)
        paths.append(path)
    chg_path = os.path.join(ws, f"fchange.{args.ext}")
    with open(chg_path, "w", encoding=ENCODING, newline="\n") as fh:
        fh.write(content)

    client = LspClient([args.semgrep, "lsp"], cwd=ws)
    rows = []
    init_ms = None
    try:
        t0 = time.perf_counter()
        client.request(1, "initialize", {
            "processId": os.getpid(),
            "rootUri": uri(ws),
            "workspaceFolders": [{"uri": uri(ws), "name": "ws"}],
            "capabilities": {
                "workspace": {"workspaceFolders": True, "configuration": True},
                "textDocument": {"publishDiagnostics": {"relatedInformation": True},
                                 "synchronization": {"didSave": True}},
            },
            "initializationOptions": {
                "scan": {"configuration": [args.rules], "jobs": 1},
                "metrics": {"enabled": False},
            },
        })
        init = client.wait(args.timeout, lambda m: m.get("id") == 1)
        init_ms = (time.perf_counter() - t0) * 1000
        client.notify("initialized", {})
        print(json.dumps({"init_ms": round(init_ms, 1),
                          "init_err": None if init and "result" in init else
                          (json.dumps(init)[:300] if init else "timeout")}), flush=True)

        msg_id = 10
        for i in range(args.n):
            path = paths[i]
            before = stats(client.proc.pid)
            t0 = time.perf_counter()
            client.notify("textDocument/didOpen", {"textDocument": {
                "uri": uri(path), "languageId": args.language_id, "version": 1,
                "text": content}})
            msg = client.wait(args.timeout, lambda m: m.get("method") == "textDocument/publishDiagnostics"
                              and uri_matches(m.get("params", {}).get("uri"), path))
            ms = (time.perf_counter() - t0) * 1000
            diags = len(msg["params"].get("diagnostics", [])) if msg and "params" in msg else None
            row = {"i": i, "ms": round(ms, 1) if msg else None, "diagnostics": diags,
                   "timed_out": msg is None, "rss_before": before.get("rss_mb"),
                   **stats(client.proc.pid)}
            rows.append(row)
            print(json.dumps(row), flush=True)
            msg_id += 1
            if msg is None:
                break

        client.notify("textDocument/didOpen", {"textDocument": {
            "uri": uri(chg_path), "languageId": args.language_id, "version": 1,
            "text": content}})
        client.wait(args.timeout, lambda m: m.get("method") == "textDocument/publishDiagnostics"
                    and uri_matches(m.get("params", {}).get("uri"), chg_path))
        for k in range(3):
            version = k + 2
            t0 = time.perf_counter()
            client.notify("textDocument/didChange", {
                "textDocument": {"uri": uri(chg_path), "version": version},
                "contentChanges": [{"text": content + f"\n// rev {k}\n"}],
            })
            msg = client.wait(args.timeout, lambda m: m.get("method") == "textDocument/publishDiagnostics"
                              and uri_matches(m.get("params", {}).get("uri"), chg_path))
            dur = (time.perf_counter() - t0) * 1000
            row = {"i": k, "phase": "change", "ms": round(dur, 1) if msg else None,
                   "diagnostics": len(msg["params"].get("diagnostics", [])) if msg else None,
                   "timed_out": msg is None, **stats(client.proc.pid)}
            rows.append(row)
            print(json.dumps(row), flush=True)
            if msg is None:
                break
    finally:
        client.close()
        if args.out:
            with open(args.out, "w", encoding=ENCODING) as fh:
                json.dump({"init_ms": init_ms, "rows": rows,
                           "seen": [{"method": m.get("method"), "id": m.get("id"),
                                     "uri": m.get("params", {}).get("uri"),
                                     "ndiag": len(m.get("params", {}).get("diagnostics", [])
                                                  if isinstance(m.get("params"), dict) else [])}
                                    for m in client.seen],
                           "stderr_tail": client.stderr_lines[-15:]}, fh, indent=2)


if __name__ == "__main__":
    main()
