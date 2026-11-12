import json
import os
import re
import subprocess
import tempfile

import yaml

BIN = os.environ["SEMGREP_BIN"].split("|")
CORE = os.environ["SEMGREP_CORE"]

CROSS = [
    {"id": "dup-key-test", "languages": ["python"], "message": "py body",
     "severity": "ERROR", "pattern": "py_marker($X)"},
    {"id": "dup-key-test", "languages": ["typescript"], "message": "ts body",
     "severity": "ERROR", "pattern": "ts_marker($X)"},
]
SAME = [
    {"id": "dup-key-test", "languages": ["python"], "message": "py body a",
     "severity": "ERROR", "pattern": "py_alpha($X)"},
    {"id": "dup-key-test", "languages": ["python"], "message": "py body b",
     "severity": "ERROR", "pattern": "py_beta($X)"},
]
CONTROL = [
    {"id": "ctrl-py", "languages": ["python"], "message": "py body",
     "severity": "ERROR", "pattern": "py_marker($X)"},
    {"id": "ctrl-ts", "languages": ["typescript"], "message": "ts body",
     "severity": "ERROR", "pattern": "ts_marker($X)"},
]
RENAMED = [
    {"id": "dup-key-test.alpha", "languages": ["python"], "message": "py body a",
     "severity": "ERROR", "pattern": "py_alpha($X)"},
    {"id": "dup-key-test.beta", "languages": ["python"], "message": "py body b",
     "severity": "ERROR", "pattern": "py_beta($X)"},
]


def write(root, rules, files):
    cfg = os.path.join(root, "rules.yaml")
    with open(cfg, "w", encoding="utf-8") as fh:
        yaml.safe_dump({"rules": rules}, fh, sort_keys=False, allow_unicode=True)
    for name, body in files.items():
        with open(os.path.join(root, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
    with open(os.path.join(root, ".semgrepignore"), "w", encoding="utf-8") as fh:
        fh.write("")
    return cfg


def run_cli(root, cfg, timeout=180):
    empty = os.path.join(root, "_empty.txt")
    with open(empty, "a", encoding="utf-8"):
        pass
    with open(empty, "r", encoding="utf-8") as stdin_fh:
        proc = subprocess.run(
            [*BIN, "scan", "--config", cfg, "--json", "--metrics", "off",
             "--disable-version-check", "--x-semgrepignore-filename", ".semgrepignore", "."],
            cwd=root, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, stdin=stdin_fh)
    doc = {}
    start = proc.stdout.find("{")
    if start >= 0:
        try:
            doc = json.loads(proc.stdout[start:].lstrip("\ufeff"))
        except Exception:
            doc = {}
    m = re.search(r"Ran (\d+) rules?", proc.stderr or "")
    return {
        "rc": proc.returncode,
        "ran_rules": int(m.group(1)) if m else None,
        "check_ids": sorted({r.get("check_id") for r in doc.get("results", [])}),
        "results": [{"check_id": r.get("check_id"), "path": r.get("path"),
                     "start": (r.get("start") or {}).get("line")}
                    for r in doc.get("results", [])],
        "errors": len(doc.get("errors") or []),
        "stderr_tail": (proc.stderr or "").strip().splitlines()[-3:],
    }


def run_core(root, cfg, names, timeout=180):
    targets = os.path.join(root, "_targets.json")
    with open(targets, "w", encoding="utf-8") as fh:
        json.dump(["Targets", [["CodeTarget", {
            "path": {"fpath": os.path.join(root, n), "ppath": "/" + n},
            "analyzer": "python" if n.endswith(".py") else "typescript",
            "products": ["sast"]}] for n in names]], fh)
    proc = subprocess.run([CORE, "-rules", cfg, "-targets", targets, "-json"],
                          cwd=root, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)
    doc = {}
    start = proc.stdout.find("{")
    if start >= 0:
        try:
            doc = json.loads(proc.stdout[start:].lstrip("\ufeff"))
        except Exception:
            doc = {}
    return {
        "rc": proc.returncode,
        "check_ids": sorted({r.get("check_id") for r in doc.get("results", [])}),
        "results": [{"check_id": r.get("check_id"), "path": r.get("path"),
                     "start": (r.get("start") or {}).get("line")}
                    for r in doc.get("results", [])],
        "errors": len(doc.get("errors") or []),
    }


def case(name, rules, files):
    print("running", name, flush=True)
    root = tempfile.mkdtemp(prefix="dupkey_")
    cfg = write(root, rules, files)
    try:
        cli = run_cli(root, cfg)
    except subprocess.TimeoutExpired:
        cli = {"rc": -9, "ran_rules": None, "error": "cli timeout"}
    try:
        core = run_core(root, cfg, sorted(files))
    except subprocess.TimeoutExpired:
        core = {"rc": -9, "error": "core timeout"}
    return {"case": name, "declared": len(rules), "cli": cli, "core": core}


def main():
    out = {"semgrep_cli": BIN, "semgrep_core": CORE, "cases": []}
    for key, cmd in (("cli_version", [*BIN, "--version"]), ("core_version", [CORE, "-version"])):
        try:
            out[key] = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=120).stdout.strip()
        except subprocess.TimeoutExpired:
            out[key] = "timeout"
    out["cases"].append(case(
        "control_distinct_ids", CONTROL,
        {"a.py": "py_marker(1)\n", "b.ts": "ts_marker(1);\n"}))
    out["cases"].append(case(
        "cross_language_same_id", CROSS,
        {"a.py": "py_marker(1)\n", "b.ts": "ts_marker(1);\n"}))
    out["cases"].append(case(
        "same_language_same_id", SAME,
        {"a.py": "py_alpha(1)\npy_beta(2)\n"}))
    out["cases"].append(case(
        "renamed_unique_ids", RENAMED,
        {"a.py": "py_alpha(1)\npy_beta(2)\n"}))
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
