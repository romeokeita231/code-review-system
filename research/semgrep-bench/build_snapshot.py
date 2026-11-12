import argparse
from collections import Counter
import hashlib
import json
import os
import re
import subprocess

import yaml

TARGET_LANGS = {"python", "javascript", "typescript", "tsx", "jsx"}
CWE7 = {"022", "078", "079", "089", "094", "798", "918"}
CWE_RE = re.compile(r"CWE-(\d{1,4})")
GENERIC_DIRS = {"python", "javascript", "typescript", "tsx", "jsx", "security", "audit"}


def normalize_cwe(value):
    if value is None:
        return set()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return set()
    found = set()
    for item in value:
        if isinstance(item, str):
            for m in CWE_RE.finditer(item):
                found.add(str(int(m.group(1))).zfill(3))
    return found


def git_out(repo, *args):
    try:
        return subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True, text=True, encoding="utf-8", timeout=30,
        ).stdout.strip()
    except Exception:
        return ""


def rule_row(rule, rel_path):
    meta = rule.get("metadata") or {}
    mode = rule.get("mode") or "search"
    has_sources = "sources" in rule
    has_sinks = "sinks" in rule
    is_taint = mode == "taint" or (has_sources and has_sinks)
    return {
        "id": rule.get("id"),
        "source_file": rel_path,
        "languages": list(rule.get("languages") or []),
        "mode": mode,
        "mode_taint": mode == "taint",
        "has_sources_key": has_sources,
        "has_sinks_key": has_sinks,
        "is_taint": is_taint,
        "cwe": sorted(normalize_cwe(meta.get("cwe"))),
        "severity": rule.get("severity"),
    }


def dump_yaml(path, rules):
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump({"rules": rules}, fh, sort_keys=False, allow_unicode=True)
    with open(path, "rb") as fh:
        data = fh.read()
    return hashlib.sha256(data).hexdigest(), len(data)


def id_candidates(rel_path):
    segments = os.path.splitext(rel_path)[0].replace("\\", "/").split("/")
    lang, dirs = segments[0], segments[1:-1]
    useful = [d for d in dirs if d not in GENERIC_DIRS] or dirs
    cands = ["-".join(useful[:i]) for i in range(1, len(useful) + 1)]
    cands += ["-".join([lang, *dirs[:i]]) for i in range(1, len(dirs) + 1)]
    return cands or ["dup"]


def assign_effective_ids(pairs):
    bases = [row["id"] for _body, row in pairs]
    counts = Counter(bases)
    dup = {rid: n for rid, n in counts.items() if n > 1}
    used = set(counts)
    renames = []
    for (body, row), base in zip(pairs, bases):
        row["upstream_id"] = base
        if counts[base] == 1:
            continue
        eff = None
        for suffix in id_candidates(row["source_file"]):
            cand = f"{base}.{suffix}"
            if cand not in used:
                eff = cand
                break
        if eff is None:
            i = 2
            while f"{base}.dup{i}" in used:
                i += 1
            eff = f"{base}.dup{i}"
        used.add(eff)
        body["id"] = eff
        row["id"] = eff
        renames.append({
            "upstream_id": base,
            "effective_id": eff,
            "source_file": row["source_file"],
        })
    return dup, renames


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-repo", required=True, help="semgrep-rules checkout root")
    parser.add_argument("--out", required=True, help="output dir for rules.yaml + manifest.json")
    parser.add_argument("--block-ids", help="JSON list of rule ids that fire on their own test file")
    args = parser.parse_args()

    rules = []
    table = []
    files = 0
    for lang_dir in ("python", "javascript", "typescript"):
        base = os.path.join(args.rules_repo, lang_dir)
        for dirpath, _dirnames, filenames in os.walk(base):
            for fn in filenames:
                if not fn.endswith((".yaml", ".yml")):
                    continue
                files += 1
                abs_path = os.path.join(dirpath, fn)
                with open(abs_path, "r", encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh)
                if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
                    continue
                for rule in doc["rules"]:
                    langs = set(rule.get("languages") or [])
                    if not (langs & TARGET_LANGS):
                        continue
                    if normalize_cwe((rule.get("metadata") or {}).get("cwe")) & CWE7:
                        rules.append(rule)
                        table.append(rule_row(rule, os.path.relpath(abs_path, args.rules_repo)))

    os.makedirs(args.out, exist_ok=True)

    pairs = list(zip(rules, table))
    dup_ids, renames = assign_effective_ids(pairs)
    py_pairs = [(b, t) for b, t in pairs if "python" in t["languages"]]
    js_pairs = [(b, t) for b, t in pairs if set(t["languages"]) & {"javascript", "jsx"}]
    ts_pairs = [(b, t) for b, t in pairs if set(t["languages"]) & {"typescript", "tsx"}]

    def dedupe_first(pairs_):
        seen = set()
        out = []
        for body, row in pairs_:
            if row["upstream_id"] in seen:
                continue
            seen.add(row["upstream_id"])
            out.append(body)
        return out

    subsets = {
        "rules.yaml": rules,
        "py_all.yaml": [b for b, _t in py_pairs],
        "py_taint.yaml": [b for b, t in py_pairs if t["is_taint"]],
        "py_nontaint.yaml": [b for b, t in py_pairs if not t["is_taint"]],
        "js_all.yaml": [b for b, _t in js_pairs],
        "ts_all.yaml": [b for b, _t in ts_pairs],
        "ts_dedup.yaml": dedupe_first(ts_pairs),
    }
    if args.block_ids:
        with open(args.block_ids, "r", encoding="utf-8") as fh:
            block_ids = set(json.load(fh))
        subsets["py_block.yaml"] = [b for b, t in py_pairs if t["upstream_id"] in block_ids]
    digests = {}
    for name, rows in subsets.items():
        sha, size = dump_yaml(os.path.join(args.out, name), rows)
        digests[name] = {"sha256": sha, "bytes": size, "rules": len(rows)}

    with open(os.path.join(args.out, "rules_table.json"), "w", encoding="utf-8") as fh:
        json.dump({
            "rules_total": len(table),
            "is_taint_total": sum(1 for r in table if r["is_taint"]),
            "mode_taint_total": sum(1 for r in table if r["mode_taint"]),
            "rules": table,
        }, fh, indent=1)

    all_cwes = sorted({c for t in table for c in t["cwe"]})
    by_lang = {}
    for t in table:
        for lang in t["languages"]:
            if lang in TARGET_LANGS:
                by_lang.setdefault(lang, {"rules": 0, "taint": 0})
                by_lang[lang]["rules"] += 1
                by_lang[lang]["taint"] += 1 if t["is_taint"] else 0

    manifest = {
        "rules_repo": args.rules_repo,
        "rules_repo_remote": git_out(args.rules_repo, "remote", "get-url", "origin"),
        "rules_repo_commit": git_out(args.rules_repo, "rev-parse", "HEAD"),
        "rules_repo_commit_date": git_out(args.rules_repo, "show", "-s", "--format=%cI", "HEAD"),
        "rules_repo_dirty": bool(git_out(args.rules_repo, "status", "--porcelain")),
        "lang_dirs": ["python", "javascript", "typescript"],
        "target_languages": sorted(TARGET_LANGS),
        "cwe_filter": sorted(CWE7),
        "cwe_normalization": "int(CWE-<n>) -> zfill(3)",
        "rule_files_scanned": files,
        "rules_kept": len(rules),
        "rules_unique_effective_ids": len({t["id"] for t in table}),
        "duplicate_upstream_ids": dup_ids,
        "id_renames": renames,
        "id_rename_scheme": "<upstream_id>.<first non-generic dir under language root>",
        "rules_by_language": by_lang,
        "rules_by_cwe": {c: sum(1 for t in table if c in t["cwe"]) for c in all_cwes},
        "artifacts": digests,
        "block_subset": {
            "definition": "python rules whose own upstream test file yields >=1 result",
            "source": os.path.basename(args.block_ids) if args.block_ids else None,
            "rules": len(subsets["py_block.yaml"]) if "py_block.yaml" in subsets else None,
        },
        "rules_yaml_sha256": digests["rules.yaml"]["sha256"],
        "rules_yaml_bytes": digests["rules.yaml"]["bytes"],
        "builder": "research/semgrep-bench/build_snapshot.py",
    }
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
