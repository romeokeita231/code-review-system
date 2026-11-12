"""Markdown report generation from replay run JSONL rows."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from statistics import median
from typing import Any, Iterable, Mapping, Sequence

from .metrics import (
    aggregate,
    assert_single_mode,
    block_metrics,
    source_error_rates,
    unknown_coverage,
)

BASELINES = ["B0", "B1", "B2", "B3", "B4g", "B4"]
ABLATION_STAGES = ("merge", "conflict", "calibrate", "vote")
EXTRAPOLATION_SIZES = (30, 100, 250)


def load_rows(runs_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(Path(runs_dir).rglob("*.jsonl")):
        if path.name.startswith("pairing"):
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    return rows


def load_configs(runs_dir: Path) -> dict[str, dict[str, Any]]:
    configs: dict[str, dict[str, Any]] = {}
    for path in sorted(Path(runs_dir).rglob("config.json")):
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if isinstance(payload, dict) and "config_hash" in payload and "config" in payload:
            configs[str(payload["config_hash"])] = payload["config"]
    return configs


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def load_truth(dataset_dir: Path) -> tuple[dict[str, list[dict[str, Any]]], set[str], set[str]]:
    """Load gold spans and the vulnerable/detectable sample sets from the dataset."""
    dataset_dir = Path(dataset_dir)
    manifest = json.loads((dataset_dir / "manifest.json").read_text(encoding="utf-8"))
    labels: dict[str, list[dict[str, Any]]] = {}
    vulnerable: set[str] = set()
    detectable: set[str] = set()
    for entry in manifest.get("samples", []):
        sample_id = str(entry["sample_id"])
        payload = json.loads(
            (dataset_dir / "samples" / f"{sample_id}.json").read_text(encoding="utf-8")
        )
        sample_labels = payload.get("labels") or []
        labels[sample_id] = sample_labels
        if sample_labels:
            vulnerable.add(sample_id)
        if entry.get("expected_detectable_by"):
            detectable.add(sample_id)
    return labels, vulnerable, detectable


def attach_truth(
    rows: Sequence[Mapping[str, Any]],
    labels: Mapping[str, Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """Join dataset labels onto rows so line-union metrics have a ground truth."""
    attached: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        gold = labels.get(str(row.get("sample")), [])
        item["gt"] = [
            {"startLine": int(span["startLine"]), "endLine": int(span["endLine"])} for span in gold
        ]
        predicted = row.get("findings_merged") or (row.get("disposition") or {}).get("findings") or []
        item["predicted"] = [
            {"startLine": int(finding["startLine"]), "endLine": int(finding["endLine"])}
            for finding in predicted
        ]
        attached.append(item)
    return attached


def validate_rows(
    rows: Sequence[Mapping[str, Any]],
    configs: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[str]:
    """Validate hash/mode consistency and return the sorted config hash set."""
    assert_single_mode(rows)
    hashes: set[str] = set()
    seen: dict[tuple[Any, ...], str] = {}
    for row in rows:
        config_hash = row.get("config_hash")
        if not config_hash:
            raise ValueError(f"row {row.get('sample')} is missing config_hash")
        config_hash = str(config_hash)
        hashes.add(config_hash)
        if "config_json" in row:
            if _digest(row["config_json"]) != config_hash:
                raise ValueError(
                    f"config hash mismatch for sample {row.get('sample')}: "
                    f"{config_hash} does not match embedded config"
                )
        if configs is not None and config_hash in configs:
            if _digest(configs[config_hash]) != config_hash:
                raise ValueError(f"config hash mismatch for provided config {config_hash}")
        key = (
            row.get("baseline"),
            row.get("sample"),
            row.get("tier"),
            row.get("repeat"),
        )
        previous = seen.get(key)
        if previous is not None and previous != config_hash:
            raise ValueError(
                f"config hash mismatch for {key}: {previous} != {config_hash}"
            )
        seen[key] = config_hash
    return sorted(hashes)


def _stages(row: Mapping[str, Any], configs: Mapping[str, Mapping[str, Any]] | None) -> dict[str, bool]:
    config = row.get("config_json")
    if not config and configs is not None:
        config = configs.get(str(row.get("config_hash")))
    stages = (config or {}).get("fusionStages") or {}
    return {name: bool(stages.get(name, False)) for name in ABLATION_STAGES}


def _table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    lines = ["| " + " | ".join(str(h) for h in headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


def _subset(rows: Iterable[Mapping[str, Any]], baseline: str) -> list[Mapping[str, Any]]:
    return [row for row in rows if row.get("baseline") == baseline]


def _tokens(row: Mapping[str, Any]) -> float | None:
    value = (row.get("tokens") or {}).get("total")
    return None if value is None else float(value)


def _median_tokens(rows: Sequence[Mapping[str, Any]]) -> float | None:
    values = [value for value in (_tokens(row) for row in rows) if value is not None]
    return median(values) if values else None


def detection_table(rows: Sequence[Mapping[str, Any]]) -> str:
    body = []
    for baseline in BASELINES:
        subset = _subset(rows, baseline)
        summary = aggregate(subset)
        coverage = unknown_coverage(subset)
        errors = source_error_rates(subset)
        body.append(
            [
                baseline,
                len(subset),
                summary["tp"],
                summary["fp"],
                summary["fn"],
                _fmt(summary["precision"]),
                _fmt(summary["recall"]),
                _fmt(summary["f1"]),
                _fmt(coverage["unknownRate"]),
                _fmt((errors.get("semgrep") or {}).get("errorRate")),
                _fmt((errors.get("aor") or {}).get("errorRate")),
            ]
        )
    return _table(
        [
            "baseline",
            "rows",
            "TP",
            "FP",
            "FN",
            "precision",
            "recall",
            "F1",
            "unknown_coverage",
            "semgrep_err",
            "aor_err",
        ],
        body,
    )


def block_table(
    rows: Sequence[Mapping[str, Any]],
    vulnerable: set[str] | None = None,
    detectable: set[str] | None = None,
) -> str:
    body = []
    for baseline in BASELINES:
        subset = _subset(rows, baseline)
        metrics = block_metrics(
            subset,
            vulnerable=vulnerable or set(),
            detectable=detectable,
        )
        body.append(
            [
                baseline,
                metrics["n"],
                metrics["k"],
                metrics["tp"],
                metrics["fp"],
                metrics["fn"],
                _fmt(metrics["precision"]),
                _fmt(metrics["recall"]),
                "yes" if metrics["meaningful"] else "no",
            ]
        )
    return _table(
        ["baseline", "n", "k", "TP", "FP", "FN", "block precision", "block recall", "n>=15"],
        body,
    )


def cost_table(rows: Sequence[Mapping[str, Any]]) -> str:
    body = []
    for baseline in BASELINES:
        subset = _subset(rows, baseline)
        files = [int((row.get("repo") or {}).get("files_scanned", 0)) for row in subset]
        latencies = [float(row.get("latency_ms") or 0.0) for row in subset]
        body.append(
            [
                baseline,
                len(subset),
                _fmt(median(files)) if files else "n/a",
                _fmt(_median_tokens(subset)),
                _fmt(median(latencies)) if latencies else "n/a",
            ]
        )
    return _table(
        ["baseline", "rows", "files_scanned (median)", "tokens (median)", "latency_ms (median)"],
        body,
    )


def error_table(rows: Sequence[Mapping[str, Any]]) -> str:
    body = []
    for baseline in BASELINES:
        subset = _subset(rows, baseline)
        errors = source_error_rates(subset)
        for name in ("semgrep", "aor", "crg", "registry"):
            stat = errors.get(name)
            if not stat:
                continue
            body.append(
                [
                    baseline,
                    name,
                    int(stat["total"]),
                    int(stat["ok"]),
                    int(stat["timeout"]),
                    int(stat["error"]),
                    int(stat["degraded"]),
                    _fmt(stat["errorRate"]),
                ]
            )
    return _table(
        ["baseline", "source", "total", "ok", "timeout", "error", "degraded", "error_rate"],
        body,
    )


def coverage_table(rows: Sequence[Mapping[str, Any]]) -> str:
    body = []
    for baseline in BASELINES:
        subset = _subset(rows, baseline)
        coverage = unknown_coverage(subset)
        body.append(
            [
                baseline,
                len(subset),
                coverage["filesCovered"],
                coverage["filesUnknown"],
                _fmt(coverage["unknownRate"]),
            ]
        )
    return _table(
        ["baseline", "rows", "files_covered", "files_unknown", "unknown_rate"],
        body,
    )


def ablation_table(
    rows: Sequence[Mapping[str, Any]],
    configs: Mapping[str, Mapping[str, Any]] | None = None,
) -> str:
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        if row.get("baseline") != "B4g":
            continue
        stages = _stages(row, configs)
        signature = ",".join(f"{name}={'on' if stages[name] else 'off'}" for name in ABLATION_STAGES)
        groups.setdefault(signature, []).append(row)
    body = []
    for signature in sorted(groups):
        subset = groups[signature]
        summary = aggregate(subset)
        coverage = unknown_coverage(subset)
        errors = source_error_rates(subset)
        body.append(
            [
                signature,
                len(subset),
                _fmt(summary["precision"]),
                _fmt(summary["recall"]),
                _fmt(summary["f1"]),
                _fmt(coverage["unknownRate"]),
                _fmt((errors.get("semgrep") or {}).get("errorRate")),
                _fmt((errors.get("aor") or {}).get("errorRate")),
            ]
        )
    return _table(
        [
            "ablation (B4g)",
            "rows",
            "precision",
            "recall",
            "F1",
            "unknown_coverage",
            "semgrep_err",
            "aor_err",
        ],
        body,
    )


def delta_table(rows: Sequence[Mapping[str, Any]], source_baseline: str, target_baseline: str) -> str:
    source = _subset(rows, source_baseline)
    target = _subset(rows, target_baseline)
    source_metrics = aggregate(source)
    target_metrics = aggregate(target)
    body = []
    for name in ("precision", "recall", "f1"):
        before = source_metrics[name]
        after = target_metrics[name]
        body.append([name, _fmt(before), _fmt(after), _fmt(after - before)])
    before_tokens = _median_tokens(source)
    after_tokens = _median_tokens(target)
    delta = None if before_tokens is None or after_tokens is None else after_tokens - before_tokens
    body.append(["tokens (median)", _fmt(before_tokens), _fmt(after_tokens), _fmt(delta)])
    return _table(["metric", source_baseline, target_baseline, "delta"], body)


def cache_table(rows: Sequence[Mapping[str, Any]]) -> str:
    body = []
    for baseline in BASELINES:
        subset = _subset(rows, baseline)
        for state in ("cold", "warm"):
            state_rows = [row for row in subset if row.get("cache") == state]
            values = [value for value in (_tokens(row) for row in state_rows) if value is not None]
            variance = None
            if len(values) > 1:
                mean = sum(values) / len(values)
                variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
            body.append(
                [
                    baseline,
                    state,
                    len(state_rows),
                    _fmt(median(values)) if values else "n/a",
                    _fmt(variance),
                ]
            )
    return _table(["baseline", "cache", "rows", "tokens (median)", "variance"], body)


def fit_cost(points: Sequence[tuple[float, float]]) -> dict[str, float | None]:
    """Least-squares fit y = slope * x + intercept with R^2."""
    if len(points) < 2:
        return {"slope": None, "intercept": None, "r2": None, "n": float(len(points))}
    xs = [float(x) for x, _ in points]
    ys = [float(y) for _, y in points]
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    denominator = sum((x - mean_x) ** 2 for x in xs)
    if denominator == 0:
        return {"slope": None, "intercept": None, "r2": None, "n": float(len(points))}
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denominator
    intercept = mean_y - slope * mean_x
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - mean_y) ** 2 for y in ys)
    r2 = 1.0 if ss_tot == 0 and ss_res == 0 else (1 - ss_res / ss_tot if ss_tot else None)
    return {"slope": slope, "intercept": intercept, "r2": r2, "n": float(len(points))}


def cost_points(rows: Sequence[Mapping[str, Any]]) -> list[tuple[float, float]]:
    buckets: dict[int, list[float]] = {}
    for row in rows:
        files = int((row.get("repo") or {}).get("files_scanned", 0))
        value = _tokens(row)
        if files <= 0 or value is None:
            continue
        buckets.setdefault(files, []).append(value)
    return [(float(files), median(values)) for files, values in sorted(buckets.items())]


def extrapolation_table(rows: Sequence[Mapping[str, Any]]) -> str:
    points = cost_points(rows)
    fit = fit_cost(points)
    observed = ", ".join(f"{int(x)}:{y:.0f}" for x, y in points) or "n/a"
    rows_out = [
        [
            "f(files_reviewed) = a*x + b",
            _fmt(fit["slope"]),
            _fmt(fit["intercept"]),
            _fmt(fit["r2"]),
            int(fit["n"] or 0),
            ", ".join(str(size) for size in EXTRAPOLATION_SIZES),
            observed,
        ]
    ]
    return _table(["model", "a", "b", "R^2", "points", "extrapolation sizes", "observed"], rows_out)


def build_tables(
    rows: Sequence[Mapping[str, Any]],
    configs: Mapping[str, Mapping[str, Any]] | None = None,
    vulnerable: set[str] | None = None,
    detectable: set[str] | None = None,
) -> list[tuple[str, str]]:
    return [
        ("main 1: detection", detection_table(rows)),
        ("main 2: block", block_table(rows, vulnerable, detectable)),
        ("main 3: cost", cost_table(rows)),
        ("main 4: per-source errors", error_table(rows)),
        ("main 5: unknown coverage", coverage_table(rows)),
        ("main 6: ablation (B4g)", ablation_table(rows, configs)),
        ("delta: B3 -> B4g", delta_table(rows, "B3", "B4g")),
        ("delta: B4g -> B4", delta_table(rows, "B4g", "B4")),
        ("appendix A: cache", cache_table(rows)),
        ("appendix B: cost extrapolation", extrapolation_table(rows)),
    ]


def render_markdown(
    rows: Sequence[Mapping[str, Any]],
    configs: Mapping[str, Mapping[str, Any]] | None = None,
    vulnerable: set[str] | None = None,
    detectable: set[str] | None = None,
) -> str:
    hashes = validate_rows(rows, configs)
    modes = sorted({str(row.get("mode")) for row in rows if row.get("mode")})
    lines = [
        "# Code Review Evaluation Report",
        "",
        f"- config hashes: {', '.join(f'`{h}`' for h in hashes) if hashes else 'none'}",
        f"- mode: {', '.join(modes) if modes else 'unknown'}",
        f"- rows: {len(rows)}",
        "",
    ]
    for title, table in build_tables(rows, configs, vulnerable, detectable):
        lines.extend([f"## {title}", "", table, ""])
    return "\n".join(lines).rstrip() + "\n"


def write_report(
    runs_dir: Path,
    out_dir: Path,
    configs: Mapping[str, Mapping[str, Any]] | None = None,
    vulnerable: set[str] | None = None,
    detectable: set[str] | None = None,
    dataset_dir: Path | None = None,
) -> Path:
    rows = load_rows(Path(runs_dir))
    if dataset_dir is not None:
        labels, dataset_vulnerable, dataset_detectable = load_truth(Path(dataset_dir))
        rows = attach_truth(rows, labels)
        vulnerable = vulnerable if vulnerable is not None else dataset_vulnerable
        detectable = detectable if detectable is not None else dataset_detectable
    if configs is None:
        configs = load_configs(Path(runs_dir))
    markdown = render_markdown(rows, configs, vulnerable, detectable)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.md"
    path.write_text(markdown, encoding="utf-8")
    return path
