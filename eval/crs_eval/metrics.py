"""Row-level line-union metrics shared by the replay evaluation and the paper tables.

All counting is performed on the union of the line intervals of a row; per-item
accumulation is deliberately avoided.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping, Sequence

Interval = Mapping[str, Any] | tuple[int, int]

LIVE = "live"
REPLAY = "replay"


def _span(item: Interval) -> tuple[int, int]:
    if isinstance(item, Mapping):
        start = item.get("startLine", item.get("start_line", item.get("start", 0)))
        end = item.get("endLine", item.get("end_line", item.get("end", 0)))
    else:
        start, end = item
    start = int(start)
    end = int(end)
    if end < start:
        start, end = end, start
    return start, end


def _merged(intervals: Iterable[Interval]) -> list[tuple[int, int]]:
    spans = sorted(_span(item) for item in intervals)
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def union_size(intervals: Iterable[Interval]) -> int:
    return sum(end - start + 1 for start, end in _merged(intervals))


def intersection_size(left: Iterable[Interval], right: Iterable[Interval]) -> int:
    a = _merged(left)
    b = _merged(right)
    i = j = 0
    total = 0
    while i < len(a) and j < len(b):
        start = max(a[i][0], b[j][0])
        end = min(a[i][1], b[j][1])
        if start <= end:
            total += end - start + 1
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return total


def row_metrics(predicted: Iterable[Interval], gt: Iterable[Interval]) -> dict[str, int]:
    predicted = list(predicted)
    gt = list(gt)
    tp = intersection_size(predicted, gt)
    fp = union_size(predicted) - tp
    fn = union_size(gt) - tp
    return {"tp": tp, "fp": fp, "fn": fn}


def assert_single_mode(rows: Iterable[Mapping[str, Any]]) -> None:
    """Refuse to mix live and replay rows in one metric or report."""
    modes = {row.get("mode") for row in rows if row.get("mode")}
    if LIVE in modes and REPLAY in modes:
        raise ValueError("refusing to mix live and replay rows")


def _counts(row: Mapping[str, Any]) -> dict[str, int]:
    if all(key in row for key in ("tp", "fp", "fn")):
        return {"tp": int(row["tp"]), "fp": int(row["fp"]), "fn": int(row["fn"])}
    return row_metrics(row.get("predicted") or [], row.get("gt") or [])


def _ratio(numerator: float, denominator: float) -> float:
    return 0.0 if denominator == 0 else numerator / denominator


def aggregate(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    assert_single_mode(rows)
    tp = fp = fn = 0
    for row in rows:
        counts = _counts(row)
        tp += counts["tp"]
        fp += counts["fp"]
        fn += counts["fn"]
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {
        "rows": len(rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def macro_average(items: Sequence[Mapping[str, Any]]) -> dict[str, float]:
    if not items:
        return {"n": 0, "precision": 0.0, "recall": 0.0, "f1": 0.0}
    result: dict[str, float] = {"n": float(len(items))}
    for key in ("precision", "recall", "f1"):
        values = [float(item[key]) for item in items if item.get(key) is not None]
        result[key] = sum(values) / len(values) if values else 0.0
    return result


def unknown_coverage(rows: Iterable[Mapping[str, Any]]) -> dict[str, float]:
    covered = 0
    unknown = 0
    for row in rows:
        for source in row.get("sources") or []:
            coverage = source.get("coverage") or {}
            covered += int(coverage.get("filesCovered", 0))
            unknown += int(coverage.get("filesUnknown", 0))
    total = covered + unknown
    return {
        "filesCovered": covered,
        "filesUnknown": unknown,
        "total": total,
        "unknownRate": _ratio(unknown, total),
    }


def source_error_rates(rows: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, float]]:
    stats: dict[str, dict[str, float]] = defaultdict(
        lambda: {"total": 0, "ok": 0, "timeout": 0, "error": 0, "degraded": 0, "errorRate": 0.0}
    )
    for row in rows:
        for source in row.get("sources") or []:
            name = str(source.get("source"))
            status = str(source.get("status"))
            stats[name]["total"] += 1
            if status in ("ok", "timeout", "error", "degraded"):
                stats[name][status] += 1
    for stat in stats.values():
        stat["errorRate"] = _ratio(stat["timeout"] + stat["error"], stat["total"])
    return dict(stats)


def _blocked(row: Mapping[str, Any]) -> bool:
    if row.get("outcome") == "block":
        return True
    disposition = row.get("disposition") or {}
    return str(row.get("final_disposition", disposition.get("finalDisposition"))) in (
        "mechanical_block",
        "block",
    )


def block_metrics(
    rows: Iterable[Mapping[str, Any]],
    *,
    vulnerable: set[str],
    detectable: set[str] | None = None,
) -> dict[str, Any]:
    subset = [
        row
        for row in rows
        if detectable is None or str(row.get("sample")) in detectable
    ]
    tp = fp = fn = k = 0
    for row in subset:
        is_vulnerable = str(row.get("sample")) in vulnerable
        blocked = _blocked(row)
        if blocked:
            k += 1
        if blocked and is_vulnerable:
            tp += 1
        elif blocked:
            fp += 1
        elif is_vulnerable:
            fn += 1
    return {
        "n": len(subset),
        "k": k,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": _ratio(tp, k),
        "recall": _ratio(tp, tp + fn),
        "meaningful": len(subset) >= 15,
    }
