from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crs_eval.metrics import (
    aggregate,
    block_metrics,
    macro_average,
    row_metrics,
    source_error_rates,
    unknown_coverage,
)
from crs_eval.report import fit_cost, render_markdown, validate_rows, write_report


def run_row(**overrides):
    row = {
        "run_id": "exp-B4g",
        "sample": "s1",
        "tier": 2,
        "repeat": 0,
        "mode": "replay",
        "baseline": "B4g",
        "config_hash": "a" * 64,
        "sources": [
            {
                "source": "semgrep",
                "status": "ok",
                "coverage": {"filesCovered": 1, "filesUnknown": 0},
            },
            {
                "source": "aor",
                "status": "degraded",
                "coverage": {"filesCovered": 0, "filesUnknown": 1},
            },
        ],
        "outcome": "record",
        "tokens": {"total": 100},
        "latency_ms": 12.0,
        "repo": {"rev": "rev", "files_scanned": 30},
        "cache": "cold",
    }
    row.update(overrides)
    return row


def test_row_metrics_counts_line_union_not_items():
    metrics = row_metrics([{"startLine": 1, "endLine": 10}], [{"startLine": 5, "endLine": 15}])
    assert metrics == {"tp": 6, "fp": 4, "fn": 5}


def test_row_metrics_unions_overlapping_predictions():
    metrics = row_metrics(
        [{"startLine": 1, "endLine": 10}, {"startLine": 5, "endLine": 15}],
        [{"startLine": 1, "endLine": 10}],
    )
    assert metrics == {"tp": 10, "fp": 5, "fn": 0}


def test_aggregate_sums_rows_and_derives_scores():
    summary = aggregate(
        [
            {"predicted": [{"startLine": 1, "endLine": 10}], "gt": [{"startLine": 5, "endLine": 15}]},
            {"tp": 10, "fp": 0, "fn": 0},
        ]
    )
    assert summary["rows"] == 2
    assert summary["tp"] == 16
    assert summary["fp"] == 4
    assert summary["fn"] == 5
    assert summary["precision"] == pytest.approx(16 / 20)
    assert summary["recall"] == pytest.approx(16 / 21)


def test_macro_average_skips_missing_metrics():
    result = macro_average(
        [
            {"precision": 1.0, "recall": 0.5, "f1": 2 / 3},
            {"precision": 0.0, "recall": 0.5, "f1": 0.0},
        ]
    )
    assert result["n"] == 2.0
    assert result["precision"] == pytest.approx(0.5)
    assert result["recall"] == pytest.approx(0.5)


def test_unknown_coverage_and_source_errors():
    rows = [run_row(), run_row(sample="s2", sources=[{"source": "semgrep", "status": "timeout", "coverage": {"filesCovered": 0, "filesUnknown": 1}}])]
    coverage = unknown_coverage(rows)
    assert coverage == {"filesCovered": 1, "filesUnknown": 2, "total": 3, "unknownRate": pytest.approx(2 / 3)}
    errors = source_error_rates(rows)
    assert errors["aor"]["degraded"] == 1
    assert errors["semgrep"]["timeout"] == 1
    assert errors["semgrep"]["errorRate"] == pytest.approx(0.5)


def test_mixed_mode_rows_are_rejected():
    rows = [run_row(mode="live"), run_row(mode="replay", sample="s2")]
    with pytest.raises(ValueError):
        aggregate(rows)
    with pytest.raises(ValueError):
        validate_rows(rows)


def test_block_metrics_reports_n_and_k():
    rows = [
        run_row(sample="v1", outcome="block"),
        run_row(sample="v2", outcome="record"),
        run_row(sample="safe", outcome="block"),
    ]
    metrics = block_metrics(rows, vulnerable={"v1", "v2"})
    assert metrics["n"] == 3
    assert metrics["k"] == 2
    assert metrics["tp"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["precision"] == pytest.approx(0.5)
    assert metrics["recall"] == pytest.approx(0.5)
    assert metrics["meaningful"] is False


def test_config_hash_mismatch_is_rejected():
    with pytest.raises(ValueError):
        validate_rows(
            [
                run_row(sample="s1", config_hash="a" * 64),
                run_row(sample="s1", config_hash="b" * 64),
            ]
        )
    with pytest.raises(ValueError):
        validate_rows([run_row(config_json={"fusionStages": {"merge": True}})])


def test_valid_rows_return_sorted_config_hash_set():
    hashes = validate_rows(
        [
            run_row(sample="s1", config_hash="b" * 64),
            run_row(sample="s2", config_hash="a" * 64),
        ]
    )
    assert hashes == ["a" * 64, "b" * 64]
    markdown = render_markdown(
        [
            run_row(sample="s1", config_hash="b" * 64),
            run_row(sample="s2", config_hash="a" * 64),
        ]
    )
    assert "config hashes:" in markdown
    assert "`" + "a" * 64 + "`" in markdown


def test_extrapolation_fit_sanity():
    fit = fit_cost([(30, 3.0), (100, 10.0), (250, 25.0)])
    assert fit["slope"] == pytest.approx(0.1, abs=1e-6)
    assert fit["intercept"] == pytest.approx(0.0, abs=1e-6)
    assert fit["r2"] == pytest.approx(1.0, abs=1e-9)
    assert fit_cost([(30, 1.0)])["slope"] is None


def test_write_report_from_runs_directory(tmp_path):
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    rows = [
        run_row(sample="s1", baseline="B3"),
        run_row(sample="s2", baseline="B4g", config_hash="b" * 64),
    ]
    with (runs_dir / "runs.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    path = write_report(runs_dir, tmp_path / "out")
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "main 1: detection" in text
    assert "delta: B3 -> B4g" in text
    assert "appendix B: cost extrapolation" in text
