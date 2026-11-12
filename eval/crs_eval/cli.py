from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from . import metrics
from .report import load_rows, write_report


def _report(args: argparse.Namespace) -> int:
    path = write_report(Path(args.runs), Path(args.out), dataset_dir=Path(args.dataset))
    print(str(path))
    return 0


def _metrics(args: argparse.Namespace) -> int:
    rows = load_rows(Path(args.runs))
    metrics.assert_single_mode(rows)
    summary = {
        "rows": len(rows),
        "detection": metrics.aggregate(rows),
        "unknown_coverage": metrics.unknown_coverage(rows),
        "source_error_rates": metrics.source_error_rates(rows),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="crs-eval")
    subparsers = parser.add_subparsers(dest="command", required=True)

    report = subparsers.add_parser("report", help="render markdown tables from run JSONL")
    report.add_argument("--runs", required=True, help="runs directory")
    report.add_argument("--out", required=True, help="output directory")
    report.add_argument("--dataset", required=True, help="frozen dataset directory")
    report.set_defaults(handler=_report)

    metrics_parser = subparsers.add_parser("metrics", help="print aggregate metrics")
    metrics_parser.add_argument("--runs", required=True, help="runs directory")
    metrics_parser.set_defaults(handler=_metrics)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
