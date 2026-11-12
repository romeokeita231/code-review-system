import type { SourceName, SourceResult } from "../contracts/index.js";
import { intersectionSize, lineUnionSize, type Interval } from "./pairing.js";

export interface RowMetrics {
  tp: number;
  fp: number;
  fn: number;
}

export interface RowInput {
  predicted: Interval[];
  gt: Interval[];
}

export interface AggregateMetrics extends RowMetrics {
  rows: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface SourceErrorStat {
  total: number;
  ok: number;
  timeout: number;
  error: number;
  degraded: number;
  errorRate: number;
}

export interface UnknownCoverage {
  filesCovered: number;
  filesUnknown: number;
  total: number;
  unknownRate: number;
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : numerator / denominator;
}

export function rowMetrics(predicted: readonly Interval[], gt: readonly Interval[]): RowMetrics {
  const tp = intersectionSize(predicted, gt);
  const fp = lineUnionSize(predicted) - tp;
  const fn = lineUnionSize(gt) - tp;
  return { tp, fp, fn };
}

function isPrecomputed(row: RowInput | RowMetrics): row is RowMetrics {
  return typeof (row as RowMetrics).tp === "number";
}

export function aggregate(rows: readonly (RowInput | RowMetrics)[]): AggregateMetrics {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  for (const row of rows) {
    const metrics = isPrecomputed(row) ? row : rowMetrics(row.predicted, row.gt);
    tp += metrics.tp;
    fp += metrics.fp;
    fn += metrics.fn;
  }
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { rows: rows.length, tp, fp, fn, precision, recall, f1 };
}

export function sourceErrorRates(
  runs: readonly { sources: readonly SourceResult[] }[],
): Partial<Record<SourceName, SourceErrorStat>> {
  const stats: Partial<Record<SourceName, SourceErrorStat>> = {};
  for (const run of runs) {
    for (const source of run.sources) {
      const stat =
        stats[source.source] ??
        ({ total: 0, ok: 0, timeout: 0, error: 0, degraded: 0, errorRate: 0 } satisfies SourceErrorStat);
      stat.total += 1;
      if (source.status === "ok") stat.ok += 1;
      else if (source.status === "timeout") stat.timeout += 1;
      else if (source.status === "error") stat.error += 1;
      else stat.degraded += 1;
      stats[source.source] = stat;
    }
  }
  for (const stat of Object.values(stats)) {
    if (!stat) continue;
    stat.errorRate = ratio(stat.timeout + stat.error, stat.total);
  }
  return stats;
}

export function unknownCoverage(runs: readonly { sources: readonly SourceResult[] }[]): UnknownCoverage {
  let filesCovered = 0;
  let filesUnknown = 0;
  for (const run of runs) {
    for (const source of run.sources) {
      filesCovered += source.coverage.filesCovered;
      filesUnknown += source.coverage.filesUnknown;
    }
  }
  const total = filesCovered + filesUnknown;
  return { filesCovered, filesUnknown, total, unknownRate: ratio(filesUnknown, total) };
}
