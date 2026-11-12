import { describe, expect, it } from "vitest";
import type { SourceResult } from "../../src/contracts/index.js";
import { aggregate, rowMetrics, sourceErrorRates, unknownCoverage } from "../../src/l5/index.js";
import { result } from "./helpers.js";

describe("rowMetrics", () => {
  it("counts line intersections rather than items", () => {
    expect(rowMetrics([{ startLine: 1, endLine: 10 }], [{ startLine: 5, endLine: 15 }])).toEqual({
      tp: 6,
      fp: 4,
      fn: 5,
    });
  });

  it("unions overlapping predicted intervals before scoring", () => {
    expect(
      rowMetrics(
        [{ startLine: 1, endLine: 10 }, { startLine: 5, endLine: 15 }],
        [{ startLine: 1, endLine: 10 }],
      ),
    ).toEqual({ tp: 10, fp: 5, fn: 0 });
  });

  it("reports no false positives for empty predictions", () => {
    expect(rowMetrics([], [{ startLine: 3, endLine: 4 }])).toEqual({ tp: 0, fp: 0, fn: 2 });
  });
});

describe("aggregate", () => {
  it("sums counts across rows and derives precision, recall and f1", () => {
    const summary = aggregate([
      { predicted: [{ startLine: 1, endLine: 10 }], gt: [{ startLine: 5, endLine: 15 }] },
      rowMetrics([{ startLine: 20, endLine: 29 }], []),
      { predicted: [], gt: [{ startLine: 40, endLine: 49 }] },
    ]);
    expect(summary.rows).toBe(3);
    expect(summary.tp).toBe(6);
    expect(summary.fp).toBe(14);
    expect(summary.fn).toBe(15);
    expect(summary.precision).toBeCloseTo(6 / 20, 6);
    expect(summary.recall).toBeCloseTo(6 / 21, 6);
    expect(summary.f1).toBeCloseTo((2 * (6 / 20) * (6 / 21)) / (6 / 20 + 6 / 21), 6);
  });

  it("returns zeros on an empty set", () => {
    expect(aggregate([])).toEqual({
      rows: 0,
      tp: 0,
      fp: 0,
      fn: 0,
      precision: 0,
      recall: 0,
      f1: 0,
    });
  });
});

describe("source diagnostics", () => {
  const runs: { sources: SourceResult[] }[] = [
    {
      sources: [
        result("semgrep", []),
        result("aor", [], { status: "timeout", coverage: { filesCovered: 0, filesUnknown: 1 }, tokens: null }),
      ],
    },
    {
      sources: [
        result("semgrep", [], { status: "error", coverage: { filesCovered: 0, filesUnknown: 1 } }),
        result("aor", [], { status: "degraded" }),
      ],
    },
  ];

  it("derives per-source error rates", () => {
    const rates = sourceErrorRates(runs);
    expect(rates.semgrep).toMatchObject({ total: 2, ok: 1, error: 1, timeout: 0 });
    expect(rates.semgrep!.errorRate).toBeCloseTo(0.5, 6);
    expect(rates.aor).toMatchObject({ total: 2, timeout: 1, degraded: 1, ok: 0 });
    expect(rates.aor!.errorRate).toBeCloseTo(0.5, 6);
  });

  it("aggregates unknown coverage", () => {
    expect(unknownCoverage(runs)).toEqual({
      filesCovered: 2,
      filesUnknown: 2,
      total: 4,
      unknownRate: 0.5,
    });
  });
});
