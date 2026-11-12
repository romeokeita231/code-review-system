import { describe, expect, it } from "vitest";
import { evaluateAcceptance, type AcceptanceRowLike, type BlockGaps, type SampleTruth } from "../../scripts/acceptance.js";

function truthOf(sample: string, risk: string, detectable: string[], sampleCwe: string | null = "CWE-079"): SampleTruth {
  return {
    sample_id: sample,
    split: "eval",
    risk_level: risk,
    paired_safe: false,
    sample_cwe: sampleCwe,
    labels: detectable.length > 0 ? [{ path: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" }] : [],
    expected_detectable_by: detectable,
  };
}

function row(over: Partial<AcceptanceRowLike> & { sample: string; baseline: string; ts: number }): AcceptanceRowLike {
  return {
    baseline: over.baseline,
    sample: over.sample,
    mode: "live",
    disposition: {
      preDecision: "allow",
      postDecision: "none",
      finalDisposition: "record",
      text: null,
      ...(over.disposition ?? {}),
    },
    findings_merged: over.findings_merged ?? [],
    sources: over.sources ?? [],
    tokens: over.tokens ?? 100,
    latency_ms: over.latency_ms ?? 1000,
    change_event: {
      sessionId: over.change_event?.sessionId ?? "s1",
      ts: over.ts,
      phase: over.change_event?.phase,
    },
  };
}

const gaps: BlockGaps = { preregistered_at: "2026-11-11T00:00:00Z", gaps: [] };

describe("acceptance", () => {
  it("passes all five lines on a clean live set", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    const base = Date.parse("2026-11-12T01:00:00Z");
    for (let index = 0; index < 20; index += 1) {
      const sample = `s-${index}`;
      truth.set(sample, truthOf(sample, "high", ["semgrep"]));
      rows.push(
        row({
          sample,
          baseline: "B4",
          ts: base + index,
          disposition: {
            preDecision: "deny",
            postDecision: "none",
            finalDisposition: "mechanical_block",
            text: "[CRS-BLOCK] src/a.ts:1 CWE-79 rule",
          },
          findings_merged: [{ file: "src/a.ts", startLine: 1, endLine: 2, cwe: `CWE-${100 + index}` }],
        }),
      );
    }
    for (let index = 0; index < 8; index += 1) {
      const sample = `low-${index}`;
      truth.set(sample, truthOf(sample, "low", []));
      rows.push(row({ sample, baseline: "B4g", ts: base + 500 + index, latency_ms: 400, tokens: 100 }));
      rows.push(row({ sample, baseline: "B4", ts: base + 600 + index, latency_ms: 1000, tokens: 50 }));
    }
    rows.push(
      row({
        sample: "deps-1",
        baseline: "B4",
        ts: base + 900,
        disposition: {
          preDecision: "allow",
          postDecision: "inject_warn",
          finalDisposition: "instruction_correction",
          text: "[CRS-WARN] package.json:4 CWE-79 left-pad | review",
        },
        findings_merged: [{ file: "package.json", startLine: 4, endLine: 4, cwe: "CWE-79" }],
        sources: [
          {
            source: "registry",
            status: "ok",
            findings: [{ file: "package.json", cwe: null, evidence: "package not found: left-pad" }],
          },
        ],
      }),
    );
    // The correction pass rewrites the warned sample; that later row must no
    // longer carry the same class for line 3 to hold.
    rows.push(row({ sample: "deps-1", baseline: "B4", ts: base + 950 }));
    truth.set("corr", truthOf("corr", "high", ["aor"]));
    rows.push(
      row({
        sample: "corr",
        baseline: "B4",
        ts: base + 960,
        disposition: {
          preDecision: "allow",
          postDecision: "inject_warn",
          finalDisposition: "instruction_correction",
          text: "[CRS-WARN] src/a.ts:1 CWE-79 rule | review",
        },
        findings_merged: [{ file: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" }],
      }),
    );
    rows.push(row({ sample: "corr", baseline: "B4", ts: base + 970 }));
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines.map((line) => line.pass)).toEqual([true, true, true, true, true]);
    // `corr` is a labelled eval sample that was only warned (twice, so two
    // rows), so it is two missed positives; the old `expected_detectable_by`
    // selector hid it from the denominator entirely.
    expect(report.lines[0]!.metrics).toMatchObject({ n: 22, k: 20, recall: 20 / 22 });
    expect(report.verdict).toContain("5/5");
  });

  it("refuses to mix live and replay rows", () => {
    const rows = [
      row({ sample: "a", baseline: "B4", ts: 1 }),
      { ...row({ sample: "b", baseline: "B4", ts: 2 }), mode: "replay" },
    ];
    expect(() => evaluateAcceptance(rows, new Map(), gaps)).toThrow(/mixed/);
  });

  it("fails line1 when the block gap was not pre-registered", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    for (let index = 0; index < 20; index += 1) {
      const sample = `s-${index}`;
      truth.set(sample, truthOf(sample, "high", ["semgrep"]));
      rows.push(row({ sample, baseline: "B4", ts: 5000, disposition: { preDecision: "deny", postDecision: "none", finalDisposition: "mechanical_block", text: "x" } }));
    }
    const report = evaluateAcceptance(rows, truth, { preregistered_at: "2026-11-12T00:00:00Z", gaps: [] });
    expect(report.lines[0]!.pass).toBe(false);
  });

  it("fails line1 for replay rows even when precision and recall are perfect", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    for (let index = 0; index < 20; index += 1) {
      const sample = `s-${index}`;
      truth.set(sample, truthOf(sample, "high", ["semgrep"]));
      rows.push({
        ...row({ sample, baseline: "B4", ts: 2000, disposition: { preDecision: "deny", postDecision: "none", finalDisposition: "mechanical_block", text: "x" } }),
        mode: "replay",
      });
    }
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines[0]!.pass).toBe(false);
  });

  it("fails line3 when the same class recurs after a correction", () => {
    const truth = new Map<string, SampleTruth>([
      ["a", truthOf("a", "high", ["aor"])],
      ["b", truthOf("b", "high", ["aor"])],
    ]);
    const rows = [
      row({
        sample: "a",
        baseline: "B4",
        ts: 10,
        disposition: { preDecision: "allow", postDecision: "inject_warn", finalDisposition: "instruction_correction", text: "[CRS-WARN] src/a.ts:1 CWE-79 r" },
        findings_merged: [{ file: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" }],
      }),
      row({
        sample: "b",
        baseline: "B4",
        ts: 20,
        findings_merged: [{ file: "src/a.ts", startLine: 5, endLine: 6, cwe: "CWE-79" }],
      }),
    ];
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines[2]!.pass).toBe(false);
    expect(report.lines[2]!.metrics).toMatchObject({ repeats: 1 });
  });

  it("counts each sample once when a live write emits pre and post rows", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    for (let index = 0; index < 20; index += 1) {
      const sample = `s-${index}`;
      truth.set(sample, truthOf(sample, "high", ["semgrep"]));
      rows.push(
        row({
          sample,
          baseline: "B4",
          ts: 100 + index,
          change_event: { sessionId: "s1", ts: 100 + index, phase: "pre" },
          disposition: { preDecision: "deny", postDecision: "not_run", finalDisposition: "mechanical_block", text: "x" },
        }),
      );
      rows.push(
        row({
          sample,
          baseline: "B4",
          ts: 200 + index,
          change_event: { sessionId: "s1", ts: 200 + index, phase: "post" },
        }),
      );
    }
    // Precision needs a defect-free denominator; without these eight rows the
    // run would report a vacuous tp/tp = 1. A live run emits a pre row for
    // every write, so the negatives carry the same phase as the positives.
    for (let index = 0; index < 8; index += 1) {
      const sample = `low-${index}`;
      truth.set(sample, truthOf(sample, "low", []));
      rows.push(
        row({
          sample,
          baseline: "B4",
          ts: 300 + index,
          change_event: { sessionId: "s1", ts: 300 + index, phase: "pre" },
        }),
      );
    }
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines[0]!.metrics).toMatchObject({ n: 20, k: 20, recall: 1, precision: 1, negatives: 8 });
  });

  it("does not use expected_detectable_by as the recall denominator", () => {
    const truth = new Map<string, SampleTruth>([
      ["aor-only", truthOf("aor-only", "high", ["aor"])],
      ["low-0", truthOf("low-0", "low", [])],
    ]);
    const rows = [
      row({
        sample: "aor-only",
        baseline: "B4",
        ts: 10,
        disposition: { preDecision: "deny", postDecision: "none", finalDisposition: "mechanical_block", text: "x" },
      }),
      row({ sample: "low-0", baseline: "B4", ts: 20 }),
    ];
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines[0]!.metrics).toMatchObject({ n: 1, k: 1, recall: 1 });
  });

  it("reports classes the ruleset cannot see as an explicit excluded row", () => {
    const truth = new Map<string, SampleTruth>([
      ["covered", truthOf("covered", "high", ["both"], "CWE-079")],
      ["uncovered", truthOf("uncovered", "high", ["both"], "CWE-502")],
      ["low-0", truthOf("low-0", "low", [], "CWE-798")],
    ]);
    const rows = [
      row({
        sample: "covered",
        baseline: "B4",
        ts: 10,
        disposition: { preDecision: "deny", postDecision: "none", finalDisposition: "mechanical_block", text: "x" },
      }),
      row({ sample: "uncovered", baseline: "B4", ts: 20 }),
      row({ sample: "low-0", baseline: "B4", ts: 30 }),
    ];
    const report = evaluateAcceptance(rows, truth, gaps, {
      coverage: { language: "typescript", perCwe: { "079": 35, "502": 0 } },
    });
    expect(report.lines[0]!.metrics).toMatchObject({ n: 1, k: 1, excluded: 1, excluded_classes: "502" });
    expect(report.resultsTable).toContain("CWE-502");
    expect(report.resultsTable).toContain("ruleset declares no rule");
  });

  it("refuses a precision that has no defect-free denominator", () => {
    const truth = new Map<string, SampleTruth>([["p", truthOf("p", "high", ["both"])]]);
    const rows = [
      row({
        sample: "p",
        baseline: "B4",
        ts: 10,
        disposition: { preDecision: "deny", postDecision: "none", finalDisposition: "mechanical_block", text: "x" },
      }),
    ];
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines[0]!.metrics).toMatchObject({ n: 1, precision: null, negatives: 0 });
    expect(report.lines[0]!.pass).toBe(false);
  });

  it("passes line3 when the corrected file no longer carries the class", () => {
    const truth = new Map<string, SampleTruth>([["a", truthOf("a", "high", ["aor"])]]);
    const rows = [
      row({
        sample: "a",
        baseline: "B4",
        ts: 10,
        change_event: { sessionId: "s1", ts: 10, phase: "post" },
        disposition: {
          preDecision: "allow",
          postDecision: "inject_warn",
          finalDisposition: "instruction_correction",
          text: "[CRS-WARN] src/a.ts:1 CWE-79 r",
        },
        findings_merged: [{ file: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" }],
      }),
      row({
        sample: "a",
        baseline: "B4",
        ts: 20,
        change_event: { sessionId: "s1", ts: 20, phase: "post" },
      }),
    ];
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines[2]!.pass).toBe(true);
    expect(report.lines[2]!.metrics).toMatchObject({ warned: 1, corrected: 1, repeats: 0 });
  });

  it("fails line3 when the same class reappears in the corrected sample", () => {
    const truth = new Map<string, SampleTruth>([["a", truthOf("a", "high", ["aor"])]]);
    const rows = [
      row({
        sample: "a",
        baseline: "B4",
        ts: 10,
        change_event: { sessionId: "s1", ts: 10, phase: "post" },
        disposition: {
          preDecision: "allow",
          postDecision: "inject_warn",
          finalDisposition: "instruction_correction",
          text: "[CRS-WARN] src/a.ts:1 CWE-79 r",
        },
        findings_merged: [{ file: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" }],
      }),
      row({
        sample: "a",
        baseline: "B4",
        ts: 20,
        change_event: { sessionId: "s1", ts: 20, phase: "post" },
        findings_merged: [{ file: "src/a.ts", startLine: 3, endLine: 4, cwe: "CWE-79" }],
      }),
    ];
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines[2]!.pass).toBe(false);
    expect(report.lines[2]!.metrics).toMatchObject({ repeats: 1 });
  });

  it("fails line3 when a warned sample is never corrected", () => {
    const truth = new Map<string, SampleTruth>([["a", truthOf("a", "high", ["aor"])]]);
    const rows = [
      row({
        sample: "a",
        baseline: "B4",
        ts: 10,
        change_event: { sessionId: "s1", ts: 10, phase: "post" },
        disposition: {
          preDecision: "allow",
          postDecision: "inject_warn",
          finalDisposition: "instruction_correction",
          text: "[CRS-WARN] src/a.ts:1 CWE-79 r",
        },
        findings_merged: [{ file: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" }],
      }),
    ];
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines[2]!.pass).toBe(false);
    expect(report.lines[2]!.metrics).toMatchObject({ repeats: 1 });
  });
});
