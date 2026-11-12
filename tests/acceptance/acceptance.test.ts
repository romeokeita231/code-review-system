import { describe, expect, it } from "vitest";
import { evaluateAcceptance, type AcceptanceRowLike, type BlockGaps, type SampleTruth } from "../../scripts/acceptance.js";

function truthOf(sample: string, risk: string, detectable: string[]): SampleTruth {
  return {
    sample_id: sample,
    split: "eval",
    risk_level: risk,
    paired_safe: false,
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
    change_event: { sessionId: over.change_event?.sessionId ?? "s1", ts: over.ts },
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
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines.map((line) => line.pass)).toEqual([true, true, true, true, true]);
    expect(report.lines[0]!.metrics).toMatchObject({ n: 20, k: 20 });
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
});
