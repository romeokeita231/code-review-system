import { describe, expect, it } from "vitest";
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertInstrumentIdentity,
  evaluateAcceptance,
  tier0Counterfactual,
  type AcceptanceRowLike,
  type BlockGaps,
  type SampleTruth,
} from "../../scripts/acceptance.js";

function truthOf(
  sample: string,
  risk: string,
  detectable: string[],
  sampleCwe: string | null = "CWE-079",
): SampleTruth {
  return {
    sample_id: sample,
    split: "eval",
    risk_level: risk,
    paired_safe: false,
    language: "ts",
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
    review_skip_reason: over.review_skip_reason ?? null,
    instrument: over.instrument,
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
    expect(report.lines[0]!.metrics).toMatchObject({ n: 21, k: 20, rows: 22, recall: 20 / 21 });
    expect(report.verdict).toContain("5/5");
  });

  // Line 4's ratio is measured on a tree this project wrote. The counterfactual -
  // what the same rows would be in the pinned repositories - has to travel with
  // the number, and its absence has to read as absence, not as 0/0.
  it("carries the tier-0 counterfactual in line4's detail, or says it is absent", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    for (let index = 0; index < 20; index += 1) {
      const sample = `s-${index}`;
      truth.set(sample, truthOf(sample, "high", ["semgrep"]));
      rows.push(
        row({
          sample,
          baseline: "B4",
          ts: index,
          disposition: {
            preDecision: "deny",
            postDecision: "none",
            finalDisposition: "mechanical_block",
            text: "[CRS-BLOCK] src/a.ts:1 CWE-79 rule",
          },
          findings_merged: [{ file: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" }],
        }),
      );
    }
    for (let index = 0; index < 8; index += 1) {
      const sample = `low-${index}`;
      truth.set(sample, truthOf(sample, "low", []));
      rows.push(row({ sample, baseline: "B4g", ts: 500 + index, latency_ms: 400, tokens: 100 }));
      rows.push(row({ sample, baseline: "B4", ts: 600 + index, latency_ms: 1000, tokens: 50 }));
    }
    const bare = evaluateAcceptance(rows, truth, gaps).lines[3]!;
    expect(bare.pass).toBe(true);
    // Nobody said where these rows came from, so the report says nobody said.
    // A fixture's ratio is shaped exactly like a measurement (ADR-0008).
    expect(bare.detail).toContain("source=unknown");
    expect(bare.detail).toContain("upstream_tier0=na");
    expect(bare.detail).toContain("counterfactual=not_measured");
    expect(bare.metrics).toMatchObject({ upstream_tier0: null, upstream_tier0_measured: null });

    const measured = evaluateAcceptance(rows, truth, gaps, {
      rowsSource: "live",
      stagedContext: tier0Counterfactual("artifacts/staged-context.json"),
    }).lines[3]!;
    expect(measured.pass).toBe(true);
    expect(measured.detail).toContain("source=live");
    expect(measured.detail).toContain("upstream_tier0=0/8");
    expect(measured.detail).toContain("本语料 18 个可测行无一为 tier 0");
    expect(measured.detail).toContain("最小 3 个 importer");
    expect(measured.detail).toContain("观测到的比值属于构造拓扑");
    expect(measured.metrics).toMatchObject({
      rows_source: "live",
      upstream_tier0: 0,
      upstream_tier0_measured: 8,
    });

    const synthetic = evaluateAcceptance(rows, truth, gaps, { rowsSource: "synthetic" }).lines[3]!;
    expect(synthetic.detail).toContain("source=synthetic");
    expect(synthetic.metrics).toMatchObject({ rows_source: "synthetic" });
  });

  it("reads the frozen counterfactual and refuses one that contradicts itself", () => {
    const counterfactual = tier0Counterfactual("artifacts/staged-context.json");
    expect(counterfactual).toMatchObject({
      pairs_measured: 8,
      pairs_tier0: 0,
      rows_measured: 18,
      rows_tier0: 0,
      min_importers: 3,
      files_max: 3,
    });
    const broken = join(tmpdir(), `staged-context-${process.pid}.json`);
    writeFileSync(
      broken,
      JSON.stringify({
        bounds: { tier0_filesMax: 3 },
        // Rows and summary disagree: one row says tier 0, the summary says none.
        rows: [
          { sample_id: "a", upstream_applicable: true, upstream_importers: 3, would_be_tier: 0 },
          { sample_id: "b", upstream_applicable: false, upstream_importers: null, would_be_tier: null },
        ],
        summary: {
          positives_upstream_tier0: 0,
          negatives_upstream_tier0: 0,
          negatives_upstream_tier_ge1: 1,
          measured_positives: 0,
        },
      }),
      "utf8",
    );
    expect(() => tier0Counterfactual(broken)).toThrow(/contradicts itself/);
    expect(() => tier0Counterfactual(join(tmpdir(), `absent-${process.pid}.json`))).toThrow();
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
    expect(report.lines[2]!.metrics).toMatchObject({ classed: 1, recurred: 0, unfixed: 1 });
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
          findings_merged: [{ file: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" }],
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

  it("counts precision per finding, not per sample", () => {
    const truth = new Map<string, SampleTruth>([
      ["p", truthOf("p", "high", ["aor"])],
      ["neg", truthOf("neg", "low", [])],
    ]);
    const rows = [
      row({
        sample: "p",
        baseline: "B4",
        ts: 10,
        findings_merged: [
          { file: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" },
          { file: "src/a.ts", startLine: 2, endLine: 3, cwe: "CWE-79" },
          { file: "src/a.ts", startLine: 40, endLine: 41, cwe: "CWE-79" },
        ],
      }),
      row({
        sample: "neg",
        baseline: "B4",
        ts: 20,
        findings_merged: [{ file: "src/a.ts", startLine: 5, endLine: 5, cwe: "CWE-79" }],
      }),
    ];
    const report = evaluateAcceptance(rows, truth, gaps);
    // Two findings overlap the label, one is off-label and one sits on a
    // defect-free row: precision is 2/4, which no sample-level count can show.
    expect(report.lines[0]!.metrics).toMatchObject({
      n: 1,
      recall: 0,
      findings_n: 4,
      findings_tp: 2,
      precision: 0.5,
      precision_status: "insufficient_n",
    });
    expect(report.lines[0]!.pass).toBe(false);
  });

  it("reports recall descriptively when fewer samples than the gate were staged", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    for (let index = 0; index < 10; index += 1) {
      const sample = `s-${index}`;
      truth.set(sample, truthOf(sample, "high", ["semgrep"]));
      rows.push(
        row({
          sample,
          baseline: "B4",
          ts: 10 + index,
          disposition: {
            preDecision: "deny",
            postDecision: "none",
            finalDisposition: "mechanical_block",
            text: "[CRS-BLOCK] src/a.ts:1 CWE-79 r",
          },
          findings_merged: [{ file: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" }],
        }),
      );
    }
    for (let index = 0; index < 8; index += 1) {
      const sample = `neg-${index}`;
      truth.set(sample, truthOf(sample, "low", []));
      rows.push(row({ sample, baseline: "B4", ts: 100 + index }));
    }
    const report = evaluateAcceptance(rows, truth, gaps);
    expect(report.lines[0]!.pass).toBe(false);
    expect(report.lines[0]!.metrics).toMatchObject({
      n: 10,
      recall: 1,
      recall_status: "insufficient_n",
      available: 10,
      staged: 10,
      not_staged: 0,
      findings_n: 10,
      precision_status: "insufficient_n",
    });
    // The number survives the failed gate: a report that says only
    // "insufficient_n" would hide a measured 10/10.
    expect(report.lines[0]!.metrics!["wilson_low"]).toBeGreaterThan(0.7);
    expect(report.resultsTable).toContain("descriptive, not gated");
    expect(report.verdict).toContain("召回面 insufficient_n");
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
    expect(report.lines[2]!.metrics).toMatchObject({
      warned_rows: 1,
      classed: 1,
      corrected: 1,
      recurred: 0,
      unfixed: 0,
    });
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
    expect(report.lines[2]!.metrics).toMatchObject({ classed: 1, recurred: 1, unfixed: 0 });
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
    expect(report.lines[2]!.metrics).toMatchObject({ classed: 1, corrected: 0, unfixed: 1 });
  });

  it("keeps a never-attempted language out of the recall denominator", () => {
    const ts = Date.parse("2026-11-12T01:00:00Z");
    const truth = new Map<string, SampleTruth>([
      ["ts-1", truthOf("ts-1", "high", ["semgrep"])],
      ["js-1", truthOf("js-1", "high", ["semgrep"])],
      ["neg", truthOf("neg", "high", [])],
    ]);
    const rows = [
      row({
        sample: "ts-1",
        baseline: "B4",
        ts,
        disposition: { preDecision: "deny", postDecision: "none", finalDisposition: "mechanical_block", text: "[CRS-BLOCK] a" },
      }),
      row({
        sample: "js-1",
        baseline: "B4",
        ts: ts + 1,
        review_skip_reason: "language_unsupported",
        sources: [{ source: "semgrep", status: "degraded", errorKind: "language_unsupported", findings: [] }],
      }),
      row({ sample: "neg", baseline: "B4", ts: ts + 2 }),
    ];
    const report = evaluateAcceptance(rows, truth, gaps, {
      minSamples: 1,
      coverage: { language: "typescript", perCwe: { "079": 35 } },
    });
    // The JavaScript row was never scanned, so it is neither a miss nor a
    // denominator row; the timeout rule does not apply to it.
    expect(report.lines[0]!.metrics).toMatchObject({
      n: 1,
      scannable: 1,
      out_of_scope: 1,
      recall: 1,
    });
    expect(report.resultsTable).toContain("never attempted");
  });
});

const FROZEN = {
  semgrep: { version: "1.184.0" },
  ocr: { commit: "04deca6" },
  aor_model: {
    provider: "deepseek",
    id: "deepseek-flash",
    url: "https://api.deepseek.com",
    configured: "deepseek-chat",
  },
};

const instrument = (over: Partial<AcceptanceRowLike["instrument"]> = {}): AcceptanceRowLike["instrument"] => ({
  semgrep: { name: "semgrep", version: "1.184.0", commit: null, source: "observed" },
  ocr: { name: "ocr", version: "v1.13.6", commit: "04deca6", source: "observed" },
  aor_model: {
    provider: "deepseek",
    id: "deepseek-flash",
    params: { url: "https://api.deepseek.com", configured: "deepseek-chat" },
    source: "observed",
  },
  ...over,
});

describe("instrument identity", () => {
  const oneRow = (over: Partial<AcceptanceRowLike> = {}): AcceptanceRowLike =>
    row({ sample: "a", baseline: "B4", ts: 1, instrument: instrument(), ...over });

  it("refuses a row that carries no instrument identity", () => {
    expect(() => assertInstrumentIdentity([oneRow({ instrument: undefined })], FROZEN)).toThrow(
      /carry no instrument identity/,
    );
  });

  it("refuses an identity that was declared from config rather than observed", () => {
    const declared = instrument({
      semgrep: { name: "semgrep", version: "1.184.0", commit: null, source: "declared" },
    });
    expect(() => assertInstrumentIdentity([oneRow({ instrument: declared })], FROZEN)).toThrow(
      /declared from config, not observed/,
    );
  });

  it("refuses a drifted ocr commit", () => {
    const drifted = instrument({
      ocr: { name: "ocr", version: "v1.13.8", commit: "4236c87", source: "observed" },
    });
    expect(() => assertInstrumentIdentity([oneRow({ instrument: drifted })], FROZEN)).toThrow(
      /ocr commit 4236c87 != frozen 04deca6/,
    );
  });

  it("refuses a drifted semgrep version", () => {
    const drifted = instrument({
      semgrep: { name: "semgrep", version: "1.100.0", commit: null, source: "observed" },
    });
    expect(() => assertInstrumentIdentity([oneRow({ instrument: drifted })], FROZEN)).toThrow(
      /semgrep 1\.100\.0 != frozen 1\.184\.0/,
    );
  });

  it("refuses rows produced on two different instruments", () => {
    const other = oneRow({
      sample: "b",
      instrument: instrument({ ocr: { name: "ocr", version: "v1.13.8", commit: "4236c87", source: "observed" } }),
    });
    expect(() => assertInstrumentIdentity([oneRow(), other], FROZEN)).toThrow(/different instruments/);
  });

  it("refuses to evaluate at all when the pin does not match", () => {
    const truth = new Map([["a", truthOf("a", "high", ["semgrep"])]]);
    expect(() =>
      evaluateAcceptance([oneRow()], truth, gaps, {
        frozenInstruments: { ...FROZEN, ocr: { commit: "deadbee" } },
      }),
    ).toThrow(/refusing to report/);
  });

  it("refuses a row whose AOR model is not the frozen model", () => {
    const drifted = instrument({
      aor_model: {
        provider: "deepseek",
        id: "deepseek-chat",
        params: { url: "https://api.deepseek.com", configured: "deepseek-chat" },
        source: "observed",
      },
    });
    expect(() => assertInstrumentIdentity([oneRow({ instrument: drifted })], FROZEN)).toThrow(
      /aor model deepseek-chat != frozen deepseek-flash/,
    );
  });

  it("refuses a row whose endpoint or requested model moved", () => {
    const moved = instrument({
      aor_model: {
        provider: "deepseek",
        id: "deepseek-flash",
        params: { url: "https://api.example.com", configured: "deepseek-chat" },
        source: "observed",
      },
    });
    expect(() => assertInstrumentIdentity([oneRow({ instrument: moved })], FROZEN)).toThrow(
      /aor endpoint https:\/\/api.example.com/,
    );
    const reasked = instrument({
      aor_model: {
        provider: "deepseek",
        id: "deepseek-flash",
        params: { url: "https://api.deepseek.com", configured: "deepseek-v4" },
        source: "observed",
      },
    });
    expect(() => assertInstrumentIdentity([oneRow({ instrument: reasked })], FROZEN)).toThrow(
      /aor requested model deepseek-v4/,
    );
  });

  it("refuses a row with no aor model at all", () => {
    const missing = instrument();
    delete (missing as { aor_model?: unknown }).aor_model;
    expect(() => assertInstrumentIdentity([oneRow({ instrument: missing })], FROZEN)).toThrow(
      /no aor model identity/,
    );
  });

  it("prints the observed identity when it matches the pin", () => {
    const truth = new Map([["a", truthOf("a", "high", ["semgrep"])]]);
    const report = evaluateAcceptance([oneRow()], truth, gaps, { frozenInstruments: FROZEN });
    expect(report.resultsTable).toContain("instruments (observed");
    expect(report.resultsTable).toContain("04deca6");
    expect(report.verdict).toContain("与钉定值一致");
  });
});

describe("event kinds in the false-positive denominator", () => {
  it("splits the denominator by event kind and refuses a claim for a single create", () => {
    const truth = new Map<string, SampleTruth>([
      ["pos", truthOf("pos", "high", ["semgrep"])],
      ["neg-edit", { ...truthOf("neg-edit", "low", []), event_kind: "edit" }],
      ["neg-create", { ...truthOf("neg-create", "low", []), event_kind: "create" }],
    ]);
    const report = evaluateAcceptance(
      [
        row({
          sample: "pos",
          baseline: "B4",
          ts: 0,
          disposition: {
            preDecision: "deny",
            postDecision: "none",
            finalDisposition: "mechanical_block",
            text: "[CRS-BLOCK]",
          },
        }),
        row({ sample: "neg-edit", baseline: "B4", ts: 1 }),
        row({ sample: "neg-create", baseline: "B4", ts: 2 }),
      ],
      truth,
      gaps,
    );
    expect(report.lines[0]!.metrics).toMatchObject({ negatives: 2, negatives_edit: 1, negatives_create: 1 });
    expect(report.resultsTable).toContain("1 edit, 1 create");
    expect(report.verdict).toContain("不支撑任何精度主张");
  });

  it("reports line1 as na when the config certifies no block rule for the language", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    for (let index = 0; index < 3; index += 1) {
      const sample = `p-${index}`;
      truth.set(sample, truthOf(sample, "high", ["semgrep"]));
      rows.push(row({ sample, baseline: "B4", ts: 10 + index }));
    }
    const report = evaluateAcceptance(rows, truth, gaps, {
      subsets: [{ langs: ["typescript"], blockRules: [] }],
    });
    // `blockRules: []` means a finding can never be certified, and an
    // uncertified finding never reaches `triggering`, so `deny` is unreachable:
    // the number 0 would describe the config, not the detector.
    expect(report.lines[0]!.state).toBe("na");
    expect(report.lines[0]!.na_reason).toMatch(/no certified TS rule/);
    expect(report.lines[0]!.pass).toBe(false);
    expect(report.lines[0]!.metrics).toMatchObject({
      n: 3,
      k: 0,
      recall_status: "na",
      block_face: "na",
      certified: 0,
      uncertified: 3,
    });
  });

  it("keeps line1 gated when the config certifies a rule for the language", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    for (let index = 0; index < 3; index += 1) {
      const sample = `p-${index}`;
      truth.set(sample, truthOf(sample, "high", ["semgrep"]));
      rows.push(row({ sample, baseline: "B4", ts: 10 + index }));
    }
    const report = evaluateAcceptance(rows, truth, gaps, {
      subsets: [{ langs: ["typescript"], blockRules: ["certified-rule"] }],
    });
    expect(report.lines[0]!.state).toBe("fail");
    expect(report.lines[0]!.metrics).toMatchObject({
      certified: 3,
      uncertified: 0,
      block_face: "measurable",
      recall_status: "insufficient_n",
    });
  });

  it("counts a sample as recurred when any warning reappeared, even if another was never revisited", () => {
    const truth = new Map<string, SampleTruth>([["a", truthOf("a", "high", ["aor"])]]);
    const warn = (ts: number): AcceptanceRowLike =>
      row({
        sample: "a",
        baseline: "B4",
        ts,
        change_event: { sessionId: "s1", ts, phase: "post" },
        disposition: {
          preDecision: "allow",
          postDecision: "inject_warn",
          finalDisposition: "instruction_correction",
          text: "[CRS-WARN] src/a.ts:1 CWE-79 r",
        },
        findings_merged: [{ file: "src/a.ts", startLine: 1, endLine: 2, cwe: "CWE-79" }],
      });
    const rows = [
      warn(10),
      warn(30),
      row({
        sample: "a",
        baseline: "B4",
        ts: 20,
        change_event: { sessionId: "s1", ts: 20, phase: "post" },
        findings_merged: [{ file: "src/a.ts", startLine: 9, endLine: 9, cwe: "CWE-79" }],
      }),
    ];
    const report = evaluateAcceptance(rows, truth, gaps);
    // The write after the first warning still carries the class (recurred); the
    // last warning lands on what turns out to be the final write (unfixed). The
    // sample is one recurrence: letting `unfixed` win would let a confirmed
    // reappearance hide behind a warning nobody could have answered.
    expect(report.lines[2]!.metrics).toMatchObject({
      classed: 1,
      recurred: 1,
      unfixed: 0,
      recurred_rows: 1,
      unfixed_rows: 1,
    });
    expect(report.lines[2]!.pass).toBe(false);
  });

  it("derives a token ratio of 0 only when the row says AOR was never asked", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    // One labelled positive, or the report refuses to run at all (a denominator
    // of zero rows next to sixteen is a wiring error, not this line's subject).
    truth.set("pos-1", truthOf("pos-1", "high", ["semgrep"]));
    rows.push(row({ sample: "pos-1", baseline: "B4", ts: 1 }));
    for (let index = 0; index < 8; index += 1) {
      const sample = `low-${index}`;
      truth.set(sample, truthOf(sample, "low", []));
      rows.push({
        ...row({ sample, baseline: "B4", ts: 500 + index, latency_ms: 400 }),
        tokens: null,
        tier: 0,
        tier_source: "triage",
      });
      rows.push({
        ...row({ sample, baseline: "B4g", ts: 600 + index, latency_ms: 400 }),
        tokens: [9000, 11000, 12000][index % 3]!,
        tier: 2,
        tier_source: "none",
      });
    }
    const report = evaluateAcceptance(rows, truth, gaps, { rowsSource: "live" });
    // The B4 side never asked AOR (tier 0 via triage), so its cost is 0 by
    // construction. The raw ratio is still `na`, and both numbers are printed:
    // filling 0 silently would turn "nothing was asked" into "100% saved".
    expect(report.lines[3]!.state).toBe("pass");
    expect(report.lines[3]!.metrics).toMatchObject({
      pairs: 8,
      median_token_ratio: null,
      median_token_ratio_derived: 0,
      tokens_derived_pairs: 8,
    });
    expect(report.lines[3]!.detail).toContain("median_token_ratio=na");
    expect(report.lines[3]!.detail).toContain("median_token_ratio_derived=0.000");
  });

  it("refuses to derive 0 for a row that did ask AOR and lost the token count", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    truth.set("pos-1", truthOf("pos-1", "high", ["semgrep"]));
    rows.push(row({ sample: "pos-1", baseline: "B4", ts: 1 }));
    for (let index = 0; index < 8; index += 1) {
      const sample = `low-${index}`;
      truth.set(sample, truthOf(sample, "low", []));
      rows.push({
        ...row({ sample, baseline: "B4", ts: 500 + index, latency_ms: 400 }),
        tokens: null,
        tier: 2,
        tier_source: "none",
        aor_invoked: true,
      });
      rows.push({
        ...row({ sample, baseline: "B4g", ts: 600 + index, latency_ms: 400 }),
        tokens: 10000,
        tier: 2,
        tier_source: "none",
        aor_invoked: true,
      });
    }
    const report = evaluateAcceptance(rows, truth, gaps, { rowsSource: "live" });
    // `aor_invoked: true` with `tokens: null` is a lost measurement, not a 0, and
    // a pair without a ratio makes the whole line undetermined rather than
    // passable on the strength of a shorter median.
    expect(report.lines[3]!.state).toBe("na");
    expect(report.lines[3]!.na_reason).toMatch(/undetermined_pairs/);
    expect(report.lines[3]!.metrics).toMatchObject({
      median_token_ratio: null,
      median_token_ratio_derived: null,
      tokens_derived_pairs: 0,
      undetermined_pairs: 8,
    });
  });

  it("refuses to pass line4 on one computable pair out of eight", () => {
    const truth = new Map<string, SampleTruth>();
    const rows: AcceptanceRowLike[] = [];
    truth.set("pos-1", truthOf("pos-1", "high", ["semgrep"]));
    rows.push(row({ sample: "pos-1", baseline: "B4", ts: 1 }));
    for (let index = 0; index < 8; index += 1) {
      const sample = `low-${index}`;
      truth.set(sample, truthOf(sample, "low", []));
      // Seven pairs asked AOR and lost the count; one measured 0 against 1000.
      // "pairs === 8" and "median(<=1)" both hold here, which is exactly the
      // silent pass this line must not be able to produce.
      rows.push({
        ...row({ sample, baseline: "B4", ts: 500 + index, latency_ms: 400 }),
        tokens: index === 0 ? 0 : null,
        tier: 2,
        tier_source: "none",
        aor_invoked: true,
      });
      rows.push({
        ...row({ sample, baseline: "B4g", ts: 600 + index, latency_ms: 400 }),
        tokens: 1000,
        tier: 2,
        tier_source: "none",
        aor_invoked: true,
      });
    }
    const report = evaluateAcceptance(rows, truth, gaps, { rowsSource: "live" });
    expect(report.lines[3]!.state).toBe("na");
    expect(report.lines[3]!.pass).toBe(false);
    expect(report.lines[3]!.metrics).toMatchObject({ pairs: 8, undetermined_pairs: 7 });
    // The consequence is stated where a reader meets it: `na` on a gate line is
    // worse than `fail`, because it shrinks the gate denominator as well.
  });
  it("refuses an empty denominator instead of reporting it as insufficient_n", () => {
    // The wiring bug this guards: truth and rows disagree about which samples
    // exist, so `available` is 0 next to a pile of rows. That is not a small
    // sample, and it once rendered as a completed measurement.
    const truth = new Map<string, SampleTruth>([["pos", truthOf("pos", "high", ["semgrep"])]]);
    expect(() =>
      evaluateAcceptance([row({ sample: "pos", baseline: "B4", ts: 1 })], truth, gaps, {
        // The class is not in the declared coverage, so every candidate row is
        // excluded and the denominator is empty next to a non-empty row set.
        coverage: { language: "typescript", perCwe: {} },
      }),
    ).toThrow(/the truth and the rows do not describe the same population/);
  });
});
