import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import type { Finding, MergedFinding, RunConfig, SourceResult } from "../../src/contracts/index.js";
import { parseConfig } from "../../src/config/index.js";
import {
  applyCalibration,
  fitCalibration,
  fuse,
  fuseProbability,
  mergeFindings,
  resolveConflicts,
  vote,
  weightFor,
} from "../../src/l4/index.js";

const config = (): RunConfig => parseConfig(JSON.parse(readFileSync("configs/b4g.json", "utf8")));

const finding = (over: Partial<Finding> = {}): Finding => ({
  file: "src/a.py",
  startLine: 10,
  endLine: 12,
  severity: 2,
  confidence: 0.8,
  source: "aor",
  cwe: "CWE-79",
  evidence: "x",
  rawId: "aor-1",
  ...over,
});

const merged = (over: Partial<MergedFinding> = {}): MergedFinding => ({
  ...finding(),
  sources: ["aor"],
  rawIds: ["aor-1"],
  evidenceSources: ["aor"],
  certified: true,
  cweComparable: true,
  conflictResolution: "none",
  blockable: true,
  ...over,
});

describe("merge", () => {
  it("does not merge overlapping hits with different CWEs", () => {
    const out = mergeFindings([
      finding({ rawId: "s1", source: "semgrep", cwe: "CWE-89" }),
      finding({ rawId: "a1", source: "aor", cwe: "CWE-79" }),
    ]);
    expect(out).toHaveLength(2);
  });

  it("does not merge adjacent different categories", () => {
    const out = mergeFindings([
      finding({ rawId: "a1", cwe: "CWE-79", startLine: 10, endLine: 10 }),
      finding({ rawId: "a2", cwe: "CWE-89", startLine: 11, endLine: 11 }),
    ]);
    expect(out).toHaveLength(2);
  });

  it("keeps both sources and raw ids when merging comparable hits", () => {
    const out = mergeFindings([
      finding({ rawId: "s1", source: "semgrep", cwe: "CWE-79", startLine: 10, endLine: 11 }),
      finding({ rawId: "a1", source: "aor", cwe: "CWE-79", startLine: 11, endLine: 13 }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]!.sources).toEqual(["aor", "semgrep"]);
    expect(out[0]!.rawIds.sort()).toEqual(["a1", "s1"]);
    expect(out[0]!.startLine).toBe(10);
    expect(out[0]!.endLine).toBe(13);
  });

  it("marks comparability false when only one side carries a CWE", () => {
    const out = mergeFindings([
      finding({ rawId: "s1", source: "semgrep", cwe: "CWE-79" }),
      finding({ rawId: "a1", source: "aor", cwe: null }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]!.cweComparable).toBe(false);
  });
});

describe("conflict", () => {
  it("never promotes a conflicted record to blockable", () => {
    const out = resolveConflicts([
      merged({ sources: ["aor", "semgrep"], rawIds: ["a", "s"], cweComparable: false, evidence: null }),
    ]);
    expect(out[0]!.blockable).toBe(false);
    expect(out[0]!.conflictResolution).toBe("downgraded");
  });

  it("prefers verifiable evidence", () => {
    const out = resolveConflicts([
      merged({
        sources: ["aor", "semgrep"],
        rawIds: ["a", "s"],
        evidenceSources: ["aor", "semgrep"],
        evidence: "os.system(cmd)",
      }),
    ]);
    expect(out[0]!.conflictResolution).toBe("evidence_preferred");
    expect(out[0]!.blockable).toBe(true);
  });
});

describe("calibration", () => {
  it("produces a monotone mapping inside [p_prior, 0.95]", () => {
    const artifact = fitCalibration(
      [
        { source: "semgrep", category: "CWE-78", raw: 0.2, label: 0 },
        { source: "semgrep", category: "CWE-78", raw: 0.5, label: 1 },
        { source: "semgrep", category: "CWE-78", raw: 0.8, label: 0 },
        { source: "semgrep", category: "CWE-78", raw: 0.9, label: 1 },
        { source: "semgrep", category: "CWE-78", raw: 0.95, label: 1 },
      ],
      {
        pPrior: 0.3,
        shrinkageN0: 10,
        pMax: 0.95,
        datasetVersion: "ds-test",
        rulesetFingerprint: "fp-test",
        categories: ["CWE-78"],
      },
      "fitroot",
    );
    const grid = artifact.grids[0]!;
    const values = grid.points.map((point) => point.p);
    for (let i = 1; i < values.length; i += 1) {
      expect(values[i]!).toBeGreaterThanOrEqual(values[i - 1]!);
    }
    for (const value of values) {
      expect(value).toBeGreaterThanOrEqual(0.3);
      expect(value).toBeLessThanOrEqual(0.95);
    }
    const mapped = applyCalibration({ source: "semgrep", cwe: "CWE-78", confidence: 0.9 }, artifact, 0.3);
    expect(mapped).toBeGreaterThanOrEqual(0.3);
    expect(mapped).toBeLessThanOrEqual(0.95);
  });

  it("returns the prior when no artifact is available", () => {
    expect(applyCalibration({ source: "aor", cwe: "CWE-79", confidence: 0.9 }, null, 0.25)).toBe(0.25);
  });
});

describe("vote", () => {
  it("uses w=1 for single source and w=0.75 for dual source", () => {
    const cfg = config();
    expect(weightFor(1, cfg)).toBe(1);
    expect(weightFor(2, cfg)).toBe(0.75);
  });

  it("discounts dual-source evidence instead of taking the max", () => {
    const full = fuseProbability([0.9, 0.9], 1, 0.3);
    const dual = fuseProbability([0.9, 0.9], 0.75, 0.3);
    expect(dual).toBeLessThan(full);
    expect(dual).not.toBeCloseTo(0.9);
    const cfg = config();
    const voted = vote([merged({ confidence: 0.5, sources: ["aor", "semgrep"], rawIds: ["a", "s"] })], new Map([
      ["a", 0.9],
      ["s", 0.6],
    ]), cfg);
    expect(voted[0]!.confidence).toBeGreaterThan(0.6);
    expect(voted[0]!.confidence).toBeLessThan(fuseProbability([0.9, 0.6], 1, 0.3));
  });
});

describe("fusion stages", () => {
  it("behaves like B3 when all stages are off", () => {
    const cfg = config();
    cfg.fusionStages.merge = false;
    cfg.fusionStages.conflict = false;
    cfg.fusionStages.calibrate = false;
    cfg.fusionStages.vote = false;
    const sources: SourceResult[] = [
      {
        source: "semgrep",
        status: "ok",
        findings: [finding({ rawId: "s1", source: "semgrep", confidence: 0.8 })],
        coverage: { filesCovered: 1, filesUnknown: 0 },
        tokens: null,
        latencyMs: 1,
      },
      {
        source: "aor",
        status: "ok",
        findings: [finding({ rawId: "a1", source: "aor", confidence: 0.6 })],
        coverage: { filesCovered: 1, filesUnknown: 0 },
        tokens: null,
        latencyMs: 1,
      },
    ];
    const out = fuse({ sources, config: cfg, artifact: null });
    expect(out.findings).toHaveLength(2);
    expect(out.pFused).toBeCloseTo(0.8);
  });

  it("never marks findings from degraded sources as blockable", () => {
    const cfg = config();
    const sources: SourceResult[] = [
      {
        source: "semgrep",
        status: "timeout",
        findings: [finding({ rawId: "s1", source: "semgrep", confidence: 0.99 })],
        coverage: { filesCovered: 0, filesUnknown: 1 },
        tokens: null,
        latencyMs: 1,
      },
    ];
    const out = fuse({ sources, config: cfg, artifact: null });
    expect(out.findings.every((item) => item.blockable === false)).toBe(true);
    expect(out.degradedOnly).toBe(true);
  });
});
