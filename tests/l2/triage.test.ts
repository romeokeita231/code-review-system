import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { parseConfig } from "../../src/config/index.js";
import type { ChangeEvent, Finding, SignalSource, RunConfig, SourceResult } from "../../src/contracts/index.js";
import { computeTier, review, staticTier, TurnBudgetLedger } from "../../src/l2/index.js";

const boundaries = { tier0: { filesMax: 3, nodesMax: 20 }, tier1: { filesMax: 10, nodesMax: 100 } };

const input = (over: Partial<Parameters<typeof computeTier>[0]> = {}) => ({
  changedFiles: 1,
  impactedFiles: 2,
  impactedNodes: 10,
  truncated: false,
  unresolvedCallSites: 0,
  indexReady: true,
  indexStale: false,
  ...over,
});

describe("triage", () => {
  it("assigns tier 0 to a small untouched blast radius", () => {
    expect(computeTier(input(), boundaries)).toEqual({ tier: 0, source: "triage", degraded: false, skipReason: null });
  });

  it("assigns tier 1 up to the second boundary", () => {
    expect(computeTier(input({ impactedFiles: 8, impactedNodes: 80 }), boundaries).tier).toBe(1);
  });

  it("assigns tier 2 beyond the second boundary", () => {
    expect(computeTier(input({ impactedFiles: 40, impactedNodes: 900 }), boundaries).tier).toBe(2);
  });

  it("never returns tier 0 when the query truncated or call sites are unresolved", () => {
    expect(computeTier(input({ truncated: true }), boundaries).tier).toBe(1);
    expect(computeTier(input({ unresolvedCallSites: 3 }), boundaries).tier).toBe(1);
  });

  it("falls back to a static tier when the index is not ready or stale", () => {
    const notReady = computeTier(input({ indexReady: false }), boundaries);
    expect(notReady.source).toBe("static");
    expect(notReady.degraded).toBe(true);
    expect(notReady.skipReason).toBe("index_not_ready");
    const stale = computeTier(input({ indexStale: true, changedFiles: 20 }), boundaries);
    expect(stale.tier).toBe(2);
    expect(stale.skipReason).toBe("index_stale");
  });

  it("counts changed files for the static fallback tier", () => {
    expect(staticTier(1, boundaries)).toBe(0);
    expect(staticTier(5, boundaries)).toBe(1);
    expect(staticTier(50, boundaries)).toBe(2);
  });
});

const config = (): RunConfig => parseConfig(JSON.parse(readFileSync("configs/b4.json", "utf8")));

const event: ChangeEvent = {
  id: "triage-1",
  sessionId: "s",
  rootCallId: "c",
  phase: "post",
  trigger: "write",
  files: ["src/a.py"],
  diff: null,
  diffProvenance: "observed",
  ts: 1,
};

const aor = (): SignalSource => ({
  name: "aor",
  async review() {
    const findings: Finding[] = [
      {
        file: "src/a.py",
        startLine: 4,
        endLine: 4,
        severity: 2,
        confidence: 0.8,
        source: "aor",
        cwe: "CWE-79",
        evidence: "x",
        rawId: "aor-1",
      },
    ];
    const result: SourceResult = {
      source: "aor",
      status: "ok",
      findings,
      coverage: { filesCovered: 1, filesUnknown: 0 },
      tokens: 1200,
      latencyMs: 5,
    };
    return result;
  },
});

const semgrep = (): SignalSource => ({
  name: "semgrep",
  async review() {
    return {
      source: "semgrep",
      status: "ok",
      findings: [],
      coverage: { filesCovered: 1, filesUnknown: 0 },
      tokens: null,
      latencyMs: 1,
    };
  },
});

const clock = { now: () => 0 };

describe("triage as a budget gate", () => {
  it("skips AOR entirely at tier 0 but still reports a fused probability", async () => {
    let calls = 0;
    const outcome = await review(event, {
      runId: "r",
      config: config(),
      sources: [
        {
          name: "semgrep",
          async review() {
            return {
              source: "semgrep",
              status: "ok",
              findings: [
                {
                  file: "src/a.py",
                  startLine: 1,
                  endLine: 1,
                  severity: 2,
                  confidence: 0.5,
                  source: "semgrep",
                  cwe: "CWE-798",
                  evidence: "x",
                  rawId: "s-1",
                },
              ],
              coverage: { filesCovered: 1, filesUnknown: 0 },
              tokens: null,
              latencyMs: 1,
            };
          },
        },
        { name: "aor", async review() { calls += 1; return aor().review({} as never); } },
      ],
      artifact: null,
      clock,
      ledger: new TurnBudgetLedger(60000, clock),
      triage: {
        async analyze() {
          return {
            changedFiles: ["src/a.py"],
            impactedFiles: 1,
            impactedNodes: 3,
            truncated: false,
            unresolvedCallSites: 0,
            indexReady: true,
            indexStale: false,
          };
        },
      },
    });
    expect(outcome.disposition.tier).toBe(0);
    expect(calls).toBe(0);
    expect(outcome.row.tier_source).toBe("triage");
    expect(outcome.disposition.pFused).not.toBeNull();
    expect(outcome.disposition.gate?.perFileTier["src/a.py"]).toBe(0);
  });

  it("runs AOR at tier >= 1 and records the per-file tier", async () => {
    let calls = 0;
    const outcome = await review(event, {
      runId: "r",
      config: config(),
      sources: [semgrep(), { name: "aor", async review() { calls += 1; return aor().review({} as never); } }],
      artifact: null,
      clock,
      ledger: new TurnBudgetLedger(60000, clock),
      triage: {
        async analyze() {
          return {
            changedFiles: ["src/a.py"],
            impactedFiles: 9,
            impactedNodes: 90,
            truncated: false,
            unresolvedCallSites: 0,
            indexReady: true,
            indexStale: false,
          };
        },
      },
    });
    expect(outcome.disposition.tier).toBe(1);
    expect(calls).toBe(1);
    expect(outcome.row.tier_source).toBe("triage");
  });

  it("degrades to the static tier when the triage provider is unavailable", async () => {
    const outcome = await review(event, {
      runId: "r",
      config: config(),
      sources: [semgrep(), aor()],
      artifact: null,
      clock,
      ledger: new TurnBudgetLedger(60000, clock),
      triage: {
        async analyze() {
          throw new Error("crg missing");
        },
      },
    });
    expect(outcome.row.tier_source).toBe("static");
    expect(outcome.disposition.reviewStatus).toBe("degraded");
    expect(outcome.disposition.skipReason).toBe("index_not_ready");
  });
});
