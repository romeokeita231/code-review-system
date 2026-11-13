import { describe, expect, it } from "vitest";
import { parseConfig } from "../../src/config/index.js";
import { readFileSync } from "node:fs";
import type {
  CalibrationArtifact,
  ChangeEvent,
  Finding,
  RunConfig,
  SignalSource,
  SourceResult,
} from "../../src/contracts/index.js";
import { DenyGuard, TurnBudgetLedger, review } from "../../src/l2/index.js";

const baseConfig = (): RunConfig =>
  parseConfig(JSON.parse(readFileSync("configs/b4g.json", "utf8")));

const artifact: CalibrationArtifact = {
  version: "calib-test",
  dataset_version: "ds-test",
  ruleset_fingerprint: "fp-test",
  categories: ["CWE-78", "CWE-79"],
  pPrior: 0.3,
  shrinkageN0: 10,
  pMax: 0.95,
  fitRoot: "fitroot",
  grids: [
    {
      source: "semgrep",
      category: "CWE-78",
      n: 40,
      points: [{ rawLow: 0.5, rawHigh: 1, p: 0.95 }],
    },
    {
      source: "aor",
      category: "CWE-79",
      n: 40,
      points: [{ rawLow: 0.5, rawHigh: 1, p: 0.85 }],
    },
    {
      source: "semgrep",
      category: "CWE-798",
      n: 40,
      points: [{ rawLow: 0.5, rawHigh: 1, p: 0.6 }],
    },
  ],
  thresholds: { global: { block: 0.9, warn: 0.7 }, perCategory: {}, skipped: [] },
};

const finding = (over: Partial<Finding> = {}): Finding => ({
  file: "src/demo/app.py",
  startLine: 3,
  endLine: 3,
  severity: 3,
  confidence: 0.95,
  source: "semgrep",
  cwe: "CWE-78",
  evidence: "os.system(cmd)",
  rawId: "command-injection-os-system\u0000src/demo/app.py\u00003\u00003",
  ...over,
});

const event = (over: Partial<ChangeEvent> = {}): ChangeEvent => ({
  id: "evt-1",
  sessionId: "sess-1",
  rootCallId: "call-1",
  phase: "post",
  trigger: "write",
  files: ["src/demo/app.py"],
  diff: "@@ -1 +1 @@\n-x\n+y\n",
  diffProvenance: "observed",
  ts: 1762400000000,
  ...over,
});

const result = (source: SourceResult["source"], findings: Finding[]): SourceResult => ({
  source,
  status: "ok",
  findings,
  coverage: { filesCovered: 1, filesUnknown: 0 },
  tokens: null,
  latencyMs: 10,
});

const source = (name: SignalSource["name"], script: SourceResult[]): SignalSource => {
  let index = 0;
  return {
    name,
    async review() {
      const next = script[Math.min(index, script.length - 1)]!;
      index += 1;
      return next;
    },
  };
};

function withConfig(over: (config: RunConfig) => void): RunConfig {
  const config = baseConfig();
  over(config);
  return parseConfig(JSON.parse(JSON.stringify(config)));
}

describe("review facade", () => {
  it("denies a blocking semgrep finding with the CRS-BLOCK template", async () => {
    const outcome = await review(event(), {
      runId: "run-1",
      config: withConfig((config) => {
        config.sources.registry.enabled = false;
      }),
      sources: [source("semgrep", [result("semgrep", [finding()])])],
      artifact,
    });
    expect(outcome.disposition.preDecision).toBe("deny");
    expect(outcome.disposition.finalDisposition).toBe("mechanical_block");
    expect(outcome.disposition.pSemgrep).toBeCloseTo(0.95);
    expect(outcome.disposition.text).toContain("[CRS-BLOCK]");
    expect(outcome.disposition.text).toContain("CWE-78");
    expect(outcome.disposition.text).toContain("command-injection-os-system");
    expect(outcome.row.config_hash).toBeTruthy();
    expect(outcome.row.pre_decision).toBe("deny");
    expect(outcome.row.review_skip_reason).toBeNull();
  });

  it("fails open on a semgrep timeout and never emits deny", async () => {
    const outcome = await review(event(), {
      runId: "run-2",
      config: withConfig((config) => {
        config.sources.registry.enabled = false;
      }),
      sources: [
        source("semgrep", [
          {
            source: "semgrep",
            status: "timeout",
            findings: [],
            coverage: { filesCovered: 0, filesUnknown: 1 },
            tokens: null,
            latencyMs: 5000,
            errorKind: "timeout",
          },
        ]),
      ],
      artifact,
    });
    expect(outcome.disposition.preDecision).not.toBe("deny");
    expect(outcome.disposition.reviewStatus).toBe("degraded");
    expect(outcome.row.status).toBe("timeout");
    expect(outcome.row.pre_decision).toBe("allow");
  });

  it("skips the scan when the turn budget is exhausted", async () => {
    const clock = { value: 0, now() { return this.value; } };
    const ledger = new TurnBudgetLedger(1000, clock);
    const outcome = await review(event(), {
      runId: "run-3",
      config: withConfig((config) => {
        config.sources.registry.enabled = false;
      }),
      sources: [source("semgrep", [result("semgrep", [finding()])])],
      artifact,
      ledger,
      clock,
    });
    expect(outcome.disposition.reviewStatus).toBe("skipped");
    expect(outcome.disposition.skipReason).toBe("turn_budget_exhausted");
    expect(outcome.disposition.preDecision).toBe("not_run");
  });

  it("stops denying the third consecutive block on the same group", async () => {
    const guard = new DenyGuard();
    const config = withConfig((config) => {
      config.sources.registry.enabled = false;
    });
    const sources = [source("semgrep", [result("semgrep", [finding()])])];
    const first = await review(event(), { runId: "r", config, sources, artifact, guard });
    const second = await review(event(), { runId: "r", config, sources, artifact, guard });
    const third = await review(event(), { runId: "r", config, sources, artifact, guard });
    expect(first.disposition.preDecision).toBe("deny");
    expect(second.disposition.preDecision).toBe("deny");
    expect(third.disposition.preDecision).toBe("allow");
    expect(third.disposition.blockLoop).toBe(true);
  });

  it("keeps p_fused as the single-source calibrated value at tier 0", async () => {
    let aorCalls = 0;
    const outcome = await review(event(), {
      runId: "run-4",
      config: withConfig((config) => {
        config.triage.enabled = true;
        config.sources.registry.enabled = false;
      }),
      sources: [
        source("semgrep", [result("semgrep", [finding({ cwe: "CWE-798", confidence: 0.6, severity: 2 })])]),
        {
          name: "aor",
          async review() {
            aorCalls += 1;
            return result("aor", []);
          },
        },
      ],
      artifact,
      triage: {
        async analyze() {
          return {
            changedFiles: ["src/demo/app.py"],
            impactedFiles: 1,
            impactedNodes: 5,
            truncated: false,
            unresolvedCallSites: 0,
            indexReady: true,
            indexStale: false,
          };
        },
      },
    });
    expect(outcome.disposition.tier).toBe(0);
    expect(aorCalls).toBe(0);
    expect(outcome.disposition.pFused).toBeCloseTo(0.6);
  });

  it("injects a CRS-WARN for a semantic finding above the warn threshold", async () => {
    const outcome = await review(event(), {
      runId: "run-5",
      config: withConfig((config) => {
        config.sources.registry.enabled = false;
      }),
      sources: [
        source("semgrep", [result("semgrep", [])]),
        source("aor", [
          result("aor", [
            finding({
              source: "aor",
              cwe: "CWE-79",
              evidence: "returns unescaped user input",
              rawId: "aor-1",
            }),
          ]),
        ]),
      ],
      artifact,
    });
    expect(outcome.disposition.postDecision).toBe("inject_warn");
    expect(outcome.disposition.text).toContain("[CRS-WARN]");
    expect(outcome.disposition.text).toContain("CWE-79");
    expect(outcome.disposition.finalDisposition).toBe("instruction_correction");
  });

  it("records command events without reviewing them", async () => {
    const outcome = await review(event({ trigger: "command", files: null, diff: null, diffProvenance: "none" }), {
      runId: "run-6",
      config: baseConfig(),
      sources: [source("semgrep", [result("semgrep", [finding()])])],
      artifact,
    });
    expect(outcome.disposition.reviewStatus).toBe("skipped");
    expect(outcome.disposition.skipReason).toBe("command_event");
    expect(outcome.row.change_event.files).toBeNull();
    expect(outcome.disposition.finalDisposition).toBe("record");
  });

  it("keeps semgrep blocking independent from the triage gate", async () => {
    const enabled = await review(event(), {
      runId: "run-7",
      config: withConfig((config) => {
        config.triage.enabled = true;
        config.sources.registry.enabled = false;
      }),
      sources: [source("semgrep", [result("semgrep", [finding()])])],
      artifact,
      triage: {
        async analyze() {
          return {
            changedFiles: ["src/demo/app.py"],
            impactedFiles: 40,
            impactedNodes: 900,
            truncated: false,
            unresolvedCallSites: 0,
            indexReady: true,
            indexStale: false,
          };
        },
      },
    });
    expect(enabled.disposition.tier).toBe(2);
    expect(enabled.disposition.preDecision).toBe("deny");
  });

  it("propagates an unfittable threshold instead of substituting a constant", async () => {
    const unfittable: CalibrationArtifact = {
      ...artifact,
      thresholds: { global: { block: null, warn: null }, perCategory: {}, skipped: [] },
    };
    const config = withConfig((cfg) => {
      cfg.sources.registry.enabled = false;
    });

    // The block face is gated by rule certification, not by a probability the
    // artifact could not certify.
    const certified = await review(event(), {
      runId: "run-8",
      config,
      sources: [source("semgrep", [result("semgrep", [finding()])])],
      artifact: unfittable,
    });
    expect(certified.disposition.preDecision).toBe("deny");

    // A finding the ruleset did not certify still cannot block.
    const uncertified = await review(event(), {
      runId: "run-9",
      config,
      sources: [source("semgrep", [result("semgrep", [finding({ certified: false })])])],
      artifact: unfittable,
    });
    expect(uncertified.disposition.preDecision).toBe("allow");

    // A warning is a precision claim, so no probability threshold may be
    // invented. It need not be *silent*: the sources' own severity is a policy
    // with no fitted parameter, and the row says so.
    const warned = await review(event(), {
      runId: "run-10",
      config,
      sources: [
        source("semgrep", [result("semgrep", [])]),
        source("aor", [
          result("aor", [
            finding({ source: "aor", cwe: "CWE-79", rawId: "aor-1", evidence: "returns user input" }),
          ]),
        ]),
      ],
      artifact: unfittable,
    });
    expect(warned.disposition.postDecision).toBe("inject_warn");
    expect(warned.disposition.thresholdSource).toBe("severity_policy");
    expect(warned.row.threshold_source).toBe("severity_policy");
    expect(warned.disposition.text).toContain("via=aor/sev=aor");

    // The policy is the source's own "warning or worse", not "any finding".
    const info = await review(event(), {
      runId: "run-11",
      config,
      sources: [
        source("semgrep", [result("semgrep", [])]),
        source("aor", [
          result("aor", [
            finding({ source: "aor", cwe: "CWE-79", rawId: "aor-2", severity: 1, evidence: "note" }),
          ]),
        ]),
      ],
      artifact: unfittable,
    });
    expect(info.disposition.postDecision).not.toBe("inject_warn");
  });
});
