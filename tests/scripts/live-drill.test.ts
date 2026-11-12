import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { ReviewRow } from "../../src/contracts/index.js";
import { allSamples, planDrill, toAcceptanceRows, writePrompt } from "../../scripts/live-drill.js";

describe("live drill plan", () => {
  it("plans 20 semgrep-detectable eval positives, 8 low-risk samples and one dep probe", () => {
    const plan = planDrill("datasets/self-built");
    expect(plan.positives).toHaveLength(20);
    expect(plan.lowRisk).toHaveLength(8);
    expect(plan.probe.kind).toBe("dep-probe");
    for (const sample of plan.positives) {
      expect(sample.kind).toBe("positive");
      expect(sample.path.endsWith(".ts")).toBe(true);
      expect(sample.staged.startsWith(".staging/")).toBe(true);
    }
    for (const sample of plan.lowRisk) expect(sample.kind).toBe("low-risk");
  });

  it("keeps the live set free of duplicate paths", () => {
    const plan = planDrill("datasets/self-built");
    const paths = allSamples(plan).map((sample) => sample.path);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it("selects only eval-split, labelled, semgrep-detectable positives", () => {
    const manifest = JSON.parse(readFileSync("datasets/self-built/manifest.json", "utf8")) as {
      samples: Array<{ sample_id: string; split: string; expected_detectable_by: string[] }>;
    };
    const byId = new Map(manifest.samples.map((entry) => [entry.sample_id, entry]));
    for (const sample of planDrill("datasets/self-built").positives) {
      const entry = byId.get(sample.sampleId);
      expect(entry?.split).toBe("eval");
      expect(entry?.expected_detectable_by).toContain("semgrep");
    }
  });

  it("asks the driver for one write per entry and no shell", () => {
    const prompt = writePrompt(29);
    expect(prompt).toContain("There are 29 entries");
    expect(prompt).toContain("write tool");
    expect(prompt).toContain("do not use bash");
  });
});

const row = (over: Partial<ReviewRow> = {}): ReviewRow => ({
  run_id: "run-1",
  config_hash: "hash",
  baseline: "B4",
  mode: "live",
  change_event: {
    id: "evt",
    sessionId: "sess",
    rootCallId: "call",
    phase: "post",
    trigger: "write",
    files: ["src/a.ts"],
    diff: null,
    diffProvenance: "observed",
    ts: 1,
  },
  tier: 0,
  tier_source: "triage",
  sources: [
    {
      source: "semgrep",
      status: "degraded",
      findings: [],
      coverage: { filesCovered: 0, filesUnknown: 1 },
      tokens: null,
      latencyMs: 3,
      errorKind: "semgrep_failed",
    },
  ],
  findings_merged: [],
  p_semgrep: null,
  p_fused: null,
  pre_decision: "allow",
  post_decision: "none",
  final_disposition: "record",
  review_status: "degraded",
  review_skip_reason: null,
  block_loop: false,
  text: null,
  tokens: null,
  latency_ms: 4,
  status: "ok",
  toolchain: { semgrep: "1.184.0", aor: "04deca6", crg: "python", node: "v22", platform: "win32" },
  ...over,
});

describe("acceptance row conversion", () => {
  it("maps a plugin row to the evaluator shape", () => {
    const [converted] = toAcceptanceRows([row()], new Map([["src/a.ts", "s-1"]]), "B4");
    expect(converted?.sample).toBe("s-1");
    expect(converted?.mode).toBe("live");
    expect(converted?.disposition.preDecision).toBe("allow");
    expect(converted?.change_event?.phase).toBe("post");
  });

  it("drops command events and unplanned paths", () => {
    const command = row({
      change_event: {
        id: "c",
        sessionId: "s",
        rootCallId: "c",
        phase: "post",
        trigger: "command",
        files: null,
        diff: null,
        diffProvenance: "none",
        ts: 1,
      },
    });
    const unplanned = row();
    unplanned.change_event = { ...unplanned.change_event, files: ["src/other.ts"] };
    expect(toAcceptanceRows([command], new Map([["src/a.ts", "s-1"]]), "B4")).toHaveLength(0);
    expect(toAcceptanceRows([unplanned], new Map([["src/a.ts", "s-1"]]), "B4")).toHaveLength(0);
  });

  it("keeps both phases so the evaluator can separate them", () => {
    const pre = row({ change_event: { ...row().change_event, phase: "pre" } });
    const converted = toAcceptanceRows([pre, row()], new Map([["src/a.ts", "s-1"]]), "B4");
    expect(converted.map((entry) => entry.change_event?.phase)).toEqual(["pre", "post"]);
  });
});
