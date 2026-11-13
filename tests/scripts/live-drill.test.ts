import { existsSync, readFileSync as readSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ReviewRow } from "../../src/contracts/index.js";
import {
  allSamples,
  assertRunDir,
  evaluate,
  frozenInstrumentsOf,
  newRunDir,
  NON_DEGRADABLE_GATES,
  parseDegradedGates,
  POSITIVE_CAP_PER_CLASS,
  planDrill,
  readRunManifest,
  stageDrill,
  toAcceptanceRows,
  writePrompt,
} from "../../scripts/live-drill.js";

const DATASET = "datasets/self-built";
const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

interface SampleStub {
  id: string;
  cwe: string | null;
  split?: "fit" | "eval";
  labels?: boolean;
  risk?: "low" | "medium" | "high";
  detectable?: string[];
  pairedSafe?: boolean;
}

/** A dataset + rules table small enough to reason about by hand. */
async function synthetic(samples: SampleStub[], rules: unknown[]): Promise<{ dir: string; rules: string }> {
  const root = await mkdtemp(join(tmpdir(), "crs-plan-"));
  tempDirs.push(root);
  const dir = join(root, "dataset");
  await mkdir(join(dir, "samples"), { recursive: true });
  const manifest = { version: "test", content_sha256_root: "x", samples: [] as unknown[] };
  for (const [index, stub] of samples.entries()) {
    const split = stub.split ?? "eval";
    const row = {
      sample_id: stub.id,
      group_id: `g${index}`,
      split,
      cwe: stub.cwe,
      risk_level: stub.risk ?? "high",
      paired_safe: stub.pairedSafe ?? false,
      language: "ts",
      path: `src/${stub.id}.ts`,
      before: "const a = 1;\n",
      after: "const a = 2;\n",
      changed_lines: 1,
      expected_detectable_by: stub.detectable ?? ["semgrep", "aor"],
      labels: stub.labels === false ? [] : [{ path: `src/${stub.id}.ts`, startLine: 1, endLine: 1, cwe: stub.cwe }],
    };
    await writeFile(join(dir, "samples", `${stub.id}.json`), JSON.stringify(row), "utf8");
    manifest.samples.push({ ...row, content_sha256: "x" });
  }
  await writeFile(join(dir, "manifest.json"), JSON.stringify(manifest), "utf8");
  const rulesPath = join(root, "rules_table.json");
  await writeFile(rulesPath, JSON.stringify({ rules }), "utf8");
  return { dir, rules: rulesPath };
}

describe("live drill plan", () => {
  it("plans a stratified positive set, low-risk samples and one dep probe", () => {
    const plan = planDrill(DATASET);
    // ds-2 stages one language per run and carries fewer eval positives than the
    // 20 the drill asks for, so the plan reports the shortfall in `warnings`.
    expect(plan.positives.length).toBeGreaterThan(0);
    expect(plan.positives.length).toBeLessThanOrEqual(20);
    // The low-risk pool is line 1's false-positive denominator, so it is staged
    // whole rather than capped: a cap would silently drop the create row.
    expect(plan.lowRisk.length).toBeGreaterThanOrEqual(8);
    expect(plan.warnings.some((warning) => warning.includes("rows in another language"))).toBe(true);
    expect(plan.probe.kind).toBe("dep-probe");
    for (const sample of plan.positives) {
      expect(sample.kind).toBe("positive");
      expect(sample.path.endsWith(".ts")).toBe(true);
      expect(sample.staged.startsWith(".staging/")).toBe(true);
    }
    for (const sample of plan.lowRisk) expect(sample.kind).toBe("low-risk");
  });

  it("caps each class and still covers at least five classes", () => {
    const plan = planDrill(DATASET);
    const perClass = new Map<string, number>();
    for (const sample of plan.positives) {
      const key = sample.cwe ?? "null";
      perClass.set(key, (perClass.get(key) ?? 0) + 1);
    }
    expect(perClass.size).toBeGreaterThanOrEqual(5);
    for (const [cwe, count] of perClass) {
      expect(count, `${cwe} exceeds the per-class cap`).toBeLessThanOrEqual(POSITIVE_CAP_PER_CLASS);
    }
  });

  it("orders positives by sha256(sample_id), not by id prefix", () => {
    const plan = planDrill(DATASET);
    const ids = plan.positives.map((sample) => sample.sampleId);
    // `localeCompare` ordering clusters by class prefix and was how the drill
    // ended up with ten CWE-022 and ten CWE-502 samples and nothing else.
    expect(ids).not.toEqual([...ids].sort((a, b) => a.localeCompare(b)));
    expect(planDrill(DATASET).positives.map((sample) => sample.sampleId)).toEqual(ids);
  });

  it("keeps the live set free of duplicate paths", () => {
    const plan = planDrill(DATASET);
    const paths = allSamples(plan).map((sample) => sample.path);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it("selects only eval-split, labelled positives", () => {
    const manifest = readSync(join(DATASET, "manifest.json"), "utf8");
    const byId = new Map(
      (JSON.parse(manifest) as { samples: Array<{ sample_id: string; split: string }> }).samples.map((entry) => [
        entry.sample_id,
        entry,
      ]),
    );
    for (const sample of planDrill(DATASET).positives) {
      const entry = byId.get(sample.sampleId);
      expect(entry?.split).toBe("eval");
      const row = JSON.parse(readSync(join(DATASET, "samples", `${sample.sampleId}.json`), "utf8")) as {
        defects: unknown[];
      };
      expect(row.defects.length).toBeGreaterThan(0);
    }
  });

  it("lists samples the ruleset cannot see instead of silently dropping them", () => {
    const plan = planDrill(DATASET);
    const uncovered = plan.coverage.uncovered;
    const picked = new Set(plan.positives.map((sample) => sample.sampleId));
    // Uncovered rows never enter the recall denominator...
    expect(uncovered.some((sample) => picked.has(sample.sampleId))).toBe(false);
    // ...and if there are any, the plan says so rather than dropping them.
    if (uncovered.length > 0) {
      expect(plan.warnings.some((warning) => warning.includes("outside the recall denominator"))).toBe(true);
    }
    for (const [cwe, count] of Object.entries(plan.coverage.declared)) {
      expect(count, `${cwe} declares no rule`).toBeGreaterThan(0);
    }
  });

  it("stages every defect-free low-risk row for line4 and line1", () => {
    // The negatives are small safe edits now, so a defect-free row is `low`
    // risk: the same pool serves line 4's B4/B4g pairs and line 1's
    // false-positive denominator. It is nine rows - eight edits and the create
    // smoke sample - and staging fewer would drop a kind out of the denominator.
    const plan = planDrill(DATASET);
    expect(plan.lowRisk.length).toBe(9);
    expect(plan.lowRisk.filter((sample) => sample.eventKind === "create").length).toBe(1);
    const defectFree = [...plan.lowRisk, ...plan.controls].filter((sample) => {
      const row = JSON.parse(readSync(join(DATASET, "samples", `${sample.sampleId}.json`), "utf8")) as {
        defects: unknown[];
        risk_level: string;
      };
      expect(row.risk_level).toBe("low");
      return row.defects.length === 0;
    });
    expect(defectFree.length).toBeGreaterThanOrEqual(8);
    expect(plan.warnings.some((warning) => warning.includes("no defect-free row"))).toBe(false);
  });

  it("does not select positives by expected_detectable_by", async () => {
    const { dir, rules } = await synthetic(
      [
        { id: "ts-cwe079-0001", cwe: "CWE-079", detectable: ["aor"] },
        { id: "ts-cwe079-0002", cwe: "CWE-079", detectable: ["semgrep"] },
        { id: "ts-cwe502-0001", cwe: "CWE-502", detectable: ["both"] },
        { id: "ts-cwe798-0003", cwe: "CWE-798", risk: "low", labels: false, pairedSafe: true },
      ],
      [{ id: "xss", languages: ["javascript", "typescript"], cwe: ["079"] }],
    );
    const plan = planDrill(dir, { limitPositives: 2, rulesTablePath: rules });
    expect(new Set(plan.positives.map((sample) => sample.sampleId))).toEqual(
      new Set(["ts-cwe079-0001", "ts-cwe079-0002"]),
    );
    expect(plan.coverage.uncovered.map((sample) => sample.sampleId)).toEqual(["ts-cwe502-0001"]);
    expect(plan.lowRisk.map((sample) => sample.sampleId)).toEqual(["ts-cwe798-0003"]);
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
  threshold_source: null,
  text: null,
  tokens: null,
  latency_ms: 4,
  status: "ok",
  toolchain: { semgrep: "1.184.0", aor: "04deca6", crg: "python", node: "v22", platform: "win32" },
  instrument: {
    semgrep: { name: "semgrep", version: "1.184.0", commit: null, source: "observed" },
    ocr: { name: "ocr", version: "v1.13.6", commit: "04deca6", source: "observed" },
  },
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

  it("carries the observed instrument through to the acceptance row", () => {
    const [converted] = toAcceptanceRows([row()], new Map([["src/a.ts", "s-1"]]), "B4");
    expect(converted?.instrument?.ocr.commit).toBe("04deca6");
  });
});

describe("degraded gates", () => {
  const known = ["semgrep version", "ocr pin", "dsh profile"];

  it("refuses the bare flag: a waiver has to name its gate", () => {
    expect(() => parseDegradedGates(["--allow-degraded"], known)).toThrow(/needs the gate names/);
  });

  it("refuses a gate that protects the measurement", () => {
    for (const gate of NON_DEGRADABLE_GATES) {
      expect(() => parseDegradedGates([`--allow-degraded=${gate}`], [...known, gate])).toThrow(
        /never be degraded/,
      );
    }
  });

  it("refuses a gate name that does not exist", () => {
    expect(() => parseDegradedGates(["--allow-degraded=semgrep scans"], known)).toThrow(/unknown gate/);
  });

  it("waives a named gate, once, and only that one", () => {
    expect(
      parseDegradedGates(["--allow-degraded=dsh profile", "--allow-degraded=dsh profile"], known),
    ).toEqual(["dsh profile"]);
  });
});

describe("run identity", () => {
  it("refuses an unnamed run directory", () => {
    // `runs/live` is exactly where the ds-1 staging and the ds-2 run would
    // otherwise share a directory.
    expect(() => assertRunDir("runs/live")).toThrow(/not a named run directory/);
    expect(() => assertRunDir("runs/live/scratch")).toThrow(/not a named run directory/);
  });

  it("mints a stamped directory that carries the dataset version", () => {
    const dir = newRunDir("runs/live", "ds-2.0.0", "eval", new Date("2026-11-13T04:30:05"));
    expect(dir.replace(/\\/g, "/")).toMatch(/runs\/live\/eval-ds-2\.0\.0-\d{8}T\d{6}$/);
    expect(() => assertRunDir(dir)).not.toThrow();
  });

  it("refuses a run staged on another dataset", async () => {
    const root = await mkdtemp(join(tmpdir(), "crs-run-"));
    tempDirs.push(root);
    const dir = join(root, "eval-ds-1.0.0-20261101T000000");
    await mkdir(dir, { recursive: true });
    await writeFile(
      join(dir, "run.json"),
      `${JSON.stringify({ dataset_version: "ds-1.0.0", degraded_gates: [] }, null, 2)}\n`,
      "utf8",
    );
    expect(() => readRunManifest(dir, DATASET)).toThrow(/refusing to mix measurements/);
  });

  it("refuses a directory that was never staged", async () => {
    const root = await mkdtemp(join(tmpdir(), "crs-run-"));
    tempDirs.push(root);
    const dir = join(root, "eval-ds-2.0.0-20261101T000000");
    await mkdir(dir, { recursive: true });
    expect(() => readRunManifest(dir, DATASET)).toThrow(/has no run.json/);
  });

  it("stages a run whose run.json names its dataset, pin and waived gates", { timeout: 120000 }, async () => {
    const root = await mkdtemp(join(tmpdir(), "crs-stage-"));
    tempDirs.push(root);
    const outDir = newRunDir(root, "ds-2.0.0", "eval", new Date("2026-11-13T04:30:05"));
    const plan = planDrill(DATASET, { limitPositives: 1 });
    await stageDrill({
      datasetDir: DATASET,
      outDir,
      baseConfig: "configs/b4.json",
      profile: "crs-live",
      plan,
      degradedGates: ["dsh profile"],
    });

    const manifest = readRunManifest(outDir, DATASET);
    expect(manifest.dataset_version).toBe("ds-2.0.0");
    expect(manifest.frozen_instruments).toEqual({
      semgrep: { version: "1.184.0" },
      ocr: { commit: "04deca6" },
    });
    expect(manifest.degraded_gates).toEqual(["dsh profile"]);
    expect(manifest.plan.negatives_create).toBe(1);

    for (const baseline of ["B4", "B4g"]) {
      expect(existsSync(join(outDir, "scratch", baseline, "plan.json"))).toBe(true);
      expect(existsSync(join(outDir, baseline, "config.json"))).toBe(true);
      const config = JSON.parse(readSync(join(outDir, baseline, "config.json"), "utf8")) as { mode: string };
      expect(config.mode).toBe("live");
    }
    // The staged text is the sample's `after`, so a create row really is a whole
    // file and an edit row is the whole edited file.
    const create = plan.lowRisk.find((sample) => sample.eventKind === "create")!;
    const staged = readSync(join(outDir, "scratch", "B4", create.staged), "utf8");
    const sample = JSON.parse(readSync(join(DATASET, "samples", `${create.sampleId}.json`), "utf8")) as {
      after: string;
      before: string;
    };
    expect(sample.before).toBe("");
    expect(staged).toBe(sample.after);
  });
});

describe("evaluate refuses a drifted measurement", () => {
  async function collectedRun(drifted: boolean): Promise<{ root: string; outDir: string }> {
    const root = await mkdtemp(join(tmpdir(), "crs-eval-"));
    tempDirs.push(root);
    const outDir = newRunDir(root, "ds-2.0.0", "eval", new Date("2026-11-13T04:30:05"));
    await mkdir(outDir, { recursive: true });
    await writeFile(
      join(outDir, "run.json"),
      `${JSON.stringify(
        {
          dataset_version: "ds-2.0.0",
          dataset_dir: DATASET,
          config_hash: "hash",
          frozen_instruments: frozenInstrumentsOf("configs/b4.json"),
          created_at: "2026-11-13T04:30:05Z",
          plan: { positives: 1, low_risk: 1, controls: 0, probe: 1, negatives_create: 1 },
          degraded_gates: [],
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    const instrumentRow = {
      semgrep: { name: "semgrep", version: "1.184.0", commit: null, source: "observed" as const },
      ocr: drifted
        ? { name: "ocr", version: "v1.13.8", commit: "4236c87", source: "observed" as const }
        : { name: "ocr", version: "v1.13.6", commit: "04deca6", source: "observed" as const },
    };
    const rows = [
      toAcceptanceRows([row()], new Map([["src/a.ts", "ts-cwe079-0001"]]), "B4")[0]!,
    ].map((entry) => ({ ...entry, instrument: instrumentRow }));
    await writeFile(join(outDir, "rows.jsonl"), `${rows.map((entry) => JSON.stringify(entry)).join("\n")}\n`, "utf8");
    return { root, outDir };
  }

  it("refuses to write a report when the pinned ocr commit changed", async () => {
    const { root, outDir } = await collectedRun(true);
    await expect(
      evaluate(outDir, DATASET, "artifacts/block-gaps.json", join(root, "out"), {
        language: "typescript",
        perCwe: {},
      }),
    ).rejects.toThrow(/refusing to report/);
  });

  it("writes a report that names the instruments it was produced on", async () => {
    const { root, outDir } = await collectedRun(false);
    const result = await evaluate(outDir, DATASET, "artifacts/block-gaps.json", join(root, "out"), {
      language: "typescript",
      perCwe: {},
    });
    expect(result.lines).toHaveLength(5);
    const report = readSync(join(root, "out", "report.md"), "utf8");
    expect(report).toContain("instruments (observed");
    expect(report).toContain("04deca6");
  });
});
