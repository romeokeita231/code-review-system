import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  AnnotationSample,
  Finding,
  RunConfig,
  SourceName,
  SourceResult,
} from "../../src/contracts/index.js";
import type { DatasetSample } from "../../src/l5/index.js";

export const BASE_CONFIG: RunConfig = {
  version: "1.0.0",
  mode: "replay",
  baseline: "B4g",
  sources: {
    semgrep: {
      enabled: true,
      command: "semgrep",
      osemgrepCommand: "osemgrep",
      version: "1.184.0",
      fullBlockMaxBytes: 102400,
      subsets: [
        {
          id: "py-block",
          path: "research/semgrep-bench/snapshot/py_block.yaml",
          sha256: "612934ee063172544c19624a043d03b9fc576be518a74b0b9d72fbacd1f98e90",
          langs: ["python"],
          blockRules: [],
        },
      ],
      timeoutsMs: { callMs: 5000 },
    },
    aor: {
      enabled: true,
      command: "ocr",
      versionCommit: "04deca6",
      outerCapMs: 180000,
      concurrency: 2,
      timeoutPerFileMs: 120000,
      maxChunks: 50,
      preview: { enabled: true, budgetSwitchRatio: 0.6 },
      tierTokens: { tier1: 60000, tier2: 150000 },
      tier2MaxTools: 100,
    },
    crg: { enabled: true, command: "python", indexTimeoutMs: 5000 },
    registry: { enabled: false, command: "npm", timeoutMs: 3000 },
  },
  fusionStages: { merge: true, conflict: true, calibrate: true, vote: true },
  tieBreak: "max",
  triage: {
    enabled: false,
    tier0: { filesMax: 3, nodesMax: 20 },
    tier1: { filesMax: 10, nodesMax: 100 },
  },
  budgets: {
    callMs: 8000,
    turnMs: 8000,
    semgrepKillMs: 5000,
    crgQueryMs: 300,
    fusionWriteMs: 500,
    softCapMs: 6000,
    cacheTtlMs: 300000,
    maxConcurrency: 2,
  },
  thresholds: { block: 0.9, warn: 0.7 },
  weights: { single: 1, dual: 0.75 },
  prior: { pPrior: 0.3 },
  calibration: { artifactPath: "artifacts/calibration.json", version: "calib-v1" },
  sMax: { python: 743188 },
  persistence: {
    jsonlPath: "runs/review.jsonl",
    rawDir: "runs/raw",
    turnStatePath: "runs/turn-state.json",
  },
};

export function makeConfig(overrides: Partial<RunConfig> = {}): RunConfig {
  return structuredClone({ ...BASE_CONFIG, ...overrides });
}

export function finding(
  source: SourceName,
  file: string,
  startLine: number,
  endLine: number,
  options: { cwe?: string | null; confidence?: number; id?: string } = {},
): Finding {
  const cwe = options.cwe === undefined ? "CWE-78" : options.cwe;
  const rawId = options.id ?? `${source}:${file}:${startLine}:${endLine}:${cwe ?? "-"}`;
  return {
    file,
    startLine,
    endLine,
    symbol: null,
    severity: 3,
    confidence: options.confidence ?? 0.4,
    source,
    cwe,
    evidence: null,
    rawId,
  };
}

export function result(
  source: SourceName,
  findings: Finding[],
  overrides: Partial<SourceResult> = {},
): SourceResult {
  return {
    source,
    status: "ok",
    findings,
    coverage: { filesCovered: 1, filesUnknown: 0 },
    tokens: source === "aor" ? 120 : null,
    latencyMs: 10,
    errorKind: null,
    ...overrides,
  };
}

export function makeSample(
  overrides: Partial<DatasetSample> & { sample_id: string },
): DatasetSample {
  const path = overrides.path ?? "src/app.py";
  return {
    group_id: overrides.group_id ?? `group-${overrides.sample_id}`,
    split: overrides.split ?? "eval",
    cwe: overrides.cwe === undefined ? "CWE-78" : overrides.cwe,
    risk_level: overrides.risk_level ?? "high",
    paired_safe: overrides.paired_safe ?? false,
    language: overrides.language ?? "python",
    path,
    changed_lines: overrides.changed_lines ?? 3,
    content_sha256: overrides.content_sha256 ?? "sha",
    expected_detectable_by: overrides.expected_detectable_by ?? ["semgrep", "aor"],
    before: overrides.before ?? "print('before')\n",
    after: overrides.after ?? "import os\nos.system(input())\n",
    labels: overrides.labels ?? [{ path, startLine: 2, endLine: 2, cwe: "CWE-78" }],
    sample_id: overrides.sample_id,
  };
}

function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export async function writeDataset(dir: string, samples: DatasetSample[]): Promise<void> {
  await mkdir(join(dir, "samples"), { recursive: true });
  const entries: AnnotationSample[] = samples.map((sample) => ({
    sample_id: sample.sample_id,
    group_id: sample.group_id,
    split: sample.split,
    cwe: sample.cwe,
    risk_level: sample.risk_level,
    paired_safe: sample.paired_safe,
    language: sample.language,
    path: sample.path,
    changed_lines: sample.changed_lines,
    content_sha256: sha256(sample.after),
    expected_detectable_by: sample.expected_detectable_by,
  }));
  const manifest = {
    version: "1.0.0",
    content_sha256_root: sha256(samples.map((sample) => sample.after).join("\n")),
    samples: entries,
  };
  await writeFile(join(dir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  for (const sample of samples) {
    await writeFile(
      join(dir, "samples", `${sample.sample_id}.json`),
      `${JSON.stringify(sample, null, 2)}\n`,
      "utf8",
    );
  }
}

export async function writeRecorded(
  dir: string,
  sampleId: string,
  results: SourceResult[],
): Promise<void> {
  const sampleDir = join(dir, sampleId);
  await mkdir(sampleDir, { recursive: true });
  for (const entry of results) {
    await writeFile(
      join(sampleDir, `${entry.source}.json`),
      `${JSON.stringify(entry, null, 2)}\n`,
      "utf8",
    );
  }
}
